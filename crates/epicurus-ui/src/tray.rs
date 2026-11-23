//! The tray agent (`epicurus ui --tray`): a status icon in the notification
//! area plus toasts for incidents. It runs in the user's session without a
//! window and is started by the service at logon.

use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use epicurus_core::incident::ActionKind;
use epicurus_core::ipc::{Client, Event, ProtectionState, Request, Response};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::System::WinRT::{RO_INIT_SINGLETHREADED, RoInitialize};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MSG, MsgWaitForMultipleObjects, PM_REMOVE, PeekMessageW, QS_ALLINPUT,
    TranslateMessage, WM_QUIT,
};
use windows::core::w;

use crate::client::Verifier;
use crate::icon::{Tone, shield_rgba};
use crate::toast::{self, ToastAction};

enum FromService {
    Event(Event),
    Status(Result<(ProtectionState, usize), String>),
}

fn icon(tone: Tone) -> Option<Icon> {
    Icon::from_rgba(shield_rgba(32, tone), 32, 32).ok()
}

fn spawn_dashboard(incident: Option<&str>) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("ui");
    if let Some(id) = incident {
        cmd.args(["--incident", id]);
    }
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let _ = cmd.spawn();
}

/// Subscribes to pushed events, reconnecting with backoff.
fn event_thread(pipe: String, verifier: Verifier, tx: Sender<FromService>) {
    std::thread::spawn(move || {
        let mut backoff = Duration::from_secs(1);
        loop {
            if let Ok(mut c) = Client::connect(&pipe)
                && verifier(&c)
                && c.subscribe().is_ok()
            {
                backoff = Duration::from_secs(1);
                while let Ok(ev) = c.next_event() {
                    if tx.send(FromService::Event(ev)).is_err() {
                        return;
                    }
                }
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    });
}

/// Polls status every few seconds for the icon color.
fn status_thread(pipe: String, verifier: Verifier, tx: Sender<FromService>) {
    std::thread::spawn(move || {
        loop {
            let r = Client::connect(&pipe)
                .map_err(|e| e.to_string())
                .and_then(|mut c| {
                    if !verifier(&c) {
                        return Err("pipe not owned by the service".to_string());
                    }
                    match c.call(Request::Status) {
                        Ok(Response::Status(s)) => Ok((s.protection, s.pending.len())),
                        Ok(_) => Err("unexpected reply".into()),
                        Err(e) => Err(e.to_string()),
                    }
                });
            if tx.send(FromService::Status(r)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

fn do_action(pipe: &str, verifier: &Verifier, id: String, action: ActionKind) {
    let pipe = pipe.to_string();
    let verifier = verifier.clone();
    std::thread::spawn(move || {
        if let Ok(mut c) = Client::connect(&pipe)
            && verifier(&c)
        {
            let _ = c.call(Request::IncidentAction { id, action });
        }
    });
}

/// Runs the agent until "Quit" is chosen.
pub fn run(pipe: String, verifier: Verifier) -> crate::error::Result<()> {
    // One agent per session.
    // SAFETY: named mutex in the session namespace; kept for process lifetime.
    let _mutex = unsafe { CreateMutexW(None, true, w!("Local\\EpicurusTrayAgent")) }?;
    // SAFETY: reads the thread's last error right after CreateMutexW.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Ok(());
    }
    // SAFETY: initializes WinRT for toasts on this thread.
    unsafe { RoInitialize(RO_INIT_SINGLETHREADED) }?;
    toast::register_aumid();

    let menu = Menu::new();
    let status_item = MenuItem::new("Status: connecting...", false, None);
    let open_item = MenuItem::new("Open dashboard", true, None);
    let quit_item = MenuItem::new("Quit tray icon", true, None);
    menu.append_items(&[
        &status_item,
        &PredefinedMenuItem::separator(),
        &open_item,
        &quit_item,
    ])?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Epicurus")
        .with_icon(
            icon(Tone::Gray)
                .ok_or_else(|| crate::error::UiError::Tray("could not build the icon".into()))?,
        )
        .build()?;

    let (svc_tx, svc_rx): (Sender<FromService>, Receiver<FromService>) = std::sync::mpsc::channel();
    let (act_tx, act_rx) = std::sync::mpsc::channel::<ToastAction>();
    event_thread(pipe.clone(), verifier.clone(), svc_tx.clone());
    status_thread(pipe.clone(), verifier.clone(), svc_tx);

    let mut tone = Tone::Gray;
    let mut last_click = Instant::now() - Duration::from_secs(10);
    loop {
        // Pump Win32 messages for the tray window.
        let mut msg = MSG::default();
        // SAFETY: standard message loop on this thread.
        unsafe {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == WM_QUIT {
                    return Ok(());
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            MsgWaitForMultipleObjects(None, false, 200, QS_ALLINPUT);
        }

        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == open_item.id() {
                spawn_dashboard(None);
            } else if ev.id == quit_item.id() {
                return Ok(());
            }
        }
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::DoubleClick { .. } = ev
                && last_click.elapsed() > Duration::from_secs(1)
            {
                last_click = Instant::now();
                spawn_dashboard(None);
            }
        }
        while let Ok(a) = act_rx.try_recv() {
            match a {
                ToastAction::Kill(id) => do_action(&pipe, &verifier, id, ActionKind::KillTree),
                ToastAction::Resume(id) => do_action(&pipe, &verifier, id, ActionKind::Resume),
                ToastAction::Open(id) => spawn_dashboard(Some(&id)),
            }
        }
        while let Ok(m) = svc_rx.try_recv() {
            match m {
                FromService::Event(Event::Incident {
                    summary,
                    toast: true,
                    ..
                }) => {
                    if let Err(e) =
                        toast::show(&toast::incident_xml(&summary), &summary.id, act_tx.clone())
                    {
                        tracing::warn!(error = %e, "toast failed");
                    }
                }
                FromService::Event(Event::TestToast) => {
                    let _ = toast::show_test(act_tx.clone());
                }
                FromService::Event(_) => {}
                FromService::Status(r) => {
                    let (new_tone, text) = match r {
                        Ok((_, pending)) if pending > 0 => (
                            Tone::Red,
                            format!("Status: {pending} incident(s) awaiting decision"),
                        ),
                        Ok((ProtectionState::Protected, _)) => {
                            (Tone::Green, "Status: protected".to_string())
                        }
                        Ok((ProtectionState::Degraded, _)) => {
                            (Tone::Amber, "Status: degraded".to_string())
                        }
                        Ok((ProtectionState::Unprotected, _)) => {
                            (Tone::Red, "Status: unprotected".to_string())
                        }
                        Err(e) => (
                            Tone::Gray,
                            format!(
                                "Status: service unreachable ({})",
                                e.chars().take(60).collect::<String>()
                            ),
                        ),
                    };
                    status_item.set_text(&text);
                    let _ = tray.set_tooltip(Some(format!(
                        "Epicurus - {}",
                        text.trim_start_matches("Status: ")
                    )));
                    if new_tone != tone {
                        tone = new_tone;
                        let _ = tray.set_icon(icon(tone));
                    }
                }
            }
        }
    }
}
