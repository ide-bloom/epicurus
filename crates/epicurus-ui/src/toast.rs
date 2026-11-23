//! Windows toast notifications with Kill / Resume / Open buttons.
//!
//! Epicurus is an unpackaged desktop app, so toasts need an AppUserModelID
//! registered either through a Start Menu shortcut (created by `install`)
//! or under `HKCU\Software\Classes\AppUserModelId` (done here at agent
//! start). Button presses arrive through the `Activated` event while the
//! tray agent is running.

use std::sync::mpsc::Sender;

use epicurus_core::incident::{IncidentStatus, IncidentSummary};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{
    ToastActivatedEventArgs, ToastNotification, ToastNotificationManager,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegSetValueExW,
};
use windows::core::{HSTRING, IInspectable, Interface, PCWSTR};

/// What the user clicked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToastAction {
    /// Kill the incident's process tree.
    Kill(String),
    /// Resume it.
    Resume(String),
    /// Open the incident in the dashboard.
    Open(String),
}

/// Parses toast activation arguments (`action=kill&id=inc_...`).
pub fn parse_args(args: &str) -> Option<ToastAction> {
    let mut action = None;
    let mut id = None;
    for kv in args.split('&') {
        match kv.split_once('=') {
            Some(("action", v)) => action = Some(v.to_string()),
            Some(("id", v)) => id = Some(v.to_string()),
            _ => {}
        }
    }
    let id = id.filter(|i| epicurus_core::incident::is_valid_incident_id(i))?;
    match action?.as_str() {
        "kill" => Some(ToastAction::Kill(id)),
        "resume" => Some(ToastAction::Resume(id)),
        "open" => Some(ToastAction::Open(id)),
        _ => None,
    }
}

fn xml_escape(s: &str) -> String {
    epicurus_core::report::html::escape(s)
}

/// Builds the toast XML for an incident.
pub fn incident_xml(s: &IncidentSummary) -> String {
    let image = s.image.rsplit('\\').next().unwrap_or(&s.image);
    let pending = s.status == IncidentStatus::AwaitingDecision;
    let title = if pending {
        format!("Epicurus suspended {image}")
    } else {
        format!("Epicurus: decoy credentials opened by {image}")
    };
    let body = format!(
        "PID {} touched {} decoy(s) in {} categor{}. Severity {} ({}/100){}.",
        s.pid,
        s.decoys,
        s.categories.len(),
        if s.categories.len() == 1 { "y" } else { "ies" },
        s.severity,
        s.score,
        if s.simulated { ", simulation" } else { "" }
    );
    let id = &s.id;
    let mut actions = String::new();
    if pending {
        actions.push_str(&format!(r#"<action content="Kill" arguments="action=kill&amp;id={id}" activationType="foreground"/>"#));
        actions.push_str(&format!(r#"<action content="Resume" arguments="action=resume&amp;id={id}" activationType="foreground"/>"#));
    }
    actions.push_str(&format!(r#"<action content="Open" arguments="action=open&amp;id={id}" activationType="foreground"/>"#));
    format!(
        r#"<toast launch="action=open&amp;id={id}" scenario="{}"><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text><text placement="attribution">Epicurus</text></binding></visual><actions>{actions}</actions></toast>"#,
        if pending { "reminder" } else { "default" },
        xml_escape(&title),
        xml_escape(&body)
    )
}

/// Registers the AppUserModelID in the user's hive.
pub fn register_aumid() {
    let key_path: Vec<u16> = format!(
        r"Software\Classes\AppUserModelId\{}",
        epicurus_core::APP_USER_MODEL_ID
    )
    .encode_utf16()
    .chain([0])
    .collect();
    let mut key = HKEY::default();
    // SAFETY: creating our own key under HKCU.
    if unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
    }
    .is_err()
    {
        return;
    }
    let set_sz = |name: &str, value: &str| {
        let n: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let v: Vec<u8> = value
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        // SAFETY: key open for write; buffers valid.
        let _ = unsafe { RegSetValueExW(key, PCWSTR(n.as_ptr()), Some(0), REG_SZ, Some(&v)) };
    };
    set_sz("DisplayName", "Epicurus");
    let n: Vec<u16> = "ShowInSettings".encode_utf16().chain([0]).collect();
    // SAFETY: as above.
    let _ = unsafe {
        RegSetValueExW(
            key,
            PCWSTR(n.as_ptr()),
            Some(0),
            REG_DWORD,
            Some(&1u32.to_le_bytes()),
        )
    };
    // SAFETY: key opened above.
    unsafe {
        let _ = RegCloseKey(key);
    }
}

/// Shows a toast; button presses are sent to `actions`.
pub fn show(xml: &str, tag: &str, actions: Sender<ToastAction>) -> windows::core::Result<()> {
    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(xml))?;
    let toast = ToastNotification::CreateToastNotification(&doc)?;
    toast.SetTag(&HSTRING::from(tag.chars().take(64).collect::<String>()))?;
    toast.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(
        move |_, args| {
            if let Some(args) = args.as_ref()
                && let Ok(a) = args.cast::<ToastActivatedEventArgs>()
                && let Ok(s) = a.Arguments()
                && let Some(action) = parse_args(&s.to_string_lossy())
            {
                let _ = actions.send(action);
            }
            Ok(())
        },
    ))?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
        epicurus_core::APP_USER_MODEL_ID,
    ))?;
    notifier.Show(&toast)
}

/// A simple informational toast (used by "send test").
pub fn show_test(actions: Sender<ToastAction>) -> windows::core::Result<()> {
    show(
        r#"<toast><visual><binding template="ToastGeneric"><text>Epicurus test notification</text><text>Toasts are working. Incident toasts carry Kill, Resume and Open buttons.</text></binding></visual></toast>"#,
        "epicurus-test",
        actions,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use epicurus_core::catalog::Category;
    use epicurus_core::scoring::Severity;

    fn summary(status: IncidentStatus) -> IncidentSummary {
        IncidentSummary {
            id: "inc_0123456789abcdef".into(),
            created_at: time::OffsetDateTime::now_utc(),
            severity: Severity::Critical,
            score: 95,
            status,
            simulated: false,
            pid: 7,
            image: r"C:\Temp\<evil>.exe".into(),
            decoys: 3,
            categories: vec![Category::Cloud],
        }
    }

    #[test]
    fn args_roundtrip_and_validation() {
        assert_eq!(
            parse_args("action=kill&id=inc_0123456789abcdef"),
            Some(ToastAction::Kill("inc_0123456789abcdef".into()))
        );
        assert_eq!(
            parse_args("action=open&id=inc_0123456789abcdef"),
            Some(ToastAction::Open("inc_0123456789abcdef".into()))
        );
        assert_eq!(parse_args("action=format&id=inc_0123456789abcdef"), None);
        assert_eq!(parse_args("action=kill&id=../../x"), None);
    }

    #[test]
    fn xml_escapes_and_offers_buttons_when_pending() {
        let x = incident_xml(&summary(IncidentStatus::AwaitingDecision));
        assert!(x.contains("&lt;evil&gt;"));
        assert!(x.contains(r#"content="Kill""#) && x.contains(r#"content="Resume""#));
        let doc = XmlDocument::new().unwrap();
        doc.LoadXml(&HSTRING::from(x)).unwrap();
        let y = incident_xml(&summary(IncidentStatus::Open));
        assert!(!y.contains(r#"content="Kill""#));
    }
}
