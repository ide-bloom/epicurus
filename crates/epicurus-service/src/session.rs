//! Launches the tray agent (`epicurus ui --tray`) into the protected user's
//! interactive session.
//!
//! Toasts and the tray icon must live in the user's session, but a console
//! program started from a Run key flashes a terminal window. The service
//! instead starts the agent with `CreateProcessAsUserW` and
//! `CREATE_NO_WINDOW` when the user logs on (and once at service start).

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSQueryUserToken,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, PROCESS_INFORMATION,
    STARTUPINFOW,
};
use windows::core::{PCWSTR, PWSTR};

use epicurus_sensor::winutil::{OwnedHandle, wide};

/// Active session ids.
pub fn active_sessions() -> Vec<u32> {
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: output freed with WTSFreeMemory.
    if unsafe {
        WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut info, &mut count)
    }
    .is_err()
    {
        return Vec::new();
    }
    // SAFETY: `info` points to `count` entries.
    let out = unsafe { std::slice::from_raw_parts(info, count as usize) }
        .iter()
        .filter(|s| s.State == WTSActive)
        .map(|s| s.SessionId)
        .collect();
    // SAFETY: freeing the buffer returned above.
    unsafe { WTSFreeMemory(info.cast()) };
    out
}

/// Starts the tray agent in `session` if the session belongs to `user_sid`.
/// The agent itself enforces a single instance per session.
pub fn launch_tray(session: u32, user_sid: &str, exe: &str) -> bool {
    let mut token = HANDLE::default();
    // SAFETY: requires SE_TCB (LocalSystem); token handle owned below.
    if unsafe { WTSQueryUserToken(session, &mut token) }.is_err() {
        return false;
    }
    let token = OwnedHandle(token);
    match epicurus_sensor::token::token_user(token.raw()) {
        Some((sid, _)) if sid.eq_ignore_ascii_case(user_sid) => {}
        _ => return false,
    }
    let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: env block freed with DestroyEnvironmentBlock.
    let have_env = unsafe { CreateEnvironmentBlock(&mut env, Some(token.raw()), false) }.is_ok();
    let mut cmd = wide(format!("\"{exe}\" ui --tray"));
    let mut desktop = wide("winsta0\\default");
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let app = wide(exe);
    // SAFETY: all strings are NUL-terminated and live for the call; the
    // command line buffer is mutable as CreateProcess requires.
    let ok = unsafe {
        CreateProcessAsUserW(
            Some(token.raw()),
            PCWSTR(app.as_ptr()),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            if have_env {
                Some(env.cast_const())
            } else {
                None
            },
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    }
    .is_ok();
    if have_env {
        // SAFETY: env was created above.
        unsafe {
            let _ = DestroyEnvironmentBlock(env);
        }
    }
    if ok {
        drop(OwnedHandle(pi.hThread));
        drop(OwnedHandle(pi.hProcess));
    }
    ok
}

/// Launches the agent into every active session of the protected user.
pub fn launch_everywhere(user_sid: &str, exe: &str) {
    for s in active_sessions() {
        if launch_tray(s, user_sid, exe) {
            tracing::info!(session = s, "started tray agent");
        }
    }
}
