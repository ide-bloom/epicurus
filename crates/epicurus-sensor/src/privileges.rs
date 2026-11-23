//! Token privileges and elevation checks.

use windows::Win32::Foundation::{ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use crate::winutil::{OwnedHandle, wide};

/// Privileges the service enables at startup.
pub const SERVICE_PRIVILEGES: &[&str] = &[
    "SeDebugPrivilege",         // open any process for triage and containment
    "SeSecurityPrivilege",      // SACLs and audit policy (fallback sensor)
    "SeRestorePrivilege",       // set decoy owner to the protected user
    "SeTakeOwnershipPrivilege", // same
    "SeBackupPrivilege",        // read decoys regardless of ACL changes
];

fn current_token(access: windows::Win32::Security::TOKEN_ACCESS_MASK) -> Option<OwnedHandle> {
    let mut h = HANDLE::default();
    // SAFETY: pseudo-handle for the current process; token handle is owned.
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut h) }.ok()?;
    Some(OwnedHandle(h))
}

/// Enables one privilege on the current process token. Returns false if the
/// token does not hold it.
pub fn enable(name: &str) -> bool {
    let Some(token) = current_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) else {
        return false;
    };
    let n = wide(name);
    let mut luid = LUID::default();
    // SAFETY: name is NUL-terminated; luid is an out-parameter.
    if unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(n.as_ptr()), &mut luid) }.is_err() {
        return false;
    }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: tp is a valid single-entry TOKEN_PRIVILEGES.
    let ok = unsafe { AdjustTokenPrivileges(token.raw(), false, Some(&tp), 0, None, None) }.is_ok();
    // AdjustTokenPrivileges succeeds even when the privilege is absent; the
    // real answer is in the last error.
    // SAFETY: reads thread-local last error.
    ok && unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED
}

/// Enables every privilege in `names`, returning those that failed.
pub fn enable_all(names: &[&str]) -> Vec<String> {
    names
        .iter()
        .filter(|n| !enable(n))
        .map(|n| (*n).to_string())
        .collect()
}

/// True when the current process token is elevated.
pub fn is_elevated() -> bool {
    let Some(token) = current_token(TOKEN_QUERY) else {
        return false;
    };
    let mut elev = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: buffer is a TOKEN_ELEVATION of the advertised size.
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            Some((&mut elev as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    }
    .is_ok();
    ok && elev.TokenIsElevated != 0
}
