//! Token queries: user SID and name, integrity level.

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW, PSID,
    SID_NAME_USE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PWSTR;

use crate::winutil::{OwnedHandle, from_wide};

fn token_info(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Option<Vec<u8>> {
    let mut len = 0u32;
    // SAFETY: size query.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut len) };
    if len == 0 {
        return None;
    }
    // u64 backing keeps the buffer aligned for the structures inside.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: buffer is at least `len` bytes.
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), len, &mut len) }
        .ok()?;
    let bytes: Vec<u8> = buf.iter().flat_map(|w| w.to_ne_bytes()).collect();
    Some(bytes)
}

/// String form of a SID.
pub fn sid_to_string(sid: PSID) -> Option<String> {
    let mut s = PWSTR::null();
    // SAFETY: sid is valid for the call; output freed with LocalFree.
    unsafe { ConvertSidToStringSidW(sid, &mut s) }.ok()?;
    // SAFETY: s is a LocalAlloc'd NUL-terminated string.
    let out = unsafe { s.to_string() }.ok();
    // SAFETY: freeing the LocalAlloc'd buffer once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(s.0.cast())));
    }
    out
}

/// `DOMAIN\name` for a SID.
pub fn sid_to_account(sid: PSID) -> Option<String> {
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let mut nlen = name.len() as u32;
    let mut dlen = domain.len() as u32;
    let mut use_ = SID_NAME_USE::default();
    // SAFETY: buffers and lengths are consistent.
    unsafe {
        LookupAccountSidW(
            None,
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut nlen,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut dlen,
            &mut use_,
        )
    }
    .ok()?;
    let d = from_wide(&domain);
    let n = from_wide(&name);
    Some(if d.is_empty() { n } else { format!(r"{d}\{n}") })
}

/// User SID string and account name of a token.
pub fn token_user(token: HANDLE) -> Option<(String, Option<String>)> {
    let buf = token_info(token, TokenUser)?;
    // SAFETY: buffer holds a TOKEN_USER written by the kernel; alignment is
    // guaranteed by the u64 backing in token_info.
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = tu.User.Sid;
    Some((sid_to_string(sid)?, sid_to_account(sid)))
}

/// Integrity level label of a token.
pub fn token_integrity(token: HANDLE) -> Option<String> {
    let buf = token_info(token, TokenIntegrityLevel)?;
    // SAFETY: buffer holds a TOKEN_MANDATORY_LABEL.
    let label = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let sid = label.Label.Sid;
    // SAFETY: sid points into `buf`, which outlives these calls.
    let rid = unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return None;
        }
        *GetSidSubAuthority(sid, u32::from(count) - 1)
    };
    Some(integrity_label(rid).to_string())
}

/// Maps a mandatory-label RID to a name.
pub fn integrity_label(rid: u32) -> &'static str {
    match rid {
        r if r < 0x1000 => "untrusted",
        r if r < 0x2000 => "low",
        r if r < 0x2100 => "medium",
        r if r < 0x3000 => "medium-plus",
        r if r < 0x4000 => "high",
        r if r < 0x5000 => "system",
        _ => "protected",
    }
}

/// SID string of the user running the current process.
pub fn current_user_sid() -> Option<String> {
    let mut h = HANDLE::default();
    // SAFETY: pseudo-handle; token handle owned below.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) }.ok()?;
    let token = OwnedHandle(h);
    token_user(token.raw()).map(|(sid, _)| sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_labels() {
        assert_eq!(integrity_label(0x2000), "medium");
        assert_eq!(integrity_label(0x3000), "high");
        assert_eq!(integrity_label(0x4000), "system");
        assert_eq!(integrity_label(0x1000), "low");
    }

    #[test]
    fn current_user_has_a_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"));
    }
}
