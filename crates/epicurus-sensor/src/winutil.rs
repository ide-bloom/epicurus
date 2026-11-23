//! Small Win32 helpers: wide strings, owned handles, registry reads and
//! precise wall-clock time.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use time::OffsetDateTime;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Registry::{
    HKEY, KEY_READ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW,
    RegGetValueW, RegOpenKeyExW,
};
use windows::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows::core::PCWSTR;

/// NUL-terminated UTF-16.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// UTF-16 slice (possibly NUL-terminated) to String.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Reads a NUL-terminated wide string from a raw pointer.
///
/// # Safety
/// `p` must be null or point to a valid NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL termination.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// A handle closed on drop.
#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    /// Raw handle.
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: we own the handle and close it exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// SAFETY: kernel handles are process-wide and may be used from any thread.
unsafe impl Send for OwnedHandle {}
// SAFETY: as above; the handle value itself is immutable.
unsafe impl Sync for OwnedHandle {}

/// Precise current time (100 ns resolution), used to timestamp oplock breaks
/// so they can be correlated with ETW events.
pub fn precise_now() -> OffsetDateTime {
    // SAFETY: plain out-parameter call.
    let ft = unsafe { GetSystemTimePreciseAsFileTime() };
    filetime_to_datetime(ft).unwrap_or_else(OffsetDateTime::now_utc)
}

/// FILETIME to UTC.
pub fn filetime_to_datetime(ft: FILETIME) -> Option<OffsetDateTime> {
    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    if ticks == 0 {
        return None;
    }
    epicurus_core::timefmt::from_filetime(ticks)
}

/// Reads a REG_SZ / REG_EXPAND_SZ value without expanding it.
pub fn reg_get_string(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let sk = wide(subkey);
    let v = wide(value);
    let mut size: u32 = 0;
    // SAFETY: size query with null buffer.
    let rc = unsafe {
        RegGetValueW(
            root,
            PCWSTR(sk.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            None,
            None,
            Some(&mut size),
        )
    };
    if rc.is_err() || size == 0 {
        return None;
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
    let mut size2 = (buf.len() * 2) as u32;
    // SAFETY: buffer is at least `size2` bytes.
    let rc = unsafe {
        RegGetValueW(
            root,
            PCWSTR(sk.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size2),
        )
    };
    if rc.is_err() {
        return None;
    }
    Some(from_wide(&buf))
}

/// Names of the direct subkeys of `root\subkey`.
pub fn reg_subkeys(root: HKEY, subkey: &str) -> Vec<String> {
    let sk = wide(subkey);
    let mut key = HKEY::default();
    // SAFETY: out-parameter call; key closed below.
    if unsafe { RegOpenKeyExW(root, PCWSTR(sk.as_ptr()), Some(0), KEY_READ, &mut key) }.is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut idx = 0u32;
    loop {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: name buffer and length are consistent.
        let rc = unsafe {
            RegEnumKeyExW(
                key,
                idx,
                Some(windows::core::PWSTR(name.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if rc.is_err() {
            break;
        }
        out.push(String::from_utf16_lossy(&name[..len as usize]));
        idx += 1;
    }
    // SAFETY: key was opened above.
    unsafe {
        let _ = RegCloseKey(key);
    }
    out
}

/// Expands `%VAR%` in registry values using the protected user's profile
/// rather than the service's environment.
pub fn expand_profile_vars(value: &str, profile: &str) -> String {
    let mut env =
        epicurus_core::paths::EnvMap::for_profile(std::path::Path::new(profile), None, None)
            .with_system_vars();
    env.set("HOMEDRIVE", profile.get(..2).unwrap_or("C:"));
    env.expand(value).unwrap_or_else(|_| value.to_string())
}

/// Reads a REG_DWORD value.
pub fn reg_get_dword(root: HKEY, subkey: &str, value: &str) -> Option<u32> {
    let sk = wide(subkey);
    let v = wide(value);
    let mut data: u32 = 0;
    let mut size: u32 = 4;
    // SAFETY: data is a 4-byte buffer matching `size`.
    let rc = unsafe {
        RegGetValueW(
            root,
            PCWSTR(sk.as_ptr()),
            PCWSTR(v.as_ptr()),
            windows::Win32::System::Registry::RRF_RT_REG_DWORD,
            None,
            Some((&mut data as *mut u32).cast()),
            Some(&mut size),
        )
    };
    rc.is_ok().then_some(data)
}
