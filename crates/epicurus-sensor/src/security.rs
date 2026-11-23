//! Security descriptor helpers: DACLs from SDDL, owner changes, SACLs for
//! the audit fallback, and SECURITY_ATTRIBUTES for the named pipe.

use std::path::Path;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl,
    OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
};
use windows::core::{BOOL, PCWSTR};

use crate::error::{Result, SensorError};
use crate::winutil::wide;

/// A security descriptor parsed from SDDL, freed on drop.
pub struct Sd {
    sd: PSECURITY_DESCRIPTOR,
}

impl Sd {
    /// Parses SDDL.
    pub fn from_sddl(sddl: &str) -> Result<Self> {
        let w = wide(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: output freed with LocalFree in Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(w.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(|e| {
            SensorError::from_win("ConvertStringSecurityDescriptorToSecurityDescriptorW", &e)
        })?;
        Ok(Self { sd })
    }

    /// Raw descriptor pointer.
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.sd
    }

    fn dacl(&self) -> Option<*mut ACL> {
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: sd is a valid descriptor.
        unsafe { GetSecurityDescriptorDacl(self.sd, &mut present, &mut acl, &mut defaulted) }
            .ok()?;
        present.as_bool().then_some(acl)
    }

    fn sacl(&self) -> Option<*mut ACL> {
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: sd is a valid descriptor.
        unsafe { GetSecurityDescriptorSacl(self.sd, &mut present, &mut acl, &mut defaulted) }
            .ok()?;
        present.as_bool().then_some(acl)
    }

    /// SECURITY_ATTRIBUTES pointing at this descriptor (must not outlive it).
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: BOOL(0),
        }
    }
}

impl Drop for Sd {
    fn drop(&mut self) {
        if !self.sd.0.is_null() {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.sd.0)));
            }
        }
    }
}

// SAFETY: the descriptor is immutable heap memory owned by this value.
unsafe impl Send for Sd {}
// SAFETY: as above.
unsafe impl Sync for Sd {}

fn set_named(
    path: &Path,
    info: OBJECT_SECURITY_INFORMATION,
    owner: Option<PSID>,
    dacl: Option<*const ACL>,
    sacl: Option<*const ACL>,
) -> Result<()> {
    let w = wide(path);
    // SAFETY: path NUL-terminated; ACL/SID pointers valid for the call.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            info,
            owner,
            None,
            dacl,
            sacl,
        )
    };
    if rc.is_err() {
        return Err(SensorError::win32(
            format!("SetNamedSecurityInfoW({})", path.display()),
            rc.0,
        ));
    }
    Ok(())
}

/// Replaces the DACL of a file or directory with a protected DACL from SDDL.
pub fn apply_sddl(path: &Path, sddl: &str, _is_dir: bool) -> Result<()> {
    let sd = Sd::from_sddl(sddl)?;
    let dacl = sd
        .dacl()
        .ok_or_else(|| SensorError::Unsupported("SDDL has no DACL".into()))?;
    set_named(
        path,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        Some(dacl),
        None,
    )
}

/// Sets an audit SACL from SDDL (requires SeSecurityPrivilege).
pub fn apply_sacl(path: &Path, sddl: &str) -> Result<()> {
    let sd = Sd::from_sddl(sddl)?;
    let sacl = sd
        .sacl()
        .ok_or_else(|| SensorError::Unsupported("SDDL has no SACL".into()))?;
    set_named(path, SACL_SECURITY_INFORMATION, None, None, Some(sacl))
}

/// Sets the owner to a SID string (requires SeRestorePrivilege for SIDs other
/// than the caller's).
pub fn set_owner(path: &Path, sid: &str) -> Result<()> {
    let w = wide(sid);
    let mut psid = PSID::default();
    // SAFETY: output freed with LocalFree below.
    unsafe { ConvertStringSidToSidW(PCWSTR(w.as_ptr()), &mut psid) }
        .map_err(|e| SensorError::from_win("ConvertStringSidToSidW", &e))?;
    let r = set_named(path, OWNER_SECURITY_INFORMATION, Some(psid), None, None);
    // SAFETY: freeing the SID allocated above.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psid.0)));
    }
    r
}

/// SDDL for `%ProgramData%\Epicurus`: SYSTEM and Administrators only,
/// inherited by everything below.
pub const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// SDDL for the install directory: SYSTEM/Administrators full, users read+execute.
pub const INSTALL_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// Named pipe DACL: SYSTEM, Administrators and the installing user.
pub fn pipe_sddl(user_sid: Option<&str>) -> String {
    let mut s = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(sid) = user_sid.filter(|s| crate::profile::is_valid_sid_string(s)) {
        s.push_str(&format!("(A;;GRGW;;;{sid})"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_sddl_includes_valid_user_only() {
        assert!(
            pipe_sddl(Some("S-1-5-21-1-2-3-1001")).ends_with("(A;;GRGW;;;S-1-5-21-1-2-3-1001)")
        );
        assert_eq!(
            pipe_sddl(Some("S-1-5-21)(A;;GA;;;WD")),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        );
        assert!(Sd::from_sddl(&pipe_sddl(None)).is_ok());
        assert!(Sd::from_sddl("garbage(").is_err());
    }

    #[test]
    fn owner_can_be_set_to_self() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x");
        std::fs::write(&f, b"x").unwrap();
        let sid = crate::token::current_user_sid().unwrap();
        set_owner(&f, &sid).unwrap();
    }
}
