//! Locating the protected user's profile, redirected folders and OneDrive
//! roots from the registry. The service runs as LocalSystem, so it cannot use
//! its own environment for any of this.

use std::path::PathBuf;

use epicurus_core::environment::{SyncProvider, SyncedRoot};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY_USERS};

use crate::winutil::{expand_profile_vars, reg_get_string, reg_subkeys};

/// Profile facts for a user SID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile {
    /// SID.
    pub sid: String,
    /// Profile root, e.g. `C:\Users\dev`.
    pub profile: PathBuf,
    /// Roaming AppData when redirected away from the default.
    pub appdata: Option<PathBuf>,
    /// Local AppData when redirected away from the default.
    pub localappdata: Option<PathBuf>,
}

/// Validates a SID string's shape before it is used in registry paths.
pub fn is_valid_sid_string(sid: &str) -> bool {
    sid.starts_with("S-1-")
        && sid.len() <= 184
        && sid[4..]
            .split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
}

/// Looks the profile up in `ProfileList` and the user's shell folders.
pub fn lookup(sid: &str) -> Option<UserProfile> {
    if !is_valid_sid_string(sid) {
        return None;
    }
    let raw = reg_get_string(
        HKEY_LOCAL_MACHINE,
        &format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"),
        "ProfileImagePath",
    )?;
    let profile_str = expand_profile_vars(&raw, &raw);
    let profile = PathBuf::from(&profile_str);
    // The user hive is only loaded while the user is logged on; fall back to
    // default locations otherwise.
    let shell =
        format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
    let folder = |name: &str, default: PathBuf| -> Option<PathBuf> {
        let v = reg_get_string(HKEY_USERS, &shell, name)?;
        let p = PathBuf::from(expand_profile_vars(&v, &profile_str));
        (p != default).then_some(p)
    };
    let appdata = folder("AppData", profile.join("AppData").join("Roaming"));
    let localappdata = folder("Local AppData", profile.join("AppData").join("Local"));
    Some(UserProfile {
        sid: sid.to_string(),
        profile,
        appdata,
        localappdata,
    })
}

/// OneDrive roots and Known-Folder-Move targets from the user's hive.
pub fn onedrive_roots(sid: &str, profile: &str) -> Vec<SyncedRoot> {
    if !is_valid_sid_string(sid) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let accounts = format!(r"{sid}\Software\Microsoft\OneDrive\Accounts");
    for acct in reg_subkeys(HKEY_USERS, &accounts) {
        if let Some(folder) =
            reg_get_string(HKEY_USERS, &format!(r"{accounts}\{acct}"), "UserFolder")
            && !folder.is_empty()
        {
            out.push(SyncedRoot {
                provider: SyncProvider::OneDrive,
                path: PathBuf::from(expand_profile_vars(&folder, profile)),
            });
        }
    }
    for var in ["OneDrive", "OneDriveCommercial", "OneDriveConsumer"] {
        if let Some(v) = reg_get_string(HKEY_USERS, &format!(r"{sid}\Environment"), var)
            && !v.is_empty()
        {
            out.push(SyncedRoot {
                provider: SyncProvider::OneDrive,
                path: PathBuf::from(expand_profile_vars(&v, profile)),
            });
        }
    }
    // Google Drive for desktop mirror folders.
    if let Some(v) = reg_get_string(
        HKEY_USERS,
        &format!(r"{sid}\Software\Google\DriveFS"),
        "DefaultMountPoint",
    ) && v.contains('\\')
    {
        out.push(SyncedRoot {
            provider: SyncProvider::GoogleDrive,
            path: PathBuf::from(expand_profile_vars(&v, profile)),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_validation() {
        assert!(is_valid_sid_string(
            "S-1-5-21-1004336348-1177238915-682003330-1001"
        ));
        assert!(is_valid_sid_string("S-1-5-18"));
        assert!(!is_valid_sid_string(r"S-1-5-21\..\x"));
        assert!(!is_valid_sid_string("S-1-"));
        assert!(!is_valid_sid_string("hello"));
    }

    #[test]
    fn current_user_profile_resolves() {
        let sid = crate::token::current_user_sid().unwrap();
        let p = lookup(&sid).unwrap();
        assert!(p.profile.is_dir());
    }
}
