//! Facts about the machine that decide where decoys may go: cloud-synced
//! folders, git working trees and path existence.
//!
//! Planting into a synced folder would upload decoys to the cloud (and onto
//! every other device of the user); planting into a git working tree risks a
//! decoy being committed. Both are refused.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::{EnvMap, is_within};

/// Cloud sync providers we recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncProvider {
    /// Microsoft OneDrive (personal or business).
    OneDrive,
    /// Dropbox.
    Dropbox,
    /// Google Drive for desktop.
    GoogleDrive,
    /// iCloud for Windows.
    ICloud,
    /// Box Drive.
    Box,
}

/// A detected sync root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncedRoot {
    /// Provider.
    pub provider: SyncProvider,
    /// Root directory.
    pub path: PathBuf,
}

/// Filesystem queries used by the planner; abstracted for tests.
pub trait FsProbe {
    /// True if the path exists (file or directory).
    fn exists(&self, path: &Path) -> bool;
    /// The sync root containing `path`, if any.
    fn synced_root(&self, path: &Path) -> Option<SyncedRoot>;
    /// The git working tree root containing `path`, if any.
    fn git_root(&self, path: &Path) -> Option<PathBuf>;
}

/// The real filesystem plus a precomputed list of sync roots.
#[derive(Debug, Clone, Default)]
pub struct RealFs {
    /// Known sync roots.
    pub synced: Vec<SyncedRoot>,
}

impl RealFs {
    /// Detects sync roots from the profile layout plus `extra` roots found by
    /// platform code (e.g. OneDrive account folders read from the registry).
    pub fn detect(env: &EnvMap, extra: Vec<SyncedRoot>) -> Self {
        let mut synced = detect_synced_roots(env);
        for r in extra {
            if !synced.iter().any(|s| {
                crate::paths::normalize_key(&s.path.to_string_lossy())
                    == crate::paths::normalize_key(&r.path.to_string_lossy())
            }) {
                synced.push(r);
            }
        }
        Self { synced }
    }
}

impl FsProbe for RealFs {
    fn exists(&self, path: &Path) -> bool {
        // symlink_metadata so a dangling link still counts as "something is
        // there" and is never replaced.
        std::fs::symlink_metadata(path).is_ok()
    }

    fn synced_root(&self, path: &Path) -> Option<SyncedRoot> {
        self.synced
            .iter()
            .find(|r| is_within(path, &r.path))
            .cloned()
    }

    fn git_root(&self, path: &Path) -> Option<PathBuf> {
        find_git_root(path)
    }
}

/// Walks up from `path` looking for a `.git` directory or file (worktrees and
/// submodules use a `.git` file).
pub fn find_git_root(path: &Path) -> Option<PathBuf> {
    let mut cur = Some(path);
    while let Some(dir) = cur {
        if std::fs::symlink_metadata(dir.join(".git")).is_ok() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

/// Detects sync roots that are visible from the filesystem alone.
pub fn detect_synced_roots(env: &EnvMap) -> Vec<SyncedRoot> {
    let mut out = Vec::new();
    let Some(profile) = env.get("USERPROFILE").map(PathBuf::from) else {
        return out;
    };
    let mut push = |provider, path: PathBuf| {
        if !out.iter().any(|r: &SyncedRoot| r.path == path) {
            out.push(SyncedRoot { provider, path });
        }
    };

    // Profile-level folders created by the sync clients.
    if let Ok(entries) = std::fs::read_dir(&profile) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let lower = name.to_lowercase();
            let provider = if lower == "onedrive" || lower.starts_with("onedrive - ") {
                Some(SyncProvider::OneDrive)
            } else if lower == "dropbox" || lower.starts_with("dropbox (") {
                Some(SyncProvider::Dropbox)
            } else if lower == "google drive" || lower == "my drive" {
                Some(SyncProvider::GoogleDrive)
            } else if lower == "icloudrive" || lower == "iclouddrive" {
                Some(SyncProvider::ICloud)
            } else if lower == "box" {
                Some(SyncProvider::Box)
            } else {
                None
            };
            if let Some(p) = provider {
                push(p, e.path());
            }
        }
    }

    // OneDrive environment variables (present when running as the user).
    for var in ["OneDrive", "OneDriveCommercial", "OneDriveConsumer"] {
        if let Some(v) = env.get(var).filter(|v| !v.is_empty()) {
            push(SyncProvider::OneDrive, PathBuf::from(v));
        }
    }

    // Dropbox records its roots (including custom locations) in info.json.
    for base in ["APPDATA", "LOCALAPPDATA"] {
        if let Some(b) = env.get(base) {
            let info = Path::new(b).join("Dropbox").join("info.json");
            if let Ok(text) = std::fs::read_to_string(&info) {
                for p in dropbox_paths(&text) {
                    push(SyncProvider::Dropbox, p);
                }
            }
        }
    }
    out
}

/// Extracts `path` values from Dropbox's `info.json`.
pub fn dropbox_paths(json: &str) -> Vec<PathBuf> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(obj) = v.as_object() else {
        return Vec::new();
    };
    obj.values()
        .filter_map(|acct| acct.get("path").and_then(|p| p.as_str()))
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_profile_sync_folders() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::create_dir(home.join("OneDrive - Contoso")).unwrap();
        std::fs::create_dir(home.join("Dropbox")).unwrap();
        std::fs::create_dir(home.join("My Drive")).unwrap();
        std::fs::create_dir(home.join("Documents")).unwrap();
        let env = EnvMap::for_profile(home, None, None);
        let roots = detect_synced_roots(&env);
        let providers: Vec<SyncProvider> = roots.iter().map(|r| r.provider).collect();
        assert!(providers.contains(&SyncProvider::OneDrive));
        assert!(providers.contains(&SyncProvider::Dropbox));
        assert!(providers.contains(&SyncProvider::GoogleDrive));
        assert_eq!(roots.len(), 3);

        let fs = RealFs::detect(&env, Vec::new());
        assert!(
            fs.synced_root(&home.join("OneDrive - Contoso").join("a.txt"))
                .is_some()
        );
        assert!(
            fs.synced_root(&home.join("Documents").join("a.txt"))
                .is_none()
        );
    }

    #[test]
    fn dropbox_info_json_custom_location() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let appdata = home.join("AppData").join("Roaming");
        std::fs::create_dir_all(appdata.join("Dropbox")).unwrap();
        let custom = home.join("Sync").join("DB");
        let json = serde_json::json!({ "personal": { "path": custom, "host": 1 } }).to_string();
        std::fs::write(appdata.join("Dropbox").join("info.json"), json).unwrap();
        let env = EnvMap::for_profile(home, None, None);
        let fs = RealFs::detect(&env, Vec::new());
        assert!(fs.synced_root(&custom.join("x")).is_some());
    }

    #[test]
    fn extra_roots_from_registry_are_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let env = EnvMap::for_profile(dir.path(), None, None);
        let docs = dir.path().join("Documents");
        let fs = RealFs::detect(
            &env,
            vec![SyncedRoot {
                provider: SyncProvider::OneDrive,
                path: docs.clone(),
            }],
        );
        assert_eq!(
            fs.synced_root(&docs.join("Backups").join("x.csv"))
                .map(|r| r.provider),
            Some(SyncProvider::OneDrive)
        );
    }

    #[test]
    fn finds_git_trees_including_gitfile_worktrees() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("src").join("deep")).unwrap();
        assert_eq!(
            find_git_root(&repo.join("src").join("deep").join("new.env")),
            Some(repo.clone())
        );

        let wt = dir.path().join("worktree");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), "gitdir: ../repo/.git/worktrees/wt").unwrap();
        assert_eq!(find_git_root(&wt.join("x")), Some(wt.clone()));

        let plain = dir.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        // The temp dir itself is not inside a repository on CI or dev boxes
        // unless TMP points into one; only assert relative to our tree.
        let root = find_git_root(&plain.join("x"));
        assert!(
            root.is_none()
                || !crate::paths::is_within(root.as_deref().unwrap_or(Path::new("")), dir.path())
        );
    }
}
