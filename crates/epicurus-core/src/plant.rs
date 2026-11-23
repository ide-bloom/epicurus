//! Executing a plan and safely removing decoys.
//!
//! Files are created with `CREATE_NEW` semantics (`create_new(true)`), so the
//! existence check and the creation are one atomic operation: if anything
//! appears at the path between planning and planting, the create fails and
//! the foreign file is left untouched.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use time::OffsetDateTime;

use crate::manifest::{CreatedDir, Manifest, ManifestEntry, sha256_file, sha256_hex};
use crate::plan::{PlannedDecoy, PlannedFile};
use crate::{Error, Result};

/// Platform hooks applied after each create (the sensor crate sets the owner
/// to the protected user so decoys are not given away by an Administrators
/// owner).
pub trait PlantHooks {
    /// Called after a file or directory has been created.
    fn after_create(&self, path: &Path, is_dir: bool) -> Result<()>;
}

/// Hooks that do nothing (tests, dry runs, non-elevated use).
pub struct NoHooks;

impl PlantHooks for NoHooks {
    fn after_create(&self, _path: &Path, _is_dir: bool) -> Result<()> {
        Ok(())
    }
}

/// Result of planting one decoy.
#[derive(Debug, Clone, Default)]
pub struct PlantOutcome {
    /// Files written.
    pub entries: Vec<ManifestEntry>,
    /// Directories created.
    pub dirs: Vec<CreatedDir>,
}

/// Plants one decoy. On failure every file and directory created by this call
/// is removed again before the error is returned.
pub fn plant(
    decoy: &PlannedDecoy,
    hooks: &dyn PlantHooks,
    now: OffsetDateTime,
) -> Result<PlantOutcome> {
    let mut out = PlantOutcome::default();
    let result = plant_inner(decoy, hooks, now, &mut out);
    if let Err(e) = result {
        rollback(&out);
        return Err(e);
    }
    Ok(out)
}

fn plant_inner(
    decoy: &PlannedDecoy,
    hooks: &dyn PlantHooks,
    now: OffsetDateTime,
    out: &mut PlantOutcome,
) -> Result<()> {
    for file in &decoy.files {
        if let Some(parent) = file.path.parent() {
            create_dirs(parent, hooks, now, out)?;
        }
        write_new(file)?;
        out.entries.push(ManifestEntry {
            path: file.path.clone(),
            sha256: sha256_hex(&file.bytes),
            size: file.size,
            decoy_id: decoy.decoy_id.clone(),
            category: decoy.category,
            target: decoy.target.clone(),
            planted_at: now,
            canary: decoy.canary,
        });
        hooks.after_create(&file.path, false)?;
    }
    // Directory times are restored last: creating files inside a directory
    // bumps its modification time.
    for d in &out.dirs {
        let modified = decoy.files.first().map_or(now, |f| f.modified);
        set_dir_times(&d.path, modified);
    }
    Ok(())
}

/// Creates missing ancestors one level at a time so exactly the directories we
/// created are recorded (and later removed).
fn create_dirs(
    dir: &Path,
    hooks: &dyn PlantHooks,
    now: OffsetDateTime,
    out: &mut PlantOutcome,
) -> Result<()> {
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if std::fs::symlink_metadata(d).is_ok() {
            break;
        }
        missing.push(d.to_path_buf());
        cur = d.parent();
    }
    for d in missing.into_iter().rev() {
        match std::fs::create_dir(&d) {
            Ok(()) => {
                out.dirs.push(CreatedDir {
                    path: d.clone(),
                    created_at: now,
                });
                hooks.after_create(&d, true)?;
            }
            // Someone else created it concurrently: it is theirs, not ours.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Error::io(&d, e)),
        }
    }
    Ok(())
}

fn write_new(file: &PlannedFile) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;
        let mut attrs = 0;
        if file.attributes.hidden {
            attrs |= FILE_ATTRIBUTE_HIDDEN;
        }
        if file.attributes.not_content_indexed {
            attrs |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        }
        opts.attributes(if attrs == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            attrs
        });
    }
    let mut f = opts.open(&file.path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Safety(format!(
                "{} appeared after planning; refusing to touch it",
                file.path.display()
            ))
        } else {
            Error::io(&file.path, e)
        }
    })?;
    let written = f
        .write_all(&file.bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| set_file_times(&f, file.modified));
    if let Err(e) = written {
        drop(f);
        // We created this file a moment ago with CREATE_NEW, so it is ours.
        let _ = std::fs::remove_file(&file.path);
        return Err(Error::io(&file.path, e));
    }
    Ok(())
}

fn set_file_times(f: &std::fs::File, modified: OffsetDateTime) -> std::io::Result<()> {
    let st: std::time::SystemTime = modified.into();
    let times = std::fs::FileTimes::new().set_modified(st).set_accessed(st);
    #[cfg(windows)]
    let times = {
        use std::os::windows::fs::FileTimesExt;
        times.set_created(st)
    };
    f.set_times(times)
}

fn set_dir_times(dir: &Path, modified: OffsetDateTime) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        if let Ok(f) = OpenOptions::new()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)
        {
            // Directory timestamps are cosmetic; failure is not an error.
            let _ = set_file_times(&f, modified);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (dir, modified);
    }
}

fn rollback(out: &PlantOutcome) {
    for e in &out.entries {
        let _ = std::fs::remove_file(&e.path);
    }
    for d in out.dirs.iter().rev() {
        let _ = std::fs::remove_dir(&d.path);
    }
}

/// What unplanting did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct UnplantReport {
    /// Files removed.
    pub removed: Vec<PathBuf>,
    /// Files left alone because their content no longer matches the manifest.
    pub kept_modified: Vec<PathBuf>,
    /// Files already gone.
    pub missing: Vec<PathBuf>,
    /// Files that could not be removed (with the error).
    pub failed: Vec<(PathBuf, String)>,
    /// Directories removed.
    pub dirs_removed: Vec<PathBuf>,
    /// Directories kept because they are not empty.
    pub dirs_kept: Vec<PathBuf>,
}

impl UnplantReport {
    /// Manifest entries that should be forgotten (removed or missing). Entries
    /// that were modified or failed stay in the manifest.
    pub fn forgettable(&self) -> impl Iterator<Item = &PathBuf> {
        self.removed.iter().chain(self.missing.iter())
    }
}

/// Removes manifest files whose hash still matches, then the directories
/// Epicurus created, deepest first, only if they are empty.
pub fn unplant(manifest: &Manifest) -> UnplantReport {
    let mut report = UnplantReport::default();
    for e in &manifest.entries {
        match std::fs::symlink_metadata(&e.path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                report.missing.push(e.path.clone());
                continue;
            }
            Err(err) => {
                report.failed.push((e.path.clone(), err.to_string()));
                continue;
            }
            Ok(meta) if !meta.is_file() => {
                // Something replaced our file with a directory or link.
                report.kept_modified.push(e.path.clone());
                continue;
            }
            Ok(_) => {}
        }
        match sha256_file(&e.path) {
            Ok(h) if h == e.sha256 => match remove_file_clearing_readonly(&e.path) {
                Ok(()) => report.removed.push(e.path.clone()),
                Err(err) => report.failed.push((e.path.clone(), err.to_string())),
            },
            Ok(_) => report.kept_modified.push(e.path.clone()),
            Err(err) => report.failed.push((e.path.clone(), err.to_string())),
        }
    }
    let mut dirs: Vec<&CreatedDir> = manifest.dirs.iter().collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.path.components().count()));
    for d in dirs {
        match std::fs::remove_dir(&d.path) {
            Ok(()) => report.dirs_removed.push(d.path.clone()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                report.dirs_removed.push(d.path.clone())
            }
            Err(_) => report.dirs_kept.push(d.path.clone()),
        }
    }
    report
}

fn remove_file_clearing_readonly(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let mut perms = std::fs::metadata(path)?.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            std::fs::set_permissions(path, perms)?;
            std::fs::remove_file(path)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Category;
    use crate::plan::Attributes;

    fn planned(root: &Path, files: &[(&str, &[u8])]) -> PlannedDecoy {
        let now = OffsetDateTime::now_utc();
        PlannedDecoy {
            decoy_id: "test".into(),
            category: Category::Cloud,
            target: root.join(files[0].0),
            files: files
                .iter()
                .map(|(rel, bytes)| PlannedFile {
                    path: root.join(rel),
                    bytes: bytes.to_vec(),
                    size: bytes.len() as u64,
                    modified: now - time::Duration::days(100),
                    attributes: Attributes {
                        hidden: false,
                        not_content_indexed: true,
                    },
                })
                .collect(),
            canary: false,
            candidate_index: 0,
        }
    }

    fn manifest_of(outcomes: &[PlantOutcome]) -> Manifest {
        Manifest {
            entries: outcomes.iter().flat_map(|o| o.entries.clone()).collect(),
            dirs: outcomes.iter().flat_map(|o| o.dirs.clone()).collect(),
        }
    }

    #[test]
    fn plants_with_backdated_times_and_records_created_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let d = planned(dir.path(), &[("a/b/c.txt", b"secret-ish")]);
        let out = plant(&d, &NoHooks, OffsetDateTime::now_utc()).unwrap();
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.dirs.len(), 2, "a and a/b were created");
        let meta = std::fs::metadata(dir.path().join("a/b/c.txt")).unwrap();
        let age = std::time::SystemTime::now()
            .duration_since(meta.modified().unwrap())
            .unwrap();
        assert!(age.as_secs() > 99 * 86_400);
        assert_eq!(out.entries[0].sha256, sha256_hex(b"secret-ish"));
    }

    #[test]
    fn never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("credentials");
        std::fs::write(&p, b"REAL USER DATA").unwrap();
        let d = planned(dir.path(), &[("credentials", b"decoy")]);
        let err = plant(&d, &NoHooks, OffsetDateTime::now_utc()).unwrap_err();
        assert!(matches!(err, Error::Safety(_)));
        assert_eq!(std::fs::read(&p).unwrap(), b"REAL USER DATA");
    }

    #[test]
    fn failure_rolls_back_only_what_this_call_created() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("x")).unwrap();
        std::fs::write(dir.path().join("x/2"), b"foreign").unwrap();
        let d = planned(dir.path(), &[("x/new/1", b"one"), ("x/2", b"two")]);
        assert!(plant(&d, &NoHooks, OffsetDateTime::now_utc()).is_err());
        assert!(!dir.path().join("x/new/1").exists());
        assert!(!dir.path().join("x/new").exists());
        assert_eq!(std::fs::read(dir.path().join("x/2")).unwrap(), b"foreign");
        assert!(dir.path().join("x").exists(), "pre-existing directory kept");
    }

    #[test]
    fn unplant_removes_only_matching_files_and_empty_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let a = plant(
            &planned(dir.path(), &[("d1/a", b"aaa")]),
            &NoHooks,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        let b = plant(
            &planned(dir.path(), &[("d2/b", b"bbb")]),
            &NoHooks,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        let c = plant(
            &planned(dir.path(), &[("d3/c", b"ccc")]),
            &NoHooks,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        // b is modified by someone: it must survive.
        std::fs::write(dir.path().join("d2/b"), b"user edited").unwrap();
        // A foreign file appears in d3: the directory must survive.
        std::fs::write(dir.path().join("d3/user.txt"), b"mine").unwrap();
        let m = manifest_of(&[a, b, c]);
        let r = unplant(&m);
        assert_eq!(r.removed.len(), 2);
        assert_eq!(r.kept_modified, vec![dir.path().join("d2/b")]);
        assert!(!dir.path().join("d1").exists());
        assert!(dir.path().join("d2/b").exists());
        assert!(dir.path().join("d3/user.txt").exists());
        assert!(r.dirs_kept.contains(&dir.path().join("d3")));
        // Second run: the removed files are reported missing, nothing else changes.
        let r2 = unplant(&m);
        assert_eq!(r2.missing.len(), 2);
        assert!(dir.path().join("d2/b").exists());
    }

    #[test]
    fn hooks_run_for_every_created_path() {
        use std::cell::RefCell;
        struct Recorder(RefCell<Vec<(PathBuf, bool)>>);
        impl PlantHooks for Recorder {
            fn after_create(&self, path: &Path, is_dir: bool) -> Result<()> {
                self.0.borrow_mut().push((path.to_path_buf(), is_dir));
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let rec = Recorder(RefCell::new(Vec::new()));
        plant(
            &planned(dir.path(), &[("n/f", b"x")]),
            &rec,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        let calls = rec.0.into_inner();
        assert_eq!(
            calls,
            vec![
                (dir.path().join("n"), true),
                (dir.path().join("n/f"), false)
            ]
        );
    }
}
