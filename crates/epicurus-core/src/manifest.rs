//! The manifest: the authoritative record of every file and directory
//! Epicurus created. Nothing outside the manifest is ever modified or
//! deleted, and a manifest file is only deleted while its hash still matches.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::catalog::Category;
use crate::paths::normalize_key;

/// One planted file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Absolute path.
    pub path: PathBuf,
    /// Lower-case hex SHA-256 of the bytes written.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
    /// Catalog decoy id.
    pub decoy_id: String,
    /// Category.
    pub category: Category,
    /// The decoy's chosen target (the file itself, or the directory for
    /// multi-file decoys). Re-planting reuses it.
    pub target: PathBuf,
    /// When it was planted.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub planted_at: OffsetDateTime,
    /// True when it contains user-supplied canary values.
    pub canary: bool,
}

/// One directory Epicurus created (removed on unplant only if empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedDir {
    /// Absolute path.
    pub path: PathBuf,
    /// When it was created.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub created_at: OffsetDateTime,
}

/// In-memory manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Files.
    pub entries: Vec<ManifestEntry>,
    /// Directories.
    pub dirs: Vec<CreatedDir>,
}

impl Manifest {
    /// True if `path` is a file or directory Epicurus created.
    pub fn owns(&self, path: &Path) -> bool {
        let key = normalize_key(&path.to_string_lossy());
        self.entries
            .iter()
            .any(|e| normalize_key(&e.path.to_string_lossy()) == key)
            || self
                .dirs
                .iter()
                .any(|d| normalize_key(&d.path.to_string_lossy()) == key)
    }

    /// Looks up a planted file by path (case-insensitive).
    pub fn entry_for(&self, path: &Path) -> Option<&ManifestEntry> {
        let key = normalize_key(&path.to_string_lossy());
        self.entries
            .iter()
            .find(|e| normalize_key(&e.path.to_string_lossy()) == key)
    }

    /// Entries belonging to a decoy.
    pub fn for_decoy<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a ManifestEntry> + 'a {
        self.entries.iter().filter(move |e| e.decoy_id == id)
    }

    /// Set of normalized file paths, for fast sensor filtering.
    pub fn path_keys(&self) -> HashSet<String> {
        self.entries
            .iter()
            .map(|e| normalize_key(&e.path.to_string_lossy()))
            .collect()
    }

    /// Distinct parent directories of planted files.
    pub fn directories(&self) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for e in &self.entries {
            if let Some(parent) = e.path.parent()
                && seen.insert(normalize_key(&parent.to_string_lossy()))
            {
                out.push(parent.to_path_buf());
            }
        }
        out
    }
}

/// Lower-case hex SHA-256 of bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Streams a file through SHA-256.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
