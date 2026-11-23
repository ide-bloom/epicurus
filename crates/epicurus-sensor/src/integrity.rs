//! Integrity watcher: `ReadDirectoryChangesW` on every directory holding
//! decoys, so deletion, rename or modification of a decoy is noticed even
//! when it happens through a path the other sensors miss. Some stealers
//! delete what they take.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use epicurus_core::paths::normalize_key;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_OLD_NAME,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadDirectoryChangesW,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::core::PCWSTR;

use crate::error::Result;
use crate::events::{IntegrityChange, SensorEvent};
use crate::iocp::{Packet, Port, WAKE_KEY};
use crate::winutil::{OwnedHandle, precise_now, wide};

const BUF_BYTES: usize = 16 * 1024;

enum Cmd {
    SetFiles(Vec<PathBuf>),
    Suppress(String, Instant),
    Shutdown,
}

/// Owns the watcher thread.
pub struct IntegrityWatcher {
    tx: Sender<Cmd>,
    port: Arc<Port>,
    thread: Option<JoinHandle<()>>,
    /// Directories currently watched.
    pub watched: Arc<AtomicU32>,
}

impl IntegrityWatcher {
    /// Starts the watcher thread.
    pub fn start(events: Sender<SensorEvent>) -> Result<Self> {
        let port = Arc::new(Port::new()?);
        let (tx, rx) = std::sync::mpsc::channel();
        let watched = Arc::new(AtomicU32::new(0));
        let (p, w) = (port.clone(), watched.clone());
        let thread = std::thread::Builder::new()
            .name("integrity-watcher".into())
            .spawn(move || {
                Worker {
                    port: p,
                    events,
                    dirs: HashMap::new(),
                    next_key: 1,
                    suppressed: HashMap::new(),
                    watched: w,
                }
                .run(rx)
            })?;
        Ok(Self {
            tx,
            port,
            thread: Some(thread),
            watched,
        })
    }

    /// Replaces the watched decoy files.
    pub fn set_files(&self, files: Vec<PathBuf>) {
        let _ = self.tx.send(Cmd::SetFiles(files));
        self.port.wake();
    }

    /// Ignores changes to `path` for `dur` (our own writes).
    pub fn suppress(&self, path: &str, dur: Duration) {
        let _ = self
            .tx
            .send(Cmd::Suppress(normalize_key(path), Instant::now() + dur));
        self.port.wake();
    }
}

impl Drop for IntegrityWatcher {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Shutdown);
        self.port.wake();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// u32-aligned notification buffer.
struct Buf([u32; BUF_BYTES / 4]);

struct Dir {
    path: PathBuf,
    files: HashSet<String>,
    handle: Option<OwnedHandle>,
    ov: Box<OVERLAPPED>,
    buf: Box<Buf>,
    pending: bool,
    closing: bool,
}

struct Worker {
    port: Arc<Port>,
    events: Sender<SensorEvent>,
    dirs: HashMap<usize, Dir>,
    next_key: usize,
    suppressed: HashMap<String, Instant>,
    watched: Arc<AtomicU32>,
}

impl Worker {
    fn run(mut self, rx: Receiver<Cmd>) {
        loop {
            match self.port.wait(1000) {
                Packet::Timeout | Packet::Io { key: WAKE_KEY, .. } => {}
                Packet::Io {
                    key, bytes, error, ..
                } => self.on_completion(key, bytes, error),
            }
            loop {
                match rx.try_recv() {
                    Ok(Cmd::SetFiles(f)) => self.set_files(f),
                    Ok(Cmd::Suppress(k, until)) => {
                        self.suppressed.insert(k, until);
                    }
                    Ok(Cmd::Shutdown) | Err(TryRecvError::Disconnected) => {
                        self.close_all();
                        return;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
            let now = Instant::now();
            self.suppressed.retain(|_, t| *t > now);
            // Re-open directories that disappeared and came back (re-plant).
            let idle: Vec<usize> = self
                .dirs
                .iter()
                .filter(|(_, d)| !d.pending)
                .map(|(k, _)| *k)
                .collect();
            for k in idle {
                self.issue(k);
            }
            self.watched.store(
                self.dirs.values().filter(|d| d.pending).count() as u32,
                Ordering::Relaxed,
            );
        }
    }

    fn set_files(&mut self, files: Vec<PathBuf>) {
        self.close_all();
        let mut by_dir: HashMap<String, (PathBuf, HashSet<String>)> = HashMap::new();
        for f in files {
            let (Some(parent), Some(name)) = (f.parent(), f.file_name()) else {
                continue;
            };
            by_dir
                .entry(normalize_key(&parent.to_string_lossy()))
                .or_insert_with(|| (parent.to_path_buf(), HashSet::new()))
                .1
                .insert(name.to_string_lossy().to_lowercase());
        }
        for (_, (path, files)) in by_dir {
            let key = self.next_key;
            self.next_key += 1;
            self.dirs.insert(
                key,
                Dir {
                    path,
                    files,
                    handle: None,
                    ov: Box::default(),
                    buf: Box::new(Buf([0; BUF_BYTES / 4])),
                    pending: false,
                    closing: false,
                },
            );
            self.issue(key);
        }
    }

    fn close_all(&mut self) {
        for d in self.dirs.values_mut() {
            d.closing = true;
            d.handle = None;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.dirs.values().any(|d| d.pending) && Instant::now() < deadline {
            if let Packet::Io { key, .. } = self.port.wait(100)
                && let Some(d) = self.dirs.get_mut(&key)
            {
                d.pending = false;
            }
        }
        for (_, d) in self.dirs.drain() {
            if d.pending {
                // Never free a buffer the kernel may still write into.
                std::mem::forget(d);
            }
        }
    }

    fn issue(&mut self, key: usize) {
        let port = self.port.clone();
        let Some(d) = self.dirs.get_mut(&key) else {
            return;
        };
        if d.handle.is_none() {
            let w = wide(&d.path);
            // SAFETY: NUL-terminated path; handle owned below.
            let h = unsafe {
                CreateFileW(
                    PCWSTR(w.as_ptr()),
                    FILE_LIST_DIRECTORY.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    None,
                )
            };
            let Ok(h) = h else { return };
            let h = OwnedHandle(h);
            if port.associate(h.raw(), key).is_err() {
                return;
            }
            d.handle = Some(h);
        }
        let Some(h) = d.handle.as_ref().map(OwnedHandle::raw) else {
            return;
        };
        *d.ov = OVERLAPPED::default();
        // SAFETY: buffer and OVERLAPPED are boxed in the Dir and outlive the
        // request; the buffer is DWORD-aligned as required.
        let r = unsafe {
            ReadDirectoryChangesW(
                h,
                d.buf.0.as_mut_ptr().cast(),
                BUF_BYTES as u32,
                false,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_ATTRIBUTES
                    | FILE_NOTIFY_CHANGE_SECURITY,
                None,
                Some(&mut *d.ov),
                None,
            )
        };
        if r.is_ok() {
            d.pending = true;
        } else {
            d.handle = None;
        }
    }

    fn on_completion(&mut self, key: usize, bytes: u32, error: u32) {
        let Some(d) = self.dirs.get_mut(&key) else {
            return;
        };
        d.pending = false;
        if d.closing {
            return;
        }
        let at = precise_now();
        let mut changes: Vec<(String, IntegrityChange)> = Vec::new();
        if error != 0 {
            // The directory itself went away (deleted or renamed).
            d.handle = None;
            for f in &d.files {
                let p = d.path.join(f);
                if !p.exists() {
                    changes.push((p.to_string_lossy().into_owned(), IntegrityChange::Removed));
                }
            }
        } else if bytes == 0 {
            // Buffer overflow: we lost track, so report every file for re-verification.
            for f in &d.files {
                changes.push((
                    d.path.join(f).to_string_lossy().into_owned(),
                    IntegrityChange::Modified,
                ));
            }
        } else {
            let raw: &[u8] =
                // SAFETY: the buffer is BUF_BYTES long and `bytes` <= BUF_BYTES.
                unsafe { std::slice::from_raw_parts(d.buf.0.as_ptr().cast::<u8>(), (bytes as usize).min(BUF_BYTES)) };
            for (action, name) in parse_notifications(raw) {
                if !d.files.contains(&name.to_lowercase()) {
                    continue;
                }
                let change = match action {
                    a if a == FILE_ACTION_REMOVED.0 => IntegrityChange::Removed,
                    a if a == FILE_ACTION_RENAMED_OLD_NAME.0 => IntegrityChange::RenamedAway,
                    a if a == FILE_ACTION_MODIFIED.0 => IntegrityChange::Modified,
                    _ => continue,
                };
                changes.push((d.path.join(&name).to_string_lossy().into_owned(), change));
            }
        }
        let now = Instant::now();
        for (path, change) in changes {
            let suppressed = self
                .suppressed
                .get(&normalize_key(&path))
                .is_some_and(|t| now < *t);
            if !suppressed {
                let _ = self
                    .events
                    .send(SensorEvent::Integrity { at, path, change });
            }
        }
        self.issue(key);
    }
}

/// Parses a `FILE_NOTIFY_INFORMATION` chain into `(action, file name)`.
pub fn parse_notifications(buf: &[u8]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while let Some(hdr) = buf.get(off..off + 12) {
        let next = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let action = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
        let Some(name) = buf.get(off + 12..off + 12 + len) else {
            break;
        };
        let units: Vec<u16> = name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        out.push((action, String::from_utf16_lossy(&units)));
        if next == 0 {
            break;
        }
        off += next;
    }
    out
}

/// Distinct directories of a set of files (for status).
pub fn directories_of(files: &[PathBuf]) -> usize {
    files
        .iter()
        .filter_map(|f| f.parent().map(Path::to_path_buf))
        .map(|p| normalize_key(&p.to_string_lossy()))
        .collect::<HashSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(next: u32, action: u32, name: &str) -> Vec<u8> {
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut v = Vec::new();
        v.extend_from_slice(&next.to_le_bytes());
        v.extend_from_slice(&action.to_le_bytes());
        v.extend_from_slice(&(units.len() as u32).to_le_bytes());
        v.extend_from_slice(&units);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn parses_notification_chain() {
        let a = record(0, 2, "credentials");
        let mut first = record(0, 3, "config");
        let next = first.len() as u32;
        first[..4].copy_from_slice(&next.to_le_bytes());
        first.extend(a);
        let parsed = parse_notifications(&first);
        assert_eq!(
            parsed,
            vec![(3, "config".into()), (2, "credentials".into())]
        );
        assert!(parse_notifications(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn detects_deletion_and_modification() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("credentials");
        let b = dir.path().join("config.json");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        std::fs::write(dir.path().join("unrelated.txt"), b"u").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let w = IntegrityWatcher::start(tx).unwrap();
        w.set_files(vec![a.clone(), b.clone()]);
        let deadline = Instant::now() + Duration::from_secs(3);
        while w.watched.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::write(dir.path().join("unrelated.txt"), b"changed").unwrap();
        std::fs::remove_file(&a).unwrap();
        std::fs::write(&b, b"tampered").unwrap();
        let mut seen = Vec::new();
        while let Ok(ev) = rx.recv_timeout(Duration::from_secs(2)) {
            if let SensorEvent::Integrity { path, change, .. } = ev {
                seen.push((path, change));
            }
        }
        assert!(
            seen.iter()
                .any(|(p, c)| *p == a.to_string_lossy() && *c == IntegrityChange::Removed)
        );
        assert!(
            seen.iter()
                .any(|(p, c)| *p == b.to_string_lossy() && *c == IntegrityChange::Modified)
        );
        assert!(!seen.iter().any(|(p, _)| p.ends_with("unrelated.txt")));
    }
}
