//! Oplock tripwire: an early-warning sensor independent of ETW.
//!
//! For each decoy we open a handle and request an opportunistic lock with
//! `FSCTL_REQUEST_OPLOCK` through overlapped I/O. When any other process opens
//! the file in a way that conflicts with the oplock, the file system breaks it
//! and completes our pending request: that completion is the tripwire.
//!
//! Sharing semantics (see docs/architecture.md for the full discussion):
//!
//! * Our handle is opened with `FILE_SHARE_READ | FILE_SHARE_WRITE |
//!   FILE_SHARE_DELETE`, so it never causes a sharing violation for anyone,
//!   including deletes and renames.
//! * A Read-Handle (RH) oplock (`OPLOCK_LEVEL_CACHE_READ |
//!   OPLOCK_LEVEL_CACHE_HANDLE`) breaks on writes, deletes, renames and
//!   sharing conflicts, but *not* on a plain read-only open, because several
//!   readers may each hold RH. A stealer that only reads would slip past.
//! * We therefore first request Read-Write-Handle (RWH = RH plus
//!   `OPLOCK_LEVEL_CACHE_WRITE`). RWH is exclusive, so it breaks on any open
//!   by another oplock key that requests data access, including read-only
//!   opens. Attribute-only opens (e.g. Explorer listing a folder) do not
//!   break it, which keeps noise down.
//! * The opener's create waits until the break is acknowledged. We record
//!   the timestamp and acknowledge immediately by closing our handle, so the
//!   delay seen by the opener is microseconds and nothing is ever blocked.
//! * RWH can only be granted while nobody else has the file open. If it is
//!   refused (an indexer or AV scanner is mid-read) we retry with backoff and
//!   after three refusals settle for RH until the next break.
//! * Our own service opens decoys too (re-arming, hashing); those breaks are
//!   suppressed by path for a short window.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use epicurus_core::paths::normalize_key;
use windows::Win32::Foundation::{ERROR_IO_PENDING, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::{DeviceIoControl, OVERLAPPED};
use windows::Win32::System::Ioctl::{
    FSCTL_REQUEST_OPLOCK, OPLOCK_LEVEL_CACHE_HANDLE, OPLOCK_LEVEL_CACHE_READ,
    OPLOCK_LEVEL_CACHE_WRITE, REQUEST_OPLOCK_CURRENT_VERSION, REQUEST_OPLOCK_INPUT_BUFFER,
    REQUEST_OPLOCK_INPUT_FLAG_REQUEST, REQUEST_OPLOCK_OUTPUT_BUFFER,
};
use windows::core::PCWSTR;

use crate::error::Result;
use crate::events::SensorEvent;
use crate::iocp::{Packet, Port, WAKE_KEY};
use crate::winutil::{OwnedHandle, precise_now, wide};

const LEVEL_RWH: u32 =
    OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE;
const LEVEL_RH: u32 = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;

/// Counters exposed to status and doctor.
#[derive(Debug, Default)]
pub struct OplockStats {
    /// Slots with a granted oplock.
    pub armed: AtomicU32,
    /// Slots holding the exclusive RWH level.
    pub armed_rwh: AtomicU32,
    /// Total decoy files.
    pub total: AtomicU32,
    /// Breaks observed.
    pub breaks: AtomicU32,
}

enum Cmd {
    SetPaths(Vec<PathBuf>),
    Suppress(String, Instant),
    Shutdown,
}

/// Owns the tripwire thread.
pub struct OplockManager {
    tx: Sender<Cmd>,
    port: Arc<Port>,
    thread: Option<JoinHandle<()>>,
    /// Counters.
    pub stats: Arc<OplockStats>,
}

impl OplockManager {
    /// Starts the tripwire thread.
    pub fn start(events: Sender<SensorEvent>) -> Result<Self> {
        let port = Arc::new(Port::new()?);
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Arc::new(OplockStats::default());
        let (p, s) = (port.clone(), stats.clone());
        let thread = std::thread::Builder::new()
            .name("oplock-tripwire".into())
            .spawn(move || Worker::new(p, s, events).run(rx))?;
        Ok(Self {
            tx,
            port,
            thread: Some(thread),
            stats,
        })
    }

    /// Replaces the set of decoy files.
    pub fn set_paths(&self, paths: Vec<PathBuf>) {
        let _ = self.tx.send(Cmd::SetPaths(paths));
        self.port.wake();
    }

    /// Ignores breaks on `path` for `dur` (our own access).
    pub fn suppress(&self, path: &str, dur: Duration) {
        let _ = self
            .tx
            .send(Cmd::Suppress(normalize_key(path), Instant::now() + dur));
        self.port.wake();
    }
}

impl Drop for OplockManager {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Shutdown);
        self.port.wake();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct Slot {
    path: PathBuf,
    key: String,
    handle: Option<OwnedHandle>,
    // Boxed so their addresses stay fixed while I/O is pending.
    ov: Box<OVERLAPPED>,
    input: Box<REQUEST_OPLOCK_INPUT_BUFFER>,
    output: Box<REQUEST_OPLOCK_OUTPUT_BUFFER>,
    pending: bool,
    closing: bool,
    level: u32,
    refusals: u32,
    rearm_at: Option<Instant>,
}

struct Worker {
    port: Arc<Port>,
    stats: Arc<OplockStats>,
    events: Sender<SensorEvent>,
    slots: HashMap<usize, Slot>,
    next_key: usize,
    suppressed: HashMap<String, Instant>,
}

impl Worker {
    fn new(port: Arc<Port>, stats: Arc<OplockStats>, events: Sender<SensorEvent>) -> Self {
        Self {
            port,
            stats,
            events,
            slots: HashMap::new(),
            next_key: 1,
            suppressed: HashMap::new(),
        }
    }

    fn run(mut self, rx: Receiver<Cmd>) {
        loop {
            match self.port.wait(250) {
                Packet::Timeout => {}
                Packet::Io { key: WAKE_KEY, .. } => {}
                Packet::Io { key, error, .. } => self.on_completion(key, error),
            }
            loop {
                match rx.try_recv() {
                    Ok(Cmd::SetPaths(p)) => self.set_paths(p),
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
            self.rearm_due();
            self.update_stats();
        }
    }

    fn update_stats(&self) {
        let armed = self
            .slots
            .values()
            .filter(|s| s.pending && !s.closing)
            .count() as u32;
        let rwh = self
            .slots
            .values()
            .filter(|s| s.pending && !s.closing && s.level == LEVEL_RWH)
            .count() as u32;
        self.stats.armed.store(armed, Ordering::Relaxed);
        self.stats.armed_rwh.store(rwh, Ordering::Relaxed);
        self.stats
            .total
            .store(self.slots.len() as u32, Ordering::Relaxed);
    }

    fn set_paths(&mut self, paths: Vec<PathBuf>) {
        self.close_all();
        for path in paths {
            let key = self.next_key;
            self.next_key += 1;
            self.slots.insert(
                key,
                Slot {
                    key: normalize_key(&path.to_string_lossy()),
                    path,
                    handle: None,
                    ov: Box::default(),
                    input: Box::new(REQUEST_OPLOCK_INPUT_BUFFER::default()),
                    output: Box::new(REQUEST_OPLOCK_OUTPUT_BUFFER::default()),
                    pending: false,
                    closing: false,
                    level: LEVEL_RWH,
                    refusals: 0,
                    rearm_at: Some(Instant::now()),
                },
            );
        }
    }

    /// Closes every handle and waits (bounded) for the aborted requests to
    /// drain, so no kernel write can land in a freed buffer.
    fn close_all(&mut self) {
        for s in self.slots.values_mut() {
            s.closing = true;
            s.handle = None;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.slots.values().any(|s| s.pending) && Instant::now() < deadline {
            if let Packet::Io { key, .. } = self.port.wait(100)
                && let Some(s) = self.slots.get_mut(&key)
            {
                s.pending = false;
            }
        }
        // Any slot still pending keeps its buffers alive by being leaked
        // rather than freed under the kernel.
        for (_, s) in self.slots.drain() {
            if s.pending {
                std::mem::forget(s);
            }
        }
    }

    fn on_completion(&mut self, key: usize, error: u32) {
        let Some(slot) = self.slots.get_mut(&key) else {
            return;
        };
        slot.pending = false;
        if slot.closing {
            slot.closing = false;
            return;
        }
        // The request completed: the oplock broke (error 0) or the request
        // failed after being queued. Either way, record and re-arm.
        let at = precise_now();
        slot.handle = None; // closing the handle acknowledges the break
        let suppressed = self
            .suppressed
            .get(&slot.key)
            .is_some_and(|until| Instant::now() < *until);
        if error == 0 && !suppressed {
            self.stats.breaks.fetch_add(1, Ordering::Relaxed);
            let _ = self.events.send(SensorEvent::OplockBreak {
                at,
                path: slot.path.to_string_lossy().into_owned(),
            });
        }
        // Wait a moment: the opener usually still holds the file, and an
        // exclusive oplock cannot be granted until it closes.
        slot.level = LEVEL_RWH;
        slot.refusals = 0;
        slot.rearm_at = Some(Instant::now() + Duration::from_millis(300));
    }

    fn rearm_due(&mut self) {
        let now = Instant::now();
        self.suppressed.retain(|_, until| *until > now);
        let due: Vec<usize> = self
            .slots
            .iter()
            .filter(|(_, s)| !s.pending && s.rearm_at.is_some_and(|t| t <= now))
            .map(|(k, _)| *k)
            .collect();
        for key in due {
            self.arm(key);
        }
    }

    fn arm(&mut self, key: usize) {
        let port = self.port.clone();
        let Some(slot) = self.slots.get_mut(&key) else {
            return;
        };
        slot.rearm_at = None;
        // Our own open must not register as a touch in ETW-less modes.
        self.suppressed.insert(
            slot.key.clone(),
            Instant::now() + Duration::from_millis(500),
        );

        let w = wide(&slot.path);
        // SAFETY: path is NUL-terminated; handle ownership moves into OwnedHandle.
        let h = match unsafe {
            CreateFileW(
                PCWSTR(w.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        } {
            Ok(h) => OwnedHandle(h),
            Err(_) => {
                // Missing (deleted, being re-planted) or locked: retry later.
                slot.rearm_at = Some(Instant::now() + Duration::from_secs(2));
                return;
            }
        };
        if port.associate(h.raw(), key).is_err() {
            slot.rearm_at = Some(Instant::now() + Duration::from_secs(5));
            return;
        }
        *slot.input = REQUEST_OPLOCK_INPUT_BUFFER {
            StructureVersion: REQUEST_OPLOCK_CURRENT_VERSION as u16,
            StructureLength: std::mem::size_of::<REQUEST_OPLOCK_INPUT_BUFFER>() as u16,
            RequestedOplockLevel: slot.level,
            Flags: REQUEST_OPLOCK_INPUT_FLAG_REQUEST,
        };
        *slot.output = REQUEST_OPLOCK_OUTPUT_BUFFER::default();
        *slot.ov = OVERLAPPED::default();
        let r = request(h.raw(), &slot.input, &mut slot.output, &mut slot.ov);
        match r {
            // Granted and pending until it breaks. (A synchronous success
            // still queues a packet, handled as a break.)
            Ok(()) => {
                slot.pending = true;
                slot.handle = Some(h);
            }
            Err(code) if code == ERROR_IO_PENDING.0 => {
                slot.pending = true;
                slot.handle = Some(h);
            }
            Err(code) => {
                drop(h);
                slot.refusals += 1;
                if slot.level == LEVEL_RWH && slot.refusals >= 3 {
                    tracing::debug!(path = %slot.path.display(), code, "RWH oplock refused repeatedly; falling back to RH");
                    slot.level = LEVEL_RH;
                }
                let backoff = 250u64 << slot.refusals.min(5);
                slot.rearm_at = Some(Instant::now() + Duration::from_millis(backoff));
            }
        }
    }
}

fn request(
    h: HANDLE,
    input: &REQUEST_OPLOCK_INPUT_BUFFER,
    output: &mut REQUEST_OPLOCK_OUTPUT_BUFFER,
    ov: &mut OVERLAPPED,
) -> std::result::Result<(), u32> {
    // SAFETY: buffers and OVERLAPPED are boxed in the slot and outlive the
    // request (the slot is only freed after its completion is dequeued).
    let r = unsafe {
        DeviceIoControl(
            h,
            FSCTL_REQUEST_OPLOCK,
            Some((input as *const REQUEST_OPLOCK_INPUT_BUFFER).cast()),
            std::mem::size_of::<REQUEST_OPLOCK_INPUT_BUFFER>() as u32,
            Some((output as *mut REQUEST_OPLOCK_OUTPUT_BUFFER).cast()),
            std::mem::size_of::<REQUEST_OPLOCK_OUTPUT_BUFFER>() as u32,
            None,
            Some(ov),
        )
    };
    r.map_err(|e| (e.code().0 as u32) & 0xFFFF)
}

/// Probes whether a directory's volume grants RWH/RH oplocks (for doctor).
/// Creates and deletes a temporary file inside `dir`.
pub fn probe_volume(dir: &std::path::Path) -> std::result::Result<&'static str, String> {
    let probe = dir.join(format!(".epicurus-oplock-probe-{}", std::process::id()));
    std::fs::write(&probe, b"probe").map_err(|e| e.to_string())?;
    let result = (|| {
        let w = wide(&probe);
        // SAFETY: as in `arm`.
        let h = unsafe {
            CreateFileW(
                PCWSTR(w.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        }
        .map_err(|e| e.message())?;
        let h = OwnedHandle(h);
        let port = Port::new().map_err(|e| e.to_string())?;
        port.associate(h.raw(), 1).map_err(|e| e.to_string())?;
        for (level, name) in [(LEVEL_RWH, "RWH"), (LEVEL_RH, "RH")] {
            let input = REQUEST_OPLOCK_INPUT_BUFFER {
                StructureVersion: REQUEST_OPLOCK_CURRENT_VERSION as u16,
                StructureLength: std::mem::size_of::<REQUEST_OPLOCK_INPUT_BUFFER>() as u16,
                RequestedOplockLevel: level,
                Flags: REQUEST_OPLOCK_INPUT_FLAG_REQUEST,
            };
            let mut output = Box::new(REQUEST_OPLOCK_OUTPUT_BUFFER::default());
            let mut ov = Box::new(OVERLAPPED::default());
            match request(h.raw(), &input, &mut output, &mut ov) {
                Err(code) if code == ERROR_IO_PENDING.0 => {
                    drop(h);
                    // Drain the aborted request before the buffers go away.
                    let _ = port.wait(2000);
                    return Ok(name);
                }
                Ok(()) => {
                    drop(h);
                    let _ = port.wait(2000);
                    return Ok(name);
                }
                Err(_) => continue,
            }
        }
        Err("oplocks not granted on this volume".to_string())
    })();
    let _ = std::fs::remove_file(&probe);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn temp_volume_supports_oplocks() {
        let dir = tempfile::tempdir().unwrap();
        let level = probe_volume(dir.path()).unwrap();
        assert!(level == "RWH" || level == "RH");
    }

    #[test]
    fn read_only_open_by_another_handle_breaks_the_oplock_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let decoy = dir.path().join("credentials");
        std::fs::write(&decoy, b"decoy").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mgr = OplockManager::start(tx).unwrap();
        mgr.set_paths(vec![decoy.clone()]);
        // Wait until armed.
        let deadline = Instant::now() + Duration::from_secs(5);
        while mgr.stats.armed.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            mgr.stats.armed.load(Ordering::Relaxed),
            1,
            "oplock should be armed"
        );
        // Let the self-suppression window pass.
        std::thread::sleep(Duration::from_millis(600));
        // A plain read-only open, like a stealer would do. It must not block.
        let started = Instant::now();
        let mut s = String::new();
        std::fs::File::open(&decoy)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "decoy");
        assert!(started.elapsed() < Duration::from_secs(1));
        match rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            SensorEvent::OplockBreak { path, .. } => assert_eq!(path, decoy.to_string_lossy()),
            other => panic!("unexpected {other:?}"),
        }
        // And the tripwire re-arms.
        let deadline = Instant::now() + Duration::from_secs(5);
        while mgr.stats.armed.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(mgr.stats.armed.load(Ordering::Relaxed), 1);
        // Deleting the decoy is never blocked by our handle.
        std::fs::remove_file(&decoy).unwrap();
        assert!(!decoy.exists());
    }
}
