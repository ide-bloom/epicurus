//! Events emitted by the sensors, and the shared filter that tells them
//! which paths matter.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use epicurus_core::paths::normalize_key;
use time::OffsetDateTime;

/// One sensor observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensorEvent {
    /// A decoy was opened (ETW Create or audit 4663).
    DecoyOpen {
        /// When.
        at: OffsetDateTime,
        /// Opening process.
        pid: u32,
        /// DOS path.
        path: String,
        /// Read data was requested (known only in audit mode).
        read_data: bool,
        /// Which sensor.
        source: epicurus_core::incident::SensorSource,
        /// Image name reported by the sensor (audit mode).
        image_hint: Option<String>,
    },
    /// A decoy was deleted or renamed (ETW DeletePath / RenamePath).
    DecoyDeleteOrRename {
        /// When.
        at: OffsetDateTime,
        /// Process.
        pid: u32,
        /// DOS path.
        path: String,
        /// True for rename.
        rename: bool,
    },
    /// An oplock on a decoy broke: something is opening it.
    OplockBreak {
        /// Precise time of the break.
        at: OffsetDateTime,
        /// DOS path.
        path: String,
    },
    /// A directory watcher saw a decoy change.
    Integrity {
        /// When.
        at: OffsetDateTime,
        /// DOS path.
        path: String,
        /// Change.
        change: IntegrityChange,
    },
    /// A process started (ETW Kernel-Process).
    ProcessStart {
        /// PID.
        pid: u32,
        /// Parent PID.
        ppid: u32,
        /// Creation time.
        create_time: OffsetDateTime,
        /// DOS image path.
        image: String,
        /// Session id.
        session: u32,
    },
    /// A process exited.
    ProcessStop {
        /// PID.
        pid: u32,
        /// Creation time.
        create_time: Option<OffsetDateTime>,
        /// Exit time.
        exit_time: OffsetDateTime,
    },
    /// Sensor failure or recovery worth surfacing.
    Health {
        /// Message.
        message: String,
    },
}

/// Directory-watcher change kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityChange {
    /// Removed.
    Removed,
    /// Content or metadata changed.
    Modified,
    /// Renamed away.
    RenamedAway,
}

/// Paths the file sensors care about. Shared between the engine (writer) and
/// the sensor threads (readers).
#[derive(Debug, Default)]
pub struct PathFilter {
    /// Normalized keys of decoy files.
    decoys: HashSet<String>,
    /// Normalized prefixes of real credential stores, used to note "other
    /// sensitive paths opened" by a suspect process.
    sensitive: Vec<String>,
}

impl PathFilter {
    /// Replaces the decoy set.
    pub fn set_decoys<'a>(&mut self, paths: impl IntoIterator<Item = &'a str>) {
        self.decoys = paths.into_iter().map(normalize_key).collect();
    }

    /// Replaces the sensitive prefixes.
    pub fn set_sensitive(&mut self, prefixes: Vec<String>) {
        self.sensitive = prefixes.into_iter().map(|p| normalize_key(&p)).collect();
    }

    /// True for a decoy path (expects a normalized key).
    pub fn is_decoy_key(&self, key: &str) -> bool {
        self.decoys.contains(key)
    }

    /// True for a real sensitive path that is not a decoy.
    pub fn is_sensitive_key(&self, key: &str) -> bool {
        !self.decoys.contains(key) && self.sensitive.iter().any(|p| key.starts_with(p.as_str()))
    }

    /// Number of decoys.
    pub fn decoy_count(&self) -> usize {
        self.decoys.len()
    }
}

/// Shared filter handle.
pub type SharedFilter = Arc<RwLock<PathFilter>>;

/// Default sensitive prefixes for a profile: the real stores stealers raid.
pub fn sensitive_prefixes(env: &epicurus_core::paths::EnvMap) -> Vec<String> {
    let rel_local = [
        r"Google\Chrome\User Data",
        r"Microsoft\Edge\User Data",
        r"BraveSoftware\Brave-Browser\User Data",
        r"github-copilot",
    ];
    let rel_roaming = [
        r"Mozilla\Firefox\Profiles",
        r"Exodus",
        r"Electrum",
        r"atomic",
        r"Telegram Desktop\tdata",
        r"discord\Local Storage",
        r"Cursor\User\globalStorage",
        r"Claude",
        r"gcloud",
    ];
    let rel_home = [
        ".ssh",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".claude",
        ".codex",
        ".cursor",
        ".gemini",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        ".openclaw",
    ];
    let mut out = Vec::new();
    if let Some(l) = env.get("LOCALAPPDATA") {
        out.extend(rel_local.iter().map(|r| format!(r"{l}\{r}")));
    }
    if let Some(a) = env.get("APPDATA") {
        out.extend(rel_roaming.iter().map(|r| format!(r"{a}\{r}")));
    }
    if let Some(h) = env.get("USERPROFILE") {
        out.extend(rel_home.iter().map(|r| format!(r"{h}\{r}")));
    }
    out
}

/// Recent sensitive-path opens per PID, kept by the ETW thread and queried
/// by triage. Bounded in PIDs, entries and age so it cannot grow without
/// limit under heavy browser activity.
#[derive(Debug, Default)]
pub struct SensitiveCache {
    by_pid: HashMap<u32, VecDeque<(OffsetDateTime, String)>>,
    order: VecDeque<u32>,
}

const MAX_PIDS: usize = 512;
const MAX_PER_PID: usize = 64;

impl SensitiveCache {
    /// Records an open.
    pub fn record(&mut self, pid: u32, at: OffsetDateTime, path: String) {
        if !self.by_pid.contains_key(&pid) {
            if self.order.len() >= MAX_PIDS
                && let Some(old) = self.order.pop_front()
            {
                self.by_pid.remove(&old);
            }
            self.order.push_back(pid);
        }
        let q = self.by_pid.entry(pid).or_default();
        if q.iter().any(|(_, p)| *p == path) {
            return;
        }
        if q.len() >= MAX_PER_PID {
            q.pop_front();
        }
        q.push_back((at, path));
    }

    /// Paths opened by `pid` at or after `since`.
    pub fn paths_since(&self, pid: u32, since: OffsetDateTime) -> Vec<String> {
        self.by_pid
            .get(&pid)
            .map(|q| {
                q.iter()
                    .filter(|(t, _)| *t >= since)
                    .map(|(_, p)| p.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Shared cache handle.
pub type SharedSensitive = Arc<Mutex<SensitiveCache>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_distinguishes_decoys_and_sensitive() {
        let mut f = PathFilter::default();
        f.set_decoys([r"C:\Users\a\.aws\credentials"]);
        f.set_sensitive(vec![r"C:\Users\a\.aws".into()]);
        assert!(f.is_decoy_key(r"c:\users\a\.aws\credentials"));
        assert!(!f.is_sensitive_key(r"c:\users\a\.aws\credentials"));
        assert!(f.is_sensitive_key(r"c:\users\a\.aws\config"));
        assert!(!f.is_sensitive_key(r"c:\users\a\documents\x"));
    }

    #[test]
    fn sensitive_cache_is_bounded() {
        let mut c = SensitiveCache::default();
        let now = OffsetDateTime::now_utc();
        for i in 0..200 {
            c.record(1, now, format!("p{i}"));
        }
        assert_eq!(c.paths_since(1, now).len(), MAX_PER_PID);
        for pid in 0..(MAX_PIDS as u32 + 10) {
            c.record(pid + 10, now, "x".into());
        }
        assert!(c.by_pid.len() <= MAX_PIDS);
        c.record(5, now, "dup".into());
        c.record(5, now, "dup".into());
        assert_eq!(c.paths_since(5, now).len(), 1);
    }
}
