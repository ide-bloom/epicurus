//! The incident model. Its JSON form is the stable export format documented
//! in docs/incident-schema.md; bump [`INCIDENT_SCHEMA_VERSION`] on breaking
//! changes.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::catalog::Category;
use crate::scoring::{Reason, Severity};

/// Version of the exported incident JSON schema.
pub const INCIDENT_SCHEMA_VERSION: u32 = 1;

/// Authenticode verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Valid signature chaining to a trusted root.
    Valid,
    /// No signature (embedded or catalog).
    Unsigned,
    /// Signature present but invalid, revoked, expired or untrusted.
    Invalid,
    /// Could not be determined (image unreadable).
    #[default]
    Unknown,
}

/// Signature details.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Verdict.
    pub status: SignatureStatus,
    /// Signer chain subject names, leaf first.
    pub chain: Vec<String>,
    /// True if validated through a security catalog rather than an embedded signature.
    pub catalog_signed: bool,
    /// WinVerifyTrust result code (hex) when not valid.
    pub error: Option<String>,
}

impl SignatureInfo {
    /// Leaf signer.
    pub fn signer(&self) -> Option<&str> {
        self.chain.first().map(String::as_str)
    }
}

/// Network endpoint owned by the process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetConnection {
    /// `tcp` / `tcp6` / `udp` / `udp6`.
    pub protocol: String,
    /// Local address:port.
    pub local: String,
    /// Remote address:port (empty for UDP/listeners).
    pub remote: String,
    /// TCP state name.
    pub state: String,
}

/// One node of a process tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessNode {
    /// PID.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Image path (or name if the path is unknown).
    pub image: String,
    /// Command line if known.
    pub command_line: Option<String>,
    /// Start time.
    #[serde(with = "crate::timefmt::serde_rfc3339::option", default)]
    pub start_time: Option<OffsetDateTime>,
    /// `ancestor`, `subject` or `child`.
    pub role: String,
}

/// Everything known about the process that touched the decoy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessProfile {
    /// PID (0 if unattributed).
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Start time (with the PID it forms the unique process key).
    #[serde(with = "crate::timefmt::serde_rfc3339::option", default)]
    pub start_time: Option<OffsetDateTime>,
    /// Image path.
    pub image_path: String,
    /// Image SHA-256.
    pub image_sha256: Option<String>,
    /// Image size.
    pub image_size: Option<u64>,
    /// Image creation time.
    #[serde(with = "crate::timefmt::serde_rfc3339::option", default)]
    pub image_created: Option<OffsetDateTime>,
    /// Signature.
    pub signature: SignatureInfo,
    /// Command line.
    pub command_line: Option<String>,
    /// `DOMAIN\user`.
    pub user: Option<String>,
    /// User SID.
    pub user_sid: Option<String>,
    /// Integrity level label.
    pub integrity: Option<String>,
    /// Image is in a user-writable location.
    pub user_writable_dir: bool,
    /// Image is in %TEMP% or Downloads.
    pub temp_or_downloads: bool,
    /// Network connections at triage time.
    pub network: Vec<NetConnection>,
    /// Loaded module paths at triage time.
    pub modules: Vec<String>,
    /// Process had already exited when triaged.
    pub exited: bool,
    /// Critical or protected (PPL) process: never contained.
    pub protected: bool,
}

/// Kind of decoy access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TouchOp {
    /// Opened.
    Open,
    /// Read data.
    Read,
    /// Deleted.
    Delete,
    /// Renamed.
    Rename,
    /// Content changed.
    Modify,
}

/// Which sensor saw a touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorSource {
    /// Kernel-File ETW.
    Etw,
    /// Oplock break.
    Oplock,
    /// Security event 4663.
    Audit,
    /// ReadDirectoryChangesW.
    Integrity,
}

/// One decoy access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyTouch {
    /// When.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub at: OffsetDateTime,
    /// Decoy id.
    pub decoy_id: String,
    /// Category.
    pub category: Category,
    /// File path.
    pub path: String,
    /// Operation.
    pub op: TouchOp,
    /// Sensor.
    pub source: SensorSource,
    /// Bytes read, when known.
    pub bytes: Option<u64>,
}

/// Lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Recorded; no decision pending.
    #[default]
    Open,
    /// Process tree is suspended, waiting for the user.
    AwaitingDecision,
    /// Closed by a user action.
    Resolved,
}

/// User decisions and automatic actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Suspend the tree.
    Suspend,
    /// Kill the tree.
    KillTree,
    /// Resume the tree.
    Resume,
    /// Terminate and move the image to quarantine.
    Quarantine,
    /// Add a firewall outbound block rule for the image.
    BlockNetwork,
    /// Allowlist the image (signer + path, or hash) and resume.
    Allowlist,
    /// Write a minidump.
    Minidump,
    /// Mark resolved without action.
    Dismiss,
}

impl ActionKind {
    /// Stable identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Suspend => "suspend",
            ActionKind::KillTree => "kill_tree",
            ActionKind::Resume => "resume",
            ActionKind::Quarantine => "quarantine",
            ActionKind::BlockNetwork => "block_network",
            ActionKind::Allowlist => "allowlist",
            ActionKind::Minidump => "minidump",
            ActionKind::Dismiss => "dismiss",
        }
    }
}

/// Who initiated an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    /// The configured policy.
    Policy,
    /// The user.
    User,
}

/// A recorded action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {
    /// When.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub at: OffsetDateTime,
    /// What.
    pub action: ActionKind,
    /// Who.
    pub actor: Actor,
    /// Succeeded.
    pub ok: bool,
    /// Details or error.
    pub detail: String,
}

/// A timeline entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// When.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub at: OffsetDateTime,
    /// Short kind.
    pub kind: String,
    /// Message.
    pub message: String,
}

/// An incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    /// Schema version.
    pub schema_version: u32,
    /// Id (`inc_` + 16 hex).
    pub id: String,
    /// Created.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub created_at: OffsetDateTime,
    /// Last updated.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Produced by `epicurus simulate`.
    pub simulated: bool,
    /// Score 0-100.
    pub score: u8,
    /// Severity.
    pub severity: Severity,
    /// Score explanation.
    pub reasons: Vec<Reason>,
    /// Status.
    pub status: IncidentStatus,
    /// Subject process.
    pub process: ProcessProfile,
    /// Ancestors (root first), the subject, and descendants.
    pub tree: Vec<ProcessNode>,
    /// Decoy touches.
    pub touches: Vec<DecoyTouch>,
    /// Other sensitive real paths the process opened in the window.
    pub related_paths: Vec<String>,
    /// Timeline.
    pub timeline: Vec<TimelineEntry>,
    /// Actions.
    pub actions: Vec<ActionRecord>,
    /// PIDs currently suspended by Epicurus.
    pub suspended_pids: Vec<u32>,
    /// Hostname.
    pub host: String,
    /// Epicurus version that produced it.
    pub epicurus_version: String,
}

impl Incident {
    /// New, empty incident for a process.
    pub fn new(process: ProcessProfile, now: OffsetDateTime, host: String) -> Self {
        Self {
            schema_version: INCIDENT_SCHEMA_VERSION,
            id: new_incident_id(),
            created_at: now,
            updated_at: now,
            simulated: false,
            score: 0,
            severity: Severity::Info,
            reasons: Vec::new(),
            status: IncidentStatus::Open,
            process,
            tree: Vec::new(),
            touches: Vec::new(),
            related_paths: Vec::new(),
            timeline: Vec::new(),
            actions: Vec::new(),
            suspended_pids: Vec::new(),
            host,
            epicurus_version: crate::VERSION.to_string(),
        }
    }

    /// Distinct decoy ids touched.
    pub fn distinct_decoys(&self) -> usize {
        let mut ids: Vec<&str> = self.touches.iter().map(|t| t.decoy_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }

    /// Distinct categories touched.
    pub fn distinct_categories(&self) -> Vec<Category> {
        let mut c: Vec<Category> = self.touches.iter().map(|t| t.category).collect();
        c.sort();
        c.dedup();
        c
    }

    /// Appends to the timeline.
    pub fn log(&mut self, at: OffsetDateTime, kind: &str, message: impl Into<String>) {
        self.timeline.push(TimelineEntry {
            at,
            kind: kind.to_string(),
            message: message.into(),
        });
        self.updated_at = at;
    }

    /// Records an action.
    pub fn record_action(
        &mut self,
        at: OffsetDateTime,
        action: ActionKind,
        actor: Actor,
        ok: bool,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        self.log(
            at,
            "action",
            format!(
                "{} ({}): {}",
                action.as_str(),
                if ok { "ok" } else { "failed" },
                detail
            ),
        );
        self.actions.push(ActionRecord {
            at,
            action,
            actor,
            ok,
            detail,
        });
    }

    /// Compact summary for lists and push notifications.
    pub fn summary(&self) -> IncidentSummary {
        IncidentSummary {
            id: self.id.clone(),
            created_at: self.created_at,
            severity: self.severity,
            score: self.score,
            status: self.status,
            simulated: self.simulated,
            pid: self.process.pid,
            image: self.process.image_path.clone(),
            decoys: self.distinct_decoys() as u32,
            categories: self.distinct_categories(),
        }
    }
}

/// Compact incident row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentSummary {
    /// Id.
    pub id: String,
    /// Created.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub created_at: OffsetDateTime,
    /// Severity.
    pub severity: Severity,
    /// Score.
    pub score: u8,
    /// Status.
    pub status: IncidentStatus,
    /// Simulated.
    pub simulated: bool,
    /// PID.
    pub pid: u32,
    /// Image path.
    pub image: String,
    /// Distinct decoys.
    pub decoys: u32,
    /// Categories.
    pub categories: Vec<Category>,
}

/// New random incident id.
pub fn new_incident_id() -> String {
    let mut b = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut b);
    format!("inc_{}", hex::encode(b))
}

/// Validates the incident id format (used on every IPC input).
pub fn is_valid_incident_id(s: &str) -> bool {
    s.len() == 20
        && s.starts_with("inc_")
        && s[4..]
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_valid_and_unique() {
        let a = new_incident_id();
        let b = new_incident_id();
        assert!(is_valid_incident_id(&a));
        assert_ne!(a, b);
        assert!(!is_valid_incident_id("inc_ABCDEF0123456789"));
        assert!(!is_valid_incident_id("inc_123"));
        assert!(!is_valid_incident_id("../../etc/passwd"));
    }

    #[test]
    fn json_roundtrip() {
        let mut i = Incident::new(
            ProcessProfile {
                pid: 42,
                ..Default::default()
            },
            OffsetDateTime::now_utc(),
            "host".into(),
        );
        i.touches.push(DecoyTouch {
            at: OffsetDateTime::now_utc(),
            decoy_id: "aws-credentials".into(),
            category: Category::Cloud,
            path: r"C:\x".into(),
            op: TouchOp::Open,
            source: SensorSource::Etw,
            bytes: None,
        });
        i.record_action(
            OffsetDateTime::now_utc(),
            ActionKind::Suspend,
            Actor::Policy,
            true,
            "ok",
        );
        let j = serde_json::to_string(&i).unwrap();
        let back: Incident = serde_json::from_str(&j).unwrap();
        // RFC 3339 keeps nanoseconds, so the roundtrip is exact.
        assert_eq!(back, i);
        assert_eq!(i.summary().decoys, 1);
    }
}
