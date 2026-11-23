//! IPC between the LocalSystem service and its unprivileged clients
//! (dashboard, tray agent, CLI) over a named pipe.
//!
//! Wire format: a 4-byte little-endian length followed by that many bytes of
//! UTF-8 JSON. Every message carries a protocol version. The server treats
//! all input as hostile: frames are size-capped before allocation, unknown
//! fields are rejected, and every string and number is range-checked by
//! [`Request::validate`] before it reaches the engine.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::allowlist::AllowEntry;
use crate::catalog::Category;
use crate::config::{PolicyConfig, SensorMode, Theme};
use crate::incident::{ActionKind, Incident, IncidentSummary, is_valid_incident_id};
use crate::manifest::ManifestEntry;
use crate::plan::{Plan, SkipReason};
use crate::plant::UnplantReport;
use crate::scoring::Severity;
use crate::storage::{EventRow, TouchLogRow};
use crate::{Error, Result};

/// Protocol version. Bump on incompatible changes.
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest request the server accepts.
pub const MAX_REQUEST_BYTES: u32 = 256 * 1024;
/// Largest response a client accepts.
pub const MAX_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;

/// Requests clients may send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Protection and sensor status.
    Status,
    /// Recent incident summaries.
    ListIncidents {
        /// Max rows (1..=1000).
        limit: u32,
    },
    /// One incident.
    GetIncident {
        /// Incident id.
        id: String,
    },
    /// Apply a user decision.
    IncidentAction {
        /// Incident id.
        id: String,
        /// Action.
        action: ActionKind,
    },
    /// Plant decoys (or compute the plan only).
    Plant {
        /// Catalog profile override.
        profile: Option<String>,
        /// Compute without changing anything.
        dry_run: bool,
    },
    /// Remove every decoy whose hash still matches.
    Unplant,
    /// Re-plant missing decoys.
    Replant,
    /// The manifest and enabled categories.
    GetManifest,
    /// Enable or disable a category (re-plants or unplants accordingly).
    SetCategory {
        /// Category.
        category: Category,
        /// Enabled.
        enabled: bool,
    },
    /// User allowlist entries.
    GetAllowlist,
    /// Replace the user allowlist.
    SetAllowlist {
        /// Entries.
        entries: Vec<AllowEntry>,
    },
    /// Alert channel configuration (secrets are never returned).
    GetAlerts,
    /// Update one alert channel.
    SetAlertChannel {
        /// Update.
        update: AlertUpdate,
    },
    /// Send a test message.
    TestAlert {
        /// Channel.
        channel: ChannelKind,
    },
    /// Settings.
    GetSettings,
    /// Update settings.
    SetSettings {
        /// Update.
        update: SettingsUpdate,
    },
    /// Service-side diagnostics.
    Doctor,
    /// Recent touch log and events.
    Activity {
        /// Look-back in hours (1..=720).
        hours: u32,
    },
    /// Turn this connection into an event stream.
    Subscribe,
}

/// Alert channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    /// Windows toast.
    Toast,
    /// Windows Event Log.
    EventLog,
    /// Discord webhook.
    Discord,
    /// Slack webhook.
    Slack,
    /// ntfy.
    Ntfy,
    /// Generic HMAC-signed webhook.
    Generic,
}

/// Change to one channel. `None` secrets keep the stored value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "snake_case", deny_unknown_fields)]
pub enum AlertUpdate {
    /// Toast.
    Toast {
        /// Enabled.
        enabled: bool,
    },
    /// Event log.
    EventLog {
        /// Enabled.
        enabled: bool,
    },
    /// Minimum severity.
    MinSeverity {
        /// Severity.
        severity: Severity,
    },
    /// Discord.
    Discord {
        /// Enabled.
        enabled: bool,
        /// New webhook URL.
        url: Option<String>,
    },
    /// Slack.
    Slack {
        /// Enabled.
        enabled: bool,
        /// New webhook URL.
        url: Option<String>,
    },
    /// ntfy.
    Ntfy {
        /// Enabled.
        enabled: bool,
        /// Server base URL.
        server: Option<String>,
        /// New topic.
        topic: Option<String>,
        /// New access token (empty string clears it).
        token: Option<String>,
    },
    /// Generic webhook.
    Generic {
        /// Enabled.
        enabled: bool,
        /// New URL.
        url: Option<String>,
        /// New HMAC key.
        secret: Option<String>,
    },
}

/// Partial settings update.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SettingsUpdate {
    /// Theme.
    pub theme: Option<Theme>,
    /// Catalog profile.
    pub profile: Option<String>,
    /// Containment policy.
    pub policy: Option<PolicyConfig>,
    /// Auto re-plant.
    pub auto_replant: Option<bool>,
    /// Oplock tripwire.
    pub oplock: Option<bool>,
    /// Sweep window.
    pub sweep_window_secs: Option<u64>,
    /// Sensor mode (takes effect after a service restart).
    pub mode: Option<SensorMode>,
}

fn check_len(name: &str, s: &str, max: usize) -> Result<()> {
    if s.len() > max {
        return Err(Error::Protocol(format!("{name} exceeds {max} bytes")));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(Error::Protocol(format!(
            "{name} contains control characters"
        )));
    }
    Ok(())
}

/// Validates a webhook URL for a channel.
pub fn validate_webhook_url(channel: ChannelKind, url: &str) -> Result<()> {
    check_len("url", url, 2048)?;
    let ok = match channel {
        ChannelKind::Discord => {
            url.starts_with("https://discord.com/api/webhooks/")
                || url.starts_with("https://discordapp.com/api/webhooks/")
                || url.starts_with("https://ptb.discord.com/api/webhooks/")
                || url.starts_with("https://canary.discord.com/api/webhooks/")
        }
        ChannelKind::Slack => url.starts_with("https://hooks.slack.com/"),
        ChannelKind::Ntfy => url.starts_with("https://") || url.starts_with("http://"),
        ChannelKind::Generic => {
            url.starts_with("https://")
                || url.starts_with("http://localhost")
                || url.starts_with("http://127.0.0.1")
        }
        ChannelKind::Toast | ChannelKind::EventLog => false,
    };
    if !ok {
        return Err(Error::Protocol(format!("URL is not valid for {channel:?}")));
    }
    if url.contains(' ') {
        return Err(Error::Protocol("URL contains spaces".into()));
    }
    Ok(())
}

impl Request {
    /// Range-checks every field. Called by the server before dispatch.
    pub fn validate(&self) -> Result<()> {
        match self {
            Request::ListIncidents { limit } if !(1..=1000).contains(limit) => {
                Err(Error::Protocol("limit must be 1..=1000".into()))
            }
            Request::GetIncident { id } | Request::IncidentAction { id, .. }
                if !is_valid_incident_id(id) =>
            {
                Err(Error::Protocol("invalid incident id".into()))
            }
            Request::IncidentAction { action, .. }
                if matches!(action, ActionKind::Suspend | ActionKind::Minidump) =>
            {
                // Suspension is the policy's job; dumps are policy-controlled.
                Err(Error::Protocol(format!(
                    "action {} is not user-invokable",
                    action.as_str()
                )))
            }
            Request::Plant {
                profile: Some(p), ..
            } => {
                if p.is_empty()
                    || p.len() > 64
                    || !p
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                {
                    Err(Error::Protocol("invalid profile name".into()))
                } else {
                    Ok(())
                }
            }
            Request::SetAllowlist { entries } => {
                if entries.len() > 500 {
                    return Err(Error::Protocol("too many allowlist entries".into()));
                }
                for e in entries {
                    check_len("name", &e.name, 200)?;
                    check_len("path", &e.path, 1024)?;
                    for s in &e.signers {
                        check_len("signer", s, 256)?;
                    }
                    e.validate()?;
                }
                Ok(())
            }
            Request::SetAlertChannel { update } => match update {
                AlertUpdate::Discord { url: Some(u), .. } => {
                    validate_webhook_url(ChannelKind::Discord, u)
                }
                AlertUpdate::Slack { url: Some(u), .. } => {
                    validate_webhook_url(ChannelKind::Slack, u)
                }
                AlertUpdate::Ntfy {
                    server,
                    topic,
                    token,
                    ..
                } => {
                    if let Some(s) = server {
                        validate_webhook_url(ChannelKind::Ntfy, s)?;
                    }
                    if let Some(t) = topic
                        && (t.is_empty()
                            || t.len() > 64
                            || !t
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
                    {
                        return Err(Error::Protocol(
                            "ntfy topic must be 1-64 of [A-Za-z0-9_-]".into(),
                        ));
                    }
                    if let Some(t) = token {
                        check_len("token", t, 512)?;
                    }
                    Ok(())
                }
                AlertUpdate::Generic { url, secret, .. } => {
                    if let Some(u) = url {
                        validate_webhook_url(ChannelKind::Generic, u)?;
                    }
                    if let Some(s) = secret {
                        check_len("secret", s, 512)?;
                        if !s.is_empty() && s.len() < 16 {
                            return Err(Error::Protocol(
                                "HMAC secret must be at least 16 characters".into(),
                            ));
                        }
                    }
                    Ok(())
                }
                _ => Ok(()),
            },
            Request::SetSettings { update } => {
                if let Some(p) = &update.profile {
                    check_len("profile", p, 64)?;
                }
                if let Some(w) = update.sweep_window_secs
                    && !(1..=300).contains(&w)
                {
                    return Err(Error::Protocol("sweep_window_secs must be 1..=300".into()));
                }
                Ok(())
            }
            Request::Activity { hours } if !(1..=720).contains(hours) => {
                Err(Error::Protocol("hours must be 1..=720".into()))
            }
            _ => Ok(()),
        }
    }

    /// True for requests that change state (logged with the client PID).
    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            Request::IncidentAction { .. }
                | Request::Plant { dry_run: false, .. }
                | Request::Unplant
                | Request::Replant
                | Request::SetCategory { .. }
                | Request::SetAllowlist { .. }
                | Request::SetAlertChannel { .. }
                | Request::SetSettings { .. }
        )
    }
}

/// Overall protection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    /// Sensors running, decoys planted.
    Protected,
    /// Running with reduced coverage (fallback mode, lost events, no decoys in a category).
    Degraded,
    /// Not protecting.
    Unprotected,
}

/// Sensor health.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SensorHealth {
    /// `etw`, `audit` or `none`.
    pub mode: String,
    /// ETW session running.
    pub etw_running: bool,
    /// Events lost by the ETW session.
    pub events_lost: u64,
    /// Real-time buffers lost.
    pub buffers_lost: u64,
    /// Oplocks currently armed.
    pub oplocks_armed: u32,
    /// Decoy files eligible for oplocks.
    pub oplocks_total: u32,
    /// Directories watched for integrity.
    pub integrity_watchers: u32,
    /// Process table size.
    pub process_table: u32,
    /// Seconds since the last sensor event, if any.
    pub last_event_age_secs: Option<u64>,
    /// Human-readable problems.
    pub problems: Vec<String>,
}

/// Status snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusInfo {
    /// Service version.
    pub version: String,
    /// State.
    pub protection: ProtectionState,
    /// Sensors.
    pub sensor: SensorHealth,
    /// Decoy files planted.
    pub decoys_planted: u32,
    /// Decoy files per category.
    pub decoys_by_category: BTreeMap<String, u32>,
    /// Touches in the last 24 hours (all dispositions).
    pub touches_24h: u32,
    /// Incidents in the last 24 hours.
    pub incidents_24h: u32,
    /// Incidents awaiting a decision.
    pub pending: Vec<IncidentSummary>,
    /// Most recent incidents.
    pub recent: Vec<IncidentSummary>,
}

/// One planned decoy (dry-run output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedItem {
    /// Decoy id.
    pub decoy_id: String,
    /// Category.
    pub category: Category,
    /// Target.
    pub target: String,
    /// Files with sizes.
    pub files: Vec<(String, u64)>,
    /// True if an alternate (not the real tool's) location was chosen.
    pub alternate: bool,
    /// Contains canary values.
    pub canary: bool,
}

/// One skipped decoy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedItem {
    /// Decoy id.
    pub decoy_id: String,
    /// Category.
    pub category: Category,
    /// Explanation.
    pub reason: String,
}

/// Plan summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSummary {
    /// Planned (or planted, after a real run).
    pub planned: Vec<PlannedItem>,
    /// Skipped.
    pub skipped: Vec<SkippedItem>,
    /// Errors while planting.
    pub errors: Vec<String>,
}

impl From<&Plan> for PlanSummary {
    fn from(p: &Plan) -> Self {
        Self {
            planned: p
                .planned
                .iter()
                .map(|d| PlannedItem {
                    decoy_id: d.decoy_id.clone(),
                    category: d.category,
                    target: d.target.to_string_lossy().into_owned(),
                    files: d
                        .files
                        .iter()
                        .map(|f| (f.path.to_string_lossy().into_owned(), f.size))
                        .collect(),
                    alternate: d.candidate_index > 0,
                    canary: d.canary,
                })
                .collect(),
            skipped: p
                .skipped
                .iter()
                .map(|s| SkippedItem {
                    decoy_id: s.decoy_id.clone(),
                    category: s.category,
                    reason: describe_skip(&s.reason),
                })
                .collect(),
            errors: Vec::new(),
        }
    }
}

/// Human description of a skip reason.
pub fn describe_skip(r: &SkipReason) -> String {
    use crate::plan::Rejection;
    match r {
        SkipReason::CategoryDisabled => "category disabled".into(),
        SkipReason::RequirementMissing => "application not installed".into(),
        SkipReason::RealInstalled { path } => {
            format!("real application installed ({})", path.display())
        }
        SkipReason::AlreadyPlanted => "already planted".into(),
        SkipReason::NoAcceptableTarget { rejections } => {
            let parts: Vec<String> = rejections
                .iter()
                .map(|(p, rej)| {
                    let why = match rej {
                        Rejection::RealToolLocation => "real tool location".to_string(),
                        Rejection::Exists { .. } => "file exists".to_string(),
                        Rejection::Synced { provider } => format!("in {provider:?} sync folder"),
                        Rejection::GitTree { root } => format!("in git tree {}", root.display()),
                        Rejection::NotFresh { dir } => format!("{} already exists", dir.display()),
                        Rejection::OutsideProfile => "outside profile".to_string(),
                    };
                    format!("{}: {why}", p.display())
                })
                .collect();
            format!("no safe location ({})", parts.join("; "))
        }
    }
}

/// Manifest view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestView {
    /// Files.
    pub entries: Vec<ManifestEntry>,
    /// Enabled categories.
    pub enabled: Vec<Category>,
    /// Active profile.
    pub profile: String,
}

/// Channel view without secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelView {
    /// Enabled.
    pub enabled: bool,
    /// A URL/topic is stored.
    pub configured: bool,
    /// Non-secret extra (ntfy server).
    pub extra: Option<String>,
}

/// Alert configuration view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertsView {
    /// Minimum severity.
    pub min_severity: Severity,
    /// Toast.
    pub toast: bool,
    /// Event log.
    pub eventlog: bool,
    /// Discord.
    pub discord: ChannelView,
    /// Slack.
    pub slack: ChannelView,
    /// ntfy.
    pub ntfy: ChannelView,
    /// Generic.
    pub generic: ChannelView,
}

/// Settings view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsView {
    /// Theme.
    pub theme: Theme,
    /// Profile.
    pub profile: String,
    /// Available profiles.
    pub profiles: Vec<String>,
    /// Policy.
    pub policy: PolicyConfig,
    /// Auto re-plant.
    pub auto_replant: bool,
    /// Oplock.
    pub oplock: bool,
    /// Sweep window.
    pub sweep_window_secs: u64,
    /// Sensor mode.
    pub mode: SensorMode,
    /// Protected user's profile.
    pub profile_path: String,
    /// Data directory.
    pub data_dir: String,
}

/// Diagnostic check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Fine.
    Ok,
    /// Informational.
    Info,
    /// Degraded.
    Warn,
    /// Broken.
    Fail,
}

/// One diagnostic check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Check name.
    pub name: String,
    /// Status.
    pub status: CheckStatus,
    /// Detail.
    pub detail: String,
}

/// Activity view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityView {
    /// Touches.
    pub touches: Vec<TouchLogRow>,
    /// Events.
    pub events: Vec<EventRow>,
}

/// Successful responses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Status.
    Status(StatusInfo),
    /// Incident list.
    Incidents {
        /// Rows.
        items: Vec<IncidentSummary>,
    },
    /// One incident.
    Incident {
        /// The incident.
        incident: Box<Incident>,
    },
    /// Action outcome.
    ActionResult {
        /// Succeeded.
        ok: bool,
        /// Detail.
        detail: String,
    },
    /// Plan / plant outcome.
    Plan(PlanSummary),
    /// Unplant outcome.
    Unplant(UnplantReport),
    /// Manifest.
    Manifest(ManifestView),
    /// Allowlist.
    Allowlist {
        /// User entries.
        entries: Vec<AllowEntry>,
        /// Built-in entries (read-only).
        builtin: Vec<AllowEntry>,
    },
    /// Alerts.
    Alerts(AlertsView),
    /// Settings.
    Settings(SettingsView),
    /// Doctor.
    Doctor {
        /// Checks.
        checks: Vec<DoctorCheck>,
    },
    /// Activity.
    Activity(ActivityView),
    /// Generic acknowledgement.
    Ack,
}

/// Server-pushed events on a subscribed connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// An incident was created or changed.
    Incident {
        /// Summary.
        summary: IncidentSummary,
        /// True on creation.
        created: bool,
        /// Raise a toast for it (respects alert settings).
        toast: bool,
    },
    /// Protection status changed.
    Status {
        /// New state.
        protection: ProtectionState,
    },
    /// Show a test toast (from the alert channel "send test" action).
    TestToast,
}

/// Error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcError {
    /// Machine code: `bad_request`, `not_found`, `internal`, `unsupported`.
    pub code: String,
    /// Message.
    pub message: String,
}

/// Client → server frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Protocol version.
    pub v: u32,
    /// Correlation id.
    pub id: u64,
    /// Request.
    pub req: Request,
}

/// Server → client payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    /// Success.
    Ok(Response),
    /// Failure.
    Error(IpcError),
    /// Pushed event.
    Event(Event),
}

/// Server → client frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplyEnvelope {
    /// Protocol version.
    pub v: u32,
    /// Correlation id (0 for events).
    pub id: u64,
    /// Payload.
    pub reply: Reply,
}

/// Parses and validates a request frame body.
pub fn decode_request(body: &[u8]) -> Result<RequestEnvelope> {
    let env: RequestEnvelope = serde_json::from_slice(body)
        .map_err(|e| Error::Protocol(format!("malformed request: {e}")))?;
    if env.v != PROTOCOL_VERSION {
        return Err(Error::Protocol(format!(
            "protocol version {} not supported (server speaks {PROTOCOL_VERSION})",
            env.v
        )));
    }
    env.req.validate()?;
    Ok(env)
}

/// Writes one frame.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let body = serde_json::to_vec(msg)?;
    let len = u32::try_from(body.len()).map_err(|_| Error::Protocol("message too large".into()))?;
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Reads one frame body, refusing frames larger than `max` before allocating.
pub fn read_frame_body<R: Read>(r: &mut R, max: u32) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > max {
        return Err(Error::Protocol(format!(
            "frame of {len} bytes exceeds limit {max}"
        )));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Reads and deserializes one frame.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R, max: u32) -> Result<T> {
    let body = read_frame_body(r, max)?;
    Ok(serde_json::from_slice(&body)?)
}

/// Validates a pipe name.
pub fn validate_pipe_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
    {
        return Err(Error::Protocol(
            "pipe name must be 1-64 of [A-Za-z0-9._-]".into(),
        ));
    }
    Ok(())
}

/// Full pipe path for a name.
pub fn pipe_path(name: &str) -> String {
    format!(r"\\.\pipe\{name}")
}

/// Blocking client.
pub struct Client {
    pipe: std::fs::File,
    next_id: u64,
}

impl Client {
    /// Connects, retrying briefly while all pipe instances are busy.
    pub fn connect(pipe_name: &str) -> Result<Self> {
        validate_pipe_name(pipe_name)?;
        let path = pipe_path(pipe_name);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
            {
                Ok(pipe) => return Ok(Self { pipe, next_id: 1 }),
                // ERROR_PIPE_BUSY: every instance is in use; wait for one.
                Err(e) if e.raw_os_error() == Some(231) && std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::NotFound(
                        "the Epicurus service is not running (pipe not found)".into(),
                    ));
                }
                Err(e) => return Err(Error::IoBare(e)),
            }
        }
    }

    /// The underlying pipe handle (for server identity checks).
    pub fn pipe(&self) -> &std::fs::File {
        &self.pipe
    }

    /// Sends a request and waits for its reply.
    pub fn call(&mut self, req: Request) -> Result<Response> {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(
            &mut self.pipe,
            &RequestEnvelope {
                v: PROTOCOL_VERSION,
                id,
                req,
            },
        )?;
        loop {
            let env: ReplyEnvelope = read_frame(&mut self.pipe, MAX_RESPONSE_BYTES)?;
            if env.v != PROTOCOL_VERSION {
                return Err(Error::Protocol(format!(
                    "server protocol version {}",
                    env.v
                )));
            }
            match env.reply {
                Reply::Ok(r) if env.id == id => return Ok(r),
                Reply::Error(e) if env.id == id => {
                    return Err(match e.code.as_str() {
                        "not_found" => Error::NotFound(e.message),
                        _ => Error::Protocol(format!("{}: {}", e.code, e.message)),
                    });
                }
                // Stray events or stale replies are skipped.
                _ => continue,
            }
        }
    }

    /// Subscribes; afterwards call [`Client::next_event`] repeatedly.
    pub fn subscribe(&mut self) -> Result<()> {
        match self.call(Request::Subscribe)? {
            Response::Ack => Ok(()),
            other => Err(Error::Protocol(format!("unexpected reply {other:?}"))),
        }
    }

    /// Blocks until the next pushed event.
    pub fn next_event(&mut self) -> Result<Event> {
        loop {
            let env: ReplyEnvelope = read_frame(&mut self.pipe, MAX_RESPONSE_BYTES)?;
            if let Reply::Event(e) = env.reply {
                return Ok(e);
            }
        }
    }
}

/// The server PID behind a connected pipe (to detect pipe squatting).
#[cfg(windows)]
pub fn server_pid(pipe: &std::fs::File) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    let mut pid = 0u32;
    // SAFETY: the handle is a live pipe handle owned by `pipe` for the
    // duration of the call.
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }.ok()?;
    Some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(req: Request) -> Result<RequestEnvelope> {
        let body = serde_json::to_vec(&RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: 1,
            req,
        })
        .unwrap();
        decode_request(&body)
    }

    #[test]
    fn accepts_valid_requests() {
        assert!(roundtrip(Request::Status).is_ok());
        assert!(roundtrip(Request::ListIncidents { limit: 50 }).is_ok());
        assert!(
            roundtrip(Request::GetIncident {
                id: "inc_0123456789abcdef".into()
            })
            .is_ok()
        );
        assert!(
            roundtrip(Request::IncidentAction {
                id: "inc_0123456789abcdef".into(),
                action: ActionKind::KillTree
            })
            .is_ok()
        );
        assert!(
            roundtrip(Request::Plant {
                profile: Some("developer".into()),
                dry_run: true
            })
            .is_ok()
        );
    }

    #[test]
    fn rejects_out_of_range_and_malicious_fields() {
        assert!(roundtrip(Request::ListIncidents { limit: 0 }).is_err());
        assert!(roundtrip(Request::ListIncidents { limit: 100_000 }).is_err());
        assert!(
            roundtrip(Request::GetIncident {
                id: r"..\..\x".into()
            })
            .is_err()
        );
        assert!(
            roundtrip(Request::IncidentAction {
                id: "inc_0123456789abcdef".into(),
                action: ActionKind::Minidump
            })
            .is_err()
        );
        assert!(
            roundtrip(Request::Plant {
                profile: Some("a b".into()),
                dry_run: false
            })
            .is_err()
        );
        assert!(roundtrip(Request::Activity { hours: 0 }).is_err());
        assert!(
            roundtrip(Request::SetAlertChannel {
                update: AlertUpdate::Discord {
                    enabled: true,
                    url: Some("https://evil.example/x".into())
                }
            })
            .is_err()
        );
        assert!(
            roundtrip(Request::SetAlertChannel {
                update: AlertUpdate::Generic {
                    enabled: true,
                    url: Some("http://10.0.0.1/hook".into()),
                    secret: None
                }
            })
            .is_err()
        );
        assert!(
            roundtrip(Request::SetAlertChannel {
                update: AlertUpdate::Generic {
                    enabled: true,
                    url: None,
                    secret: Some("short".into())
                }
            })
            .is_err()
        );
        assert!(
            roundtrip(Request::SetAllowlist {
                entries: vec![AllowEntry {
                    name: "x".into(),
                    signers: vec![],
                    path: "chrome.exe".into(),
                    sha256: None
                }]
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_fields_wrong_version_and_garbage() {
        assert!(decode_request(br#"{"v":1,"id":1,"req":{"type":"status"},"extra":1}"#).is_err());
        assert!(
            decode_request(
                br#"{"v":1,"id":1,"req":{"type":"list_incidents","limit":5,"sql":"drop"}}"#
            )
            .is_err()
        );
        assert!(decode_request(br#"{"v":2,"id":1,"req":{"type":"status"}}"#).is_err());
        assert!(decode_request(br#"{"v":1,"id":1,"req":{"type":"format_disk"}}"#).is_err());
        assert!(decode_request(b"\xff\xfe").is_err());
        assert!(decode_request(br#"{"v":1,"id":1,"req":{"type":"status"}}"#).is_ok());
    }

    #[test]
    fn frames_roundtrip_and_cap_size() {
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &RequestEnvelope {
                v: 1,
                id: 9,
                req: Request::Status,
            },
        )
        .unwrap();
        let mut cur = std::io::Cursor::new(buf.clone());
        let env: RequestEnvelope = read_frame(&mut cur, MAX_REQUEST_BYTES).unwrap();
        assert_eq!(env.id, 9);

        // A hostile length prefix is refused before any allocation.
        let mut evil = u32::MAX.to_le_bytes().to_vec();
        evil.extend_from_slice(b"{}");
        assert!(read_frame_body(&mut std::io::Cursor::new(evil), MAX_REQUEST_BYTES).is_err());
        // Truncated frames are errors, not hangs.
        let mut short = 10u32.to_le_bytes().to_vec();
        short.extend_from_slice(b"{}");
        assert!(read_frame_body(&mut std::io::Cursor::new(short), MAX_REQUEST_BYTES).is_err());
    }

    #[test]
    fn replies_roundtrip() {
        let r = ReplyEnvelope {
            v: 1,
            id: 3,
            reply: Reply::Ok(Response::ActionResult {
                ok: true,
                detail: "d".into(),
            }),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<ReplyEnvelope>(&s).unwrap(), r);
    }

    #[test]
    fn pipe_names() {
        assert!(validate_pipe_name("epicurus-v1").is_ok());
        assert!(validate_pipe_name(r"..\x").is_err());
        assert!(validate_pipe_name("").is_err());
    }

    #[test]
    fn mutating_classification() {
        assert!(!Request::Status.is_mutating());
        assert!(
            !Request::Plant {
                profile: None,
                dry_run: true
            }
            .is_mutating()
        );
        assert!(Request::Unplant.is_mutating());
    }
}
