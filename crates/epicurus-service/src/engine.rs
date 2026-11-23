//! The detection engine: turns sensor events into incidents, applies the
//! containment policy, keeps decoys planted and answers IPC requests.
//!
//! All state lives behind one mutex. Sensor threads only push events into a
//! channel; the host's engine thread drains it, and IPC requests run on
//! blocking tasks that take the same lock, so the engine never needs internal
//! synchronization.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use epicurus_core::allowlist::{AllowEntry, Allowlist, Subject};
use epicurus_core::catalog::{Catalog, Category};
use epicurus_core::config::{Config, PolicyAction, SensorMode};
use epicurus_core::environment::RealFs;
use epicurus_core::incident::{
    ActionKind, Actor, DecoyTouch, Incident, IncidentStatus, ProcessNode, ProcessProfile,
    SensorSource, SignatureStatus, TouchOp,
};
use epicurus_core::ipc::{
    ActivityView, AlertUpdate, AlertsView, ChannelKind, ChannelView, Event, IpcError, ManifestView,
    PlanSummary, ProtectionState, Request, Response, SensorHealth, SettingsUpdate, SettingsView,
    StatusInfo,
};
use epicurus_core::manifest::{Manifest, sha256_file};
use epicurus_core::paths::{DataDir, EnvMap};
use epicurus_core::plan::{PlanOptions, Planner};
use epicurus_core::plant::{NoHooks, PlantHooks};
use epicurus_core::protect::Protected;
use epicurus_core::scoring::{ScoreInput, score};
use epicurus_core::storage::{Store, TouchLogRow};
use epicurus_sensor::audit::AuditSubscription;
use epicurus_sensor::containment::{self, ProcKey};
use epicurus_sensor::etw::{ConsumerContext, EtwSession, EtwStats};
use epicurus_sensor::events::{
    IntegrityChange, PathFilter, SensitiveCache, SensorEvent, SharedFilter, SharedSensitive,
};
use epicurus_sensor::integrity::IntegrityWatcher;
use epicurus_sensor::oplock::OplockManager;
use epicurus_sensor::process_table::{Enrichment, ProcEntry, ProcessTable};
use time::OffsetDateTime;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::alerts::{AlertBody, AlertJob, Gate};
use crate::error::ServiceError;
use crate::eventlog::{EventLog, Level, ids};
use crate::options::RuntimeOptions;

/// Shared engine handle.
pub type SharedEngine = Arc<Mutex<Engine>>;

/// Which file sensor is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveMode {
    /// Kernel-File ETW.
    Etw,
    /// SACL + Security 4663.
    Audit,
    /// No file sensor.
    None,
}

impl ActiveMode {
    fn as_str(self) -> &'static str {
        match self {
            ActiveMode::Etw => "etw",
            ActiveMode::Audit => "audit",
            ActiveMode::None => "none",
        }
    }
}

/// Result of a request that may need to await an async alert test.
pub enum Outcome {
    /// Ready now.
    Ready(Box<Result<Response, IpcError>>),
    /// Await a channel test.
    AwaitTest(oneshot::Receiver<Result<String, String>>),
}

fn bad(msg: impl Into<String>) -> IpcError {
    IpcError {
        code: "bad_request".into(),
        message: msg.into(),
    }
}

fn internal(msg: impl std::fmt::Display) -> IpcError {
    IpcError {
        code: "internal".into(),
        message: msg.to_string(),
    }
}

fn not_found(msg: impl Into<String>) -> IpcError {
    IpcError {
        code: "not_found".into(),
        message: msg.into(),
    }
}

type ProcId = (u32, i128);

fn proc_id(pid: u32, ct: Option<OffsetDateTime>) -> ProcId {
    (pid, ct.map(|t| t.unix_timestamp_nanos()).unwrap_or(0))
}

/// The engine.
pub struct Engine {
    opts: RuntimeOptions,
    data: DataDir,
    config: Config,
    catalog: Catalog,
    store: Store,
    env: Option<EnvMap>,
    user_sid: Option<String>,
    manifest: Manifest,
    allow_user: Allowlist,
    allow_builtin: Allowlist,
    filter: SharedFilter,
    sensitive: SharedSensitive,
    table: ProcessTable,
    etw: Option<EtwSession>,
    etw_stats: Arc<EtwStats>,
    audit: Option<AuditSubscription>,
    oplocks: Option<OplockManager>,
    integrity: Option<IntegrityWatcher>,
    mode: ActiveMode,
    problems: Vec<String>,
    sensor_tx: Sender<SensorEvent>,
    breaks: crate::correlate::BreakQueue,
    live: HashMap<ProcId, String>,
    open: HashMap<String, Incident>,
    profiles: HashMap<ProcId, ProcessProfile>,
    gate: Gate,
    alerts_tx: mpsc::UnboundedSender<AlertJob>,
    events_tx: broadcast::Sender<Event>,
    eventlog: Option<EventLog>,
    replant_due: Option<Instant>,
    unattributed: Vec<(Instant, String, Category)>,
    own_exe: String,
    own_sha256: Option<String>,
    host: String,
    last_lost: u64,
    last_health: Instant,
    last_prune: Instant,
    last_db_prune: Instant,
}

impl Engine {
    /// Loads configuration, catalog, store and allowlists. Sensors are
    /// started separately with [`Engine::start_sensors`].
    pub fn new(
        opts: RuntimeOptions,
        sensor_tx: Sender<SensorEvent>,
        alerts_tx: mpsc::UnboundedSender<AlertJob>,
        events_tx: broadcast::Sender<Event>,
    ) -> crate::error::Result<Self> {
        let data = opts.data_dir.clone();
        std::fs::create_dir_all(data.root())
            .map_err(|e| ServiceError::io(format!("creating {}", data.root().display()), e))?;
        let mut config = Config::load(&data.config_file())
            .map_err(|e| ServiceError::core("loading config.toml", e))?;
        if let Some(root) = &opts.profile_root {
            config.install.profile_path = root.to_string_lossy().into_owned();
            config.install.appdata = None;
            config.install.localappdata = None;
        }
        if let Some(sid) = &opts.user_sid {
            config.install.user_sid = sid.clone();
        }
        let catalog = Catalog::load_with_overrides(&data.catalog_d())
            .map_err(|e| ServiceError::core("loading decoy catalog", e))?;
        let store =
            Store::open(&data.database()).map_err(|e| ServiceError::core("opening database", e))?;
        let manifest = store
            .manifest()
            .map_err(|e| ServiceError::core("reading manifest", e))?;
        let allow_user = match std::fs::read_to_string(data.allowlist_file()) {
            Ok(t) => {
                Allowlist::parse(&t).map_err(|e| ServiceError::core("parsing allowlist.toml", e))?
            }
            Err(_) => Allowlist::default(),
        };
        let env = config.env_map().map(EnvMap::with_system_vars);
        let user_sid =
            (!config.install.user_sid.is_empty()).then(|| config.install.user_sid.clone());
        let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".into());
        let own_exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(Self {
            opts,
            data,
            config,
            catalog,
            store,
            env,
            user_sid,
            manifest,
            allow_user,
            allow_builtin: Allowlist::defaults(),
            filter: Arc::new(RwLock::new(PathFilter::default())),
            sensitive: Arc::new(Mutex::new(SensitiveCache::default())),
            table: ProcessTable::default(),
            etw: None,
            etw_stats: Arc::new(EtwStats::default()),
            audit: None,
            oplocks: None,
            integrity: None,
            mode: ActiveMode::None,
            problems: Vec::new(),
            sensor_tx,
            breaks: Default::default(),
            live: HashMap::new(),
            open: HashMap::new(),
            profiles: HashMap::new(),
            gate: Gate::default(),
            alerts_tx,
            events_tx,
            eventlog: EventLog::open(),
            replant_due: None,
            unattributed: Vec::new(),
            own_sha256: sha256_file(Path::new(&own_exe)).ok(),
            own_exe,
            host,
            last_lost: 0,
            last_health: Instant::now(),
            last_prune: Instant::now(),
            last_db_prune: Instant::now(),
        })
    }

    fn log(&self, level: Level, id: u32, msg: &str) {
        match level {
            Level::Error => tracing::error!(event_id = id, "{msg}"),
            Level::Warning => tracing::warn!(event_id = id, "{msg}"),
            Level::Info => tracing::info!(event_id = id, "{msg}"),
        }
        if self.config.alerts.eventlog
            && let Some(e) = &self.eventlog
        {
            e.report(level, id, msg);
        }
    }

    fn session_name(&self) -> String {
        self.opts
            .session_name
            .clone()
            .unwrap_or_else(|| self.config.sensor.etw_session_name.clone())
    }

    /// Starts every sensor and loads the initial process table.
    pub fn start_sensors(&mut self) {
        let failed = epicurus_sensor::privileges::enable_all(
            epicurus_sensor::privileges::SERVICE_PRIVILEGES,
        );
        if !failed.is_empty() {
            self.problems
                .push(format!("privileges not held: {}", failed.join(", ")));
        }
        if let Some(env) = &self.env
            && let Ok(mut f) = self.filter.write()
        {
            f.set_sensitive(epicurus_sensor::events::sensitive_prefixes(env));
        }
        for e in epicurus_sensor::process_table::snapshot() {
            self.table.insert(e);
        }
        self.mode = ActiveMode::None;
        if self.config.sensor.mode == SensorMode::Auto {
            self.start_etw();
        }
        if self.mode == ActiveMode::None {
            self.start_audit();
        }
        if self.config.sensor.oplock {
            match OplockManager::start(self.sensor_tx.clone()) {
                Ok(m) => self.oplocks = Some(m),
                Err(e) => self
                    .problems
                    .push(format!("oplock tripwire unavailable: {e}")),
            }
        }
        match IntegrityWatcher::start(self.sensor_tx.clone()) {
            Ok(w) => self.integrity = Some(w),
            Err(e) => self
                .problems
                .push(format!("integrity watcher unavailable: {e}")),
        }
        self.refresh_sensor_paths();
        self.log(
            Level::Info,
            ids::SENSOR_MODE,
            &format!("File sensor mode: {}", self.mode.as_str()),
        );
    }

    fn start_etw(&mut self) {
        let ctx = ConsumerContext::new(
            self.sensor_tx.clone(),
            self.filter.clone(),
            self.sensitive.clone(),
            self.etw_stats.clone(),
        );
        match EtwSession::start(&self.session_name(), ctx) {
            Ok(s) => {
                self.etw = Some(s);
                self.mode = ActiveMode::Etw;
            }
            Err(e) => {
                let msg =
                    format!("Kernel-File ETW unavailable ({e}); falling back to SACL auditing");
                self.problems.push(msg.clone());
                self.log(Level::Warning, ids::SENSOR_DEGRADED, &msg);
            }
        }
    }

    fn start_audit(&mut self) {
        match epicurus_sensor::audit::enable_file_system_auditing() {
            Ok(prev) => {
                if self
                    .store
                    .kv_get("audit_policy_prev")
                    .ok()
                    .flatten()
                    .is_none()
                {
                    let _ = self.store.kv_set("audit_policy_prev", &prev.to_string());
                }
            }
            Err(e) => self
                .problems
                .push(format!("could not enable File System auditing: {e}")),
        }
        match AuditSubscription::start(self.sensor_tx.clone(), self.filter.clone()) {
            Ok(s) => {
                self.audit = Some(s);
                self.mode = ActiveMode::Audit;
            }
            Err(e) => {
                let msg =
                    format!("Security log subscription failed ({e}); no file sensor is active");
                self.problems.push(msg.clone());
                self.log(Level::Error, ids::SENSOR_DEGRADED, &msg);
            }
        }
    }

    /// Stops sensors (service shutdown).
    pub fn shutdown(&mut self) {
        self.oplocks = None;
        self.integrity = None;
        self.audit = None;
        if let Some(mut s) = self.etw.take() {
            s.stop();
        }
    }

    fn files(&self) -> Vec<PathBuf> {
        self.manifest
            .entries
            .iter()
            .map(|e| e.path.clone())
            .collect()
    }

    fn refresh_sensor_paths(&mut self) {
        let files = self.files();
        if let Ok(mut f) = self.filter.write() {
            f.set_decoys(files.iter().map(|p| p.to_str().unwrap_or_default()));
        }
        if let Some(o) = &self.oplocks {
            o.set_paths(files.clone());
        }
        if let Some(w) = &self.integrity {
            w.set_files(files.clone());
        }
        if self.mode == ActiveMode::Audit {
            for (p, e) in epicurus_sensor::audit::apply_sacls(files.iter().map(PathBuf::as_path)) {
                self.problems.push(format!("SACL on {p}: {e}"));
            }
        }
    }

    fn pause_file_sensors(&mut self) {
        if let Some(o) = &self.oplocks {
            o.set_paths(Vec::new());
        }
        if let Some(w) = &self.integrity {
            w.set_files(Vec::new());
        }
    }

    // -----------------------------------------------------------------
    // Sensor events
    // -----------------------------------------------------------------

    /// Handles one sensor event. `enrichment` carries live process facts read
    /// outside the lock for ProcessStart events.
    pub fn on_sensor_event(&mut self, ev: SensorEvent, enrichment: Option<Enrichment>) {
        match ev {
            SensorEvent::ProcessStart {
                pid,
                ppid,
                create_time,
                image,
                session,
            } => {
                let en = enrichment.unwrap_or_default();
                self.table.insert(ProcEntry {
                    pid,
                    ppid,
                    create_time,
                    exit_time: None,
                    image: en.image.unwrap_or(image),
                    command_line: en.command_line,
                    user: en.user,
                    user_sid: en.user_sid,
                    integrity: en.integrity,
                    session,
                });
            }
            SensorEvent::ProcessStop {
                pid,
                create_time,
                exit_time,
            } => self.table.mark_exit(pid, create_time, exit_time),
            SensorEvent::DecoyOpen {
                at,
                pid,
                path,
                read_data,
                source,
                image_hint,
            } => {
                let op = if read_data {
                    TouchOp::Read
                } else {
                    TouchOp::Open
                };
                self.on_touch(at, pid, &path, op, source, image_hint);
            }
            SensorEvent::DecoyDeleteOrRename {
                at,
                pid,
                path,
                rename,
            } => {
                let op = if rename {
                    TouchOp::Rename
                } else {
                    TouchOp::Delete
                };
                self.on_touch(at, pid, &path, op, SensorSource::Etw, None);
            }
            SensorEvent::OplockBreak { at, path } => {
                if let Some(s) = &self.etw {
                    // Deliver the matching Create event now rather than at the
                    // next flush-timer tick.
                    s.flush();
                }
                self.breaks.push(at, &path, Instant::now());
            }
            SensorEvent::Integrity { at, path, change } => self.on_integrity(at, &path, change),
            SensorEvent::Health { message } => {
                self.log(Level::Warning, ids::SENSOR_DEGRADED, &message);
                self.problems.push(message);
            }
        }
    }

    fn profile_for(
        &mut self,
        pid: u32,
        at: OffsetDateTime,
        image_hint: Option<String>,
    ) -> ProcessProfile {
        let entry = match self.table.find(pid, at).cloned() {
            Some(e) => Some(e),
            None => {
                let en = epicurus_sensor::process_table::enrich(pid);
                en.create_time.map(|ct| {
                    let e = ProcEntry {
                        pid,
                        ppid: 0,
                        create_time: ct,
                        exit_time: None,
                        image: en.image.clone().or(image_hint.clone()).unwrap_or_default(),
                        command_line: en.command_line.clone(),
                        user: en.user.clone(),
                        user_sid: en.user_sid.clone(),
                        integrity: en.integrity.clone(),
                        session: 0,
                    };
                    self.table.insert(e.clone());
                    e
                })
            }
        };
        let id = proc_id(pid, entry.as_ref().map(|e| e.create_time));
        if let Some(p) = self.profiles.get(&id) {
            return p.clone();
        }
        let env = self.env.clone().unwrap_or_default();
        let mut p = epicurus_sensor::introspect::build_profile(pid, entry.as_ref(), &env);
        if p.image_path.is_empty()
            && let Some(h) = image_hint
        {
            p.image_path = h;
        }
        if p.ppid == 0
            && let Some(ppid) = epicurus_sensor::process_table::toolhelp()
                .into_iter()
                .find(|(x, _, _)| *x == pid)
                .map(|(_, pp, _)| pp)
        {
            p.ppid = ppid;
        }
        self.profiles.insert(id, p.clone());
        p
    }

    fn allowlisted(&self, p: &ProcessProfile) -> Option<String> {
        let env = self.env.clone().unwrap_or_default().with_system_vars();
        let subject = Subject {
            image_path: &p.image_path,
            signature_valid: p.signature.status == SignatureStatus::Valid,
            signer: p.signature.signer(),
            sha256: p.image_sha256.as_deref(),
        };
        self.allow_user
            .find(&subject, &env)
            .or_else(|| self.allow_builtin.find(&subject, &env))
            .map(|e| e.name.clone())
    }

    fn is_simulation(&self, p: &ProcessProfile) -> bool {
        // Same binary (by hash, so a copy run from Downloads also counts) and
        // the hidden simulator flag.
        let same_binary = p.image_path.eq_ignore_ascii_case(&self.own_exe)
            || (p.image_sha256.is_some() && p.image_sha256 == self.own_sha256);
        same_binary
            && p.command_line
                .as_deref()
                .is_some_and(|c| c.contains(epicurus_core::SIMULATOR_FLAG))
    }

    fn build_tree(&self, p: &ProcessProfile) -> Vec<ProcessNode> {
        let mut out = Vec::new();
        let node = |e: &ProcEntry, role: &str| ProcessNode {
            pid: e.pid,
            ppid: e.ppid,
            image: e.image.clone(),
            command_line: e.command_line.clone(),
            start_time: Some(e.create_time),
            role: role.to_string(),
        };
        let subject_entry = p
            .start_time
            .and_then(|ct| self.table.get(p.pid, ct))
            .cloned();
        if let Some(e) = &subject_entry {
            let mut anc: Vec<ProcessNode> = self
                .table
                .ancestors(e)
                .iter()
                .map(|a| node(a, "ancestor"))
                .collect();
            anc.reverse();
            out.extend(anc);
        }
        out.push(ProcessNode {
            pid: p.pid,
            ppid: p.ppid,
            image: p.image_path.clone(),
            command_line: p.command_line.clone(),
            start_time: p.start_time,
            role: "subject".into(),
        });
        if let Some(ct) = p.start_time {
            out.extend(
                self.table
                    .descendants(p.pid, ct)
                    .iter()
                    .map(|c| node(c, "child")),
            );
        }
        out
    }

    fn on_touch(
        &mut self,
        at: OffsetDateTime,
        pid: u32,
        path: &str,
        op: TouchOp,
        source: SensorSource,
        image_hint: Option<String>,
    ) {
        if pid == std::process::id() {
            return;
        }
        let Some(entry) = self.manifest.entry_for(Path::new(path)).cloned() else {
            return;
        };
        let window = Duration::from_millis(self.config.sensor.correlation_window_ms);
        let brk = self.breaks.take_match(path, at, window);
        let profile = self.profile_for(pid, at, image_hint);
        let now = OffsetDateTime::now_utc();

        if let Some(name) = self.allowlisted(&profile) {
            let _ = self.store.log_touch(&TouchLogRow {
                at,
                pid,
                image: profile.image_path.clone(),
                path: path.to_string(),
                decoy_id: entry.decoy_id.clone(),
                disposition: "allowlisted".into(),
                note: name.clone(),
            });
            if self.gate.first_in_window(
                &format!("allow:{}", profile.image_path),
                Duration::from_secs(3600),
                Instant::now(),
            ) {
                self.log(
                    Level::Info,
                    ids::ALLOWLISTED_TOUCH,
                    &format!(
                        "Allowlisted process {} (PID {pid}, entry \"{name}\") opened decoy {}",
                        profile.image_path, entry.decoy_id
                    ),
                );
            }
            return;
        }

        let id = proc_id(pid, profile.start_time);
        let existing = self
            .live
            .get(&id)
            .cloned()
            .filter(|iid| self.open.contains_key(iid));
        let created = existing.is_none();
        let mut inc = match existing.and_then(|iid| self.open.remove(&iid)) {
            Some(i) => i,
            None => {
                let mut i = Incident::new(profile.clone(), now, self.host.clone());
                i.simulated = self.is_simulation(&profile);
                i.tree = self.build_tree(&profile);
                i.log(
                    now,
                    "detected",
                    format!("{} (PID {pid}) opened a decoy", profile.image_path),
                );
                i
            }
        };
        let old_severity = inc.severity;
        inc.touches.push(DecoyTouch {
            at,
            decoy_id: entry.decoy_id.clone(),
            category: entry.category,
            path: path.to_string(),
            op,
            source,
            bytes: None,
        });
        if let Some(b) = &brk {
            let lead = (at - b.at).whole_milliseconds();
            inc.log(
                b.at,
                "oplock",
                format!(
                    "Oplock tripwire fired on {} ({lead} ms before the {source:?} event)",
                    entry.decoy_id
                ),
            );
        }
        inc.log(
            at,
            "touch",
            format!("{op:?} {} ({})", entry.decoy_id, entry.category.label()),
        );

        let first = inc.touches.first().map(|t| t.at).unwrap_or(at);
        if let Ok(c) = self.sensitive.lock() {
            let mut related = c.paths_since(pid, first - time::Duration::seconds(30));
            related.retain(|r| !inc.related_paths.contains(r));
            inc.related_paths.extend(related);
        }
        self.rescore(&mut inc, &profile);
        let escalated = !created && inc.severity > old_severity;
        self.contain(&mut inc, &profile);

        let _ = self.store.log_touch(&TouchLogRow {
            at,
            pid,
            image: profile.image_path.clone(),
            path: path.to_string(),
            decoy_id: entry.decoy_id,
            disposition: "incident".into(),
            note: inc.id.clone(),
        });
        if let Err(e) = self.store.save_incident(&inc) {
            tracing::error!(error = %e, "saving incident failed");
        }
        if created || escalated {
            self.notify(&inc, escalated);
        } else {
            let _ = self.events_tx.send(Event::Incident {
                summary: inc.summary(),
                created: false,
                toast: false,
            });
        }
        self.live.insert(id, inc.id.clone());
        self.open.insert(inc.id.clone(), inc);
    }

    fn rescore(&self, inc: &mut Incident, p: &ProcessProfile) {
        let mut firsts: BTreeMap<&str, OffsetDateTime> = BTreeMap::new();
        for t in &inc.touches {
            firsts.entry(t.decoy_id.as_str()).or_insert(t.at);
        }
        let times: Vec<OffsetDateTime> = firsts.values().copied().collect();
        let span = match (times.iter().min(), times.iter().max()) {
            (Some(a), Some(b)) => (*b - *a).as_seconds_f64(),
            _ => 0.0,
        };
        let parent_image = inc
            .tree
            .iter()
            .find(|n| n.pid == p.ppid)
            .map(|n| n.image.clone())
            .unwrap_or_default();
        let input = ScoreInput {
            decoys_touched: inc.distinct_decoys(),
            categories_touched: inc.distinct_categories().len(),
            sweep_span_secs: span,
            sweep_window_secs: self.config.sensor.sweep_window_secs as f64,
            read_data: inc.touches.iter().any(|t| t.op == TouchOp::Read),
            destructive: inc
                .touches
                .iter()
                .any(|t| matches!(t.op, TouchOp::Delete | TouchOp::Rename | TouchOp::Modify)),
            signature: p.signature.status,
            user_writable: p.user_writable_dir,
            temp_or_downloads: p.temp_or_downloads,
            image_age_secs: p
                .image_created
                .map(|c| (OffsetDateTime::now_utc() - c).whole_seconds().max(0) as u64),
            sensitive_paths: inc.related_paths.len(),
            network_connections: p
                .network
                .iter()
                .filter(|c| !c.remote.is_empty() && c.state != "LISTEN")
                .count(),
            suspicious_parent: epicurus_sensor::introspect::is_suspicious_parent(&parent_image),
            unattributed: p.pid == 0,
        };
        let s = score(&input);
        inc.score = s.value;
        inc.severity = s.severity;
        inc.reasons = s.reasons;
    }

    fn contain(&mut self, inc: &mut Incident, p: &ProcessProfile) {
        let action = self.config.policy.action_for(inc.severity);
        if action != PolicyAction::Suspend
            || !inc.suspended_pids.is_empty()
            || inc.status == IncidentStatus::Resolved
            || p.pid == 0
        {
            return;
        }
        if inc.actions.iter().any(|a| a.action == ActionKind::Suspend) {
            return;
        }
        let now = OffsetDateTime::now_utc();
        if p.protected {
            inc.record_action(
                now,
                ActionKind::Suspend,
                Actor::Policy,
                false,
                "critical or protected process: alert only",
            );
            self.log(
                Level::Warning,
                ids::CONTAINMENT_FAILED,
                &format!(
                    "Incident {}: {} is critical or protected; not suspended",
                    inc.id, p.image_path
                ),
            );
            return;
        }
        let res = containment::suspend_tree(ProcKey {
            pid: p.pid,
            create_time: p.start_time,
        });
        let ok = !res.done.is_empty();
        let detail = if res.failed.is_empty() {
            format!("suspended {} process(es): {:?}", res.done.len(), res.done)
        } else {
            format!("suspended {:?}; failed {:?}", res.done, res.failed)
        };
        inc.record_action(now, ActionKind::Suspend, Actor::Policy, ok, detail.clone());
        if ok {
            inc.suspended_pids = res.done.clone();
            inc.status = IncidentStatus::AwaitingDecision;
            self.log(
                Level::Warning,
                ids::CONTAINMENT_ACTION,
                &format!("Incident {}: {detail}", inc.id),
            );
            if self.config.policy.minidump {
                match containment::write_minidump(
                    ProcKey {
                        pid: p.pid,
                        create_time: p.start_time,
                    },
                    &self.data.dumps(),
                ) {
                    Ok(path) => inc.record_action(
                        now,
                        ActionKind::Minidump,
                        Actor::Policy,
                        true,
                        path.display().to_string(),
                    ),
                    Err(e) => inc.record_action(
                        now,
                        ActionKind::Minidump,
                        Actor::Policy,
                        false,
                        e.to_string(),
                    ),
                }
            }
        } else {
            self.log(
                Level::Error,
                ids::CONTAINMENT_FAILED,
                &format!("Incident {}: {detail}", inc.id),
            );
        }
    }

    fn containment_line(inc: &Incident) -> String {
        match inc.status {
            IncidentStatus::AwaitingDecision => format!(
                "Suspended {} process(es); awaiting your decision",
                inc.suspended_pids.len()
            ),
            IncidentStatus::Resolved => "Resolved".into(),
            IncidentStatus::Open => {
                if inc
                    .actions
                    .iter()
                    .any(|a| a.action == ActionKind::Suspend && !a.ok)
                {
                    "Not suspended (see incident)".into()
                } else {
                    "Alert only (policy)".into()
                }
            }
        }
    }

    fn notify(&mut self, inc: &Incident, escalated: bool) {
        let level = Level::for_severity(inc.severity);
        let id = if escalated {
            ids::INCIDENT_ESCALATED
        } else {
            ids::INCIDENT_CREATED
        };
        let p = &inc.process;
        self.log(
            level,
            id,
            &format!(
                "Incident {} [{} {}/100]{}: {} (PID {}) touched {} decoy(s) in {} categor(ies). Signer: {}. {}",
                inc.id,
                inc.severity,
                inc.score,
                if inc.simulated { " (simulation)" } else { "" },
                p.image_path,
                p.pid,
                inc.distinct_decoys(),
                inc.distinct_categories().len(),
                p.signature.signer().unwrap_or("unsigned"),
                Self::containment_line(inc)
            ),
        );
        let action = self.config.policy.action_for(inc.severity);
        let wants_alert =
            action != PolicyAction::Observe && inc.severity >= self.config.alerts.min_severity;
        let key = format!(
            "{}:{}",
            p.image_sha256
                .clone()
                .unwrap_or_else(|| p.image_path.clone()),
            inc.severity
        );
        let window = Duration::from_secs(self.config.alerts.dedupe_window_secs);
        let first = wants_alert && self.gate.first_in_window(&key, window, Instant::now());
        if first {
            let _ = self.alerts_tx.send(AlertJob::Send {
                body: AlertBody::Incident {
                    summary: inc.summary(),
                    reasons: inc.reasons.clone(),
                    signer: p.signature.signer().map(str::to_string),
                    containment: Self::containment_line(inc),
                    escalated,
                },
                config: Box::new(self.config.alerts.clone()),
                host: self.host.clone(),
            });
        }
        let toast = first && self.config.alerts.toast;
        let _ = self.events_tx.send(Event::Incident {
            summary: inc.summary(),
            created: !escalated,
            toast,
        });
    }

    fn on_integrity(&mut self, at: OffsetDateTime, path: &str, change: IntegrityChange) {
        let Some(entry) = self.manifest.entry_for(Path::new(path)).cloned() else {
            return;
        };
        if change == IntegrityChange::Modified {
            if let Some(o) = &self.oplocks {
                o.suppress(path, Duration::from_secs(2));
            }
            match sha256_file(Path::new(path)) {
                Ok(h) if h == entry.sha256 => return, // metadata-only change
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return,
                _ => {}
            }
        }
        let what = match change {
            IntegrityChange::Removed => "deleted",
            IntegrityChange::RenamedAway => "renamed",
            IntegrityChange::Modified => "modified",
        };
        let msg = format!("Decoy {} at {path} was {what}", entry.decoy_id);
        let _ = self.store.log_event(at, "integrity", &msg);
        self.log(Level::Warning, ids::DECOY_INTEGRITY, &msg);
        if self.gate.first_in_window(
            &format!("integrity:{path}"),
            Duration::from_secs(300),
            Instant::now(),
        ) {
            let _ = self.alerts_tx.send(AlertJob::Send {
                body: AlertBody::Integrity {
                    path: path.to_string(),
                    decoy_id: entry.decoy_id.clone(),
                    change: what.into(),
                },
                config: Box::new(self.config.alerts.clone()),
                host: self.host.clone(),
            });
        }
        // A modified decoy is no longer ours to delete; a missing one is gone.
        // Either way it leaves the manifest, and the planner treats a
        // modified file as foreign from now on.
        let _ = self.store.remove_from_manifest([&entry.path]);
        if let Ok(m) = self.store.manifest() {
            self.manifest = m;
        }
        if self.config.protection.auto_replant {
            self.replant_due = Some(Instant::now() + Duration::from_secs(2));
        }
    }

    /// Periodic work: unattributed breaks, re-planting, health, pruning.
    pub fn tick(&mut self) {
        let now = Instant::now();
        let window = Duration::from_millis(self.config.sensor.correlation_window_ms);
        for b in self.breaks.expire(now, window) {
            self.on_unattributed_break(b.at, &b.path);
        }
        if self.replant_due.is_some_and(|t| t <= now) {
            self.replant_due = None;
            match self.plant(None, false) {
                Ok(s) if !s.planned.is_empty() => {
                    let msg = format!(
                        "Re-planted {} decoy(s): {}",
                        s.planned.len(),
                        s.planned
                            .iter()
                            .map(|p| p.decoy_id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    let _ = self
                        .store
                        .log_event(OffsetDateTime::now_utc(), "replant", &msg);
                    self.log(Level::Info, ids::DECOY_REPLANTED, &msg);
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e.message, "re-plant failed"),
            }
        }
        if now.duration_since(self.last_health) >= Duration::from_secs(5) {
            self.last_health = now;
            self.check_health();
        }
        if now.duration_since(self.last_prune) >= Duration::from_secs(60) {
            self.last_prune = now;
            self.table
                .prune(OffsetDateTime::now_utc(), time::Duration::minutes(10));
            self.open.retain(|_, i| {
                i.status != IncidentStatus::Resolved
                    && OffsetDateTime::now_utc() - i.updated_at < time::Duration::hours(24)
            });
            let open_ids: Vec<String> = self.open.keys().cloned().collect();
            self.live.retain(|_, iid| open_ids.contains(iid));
            if self.profiles.len() > 1024 {
                self.profiles.clear();
            }
        }
        if now.duration_since(self.last_db_prune) >= Duration::from_secs(3600) {
            self.last_db_prune = now;
            let _ = self
                .store
                .prune(OffsetDateTime::now_utc() - time::Duration::days(30));
        }
    }

    fn on_unattributed_break(&mut self, at: OffsetDateTime, path: &str) {
        let Some(entry) = self.manifest.entry_for(Path::new(path)).cloned() else {
            return;
        };
        let _ = self.store.log_touch(&TouchLogRow {
            at,
            pid: 0,
            image: String::new(),
            path: path.to_string(),
            decoy_id: entry.decoy_id.clone(),
            disposition: "unattributed".into(),
            note: format!("mode={}", self.mode.as_str()),
        });
        if self.gate.first_in_window(
            &format!("unattributed:{path}"),
            Duration::from_secs(600),
            Instant::now(),
        ) {
            self.log(
                Level::Warning,
                ids::UNATTRIBUTED_BREAK,
                &format!(
                    "Oplock tripwire fired on decoy {} but no sensor attributed the open",
                    entry.decoy_id
                ),
            );
        }
        // Several decoys tripped with no attribution suggests the file sensor
        // is blind (e.g. ETW tampering): raise an incident without a process.
        let now = Instant::now();
        let sweep = Duration::from_secs(self.config.sensor.sweep_window_secs);
        self.unattributed
            .retain(|(t, _, _)| now.duration_since(*t) < sweep);
        self.unattributed
            .push((now, entry.decoy_id.clone(), entry.category));
        let mut distinct: Vec<&str> = self
            .unattributed
            .iter()
            .map(|(_, d, _)| d.as_str())
            .collect();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() >= 2
            && self
                .gate
                .first_in_window("unattributed-sweep", Duration::from_secs(600), now)
        {
            let profile = ProcessProfile {
                image_path: "unknown (no process attributed)".into(),
                ..Default::default()
            };
            let mut inc = Incident::new(
                profile.clone(),
                OffsetDateTime::now_utc(),
                self.host.clone(),
            );
            for (_, d, c) in &self.unattributed {
                inc.touches.push(DecoyTouch {
                    at,
                    decoy_id: d.clone(),
                    category: *c,
                    path: String::new(),
                    op: TouchOp::Open,
                    source: SensorSource::Oplock,
                    bytes: None,
                });
            }
            inc.log(OffsetDateTime::now_utc(), "detected", "Multiple oplock tripwires fired without process attribution; the file sensor may be blinded");
            self.rescore(&mut inc, &profile);
            let _ = self.store.save_incident(&inc);
            self.notify(&inc, false);
        }
    }

    fn check_health(&mut self) {
        if let Some(s) = &self.etw {
            if !s.stats.running.load(std::sync::atomic::Ordering::Relaxed) {
                let msg =
                    "ETW consumer stopped unexpectedly (session stopped externally?); restarting"
                        .to_string();
                self.log(Level::Error, ids::SENSOR_DEGRADED, &msg);
                self.problems.push(msg);
                self.etw = None;
                self.mode = ActiveMode::None;
                self.start_etw();
                if self.mode == ActiveMode::None {
                    self.start_audit();
                    self.refresh_sensor_paths();
                }
                return;
            }
            if let Some(q) = s.query() {
                let lost = q.events_lost + q.realtime_buffers_lost;
                if lost > self.last_lost {
                    let msg = format!(
                        "ETW session lost {} event(s) / buffer(s) since last check (total {lost})",
                        lost - self.last_lost
                    );
                    self.last_lost = lost;
                    self.log(Level::Warning, ids::EVENTS_LOST, &msg);
                }
            }
        }
        self.problems.dedup();
        if self.problems.len() > 50 {
            self.problems.drain(..self.problems.len() - 50);
        }
    }

    // -----------------------------------------------------------------
    // Planting
    // -----------------------------------------------------------------

    /// Plans (and unless `dry_run`, plants) decoys.
    pub fn plant(
        &mut self,
        profile: Option<String>,
        dry_run: bool,
    ) -> Result<PlanSummary, IpcError> {
        let env = self.env.clone().ok_or_else(|| {
            bad("Epicurus is not installed for a user profile (run `epicurus install`)")
        })?;
        let categories = match &profile {
            Some(p) => {
                let mut c = self
                    .catalog
                    .profile_categories(p)
                    .map_err(|e| bad(e.to_string()))?;
                for d in &self.config.protection.disabled_categories {
                    c.remove(d);
                }
                c
            }
            None => self
                .config
                .enabled_categories(&self.catalog)
                .map_err(|e| bad(e.to_string()))?,
        };
        let extra = match (&self.user_sid, self.opts.profile_root.is_none()) {
            (Some(sid), true) => {
                epicurus_sensor::profile::onedrive_roots(sid, &self.config.install.profile_path)
            }
            _ => Vec::new(),
        };
        let fs = RealFs::detect(&env, extra);
        let seed = self.store.install_seed().map_err(internal)?;
        let plan = Planner {
            catalog: &self.catalog,
            env: &env,
            seed: &seed,
            fs: &fs,
            manifest: &self.manifest,
        }
        .plan(
            &PlanOptions {
                categories,
                canaries: self.config.canaries.clone(),
                now: OffsetDateTime::now_utc(),
            },
            &mut rand::rng(),
        )
        .map_err(|e| internal(format!("planning failed: {e}")))?;
        let mut summary = PlanSummary::from(&plan);
        if dry_run || plan.planned.is_empty() {
            return Ok(summary);
        }
        self.pause_file_sensors();
        let owner_hook = self
            .user_sid
            .clone()
            .map(|user_sid| epicurus_sensor::OwnerHook { user_sid });
        let hooks: &dyn PlantHooks = match &owner_hook {
            Some(h) => h,
            None => &NoHooks,
        };
        let now = OffsetDateTime::now_utc();
        let mut planted = 0usize;
        for d in &plan.planned {
            match epicurus_core::plant::plant(d, hooks, now) {
                Ok(out) => {
                    planted += out.entries.len();
                    if let Err(e) = self.store.add_to_manifest(&out.entries, &out.dirs) {
                        summary.errors.push(format!(
                            "{}: recorded files but manifest write failed: {e}",
                            d.decoy_id
                        ));
                    }
                }
                Err(e) => summary.errors.push(format!("{}: {e}", d.decoy_id)),
            }
        }
        self.manifest = self.store.manifest().map_err(internal)?;
        self.refresh_sensor_paths();
        if planted > 0 {
            self.log(
                Level::Info,
                ids::DECOYS_PLANTED,
                &format!(
                    "Planted {planted} decoy file(s); {} in manifest",
                    self.manifest.entries.len()
                ),
            );
        }
        Ok(summary)
    }

    /// Removes decoys (all, or one category) whose hash still matches.
    pub fn unplant(
        &mut self,
        category: Option<Category>,
    ) -> Result<epicurus_core::plant::UnplantReport, IpcError> {
        self.pause_file_sensors();
        let subset = Manifest {
            entries: self
                .manifest
                .entries
                .iter()
                .filter(|e| category.is_none_or(|c| e.category == c))
                .cloned()
                .collect(),
            dirs: self.manifest.dirs.clone(),
        };
        let report = epicurus_core::plant::unplant(&subset);
        self.store
            .remove_from_manifest(report.forgettable())
            .map_err(internal)?;
        self.store
            .remove_dirs(report.dirs_removed.iter())
            .map_err(internal)?;
        self.manifest = self.store.manifest().map_err(internal)?;
        self.refresh_sensor_paths();
        self.log(
            Level::Info,
            ids::DECOYS_REMOVED,
            &format!(
                "Removed {} decoy file(s); kept {} modified file(s); {} remain in manifest",
                report.removed.len(),
                report.kept_modified.len(),
                self.manifest.entries.len()
            ),
        );
        Ok(report)
    }

    // -----------------------------------------------------------------
    // IPC
    // -----------------------------------------------------------------

    /// Handles one request.
    pub fn handle(&mut self, req: Request, client_pid: Option<u32>) -> Outcome {
        if req.is_mutating() {
            tracing::info!(client_pid, request = ?std::mem::discriminant(&req), "mutating IPC request");
        }
        Outcome::Ready(Box::new(match req {
            Request::Status => Ok(Response::Status(self.status())),
            Request::ListIncidents { limit } => self
                .store
                .incident_summaries(limit)
                .map(|items| Response::Incidents { items })
                .map_err(internal),
            Request::GetIncident { id } => {
                match self.open.get(&id).cloned().map(Ok).unwrap_or_else(|| {
                    self.store
                        .incident(&id)
                        .map_err(internal)
                        .and_then(|o| o.ok_or_else(|| not_found("no such incident")))
                }) {
                    Ok(i) => Ok(Response::Incident {
                        incident: Box::new(i),
                    }),
                    Err(e) => Err(e),
                }
            }
            Request::IncidentAction { id, action } => self.apply_action(&id, action),
            Request::Plant { profile, dry_run } => self.plant(profile, dry_run).map(Response::Plan),
            Request::Unplant => self.unplant(None).map(Response::Unplant),
            Request::Replant => self.plant(None, false).map(Response::Plan),
            Request::GetManifest => Ok(Response::Manifest(ManifestView {
                entries: self.manifest.entries.clone(),
                enabled: self
                    .config
                    .enabled_categories(&self.catalog)
                    .map(|c| c.into_iter().collect())
                    .unwrap_or_default(),
                profile: self.config.protection.profile.clone(),
            })),
            Request::SetCategory { category, enabled } => self.set_category(category, enabled),
            Request::GetAllowlist => Ok(Response::Allowlist {
                entries: self.allow_user.entries.clone(),
                builtin: self.allow_builtin.entries.clone(),
            }),
            Request::SetAllowlist { entries } => {
                let list = Allowlist { entries };
                match list.to_toml().map_err(internal).and_then(|t| {
                    epicurus_core::config::write_atomic(&self.data.allowlist_file(), t.as_bytes())
                        .map_err(internal)
                }) {
                    Ok(()) => {
                        self.allow_user = list;
                        self.log(
                            Level::Info,
                            ids::CONFIG_CHANGED,
                            &format!("Allowlist updated by client PID {client_pid:?}"),
                        );
                        Ok(Response::Ack)
                    }
                    Err(e) => Err(e),
                }
            }
            Request::GetAlerts => Ok(Response::Alerts(self.alerts_view())),
            Request::SetAlertChannel { update } => self.set_alert(update),
            Request::TestAlert { channel } => return self.test_alert(channel),
            Request::GetSettings => Ok(Response::Settings(self.settings_view())),
            Request::SetSettings { update } => self.set_settings(update),
            Request::Doctor => Ok(Response::Doctor {
                checks: crate::doctor::service_checks(self),
            }),
            Request::Activity { hours } => {
                let since = OffsetDateTime::now_utc() - time::Duration::hours(i64::from(hours));
                Ok(Response::Activity(ActivityView {
                    touches: self.store.touches_since(since, 500).unwrap_or_default(),
                    events: self.store.events(200).unwrap_or_default(),
                }))
            }
            Request::Subscribe => Ok(Response::Ack),
        }))
    }

    fn save_config(&self) -> Result<(), IpcError> {
        // Test overrides are not persisted.
        let mut c = self.config.clone();
        if self.opts.profile_root.is_some()
            && let Ok(disk) = Config::load(&self.data.config_file())
        {
            c.install = disk.install;
        }
        c.save(&self.data.config_file()).map_err(internal)
    }

    fn set_category(&mut self, category: Category, enabled: bool) -> Result<Response, IpcError> {
        self.config
            .protection
            .disabled_categories
            .retain(|c| *c != category);
        if !enabled {
            self.config.protection.disabled_categories.push(category);
        }
        self.save_config()?;
        if enabled {
            self.plant(None, false).map(Response::Plan)
        } else {
            self.unplant(Some(category)).map(Response::Unplant)
        }
    }

    fn alerts_view(&self) -> AlertsView {
        let a = &self.config.alerts;
        AlertsView {
            min_severity: a.min_severity,
            toast: a.toast,
            eventlog: a.eventlog,
            discord: ChannelView {
                enabled: a.discord.enabled,
                configured: !a.discord.url.is_empty(),
                extra: None,
            },
            slack: ChannelView {
                enabled: a.slack.enabled,
                configured: !a.slack.url.is_empty(),
                extra: None,
            },
            ntfy: ChannelView {
                enabled: a.ntfy.enabled,
                configured: !a.ntfy.topic.is_empty(),
                extra: Some(a.ntfy.server.clone()),
            },
            generic: ChannelView {
                enabled: a.generic.enabled,
                configured: !a.generic.url.is_empty(),
                extra: Some(if a.generic.secret.is_empty() {
                    "unsigned".into()
                } else {
                    "HMAC-SHA256 signed".into()
                }),
            },
        }
    }

    fn set_alert(&mut self, update: AlertUpdate) -> Result<Response, IpcError> {
        let seal = |s: &str| Protected::seal(s).map_err(internal);
        let a = &mut self.config.alerts;
        match update {
            AlertUpdate::Toast { enabled } => a.toast = enabled,
            AlertUpdate::EventLog { enabled } => a.eventlog = enabled,
            AlertUpdate::MinSeverity { severity } => a.min_severity = severity,
            AlertUpdate::Discord { enabled, url } => {
                if let Some(u) = url {
                    a.discord.url = seal(&u)?;
                }
                a.discord.enabled = enabled && !a.discord.url.is_empty();
            }
            AlertUpdate::Slack { enabled, url } => {
                if let Some(u) = url {
                    a.slack.url = seal(&u)?;
                }
                a.slack.enabled = enabled && !a.slack.url.is_empty();
            }
            AlertUpdate::Ntfy {
                enabled,
                server,
                topic,
                token,
            } => {
                if let Some(s) = server {
                    a.ntfy.server = s;
                }
                if let Some(t) = topic {
                    a.ntfy.topic = seal(&t)?;
                }
                if let Some(t) = token {
                    a.ntfy.token = if t.is_empty() {
                        Protected::default()
                    } else {
                        seal(&t)?
                    };
                }
                a.ntfy.enabled = enabled && !a.ntfy.topic.is_empty();
            }
            AlertUpdate::Generic {
                enabled,
                url,
                secret,
            } => {
                if let Some(u) = url {
                    a.generic.url = seal(&u)?;
                }
                if let Some(s) = secret {
                    a.generic.secret = if s.is_empty() {
                        Protected::default()
                    } else {
                        seal(&s)?
                    };
                }
                a.generic.enabled = enabled && !a.generic.url.is_empty();
            }
        }
        self.save_config()?;
        self.log(
            Level::Info,
            ids::CONFIG_CHANGED,
            "Alert channel configuration changed",
        );
        Ok(Response::Alerts(self.alerts_view()))
    }

    fn test_alert(&mut self, channel: ChannelKind) -> Outcome {
        match channel {
            ChannelKind::EventLog => {
                if let Some(e) = &self.eventlog {
                    e.report(Level::Info, ids::TEST, "Test event from Epicurus");
                    Outcome::Ready(Box::new(Ok(Response::ActionResult {
                        ok: true,
                        detail: "test event written to the Application log".into(),
                    })))
                } else {
                    Outcome::Ready(Box::new(Ok(Response::ActionResult {
                        ok: false,
                        detail: "event source unavailable".into(),
                    })))
                }
            }
            ChannelKind::Toast => {
                let n = self.events_tx.send(Event::TestToast).unwrap_or(0);
                Outcome::Ready(Box::new(Ok(Response::ActionResult {
                    ok: n > 0,
                    detail: if n > 0 {
                        "test toast sent to the tray agent".into()
                    } else {
                        "no tray agent is connected".into()
                    },
                })))
            }
            _ => {
                let (tx, rx) = oneshot::channel();
                let _ = self.alerts_tx.send(AlertJob::Test {
                    channel,
                    config: Box::new(self.config.alerts.clone()),
                    host: self.host.clone(),
                    reply: tx,
                });
                Outcome::AwaitTest(rx)
            }
        }
    }

    fn settings_view(&self) -> SettingsView {
        SettingsView {
            theme: self.config.ui.theme,
            profile: self.config.protection.profile.clone(),
            profiles: self.catalog.profiles.keys().cloned().collect(),
            policy: self.config.policy.clone(),
            auto_replant: self.config.protection.auto_replant,
            oplock: self.config.sensor.oplock,
            sweep_window_secs: self.config.sensor.sweep_window_secs,
            mode: self.config.sensor.mode,
            profile_path: self.config.install.profile_path.clone(),
            data_dir: self.data.root().display().to_string(),
        }
    }

    fn set_settings(&mut self, u: SettingsUpdate) -> Result<Response, IpcError> {
        let mut replant = false;
        if let Some(t) = u.theme {
            self.config.ui.theme = t;
        }
        if let Some(p) = u.profile {
            self.catalog
                .profile_categories(&p)
                .map_err(|e| bad(e.to_string()))?;
            replant = p != self.config.protection.profile;
            self.config.protection.profile = p;
        }
        if let Some(p) = u.policy {
            self.config.policy = p;
        }
        if let Some(a) = u.auto_replant {
            self.config.protection.auto_replant = a;
        }
        if let Some(o) = u.oplock {
            self.config.sensor.oplock = o;
        }
        if let Some(w) = u.sweep_window_secs {
            self.config.sensor.sweep_window_secs = w;
        }
        if let Some(m) = u.mode {
            self.config.sensor.mode = m;
        }
        self.config.validate().map_err(|e| bad(e.to_string()))?;
        self.save_config()?;
        self.log(Level::Info, ids::CONFIG_CHANGED, "Settings changed");
        if replant {
            let _ = self.plant(None, false);
        }
        Ok(Response::Settings(self.settings_view()))
    }

    fn incident_mut(&mut self, id: &str) -> Result<Incident, IpcError> {
        if let Some(i) = self.open.remove(id) {
            return Ok(i);
        }
        self.store
            .incident(id)
            .map_err(internal)?
            .ok_or_else(|| not_found("no such incident"))
    }

    fn apply_action(&mut self, id: &str, action: ActionKind) -> Result<Response, IpcError> {
        let mut inc = self.incident_mut(id)?;
        let now = OffsetDateTime::now_utc();
        let p = inc.process.clone();
        let key = ProcKey {
            pid: p.pid,
            create_time: p.start_time,
        };
        let (ok, detail) = match action {
            ActionKind::KillTree if p.pid != 0 => {
                let r = containment::kill_tree(key);
                inc.suspended_pids.clear();
                inc.status = IncidentStatus::Resolved;
                (
                    r.failed.is_empty(),
                    format!("terminated {:?}; failed {:?}", r.done, r.failed),
                )
            }
            ActionKind::Resume if p.pid != 0 => {
                let keys: Vec<ProcKey> = inc
                    .suspended_pids
                    .iter()
                    .map(|pid| ProcKey {
                        pid: *pid,
                        create_time: if *pid == p.pid { p.start_time } else { None },
                    })
                    .collect();
                let r = containment::resume(&keys);
                inc.suspended_pids.clear();
                inc.status = IncidentStatus::Resolved;
                (
                    r.failed.is_empty(),
                    format!("resumed {:?}; failed {:?}", r.done, r.failed),
                )
            }
            ActionKind::Quarantine if p.pid != 0 => {
                let Some(sha) = p.image_sha256.clone() else {
                    self.open.insert(inc.id.clone(), inc);
                    return Err(bad("image hash unknown; cannot quarantine"));
                };
                let r = containment::kill_tree(key);
                inc.suspended_pids.clear();
                inc.status = IncidentStatus::Resolved;
                match containment::quarantine_image(
                    Path::new(&p.image_path),
                    &sha,
                    &self.data.quarantine(),
                ) {
                    Ok(dest) => (
                        true,
                        format!("terminated {:?}; image moved to {}", r.done, dest.display()),
                    ),
                    Err(e) => (
                        false,
                        format!("terminated {:?}; quarantine failed: {e}", r.done),
                    ),
                }
            }
            ActionKind::BlockNetwork if !p.image_path.is_empty() => {
                let sha = p.image_sha256.clone().unwrap_or_else(|| "unknown".into());
                match epicurus_sensor::firewall::block_outbound(Path::new(&p.image_path), &sha) {
                    Ok(rule) => {
                        let mut rules: Vec<String> = self
                            .store
                            .kv_get("firewall_rules")
                            .ok()
                            .flatten()
                            .and_then(|j| serde_json::from_str(&j).ok())
                            .unwrap_or_default();
                        rules.push(rule.clone());
                        let _ = self.store.kv_set(
                            "firewall_rules",
                            &serde_json::to_string(&rules).unwrap_or_default(),
                        );
                        (true, format!("outbound block rule \"{rule}\" added"))
                    }
                    Err(e) => (false, e.to_string()),
                }
            }
            ActionKind::Allowlist if !p.image_path.is_empty() => {
                let name = format!(
                    "{} (from {})",
                    p.image_path.rsplit('\\').next().unwrap_or(&p.image_path),
                    inc.id
                );
                let entry = match (p.signature.status, p.signature.signer()) {
                    (SignatureStatus::Valid, Some(signer)) => AllowEntry {
                        name,
                        signers: vec![signer.to_string()],
                        path: p.image_path.clone(),
                        sha256: None,
                    },
                    _ => match &p.image_sha256 {
                        Some(h) => AllowEntry {
                            name,
                            signers: Vec::new(),
                            path: String::new(),
                            sha256: Some(h.clone()),
                        },
                        None => {
                            self.open.insert(inc.id.clone(), inc);
                            return Err(bad(
                                "unsigned image with unknown hash cannot be allowlisted",
                            ));
                        }
                    },
                };
                self.allow_user.entries.push(entry);
                let saved = self.allow_user.to_toml().map_err(internal).and_then(|t| {
                    epicurus_core::config::write_atomic(&self.data.allowlist_file(), t.as_bytes())
                        .map_err(internal)
                });
                let keys: Vec<ProcKey> = inc
                    .suspended_pids
                    .iter()
                    .map(|pid| ProcKey {
                        pid: *pid,
                        create_time: None,
                    })
                    .collect();
                let r = containment::resume(&keys);
                inc.suspended_pids.clear();
                inc.status = IncidentStatus::Resolved;
                (saved.is_ok(), format!("allowlisted; resumed {:?}", r.done))
            }
            ActionKind::Dismiss => {
                inc.status = IncidentStatus::Resolved;
                (true, "dismissed".into())
            }
            _ => {
                self.open.insert(inc.id.clone(), inc);
                return Err(bad(format!(
                    "action {} is not applicable to this incident",
                    action.as_str()
                )));
            }
        };
        inc.record_action(now, action, Actor::User, ok, detail.clone());
        self.store.save_incident(&inc).map_err(internal)?;
        self.log(
            if ok { Level::Info } else { Level::Error },
            if ok {
                ids::CONTAINMENT_ACTION
            } else {
                ids::CONTAINMENT_FAILED
            },
            &format!(
                "Incident {}: user action {}: {detail}",
                inc.id,
                action.as_str()
            ),
        );
        let _ = self.events_tx.send(Event::Incident {
            summary: inc.summary(),
            created: false,
            toast: false,
        });
        if inc.status != IncidentStatus::Resolved {
            self.open.insert(inc.id.clone(), inc);
        }
        Ok(Response::ActionResult { ok, detail })
    }

    /// Protection state and sensor health.
    pub fn status(&self) -> StatusInfo {
        let mut by_cat: BTreeMap<String, u32> = BTreeMap::new();
        for e in &self.manifest.entries {
            *by_cat.entry(e.category.as_str().to_string()).or_default() += 1;
        }
        let (armed, total) = self
            .oplocks
            .as_ref()
            .map(|o| {
                (
                    o.stats.armed.load(std::sync::atomic::Ordering::Relaxed),
                    o.stats.total.load(std::sync::atomic::Ordering::Relaxed),
                )
            })
            .unwrap_or((0, 0));
        let lost = self
            .etw
            .as_ref()
            .and_then(EtwSession::query)
            .unwrap_or_default();
        let last_ft = self
            .etw_stats
            .last_event_ft
            .load(std::sync::atomic::Ordering::Relaxed);
        let last_age = epicurus_core::timefmt::from_filetime(last_ft)
            .map(|t| (OffsetDateTime::now_utc() - t).whole_seconds().max(0) as u64);
        let sensor = SensorHealth {
            mode: self.mode.as_str().into(),
            etw_running: self
                .etw
                .as_ref()
                .is_some_and(|s| s.stats.running.load(std::sync::atomic::Ordering::Relaxed)),
            events_lost: lost.events_lost,
            buffers_lost: lost.realtime_buffers_lost,
            oplocks_armed: armed,
            oplocks_total: total,
            integrity_watchers: self
                .integrity
                .as_ref()
                .map(|w| w.watched.load(std::sync::atomic::Ordering::Relaxed))
                .unwrap_or(0),
            process_table: self.table.len() as u32,
            last_event_age_secs: if last_ft == 0 { None } else { last_age },
            problems: self.problems.clone(),
        };
        let protection = if self.env.is_none()
            || self.manifest.entries.is_empty()
            || self.mode == ActiveMode::None
        {
            ProtectionState::Unprotected
        } else if self.mode == ActiveMode::Audit
            || !self.problems.is_empty()
            || (self.config.sensor.oplock && total > 0 && armed * 2 < total)
        {
            ProtectionState::Degraded
        } else {
            ProtectionState::Protected
        };
        let day = OffsetDateTime::now_utc() - time::Duration::hours(24);
        StatusInfo {
            version: epicurus_core::VERSION.into(),
            protection,
            sensor,
            decoys_planted: self.manifest.entries.len() as u32,
            decoys_by_category: by_cat,
            touches_24h: self
                .store
                .touches_since(day, 10_000)
                .map(|v| v.len() as u32)
                .unwrap_or(0),
            incidents_24h: self.store.incidents_since(day).unwrap_or(0),
            pending: self
                .store
                .pending_incidents()
                .map(|v| v.iter().map(Incident::summary).collect())
                .unwrap_or_default(),
            recent: self.store.incident_summaries(10).unwrap_or_default(),
        }
    }

    /// True when the manifest holds any decoy.
    pub fn has_decoys(&self) -> bool {
        !self.manifest.entries.is_empty()
    }

    /// SID of the protected user (pipe DACL, tray launch).
    pub fn status_user_sid(&self) -> Option<String> {
        self.user_sid.clone()
    }

    /// Records a webhook delivery failure in the Event Log.
    pub fn report_alert_failure(&self, msg: &str) {
        self.log(
            Level::Warning,
            ids::ALERT_FAILED,
            &format!("Alert delivery failed: {msg}"),
        );
    }

    // Accessors for doctor.
    pub(crate) fn mode(&self) -> ActiveMode {
        self.mode
    }
    pub(crate) fn etw(&self) -> Option<&EtwSession> {
        self.etw.as_ref()
    }
    pub(crate) fn oplocks(&self) -> Option<&OplockManager> {
        self.oplocks.as_ref()
    }
    pub(crate) fn env(&self) -> Option<&EnvMap> {
        self.env.as_ref()
    }
    pub(crate) fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }
    pub(crate) fn problems(&self) -> &[String] {
        &self.problems
    }
    pub(crate) fn user_sid(&self) -> Option<&str> {
        self.user_sid.as_deref()
    }
    pub(crate) fn data(&self) -> &DataDir {
        &self.data
    }
    pub(crate) fn table_len(&self) -> usize {
        self.table.len()
    }
    pub(crate) fn uses_profile_override(&self) -> bool {
        self.opts.profile_root.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_ids_distinguish_start_times() {
        let t = OffsetDateTime::now_utc();
        assert_ne!(
            proc_id(5, Some(t)),
            proc_id(5, Some(t + time::Duration::seconds(1)))
        );
        assert_eq!(proc_id(5, None), (5, 0));
    }
}
