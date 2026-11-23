//! Subcommands that talk to the running service over IPC, with local
//! fallbacks (elevated) for when the service is not running.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use epicurus_core::catalog::Catalog;
use epicurus_core::config::Config;
use epicurus_core::environment::RealFs;
use epicurus_core::incident::IncidentSummary;
use epicurus_core::ipc::{
    CheckStatus, Client, DoctorCheck, PlanSummary, Request, Response, StatusInfo,
};
use epicurus_core::paths::DataDir;
use epicurus_core::plan::{PlanOptions, Planner};
use epicurus_core::storage::Store;
use epicurus_service::scm;

/// Verifies that the pipe server is the Epicurus service (for the default
/// pipe). Custom pipe names are only used by the foreground test host.
pub fn verifier(pipe: &str) -> epicurus_ui::Verifier {
    let default = pipe == epicurus_core::DEFAULT_PIPE_NAME;
    Arc::new(move |c: &Client| {
        if !default {
            return true;
        }
        match (epicurus_core::ipc::server_pid(c.pipe()), scm::query()) {
            (Some(pid), scm::State::Running(svc)) => pid == svc,
            _ => false,
        }
    })
}

/// Connects and verifies.
pub fn connect(pipe: &str) -> anyhow::Result<Client> {
    let c = Client::connect(pipe)?;
    if !verifier(pipe)(&c) {
        bail!("the pipe {pipe} is not served by the Epicurus service; refusing to talk to it");
    }
    Ok(c)
}

fn call(pipe: &str, req: Request) -> anyhow::Result<Response> {
    Ok(connect(pipe)?.call(req)?)
}

/// Prints a plan summary.
pub fn print_plan(p: &PlanSummary, dry_run: bool, out: &mut dyn FnMut(String)) {
    out(format!(
        "{} decoy(s) {}:",
        p.planned.len(),
        if dry_run {
            "would be planted"
        } else {
            "planted"
        }
    ));
    for it in &p.planned {
        out(format!(
            "  + [{}] {}{}{}",
            it.category,
            it.decoy_id,
            if it.alternate {
                " (alternate location)"
            } else {
                ""
            },
            if it.canary { " (live canary)" } else { "" }
        ));
        for (path, size) in &it.files {
            out(format!("        {path}  ({size} bytes)"));
        }
    }
    if !p.skipped.is_empty() {
        out(format!("{} skipped:", p.skipped.len()));
        for s in &p.skipped {
            out(format!("  - [{}] {}: {}", s.category, s.decoy_id, s.reason));
        }
    }
    for e in &p.errors {
        out(format!("  ! {e}"));
    }
}

fn require_admin(what: &str) -> anyhow::Result<()> {
    if !epicurus_sensor::privileges::is_elevated() {
        bail!(
            "the Epicurus service is not running and {what} needs administrator rights to work without it"
        );
    }
    Ok(())
}

/// Plans/plants locally (service not running; elevated).
fn local_plant(
    data: &DataDir,
    profile: Option<String>,
    dry_run: bool,
) -> anyhow::Result<PlanSummary> {
    let config = Config::load(&data.config_file())?;
    let env = config
        .env_map()
        .context("Epicurus is not installed (no protected profile); run `epicurus install`")?;
    let catalog = Catalog::load_with_overrides(&data.catalog_d())?;
    let mut store = Store::open(&data.database())?;
    let manifest = store.manifest()?;
    let mut cats = match &profile {
        Some(p) => catalog.profile_categories(p)?,
        None => config.enabled_categories(&catalog)?,
    };
    for c in &config.protection.disabled_categories {
        cats.remove(c);
    }
    let extra = epicurus_sensor::profile::onedrive_roots(
        &config.install.user_sid,
        &config.install.profile_path,
    );
    let fs = RealFs::detect(&env, extra);
    let seed = store.install_seed()?;
    let plan = Planner {
        catalog: &catalog,
        env: &env,
        seed: &seed,
        fs: &fs,
        manifest: &manifest,
    }
    .plan(
        &PlanOptions {
            categories: cats,
            canaries: config.canaries.clone(),
            now: time::OffsetDateTime::now_utc(),
        },
        &mut rand::rng(),
    )?;
    let mut summary = PlanSummary::from(&plan);
    if dry_run {
        return Ok(summary);
    }
    let hook = epicurus_sensor::OwnerHook {
        user_sid: config.install.user_sid.clone(),
    };
    let _ = epicurus_sensor::privileges::enable("SeRestorePrivilege");
    for d in &plan.planned {
        match epicurus_core::plant::plant(d, &hook, time::OffsetDateTime::now_utc()) {
            Ok(o) => store.add_to_manifest(&o.entries, &o.dirs)?,
            Err(e) => summary.errors.push(format!("{}: {e}", d.decoy_id)),
        }
    }
    Ok(summary)
}

/// `epicurus plant`.
pub fn plant(
    pipe: &str,
    data: &DataDir,
    profile: Option<String>,
    dry_run: bool,
) -> anyhow::Result<u8> {
    let summary = match call(
        pipe,
        Request::Plant {
            profile: profile.clone(),
            dry_run,
        },
    ) {
        Ok(Response::Plan(p)) => p,
        Ok(other) => bail!("unexpected reply: {other:?}"),
        Err(e) if is_unavailable(&e) => {
            require_admin("planting")?;
            local_plant(data, profile, dry_run)?
        }
        Err(e) => return Err(e),
    };
    print_plan(&summary, dry_run, &mut |l| println!("{l}"));
    Ok(if summary.errors.is_empty() { 0 } else { 2 })
}

fn is_unavailable(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<epicurus_core::Error>(),
        Some(epicurus_core::Error::NotFound(_))
    )
}

/// `epicurus unplant`.
pub fn unplant(pipe: &str, data: &DataDir) -> anyhow::Result<u8> {
    let report = match call(pipe, Request::Unplant) {
        Ok(Response::Unplant(r)) => r,
        Ok(other) => bail!("unexpected reply: {other:?}"),
        Err(e) if is_unavailable(&e) => {
            require_admin("unplanting")?;
            let mut store = Store::open(&data.database())?;
            let r = epicurus_core::plant::unplant(&store.manifest()?);
            store.remove_from_manifest(r.forgettable())?;
            store.remove_dirs(r.dirs_removed.iter())?;
            r
        }
        Err(e) => return Err(e),
    };
    println!(
        "Removed {} decoy file(s) and {} directorie(s).",
        report.removed.len(),
        report.dirs_removed.len()
    );
    for p in &report.kept_modified {
        println!(
            "  kept (content changed since planting, so not ours to delete): {}",
            p.display()
        );
    }
    for (p, e) in &report.failed {
        println!("  failed: {}: {e}", p.display());
    }
    Ok(if report.failed.is_empty() { 0 } else { 2 })
}

fn print_summary_row(s: &IncidentSummary) {
    println!(
        "{}  {:<8} {:>3}  {:<18} PID {:<6} {} decoy(s)  {}{}",
        s.id,
        s.severity.as_str(),
        s.score,
        format!("{:?}", s.status),
        s.pid,
        s.decoys,
        s.image.rsplit('\\').next().unwrap_or(&s.image),
        if s.simulated { "  [simulation]" } else { "" }
    );
}

fn print_status(s: &StatusInfo) {
    println!("Epicurus {}", s.version);
    println!("Protection:   {:?}", s.protection);
    println!(
        "File sensor:  {}{}",
        s.sensor.mode,
        if s.sensor.etw_running {
            " (ETW session running)"
        } else {
            ""
        }
    );
    println!(
        "Oplocks:      {}/{} armed",
        s.sensor.oplocks_armed, s.sensor.oplocks_total
    );
    println!(
        "Integrity:    {} directorie(s) watched",
        s.sensor.integrity_watchers
    );
    println!(
        "Lost events:  {} events, {} real-time buffers",
        s.sensor.events_lost, s.sensor.buffers_lost
    );
    println!("Decoys:       {} file(s)", s.decoys_planted);
    for (c, n) in &s.decoys_by_category {
        println!("                {c}: {n}");
    }
    println!(
        "Last 24h:     {} touch(es), {} incident(s)",
        s.touches_24h, s.incidents_24h
    );
    for p in &s.sensor.problems {
        println!("Problem:      {p}");
    }
    if !s.pending.is_empty() {
        println!("\nAwaiting your decision (open the dashboard with `epicurus ui`):");
        for p in &s.pending {
            print_summary_row(p);
        }
    }
    if !s.recent.is_empty() {
        println!("\nRecent incidents:");
        for r in &s.recent {
            print_summary_row(r);
        }
    }
}

/// `epicurus status`.
pub fn status(pipe: &str, data: &DataDir, json: bool) -> anyhow::Result<u8> {
    match call(pipe, Request::Status) {
        Ok(Response::Status(s)) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                print_status(&s);
            }
            Ok(0)
        }
        Ok(other) => bail!("unexpected reply: {other:?}"),
        Err(e) if is_unavailable(&e) => {
            let state = scm::query();
            println!("Service:      {state:?}");
            println!("Protection:   Unprotected (the service is not running)");
            if let Ok(store) = Store::open(&data.database()) {
                println!(
                    "Decoys:       {} file(s) in manifest",
                    store.manifest().map(|m| m.entries.len()).unwrap_or(0)
                );
            }
            if state == scm::State::NotInstalled {
                println!("Run `epicurus install` to get started.");
            }
            Ok(3)
        }
        Err(e) => Err(e),
    }
}

/// `epicurus incidents`.
pub fn incidents(pipe: &str, data: &DataDir, json: bool, limit: u32) -> anyhow::Result<u8> {
    let limit = limit.clamp(1, 1000);
    let items = match call(pipe, Request::ListIncidents { limit }) {
        Ok(Response::Incidents { items }) => items,
        Ok(other) => bail!("unexpected reply: {other:?}"),
        Err(e) if is_unavailable(&e) => {
            require_admin("reading incidents")?;
            Store::open(&data.database())?.incident_summaries(limit)?
        }
        Err(e) => return Err(e),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else if items.is_empty() {
        println!("No incidents.");
    } else {
        for s in &items {
            print_summary_row(s);
        }
    }
    Ok(0)
}

/// `epicurus export <id>`.
pub fn export(pipe: &str, data: &DataDir, id: &str, out: Option<PathBuf>) -> anyhow::Result<u8> {
    if !epicurus_core::incident::is_valid_incident_id(id) {
        bail!("invalid incident id {id:?} (expected inc_ followed by 16 hex characters)");
    }
    let inc = match call(pipe, Request::GetIncident { id: id.to_string() }) {
        Ok(Response::Incident { incident }) => *incident,
        Ok(other) => bail!("unexpected reply: {other:?}"),
        Err(e) if is_unavailable(&e) => {
            require_admin("exporting")?;
            Store::open(&data.database())?
                .incident(id)?
                .context("no such incident")?
        }
        Err(e) => return Err(e),
    };
    let dir = out.unwrap_or(std::env::current_dir()?);
    for p in epicurus_core::report::export_all(&inc, &dir)? {
        println!("{}", p.display());
    }
    Ok(0)
}

fn print_check(c: &DoctorCheck) {
    let tag = match c.status {
        CheckStatus::Ok => "  ok ",
        CheckStatus::Info => " info",
        CheckStatus::Warn => " WARN",
        CheckStatus::Fail => " FAIL",
    };
    println!("[{tag}] {:<26} {}", c.name, c.detail);
}

fn windows_version() -> String {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    let key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let name = epicurus_sensor::winutil::reg_get_string(HKEY_LOCAL_MACHINE, key, "ProductName")
        .unwrap_or_default();
    let disp = epicurus_sensor::winutil::reg_get_string(HKEY_LOCAL_MACHINE, key, "DisplayVersion")
        .unwrap_or_default();
    let build = epicurus_sensor::winutil::reg_get_string(HKEY_LOCAL_MACHINE, key, "CurrentBuild")
        .unwrap_or_default();
    let ubr = epicurus_sensor::winutil::reg_get_dword(HKEY_LOCAL_MACHINE, key, "UBR")
        .map(|u| format!(".{u}"))
        .unwrap_or_default();
    // ProductName still says "Windows 10" on Windows 11; the build tells the truth.
    let name = if build.parse::<u32>().unwrap_or(0) >= 22000 {
        name.replace("Windows 10", "Windows 11")
    } else {
        name
    };
    format!(
        "{name} {disp} (build {build}{ubr}) {}",
        std::env::consts::ARCH
    )
}

/// `epicurus doctor`.
pub fn doctor(pipe: &str, data: &DataDir, json: bool) -> anyhow::Result<u8> {
    let mut checks = Vec::new();
    let mut add = |name: &str, status, detail: String| {
        checks.push(DoctorCheck {
            name: name.into(),
            status,
            detail,
        })
    };
    add("Windows", CheckStatus::Info, windows_version());
    let elevated = epicurus_sensor::privileges::is_elevated();
    add(
        "Elevation",
        if elevated {
            CheckStatus::Ok
        } else {
            CheckStatus::Info
        },
        if elevated {
            "running elevated".into()
        } else {
            "not elevated (fine for status; install/uninstall elevate automatically)".into()
        },
    );
    let state = scm::query();
    add(
        "Service",
        match state {
            scm::State::Running(_) => CheckStatus::Ok,
            scm::State::NotInstalled => CheckStatus::Fail,
            _ => CheckStatus::Warn,
        },
        format!("{state:?}"),
    );
    add(
        "Event Log source",
        if scm::event_source_registered() {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        if scm::event_source_registered() {
            "registered".into()
        } else {
            "not registered".into()
        },
    );
    add(
        "Start Menu shortcut",
        if crate::shortcut::path().exists() {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        crate::shortcut::path().display().to_string(),
    );

    let mut service_checks = Vec::new();
    match call(pipe, Request::Doctor) {
        Ok(Response::Doctor { checks }) => {
            add(
                "IPC",
                CheckStatus::Ok,
                format!("pipe {pipe} reachable and owned by the service"),
            );
            service_checks = checks;
        }
        Ok(_) => add("IPC", CheckStatus::Warn, "unexpected reply".into()),
        Err(e) => {
            add("IPC", CheckStatus::Fail, e.to_string());
            if elevated {
                let session = Config::load(&data.config_file())
                    .map(|c| c.sensor.etw_session_name)
                    .unwrap_or_else(|_| "Epicurus-Sensor".into());
                match epicurus_sensor::etw::query_session_by_name(&session) {
                    Some(q) => add(
                        "ETW session",
                        CheckStatus::Warn,
                        format!(
                            "\"{session}\" exists without the service (stale; it will be stopped on next start); lost {}",
                            q.events_lost
                        ),
                    ),
                    None => add(
                        "ETW session",
                        CheckStatus::Info,
                        format!("\"{session}\" not running"),
                    ),
                }
                let failed = epicurus_sensor::privileges::enable_all(&[
                    "SeDebugPrivilege",
                    "SeSecurityPrivilege",
                    "SeRestorePrivilege",
                ]);
                add(
                    "Privileges",
                    if failed.is_empty() {
                        CheckStatus::Ok
                    } else {
                        CheckStatus::Warn
                    },
                    if failed.is_empty() {
                        "SeDebug, SeSecurity, SeRestore available".into()
                    } else {
                        format!("missing: {}", failed.join(", "))
                    },
                );
                if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                    match epicurus_sensor::oplock::probe_volume(std::path::Path::new(&local)) {
                        Ok(l) => add(
                            "Oplock support",
                            CheckStatus::Ok,
                            format!("{} grants {l} oplocks", PathBuf::from(&local).display()),
                        ),
                        Err(e) => add("Oplock support", CheckStatus::Warn, e),
                    }
                }
            }
        }
    }
    checks.extend(service_checks);
    if json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        for c in &checks {
            print_check(c);
        }
    }
    Ok(if checks.iter().any(|c| c.status == CheckStatus::Fail) {
        1
    } else {
        0
    })
}

/// `epicurus service --foreground`.
pub fn service_foreground(
    pipe: &str,
    data: DataDir,
    session_name: Option<String>,
    profile_root: Option<PathBuf>,
    user_sid: Option<String>,
) -> anyhow::Result<()> {
    if !epicurus_sensor::privileges::is_elevated() {
        bail!(
            "the engine needs administrator rights (ETW, oplocks on other users' files, containment)"
        );
    }
    epicurus_core::ipc::validate_pipe_name(pipe)?;
    let user_sid = user_sid.or_else(epicurus_sensor::token::current_user_sid);
    let opts = epicurus_service::RuntimeOptions {
        data_dir: data,
        pipe_name: pipe.to_string(),
        session_name,
        profile_root,
        user_sid,
        as_service: false,
    };
    let (tx, rx) = tokio::sync::watch::channel(false);
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let flag = flag.clone();
        std::thread::spawn(move || {
            // Stop when stdin closes or a line is entered (test harness / Ctrl+Z).
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s);
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = tx.send(true);
        });
    }
    println!("Epicurus engine running in the foreground on pipe {pipe}. Press Enter to stop.");
    Ok(epicurus_service::host::run(opts, rx, None)?)
}
