//! End-to-end tests with real kernel sensors. They require administrator
//! rights (ETW, auditing, cross-process containment, firewall), so they only
//! build with `--features integration`; GitHub's Windows runners are
//! elevated. Run them serially: `-- --test-threads=1`.
//!
//! * ETW mode: plant into a temporary root, run the simulator, assert an
//!   incident with the simulator's PID and a suspended process, block its
//!   network, kill it, unplant, assert zero decoys remain.
//! * Audit fallback: the same flow attributed through SACLs + Security 4663.
//! * Install lifecycle (only with `EPICURUS_TEST_INSTALL=1`, set on CI's
//!   throwaway runners because it installs a real service and plants into
//!   the real profile): install, simulate, uninstall, assert zero decoys and
//!   zero services remain.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(all(windows, feature = "integration"))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use epicurus_core::incident::{ActionKind, IncidentStatus, IncidentSummary, SensorSource};
use epicurus_core::ipc::{Client, Request, Response};

const EXE: &str = env!("CARGO_BIN_EXE_epicurus");

/// A foreground engine on a private pipe, ETW session and temporary root.
struct Engine {
    child: Child,
    pipe: String,
    session: String,
    home: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Engine {
    fn start(name: &str, config: Option<&str>) -> Self {
        assert!(
            epicurus_sensor::privileges::is_elevated(),
            "integration tests must run elevated"
        );
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        if let Some(cfg) = config {
            std::fs::write(data.join("config.toml"), cfg).unwrap();
        }
        let suffix = format!("{name}-{}", std::process::id());
        let pipe = format!("epicurus-test-{suffix}");
        let session = format!("Epicurus-Test-{suffix}");
        let child = Command::new(EXE)
            .args(["--pipe", &pipe, "--data-dir"])
            .arg(&data)
            .args([
                "service",
                "--foreground",
                "--session-name",
                &session,
                "--profile-root",
            ])
            .arg(&home)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        Self {
            child,
            pipe,
            session,
            home,
            _tmp: tmp,
        }
    }

    fn client(&self) -> Client {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match Client::connect(&self.pipe) {
                Ok(c) => return c,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200))
                }
                Err(e) => panic!("engine did not come up: {e}"),
            }
        }
    }

    fn wait_for_mode(&self, c: &mut Client, mode: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Response::Status(s) = c.call(Request::Status).unwrap()
                && s.sensor.mode == mode
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "sensor mode {mode} did not start"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(stdin) = self.child.stdin.as_mut() {
            let _ = stdin.write_all(b"\n");
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn plant(c: &mut Client) {
    match c
        .call(Request::Plant {
            profile: None,
            dry_run: false,
        })
        .unwrap()
    {
        Response::Plan(p) => {
            assert!(p.errors.is_empty(), "{:?}", p.errors);
            assert!(!p.planned.is_empty());
        }
        other => panic!("{other:?}"),
    }
    // Let oplocks arm and the self-suppression window pass.
    std::thread::sleep(Duration::from_secs(2));
}

/// Kills the simulator when a test fails, so a suspended simulator never
/// outlives the test (it would lock the test binary).
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_simulator(pipe: &str) -> Child {
    Command::new(EXE)
        .args([
            "--pipe",
            pipe,
            epicurus_core::SIMULATOR_FLAG,
            "--linger-secs",
            "90",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_for_contained_incident(c: &mut Client, pid: u32) -> IncidentSummary {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Response::Incidents { items } = c.call(Request::ListIncidents { limit: 20 }).unwrap()
            && let Some(s) = items
                .into_iter()
                .find(|s| s.pid == pid && s.status == IncidentStatus::AwaitingDecision)
        {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "no contained incident for PID {pid}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn kill_unplant_and_verify(engine: Engine, mut c: Client, id: &str, sim: &mut Child) {
    let pid = sim.id();
    match c
        .call(Request::IncidentAction {
            id: id.to_string(),
            action: ActionKind::KillTree,
        })
        .unwrap()
    {
        Response::ActionResult { ok, detail } => assert!(ok, "{detail}"),
        other => panic!("{other:?}"),
    }
    let _ = sim.wait();
    // Late events for the killed process must join its incident, not open
    // a new one (ETW delivers in batches).
    std::thread::sleep(Duration::from_millis(1500));
    match c.call(Request::ListIncidents { limit: 50 }).unwrap() {
        Response::Incidents { items } => assert_eq!(
            items.iter().filter(|s| s.pid == pid).count(),
            1,
            "exactly one incident for the simulator"
        ),
        other => panic!("{other:?}"),
    }
    match c.call(Request::Unplant).unwrap() {
        Response::Unplant(r) => {
            assert!(r.failed.is_empty() && r.kept_modified.is_empty(), "{r:?}")
        }
        other => panic!("{other:?}"),
    }
    drop(c);
    let home = engine.home.clone();
    let session = engine.session.clone();
    drop(engine);
    let left = walk(&home);
    assert!(left.is_empty(), "decoys remain: {left:?}");
    assert!(
        epicurus_sensor::etw::query_session_by_name(&session).is_none(),
        "ETW session stopped"
    );
}

/// The incident once escalation from batched events has settled: three
/// categories seen, or five seconds passed.
fn settled(c: &mut Client, id: &str) -> epicurus_core::incident::Incident {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let i = incident(c, id);
        if i.distinct_categories().len() >= 3 || Instant::now() >= deadline {
            return i;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn incident(c: &mut Client, id: &str) -> epicurus_core::incident::Incident {
    match c.call(Request::GetIncident { id: id.to_string() }).unwrap() {
        Response::Incident { incident } => *incident,
        other => panic!("{other:?}"),
    }
}

#[test]
fn etw_simulator_is_detected_attributed_suspended_and_cleaned_up() {
    let engine = Engine::start("etw", None);
    let mut c = engine.client();
    engine.wait_for_mode(&mut c, "etw");
    plant(&mut c);

    let mut sim = KillOnDrop(spawn_simulator(&engine.pipe));
    let pid = sim.0.id();
    let summary = wait_for_contained_incident(&mut c, pid);
    assert_eq!(summary.pid, pid, "attributed to the simulator's PID");
    assert!(summary.simulated, "tagged as a simulation");
    assert!(
        epicurus_sensor::containment::is_suspended(pid),
        "simulator suspended"
    );
    let full = settled(&mut c, &summary.id);
    assert_eq!(
        full.severity,
        epicurus_core::scoring::Severity::Critical,
        "{:?}",
        full.reasons
    );
    assert!(full.touches.iter().all(|t| t.source == SensorSource::Etw));
    assert!(
        full.distinct_categories().len() >= 3,
        "the whole multi-category sweep was captured: {:?}",
        full.touches
    );

    // Block network: a firewall rule for the image is created, then removed.
    match c
        .call(Request::IncidentAction {
            id: summary.id.clone(),
            action: ActionKind::BlockNetwork,
        })
        .unwrap()
    {
        Response::ActionResult { ok, detail } => {
            assert!(ok, "{detail}");
            let rule = detail.split('"').nth(1).unwrap().to_string();
            assert_eq!(
                epicurus_sensor::firewall::remove_rules(&[rule]),
                1,
                "rule existed"
            );
        }
        other => panic!("{other:?}"),
    }

    kill_unplant_and_verify(engine, c, &summary.id, &mut sim.0);
}

#[test]
fn audit_fallback_attributes_the_simulator() {
    // Auditing is a machine-wide policy: remember it and put it back.
    let previous = epicurus_sensor::audit::query_file_system_policy().unwrap_or(0);
    let engine = Engine::start("audit", Some("[sensor]\nmode = \"audit\"\n"));
    let mut c = engine.client();
    engine.wait_for_mode(&mut c, "audit");
    plant(&mut c);

    let mut sim = KillOnDrop(spawn_simulator(&engine.pipe));
    let pid = sim.0.id();
    let summary = wait_for_contained_incident(&mut c, pid);
    assert_eq!(summary.pid, pid);
    let full = incident(&mut c, &summary.id);
    assert!(
        full.touches.iter().all(|t| t.source == SensorSource::Audit),
        "attributed by Security event 4663"
    );
    assert!(
        full.touches
            .iter()
            .any(|t| t.op == epicurus_core::incident::TouchOp::Read),
        "ReadData access recorded"
    );

    kill_unplant_and_verify(engine, c, &summary.id, &mut sim.0);
    let _ = epicurus_sensor::privileges::enable("SeSecurityPrivilege");
    epicurus_sensor::audit::set_file_system_policy(previous).unwrap();
}

#[test]
fn install_simulate_uninstall_leaves_nothing_behind() {
    if std::env::var("EPICURUS_TEST_INSTALL").as_deref() != Ok("1") {
        eprintln!(
            "skipped: set EPICURUS_TEST_INSTALL=1 (CI only: installs a real service into the real profile)"
        );
        return;
    }
    let run = |args: &[&str]| {
        let out = Command::new(EXE).args(args).output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        println!("$ epicurus {}\n{text}", args.join(" "));
        (out.status.code().unwrap_or(-1), text)
    };

    let (code, _) = run(&["install"]);
    assert_eq!(code, 0, "install failed");
    assert!(matches!(
        epicurus_service::scm::query(),
        epicurus_service::scm::State::Running(_)
    ));

    let mut c = Client::connect(epicurus_core::DEFAULT_PIPE_NAME).unwrap();
    let planted: Vec<PathBuf> = match c.call(Request::GetManifest).unwrap() {
        Response::Manifest(m) => m.entries.into_iter().map(|e| e.path).collect(),
        other => panic!("{other:?}"),
    };
    assert!(!planted.is_empty());
    assert!(planted.iter().all(|p| p.exists()));
    drop(c);
    std::thread::sleep(Duration::from_secs(2));

    let (code, text) = run(&["simulate"]);
    assert_eq!(code, 0, "simulate failed");
    assert!(text.contains("(matches the simulator)"), "attribution");
    assert!(text.contains("Severity:     critical"), "critical severity");
    assert!(
        text.contains("process suspended: yes (verified)"),
        "suspension"
    );

    let (code, _) = run(&["uninstall"]);
    assert_eq!(code, 0, "uninstall failed");
    assert_eq!(
        epicurus_service::scm::query(),
        epicurus_service::scm::State::NotInstalled,
        "service removed"
    );
    let left: Vec<_> = planted.iter().filter(|p| p.exists()).collect();
    assert!(left.is_empty(), "decoys remain: {left:?}");
    assert!(
        !epicurus_core::paths::DataDir::system().root().exists(),
        "data directory removed"
    );
    let programs = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    assert!(
        !Path::new(&programs).join("Epicurus").exists(),
        "install directory removed"
    );
}
