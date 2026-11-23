//! Engine pipeline without kernel sensors: plant into a temporary profile,
//! feed the engine decoy-open events from a real child process, and check
//! attribution, scoring, suspension, user actions and clean removal.
//! Runs without administrator rights (we may suspend our own child).

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(windows)]

use std::time::Duration;

use epicurus_core::incident::{ActionKind, IncidentStatus, SensorSource};
use epicurus_core::ipc::{Request, Response};
use epicurus_core::paths::DataDir;
use epicurus_sensor::events::SensorEvent;
use epicurus_service::RuntimeOptions;
use epicurus_service::engine::{Engine, Outcome};

fn ok(o: Outcome) -> Response {
    match o {
        Outcome::Ready(r) => match *r {
            Ok(r) => r,
            Err(e) => panic!("request failed: {e:?}"),
        },
        Outcome::AwaitTest(_) => panic!("unexpected async outcome"),
    }
}

#[test]
fn touch_sweep_becomes_a_contained_incident_and_unplant_leaves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let opts = RuntimeOptions {
        data_dir: DataDir::new(tmp.path().join("data")),
        pipe_name: "unused".into(),
        session_name: None,
        profile_root: Some(home.clone()),
        user_sid: epicurus_sensor::token::current_user_sid(),
        as_service: false,
    };
    let (sensor_tx, _sensor_rx) = std::sync::mpsc::channel();
    let (alerts_tx, _alerts_rx) = tokio::sync::mpsc::unbounded_channel();
    let (events_tx, mut events_rx) = tokio::sync::broadcast::channel(64);
    let mut engine = Engine::new(opts, sensor_tx, alerts_tx, events_tx).unwrap();

    // Plant.
    let plan = match ok(engine.handle(
        Request::Plant {
            profile: None,
            dry_run: false,
        },
        None,
    )) {
        Response::Plan(p) => p,
        other => panic!("{other:?}"),
    };
    assert!(plan.errors.is_empty(), "{:?}", plan.errors);
    assert!(plan.planned.len() >= 20, "planted {}", plan.planned.len());
    let manifest = match ok(engine.handle(Request::GetManifest, None)) {
        Response::Manifest(m) => m,
        other => panic!("{other:?}"),
    };
    assert!(manifest.entries.iter().all(|e| e.path.starts_with(&home)));

    // A stand-in "stealer": a real child process that idles.
    let mut child = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
        .spawn()
        .unwrap();
    let pid = child.id();
    std::thread::sleep(Duration::from_millis(800));

    // It sweeps decoys in three categories within a second.
    let mut by_cat = std::collections::BTreeMap::new();
    for e in &manifest.entries {
        by_cat.entry(e.category).or_insert(e.path.clone());
    }
    assert!(by_cat.len() >= 3);
    for path in by_cat.values().take(3) {
        engine.on_sensor_event(
            SensorEvent::DecoyOpen {
                at: time::OffsetDateTime::now_utc(),
                pid,
                path: path.to_string_lossy().into_owned(),
                read_data: false,
                source: SensorSource::Etw,
                image_hint: None,
            },
            None,
        );
    }

    let list = match ok(engine.handle(Request::ListIncidents { limit: 10 }, None)) {
        Response::Incidents { items } => items,
        other => panic!("{other:?}"),
    };
    assert_eq!(list.len(), 1, "one process, one incident");
    let inc = &list[0];
    assert_eq!(inc.pid, pid, "attributed to the right PID");
    assert_eq!(inc.decoys, 3);
    assert_eq!(
        inc.severity,
        epicurus_core::scoring::Severity::Critical,
        "a three-category sweep is critical"
    );
    assert_eq!(inc.status, IncidentStatus::AwaitingDecision);
    assert!(
        epicurus_sensor::containment::is_suspended(pid),
        "the process tree is suspended"
    );

    // The incident was pushed to subscribers (the tray agent).
    let mut saw_push = false;
    while let Ok(ev) = events_rx.try_recv() {
        if matches!(ev, epicurus_core::ipc::Event::Incident { .. }) {
            saw_push = true;
        }
    }
    assert!(saw_push);

    // Exports render.
    let full = match ok(engine.handle(Request::GetIncident { id: inc.id.clone() }, None)) {
        Response::Incident { incident } => *incident,
        other => panic!("{other:?}"),
    };
    assert!(full.reasons.iter().any(|r| r.code == "category_sweep"));
    let out = tmp.path().join("exports");
    assert_eq!(
        epicurus_core::report::export_all(&full, &out)
            .unwrap()
            .len(),
        3
    );

    // User decides: kill the tree.
    match ok(engine.handle(
        Request::IncidentAction {
            id: inc.id.clone(),
            action: ActionKind::KillTree,
        },
        None,
    )) {
        Response::ActionResult { ok, detail } => assert!(ok, "{detail}"),
        other => panic!("{other:?}"),
    }
    let status = child.wait_timeout_like(Duration::from_secs(5));
    assert!(status, "child terminated");

    // Unplant: zero decoys remain anywhere under the temporary profile.
    match ok(engine.handle(Request::Unplant, None)) {
        Response::Unplant(r) => assert!(r.kept_modified.is_empty() && r.failed.is_empty(), "{r:?}"),
        other => panic!("{other:?}"),
    }
    let leftover: Vec<_> = walk(&home);
    assert!(leftover.is_empty(), "files left behind: {leftover:?}");
    assert!(
        std::fs::read_dir(&home).unwrap().next().is_none(),
        "every created directory was removed"
    );
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
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

trait WaitTimeout {
    fn wait_timeout_like(&mut self, d: Duration) -> bool;
}

impl WaitTimeout for std::process::Child {
    fn wait_timeout_like(&mut self, d: Duration) -> bool {
        let deadline = std::time::Instant::now() + d;
        while std::time::Instant::now() < deadline {
            if let Ok(Some(_)) = self.try_wait() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.kill();
        false
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    engine: Engine,
    alerts: tokio::sync::mpsc::UnboundedReceiver<epicurus_service::alerts::AlertJob>,
}

/// Engine over a temporary profile with the default decoys planted.
fn planted_engine() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let opts = RuntimeOptions {
        data_dir: DataDir::new(tmp.path().join("data")),
        pipe_name: "unused".into(),
        session_name: None,
        profile_root: Some(home),
        user_sid: epicurus_sensor::token::current_user_sid(),
        as_service: false,
    };
    let (sensor_tx, _sensor_rx) = std::sync::mpsc::channel();
    let (alerts_tx, alerts_rx) = tokio::sync::mpsc::unbounded_channel();
    let (events_tx, _) = tokio::sync::broadcast::channel(64);
    let mut engine = Engine::new(opts, sensor_tx, alerts_tx, events_tx).unwrap();
    match ok(engine.handle(
        Request::Plant {
            profile: None,
            dry_run: false,
        },
        None,
    )) {
        Response::Plan(p) => assert!(p.errors.is_empty() && !p.planned.is_empty()),
        other => panic!("{other:?}"),
    }
    Fixture {
        _tmp: tmp,
        engine,
        alerts: alerts_rx,
    }
}

fn manifest(engine: &mut Engine) -> epicurus_core::ipc::ManifestView {
    match ok(engine.handle(Request::GetManifest, None)) {
        Response::Manifest(m) => m,
        other => panic!("{other:?}"),
    }
}

fn activity(engine: &mut Engine) -> epicurus_core::ipc::ActivityView {
    match ok(engine.handle(Request::Activity { hours: 1 }, None)) {
        Response::Activity(a) => a,
        other => panic!("{other:?}"),
    }
}

#[test]
fn allowlisted_touch_is_logged_but_never_becomes_an_incident() {
    let mut f = planted_engine();
    let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let ps = std::path::Path::new(&system).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let sha = epicurus_core::manifest::sha256_file(&ps).unwrap();
    let entry = epicurus_core::allowlist::AllowEntry {
        name: "test: PowerShell by hash".into(),
        signers: vec![],
        path: String::new(),
        sha256: Some(sha),
    };
    assert!(matches!(
        ok(f.engine.handle(
            Request::SetAllowlist {
                entries: vec![entry]
            },
            None
        )),
        Response::Ack
    ));

    let mut child = std::process::Command::new(&ps)
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(800));
    let m = manifest(&mut f.engine);
    for e in m.entries.iter().take(4) {
        f.engine.on_sensor_event(
            SensorEvent::DecoyOpen {
                at: time::OffsetDateTime::now_utc(),
                pid: child.id(),
                path: e.path.to_string_lossy().into_owned(),
                read_data: false,
                source: SensorSource::Etw,
                image_hint: None,
            },
            None,
        );
    }
    let incidents = match ok(f.engine.handle(Request::ListIncidents { limit: 10 }, None)) {
        Response::Incidents { items } => items,
        other => panic!("{other:?}"),
    };
    assert!(
        incidents.is_empty(),
        "allowlisted process must not raise an incident"
    );
    assert!(
        !epicurus_sensor::containment::is_suspended(child.id()),
        "and must not be suspended"
    );
    let a = activity(&mut f.engine);
    let allowed: Vec<_> = a
        .touches
        .iter()
        .filter(|t| t.disposition == "allowlisted")
        .collect();
    assert_eq!(allowed.len(), 4, "every touch is logged");
    assert!(allowed.iter().all(|t| t.note == "test: PowerShell by hash"));
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn deleted_decoy_is_logged_alerted_and_replanted_in_place() {
    let mut f = planted_engine();
    let m = manifest(&mut f.engine);
    let victim = m
        .entries
        .iter()
        .find(|e| e.decoy_id == "aws-credentials")
        .unwrap()
        .path
        .clone();
    let before = m.entries.len();

    // A stealer deletes what it took.
    std::fs::remove_file(&victim).unwrap();
    f.engine.on_sensor_event(
        SensorEvent::Integrity {
            at: time::OffsetDateTime::now_utc(),
            path: victim.to_string_lossy().into_owned(),
            change: epicurus_sensor::events::IntegrityChange::Removed,
        },
        None,
    );
    assert_eq!(
        manifest(&mut f.engine).entries.len(),
        before - 1,
        "gone from the manifest"
    );
    assert!(
        activity(&mut f.engine)
            .events
            .iter()
            .any(|e| e.kind == "integrity" && e.message.contains("deleted")),
        "integrity change is logged"
    );
    // An integrity alert was queued for the webhook channels.
    let job = f.alerts.try_recv().expect("alert queued");
    assert!(matches!(
        job,
        epicurus_service::alerts::AlertJob::Send {
            body: epicurus_service::alerts::AlertBody::Integrity { .. },
            ..
        }
    ));

    // Re-plant happens after a short quiet period.
    std::thread::sleep(Duration::from_millis(2200));
    f.engine.tick();
    assert!(victim.exists(), "re-planted at the same path");
    assert_eq!(manifest(&mut f.engine).entries.len(), before);
    assert!(
        activity(&mut f.engine)
            .events
            .iter()
            .any(|e| e.kind == "replant")
    );
}

#[test]
fn modified_decoy_is_left_alone_and_replaced_elsewhere() {
    let mut f = planted_engine();
    let m = manifest(&mut f.engine);
    let victim = m
        .entries
        .iter()
        .find(|e| e.decoy_id == "npmrc")
        .unwrap()
        .path
        .clone();
    std::fs::write(&victim, b"tampered by someone").unwrap();
    f.engine.on_sensor_event(
        SensorEvent::Integrity {
            at: time::OffsetDateTime::now_utc(),
            path: victim.to_string_lossy().into_owned(),
            change: epicurus_sensor::events::IntegrityChange::Modified,
        },
        None,
    );
    std::thread::sleep(Duration::from_millis(2200));
    f.engine.tick();
    // The modified file is no longer ours: never overwritten or deleted.
    assert_eq!(std::fs::read(&victim).unwrap(), b"tampered by someone");
    let after = manifest(&mut f.engine);
    let replacement = after
        .entries
        .iter()
        .find(|e| e.decoy_id == "npmrc")
        .expect("re-planted");
    assert_ne!(replacement.path, victim, "re-planted at an alternate path");
    // Unplant removes our replacement but keeps the foreign file.
    let _ = ok(f.engine.handle(Request::Unplant, None));
    assert!(victim.exists());
    assert!(!replacement.path.exists());
}

#[test]
fn event_ids_are_documented_and_covered_by_the_message_table() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let doc = std::fs::read_to_string(root.join("docs/event-ids.md")).unwrap();
    let build_rs = std::fs::read_to_string(root.join("crates/epicurus-cli/build.rs")).unwrap();
    let ranges = [(1000u32, 1099u32), (2000, 2099), (3000, 3099), (9000, 9009)];
    assert!(
        build_rs.contains("&[(1000, 1099), (2000, 2099), (3000, 3099), (9000, 9009)]"),
        "build.rs message-table ranges changed; update this test and docs/event-ids.md"
    );
    for id in epicurus_service::eventlog::ALL_IDS {
        assert!(
            doc.contains(&format!("| {id} |")),
            "event {id} missing from docs/event-ids.md"
        );
        assert!(
            ranges.iter().any(|(lo, hi)| (lo..=hi).contains(&id)),
            "event {id} outside the message table"
        );
    }
}
