//! `epicurus simulate`: a harmless stealer simulation that verifies
//! detection end to end.
//!
//! The parent launches a child (this same executable with a hidden flag).
//! The child asks the service for Epicurus's own manifest, reads a handful of
//! decoys across several categories the way a stealer sweep would, then
//! lingers like a stealer packaging its loot. It reads only manifest paths,
//! never real files, and transmits nothing. The engine recognizes the image
//! and flag and tags the incident as simulated.

use std::collections::BTreeSet;
use std::os::windows::process::CommandExt;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use epicurus_core::catalog::Category;
use epicurus_core::incident::{ActionKind, IncidentStatus};
use epicurus_core::ipc::{Request, Response};

use crate::commands::connect;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_FILES: usize = 6;

/// Child: sweep decoys from the manifest, then linger.
pub fn child(pipe: &str, linger_secs: u64) -> anyhow::Result<()> {
    let manifest = match connect(pipe)?.call(Request::GetManifest)? {
        Response::Manifest(m) => m,
        other => bail!("unexpected reply {other:?}"),
    };
    // One decoy per category first (a sweep across categories is what a real
    // stealer does), then more up to MAX_FILES.
    let mut chosen = Vec::new();
    let mut seen: BTreeSet<Category> = BTreeSet::new();
    for e in manifest.entries.iter().filter(|e| e.path.is_file()) {
        if seen.insert(e.category) {
            chosen.push(e.path.clone());
        }
    }
    for e in manifest.entries.iter().filter(|e| e.path.is_file()) {
        if chosen.len() >= MAX_FILES {
            break;
        }
        if !chosen.contains(&e.path) {
            chosen.push(e.path.clone());
        }
    }
    chosen.truncate(MAX_FILES);
    // Sweep with parallel workers, as many stealers do: a barrier releases
    // every worker at once, so all opens are issued within microseconds.
    // Epicurus contains a sequential sweep after the first file or two (the
    // first open breaks an oplock and flushes ETW); a parallel sweep shows
    // the full multi-category picture in the incident.
    let barrier = std::sync::Barrier::new(chosen.len());
    std::thread::scope(|s| {
        for p in &chosen {
            let barrier = &barrier;
            s.spawn(move || {
                barrier.wait();
                // Read and discard. The content is a decoy; nothing leaves memory.
                if let Ok(bytes) = std::fs::read(p) {
                    std::hint::black_box(bytes.len());
                }
            });
        }
    });
    std::thread::sleep(Duration::from_secs(linger_secs.min(600)));
    Ok(())
}

/// Parent: launch the child and report what Epicurus did about it.
pub fn parent(pipe: &str, linger_secs: u64, keep: bool) -> anyhow::Result<u8> {
    let status = match connect(pipe)
        .context("the Epicurus service must be running (epicurus install)")?
        .call(Request::Status)?
    {
        Response::Status(s) => s,
        other => bail!("unexpected reply {other:?}"),
    };
    if status.decoys_planted == 0 {
        bail!("no decoys are planted; run `epicurus plant` first");
    }
    let exe = std::env::current_exe()?;
    let mut child = std::process::Command::new(exe)
        .args([
            "--pipe",
            pipe,
            epicurus_core::SIMULATOR_FLAG,
            "--linger-secs",
            &linger_secs.to_string(),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let pid = child.id();
    println!(
        "Started simulated stealer (PID {pid}). It reads up to {MAX_FILES} decoys from Epicurus's manifest and transmits nothing."
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut found = None;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        let Ok(mut c) = connect(pipe) else { continue };
        if let Ok(Response::Incidents { items }) = c.call(Request::ListIncidents { limit: 20 })
            && let Some(s) = items.into_iter().find(|s| s.pid == pid)
        {
            let settled = s.status == IncidentStatus::AwaitingDecision
                || s.severity == epicurus_core::scoring::Severity::Critical;
            found = Some(s.id.clone());
            if settled {
                break;
            }
        }
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
    }
    let Some(id) = found else {
        println!("No incident was raised for PID {pid} within 30 s. Run `epicurus doctor`.");
        let _ = child.kill();
        return Ok(1);
    };
    // Give escalation a moment to finish (the sweep takes ~2 s).
    std::thread::sleep(Duration::from_secs(2));
    let inc = match connect(pipe)?.call(Request::GetIncident { id: id.clone() })? {
        Response::Incident { incident } => *incident,
        other => bail!("unexpected reply {other:?}"),
    };
    let suspended = epicurus_sensor::containment::is_suspended(pid);
    println!();
    println!(
        "Incident:     {}{}",
        inc.id,
        if inc.simulated {
            " (tagged as simulation)"
        } else {
            ""
        }
    );
    println!("Severity:     {} ({}/100)", inc.severity, inc.score);
    println!(
        "Attribution:  PID {} {}",
        inc.process.pid,
        if inc.process.pid == pid {
            "(matches the simulator)"
        } else {
            "(DOES NOT MATCH)"
        }
    );
    println!(
        "Decoys:       {} touched across {} categories",
        inc.distinct_decoys(),
        inc.distinct_categories().len()
    );
    println!(
        "Containment:  {:?}; process suspended: {}",
        inc.status,
        if suspended { "yes (verified)" } else { "no" }
    );
    println!("Why:");
    for r in inc.reasons.iter().filter(|r| r.points != 0) {
        println!("  {:+4}  {}", r.points, r.detail);
    }
    if keep {
        println!(
            "\nThe simulated process is left as is. Decide from the dashboard (`epicurus ui`) or the toast."
        );
    } else {
        let _ = connect(pipe)?.call(Request::IncidentAction {
            id: inc.id.clone(),
            action: ActionKind::KillTree,
        });
        let _ = child.kill();
        println!("\nCleaned up: the simulated process tree was killed.");
    }
    let _ = child.wait();
    Ok(if inc.process.pid == pid { 0 } else { 1 })
}
