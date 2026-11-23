//! `epicurus install` and `epicurus uninstall`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use epicurus_core::config::Config;
use epicurus_core::ipc::{Request, Response};
use epicurus_core::paths::DataDir;
use epicurus_core::storage::Store;
use epicurus_sensor::security::{DATA_DIR_SDDL, INSTALL_DIR_SDDL, apply_sddl};
use epicurus_service::scm;

use crate::commands::{connect, print_plan};
use crate::elevate::{self, Out};

fn install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("Epicurus")
}

/// Relaunches elevated if needed. Returns `Some(exit code)` when this
/// process was the non-elevated parent.
fn ensure_elevated(args: Vec<String>) -> anyhow::Result<Option<u8>> {
    if epicurus_sensor::privileges::is_elevated() {
        return Ok(None);
    }
    let report = elevate::report_path();
    let mut full = args;
    full.push("--report".into());
    full.push(report.to_string_lossy().into_owned());
    Ok(Some(elevate::relaunch(&full, &report)?))
}

/// `epicurus install`.
pub fn install(
    pipe: &str,
    data: &DataDir,
    profile: Option<String>,
    no_plant: bool,
    user_sid: Option<String>,
    report: Option<PathBuf>,
) -> anyhow::Result<u8> {
    if !epicurus_sensor::privileges::is_elevated() {
        // Capture who is installing *before* elevating: with over-the-shoulder
        // elevation the elevated token belongs to a different account.
        let sid = epicurus_sensor::token::current_user_sid()
            .context("could not determine the current user")?;
        let mut args = vec!["install".to_string(), "--user-sid".into(), sid];
        if let Some(p) = &profile {
            args.push("--profile".into());
            args.push(p.clone());
        }
        if no_plant {
            args.push("--no-plant".into());
        }
        if let Some(code) = ensure_elevated(args)? {
            return Ok(code);
        }
    }
    let mut out = Out::new(report.as_deref());
    let r = install_elevated(pipe, data, profile, no_plant, user_sid, &mut out);
    if let Err(e) = &r {
        out.line(format!("error: {e:#}"));
    }
    r
}

fn install_elevated(
    pipe: &str,
    data: &DataDir,
    profile: Option<String>,
    no_plant: bool,
    user_sid: Option<String>,
    out: &mut Out,
) -> anyhow::Result<u8> {
    let sid = match user_sid {
        Some(s) => s,
        None => epicurus_sensor::token::current_user_sid()
            .context("could not determine the current user")?,
    };
    if !epicurus_sensor::profile::is_valid_sid_string(&sid) {
        bail!("invalid user SID {sid:?}");
    }
    let prof = epicurus_sensor::profile::lookup(&sid)
        .with_context(|| format!("no user profile found for {sid}"))?;
    out.line(format!(
        "Protecting the profile of {sid} at {}",
        prof.profile.display()
    ));
    let _ =
        epicurus_sensor::privileges::enable_all(epicurus_sensor::privileges::SERVICE_PRIVILEGES);

    // 1. Install the binary where only administrators can write: a service
    //    binary in a user-writable folder would be a privilege escalation.
    let dir = install_dir();
    let target = dir.join("epicurus.exe");
    let current = std::env::current_exe()?;
    if matches!(scm::query(), scm::State::Running(_) | scm::State::Pending) {
        out.line("Stopping the running service for the upgrade...");
        let _ = scm::stop();
    }
    std::fs::create_dir_all(&dir)?;
    if !same_file(&current, &target) {
        copy_with_retry(&current, &target)?;
    }
    apply_sddl(&dir, INSTALL_DIR_SDDL, true)?;
    out.line(format!("Installed {}", target.display()));

    // 2. Data directory with a tight ACL (SYSTEM and Administrators only).
    std::fs::create_dir_all(data.root())?;
    apply_sddl(data.root(), DATA_DIR_SDDL, true)?;
    for d in [data.logs(), data.quarantine(), data.catalog_d()] {
        std::fs::create_dir_all(d)?;
    }
    out.line(format!("Data directory {}", data.root().display()));

    // 3. Config with install facts.
    let mut cfg = Config::load(&data.config_file())?;
    cfg.install.user_sid = sid.clone();
    cfg.install.profile_path = prof.profile.to_string_lossy().into_owned();
    cfg.install.appdata = prof.appdata.map(|p| p.to_string_lossy().into_owned());
    cfg.install.localappdata = prof.localappdata.map(|p| p.to_string_lossy().into_owned());
    cfg.install.install_dir = dir.to_string_lossy().into_owned();
    if let Some(p) = profile {
        cfg.protection.profile = p;
    }
    cfg.save(&data.config_file())?;
    // Initialize the database (and the per-install seed) now.
    Store::open(&data.database())?.install_seed()?;

    // 4. Event Log source and Start Menu shortcut (toast AppUserModelID).
    scm::register_event_source(&target)?;
    match crate::shortcut::create(&target) {
        Ok(p) => out.line(format!("Start Menu shortcut {}", p.display())),
        Err(e) => out.line(format!(
            "warning: could not create the Start Menu shortcut ({e}); toasts may not appear"
        )),
    }

    // 5. Service.
    scm::install(&target)?;
    scm::start()?;
    out.line("Service installed and running.");

    // 6. Plant through the service so its sensors pick the decoys up at once.
    if !no_plant {
        let mut planted = None;
        for _ in 0..40 {
            if let Ok(mut c) = connect(pipe)
                && let Ok(Response::Plan(p)) = c.call(Request::Plant {
                    profile: None,
                    dry_run: false,
                })
            {
                planted = Some(p);
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        match planted {
            Some(p) => print_plan(&p, false, &mut |l| out.line(l)),
            None => {
                out.line("warning: the service did not answer; run `epicurus plant` once it is up")
            }
        }
    }
    out.line("");
    out.line("Epicurus is protecting this machine.");
    out.line("  epicurus status     protection state and sensor health");
    out.line("  epicurus simulate   verify detection end to end");
    out.line("  epicurus ui         open the dashboard");
    Ok(0)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn copy_with_retry(from: &Path, to: &Path) -> anyhow::Result<()> {
    let mut last = None;
    for _ in 0..20 {
        match std::fs::copy(from, to) {
            Ok(_) => return Ok(()),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(anyhow::anyhow!(
        "copying to {}: {}",
        to.display(),
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Terminates other Epicurus processes running from `exe` (tray agents,
/// dashboards) so the binary can be removed.
fn stop_other_instances(exe: &Path) {
    let me = std::process::id();
    let target = exe.to_string_lossy().to_lowercase();
    for (pid, _, _) in epicurus_sensor::process_table::toolhelp() {
        if pid == me {
            continue;
        }
        let Some(h) = epicurus_sensor::process_table::open_limited(pid) else {
            continue;
        };
        if epicurus_sensor::process_table::image_path(h.raw())
            .is_some_and(|p| p.to_lowercase() == target)
        {
            drop(h);
            let _ =
                epicurus_sensor::containment::kill_tree(epicurus_sensor::containment::ProcKey {
                    pid,
                    create_time: None,
                });
        }
    }
}

/// `epicurus uninstall`.
pub fn uninstall(
    pipe: &str,
    data: &DataDir,
    keep_data: bool,
    report: Option<PathBuf>,
) -> anyhow::Result<u8> {
    let mut args = vec!["uninstall".to_string()];
    if keep_data {
        args.push("--keep-data".into());
    }
    if let Some(code) = ensure_elevated(args)? {
        return Ok(code);
    }
    let mut out = Out::new(report.as_deref());
    let r = uninstall_elevated(pipe, data, keep_data, &mut out);
    if let Err(e) = &r {
        out.line(format!("error: {e:#}"));
    }
    r
}

fn uninstall_elevated(
    pipe: &str,
    data: &DataDir,
    keep_data: bool,
    out: &mut Out,
) -> anyhow::Result<u8> {
    // Read who was protected before the data directory goes away.
    let protected_sid = Config::load(&data.config_file())
        .map(|c| c.install.user_sid)
        .unwrap_or_default();

    // 1. Remove decoys. Prefer the service: it releases its oplock and
    //    directory handles and stops watching before deleting.
    let mut removed_by_service = false;
    if let Ok(mut c) = connect(pipe)
        && let Ok(Response::Unplant(r)) = c.call(Request::Unplant)
    {
        out.line(format!("Removed {} decoy file(s).", r.removed.len()));
        for p in &r.kept_modified {
            out.line(format!(
                "  kept (modified since planting, not ours to delete): {}",
                p.display()
            ));
        }
        removed_by_service = true;
    }

    // 2. Service.
    if scm::query() != scm::State::NotInstalled {
        scm::uninstall()?;
        out.line("Service removed.");
    }

    // 3. Anything left in the manifest (service was not running), firewall
    //    rules we created, and the audit policy we may have changed.
    let mut remaining = 0usize;
    if data.database().exists() {
        let mut store = Store::open(&data.database())?;
        if !removed_by_service {
            let r = epicurus_core::plant::unplant(&store.manifest()?);
            store.remove_from_manifest(r.forgettable())?;
            store.remove_dirs(r.dirs_removed.iter())?;
            out.line(format!("Removed {} decoy file(s).", r.removed.len()));
            for p in &r.kept_modified {
                out.line(format!(
                    "  kept (modified since planting, not ours to delete): {}",
                    p.display()
                ));
            }
        } else {
            // Directories may remain if the service removed files while a
            // directory handle was still open; clean those up now.
            let m = store.manifest()?;
            let r = epicurus_core::plant::unplant(&epicurus_core::manifest::Manifest {
                entries: Vec::new(),
                dirs: m.dirs,
            });
            store.remove_dirs(r.dirs_removed.iter())?;
        }
        let m = store.manifest()?;
        remaining = m.entries.iter().filter(|e| e.path.exists()).count();
        if let Some(rules) = store
            .kv_get("firewall_rules")?
            .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
        {
            let n = epicurus_sensor::firewall::remove_rules(&rules);
            if n > 0 {
                out.line(format!("Removed {n} firewall rule(s)."));
            }
        }
        if let Some(prev) = store
            .kv_get("audit_policy_prev")?
            .and_then(|v| v.parse::<u32>().ok())
        {
            let _ = epicurus_sensor::privileges::enable("SeSecurityPrivilege");
            if epicurus_sensor::audit::set_file_system_policy(prev).is_ok() {
                out.line("Restored the File System audit policy.");
            }
        }
    }

    // 4. Shortcut, Event Log source, other processes, binary.
    if crate::shortcut::remove() {
        out.line("Start Menu shortcut removed.");
    }
    if !protected_sid.is_empty() && crate::shortcut::remove_aumid(&protected_sid) {
        out.line("Toast registration removed.");
    }
    scm::unregister_event_source();
    let dir = install_dir();
    stop_other_instances(&dir.join("epicurus.exe"));

    // 5. Data.
    if keep_data {
        out.line(format!("Kept {}", data.root().display()));
    } else if data.root().exists() {
        std::fs::remove_dir_all(data.root())
            .with_context(|| format!("removing {}", data.root().display()))?;
        out.line(format!("Removed {}", data.root().display()));
    }

    // 6. Install directory. If we are running from it, delete after exit.
    if dir.exists() {
        let running_from_it = std::env::current_exe()
            .map(|e| e.starts_with(&dir))
            .unwrap_or(false);
        if running_from_it {
            use std::os::windows::process::CommandExt;
            let cmd = format!(
                "ping 127.0.0.1 -n 3 >nul & rmdir /s /q \"{}\"",
                dir.display()
            );
            let _ = std::process::Command::new("cmd.exe")
                .args(["/c", &cmd])
                .creation_flags(0x0800_0000 | 0x0000_0008)
                .spawn();
            out.line(format!(
                "{} will be removed in a few seconds.",
                dir.display()
            ));
        } else if std::fs::remove_dir_all(&dir).is_ok() {
            out.line(format!("Removed {}", dir.display()));
        }
    }
    if remaining == 0 {
        out.line("Uninstall complete: no decoys and no service remain.");
        Ok(0)
    } else {
        out.line(format!("Uninstall complete, but {remaining} modified decoy file(s) were left in place (see above)."));
        Ok(2)
    }
}
