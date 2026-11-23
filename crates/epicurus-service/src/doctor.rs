//! Service-side diagnostics for `epicurus doctor`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use epicurus_core::environment::RealFs;
use epicurus_core::ipc::{CheckStatus, DoctorCheck};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

use crate::engine::{ActiveMode, Engine};

fn check(name: &str, status: CheckStatus, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

/// Security products and tools that commonly interfere with file sensors,
/// ETW sessions or containment, by process image name.
const KNOWN_SOFTWARE: &[(&str, &str)] = &[
    ("csfalconservice.exe", "CrowdStrike Falcon"),
    ("sentinelagent.exe", "SentinelOne"),
    ("cb.exe", "VMware Carbon Black"),
    ("repmgr.exe", "VMware Carbon Black Cloud"),
    ("cyserver.exe", "Palo Alto Cortex XDR"),
    ("elastic-agent.exe", "Elastic Agent"),
    ("elastic-endpoint.exe", "Elastic Defend"),
    ("sysmon64.exe", "Sysmon"),
    ("sysmon.exe", "Sysmon"),
    ("bdservicehost.exe", "Bitdefender"),
    ("avp.exe", "Kaspersky"),
    ("ekrn.exe", "ESET"),
    ("mcshield.exe", "McAfee / Trellix"),
    ("sophoshealth.exe", "Sophos"),
    ("mssense.exe", "Microsoft Defender for Endpoint"),
];

/// Runs every service-side check.
pub fn service_checks(e: &Engine) -> Vec<DoctorCheck> {
    let mut out = Vec::new();

    out.push(match e.mode() {
        ActiveMode::Etw => check("File sensor", CheckStatus::Ok, "Kernel-File ETW (primary)"),
        ActiveMode::Audit => check(
            "File sensor",
            CheckStatus::Warn,
            "Degraded: SACL auditing + Security event 4663",
        ),
        ActiveMode::None => check(
            "File sensor",
            CheckStatus::Fail,
            "No file sensor is running",
        ),
    });

    if let Some(s) = e.etw() {
        match s.query() {
            Some(q) => {
                let st = if q.events_lost + q.realtime_buffers_lost > 0 {
                    CheckStatus::Warn
                } else {
                    CheckStatus::Ok
                };
                out.push(check(
                    "ETW session",
                    st,
                    format!(
                        "\"{}\" running; events lost {}, real-time buffers lost {}, buffers {}; {} events delivered",
                        s.name(),
                        q.events_lost,
                        q.realtime_buffers_lost,
                        q.buffers,
                        s.stats.events.load(Ordering::Relaxed)
                    ),
                ));
            }
            None => out.push(check(
                "ETW session",
                CheckStatus::Fail,
                format!("\"{}\" is not running", s.name()),
            )),
        }
    }

    match e.oplocks() {
        Some(o) => {
            let (armed, rwh, total) = (
                o.stats.armed.load(Ordering::Relaxed),
                o.stats.armed_rwh.load(Ordering::Relaxed),
                o.stats.total.load(Ordering::Relaxed),
            );
            let st = if total == 0 || armed == total {
                CheckStatus::Ok
            } else {
                CheckStatus::Warn
            };
            out.push(check(
                "Oplock tripwire",
                st,
                format!("{armed}/{total} armed ({rwh} exclusive RWH, {} read-handle only); {} breaks so far", armed.saturating_sub(rwh), o.stats.breaks.load(Ordering::Relaxed)),
            ));
        }
        None => out.push(check(
            "Oplock tripwire",
            CheckStatus::Info,
            "disabled in configuration",
        )),
    }

    // Oplock support per volume holding decoys: probe a directory Epicurus
    // created (or, before planting, the profile's local app data) on each.
    let mut probes: BTreeMap<String, PathBuf> = BTreeMap::new();
    for d in &e.manifest().dirs {
        if let Some(vol) = d.path.to_str().and_then(|p| p.get(..2)) {
            probes
                .entry(vol.to_uppercase())
                .or_insert_with(|| d.path.clone());
        }
    }
    if probes.is_empty()
        && let Some(local) = e.env().and_then(|env| env.get("LOCALAPPDATA"))
    {
        probes.insert(
            local.get(..2).unwrap_or("?").to_uppercase(),
            PathBuf::from(local),
        );
    }
    for (vol, dir) in probes.into_iter().filter(|(_, d)| d.is_dir()) {
        out.push(match epicurus_sensor::oplock::probe_volume(&dir) {
            Ok(level) => check(
                "Oplock support",
                CheckStatus::Ok,
                format!("{vol} grants {level} oplocks (probed in {})", dir.display()),
            ),
            Err(err) => check("Oplock support", CheckStatus::Warn, format!("{vol}: {err}")),
        });
    }

    let m = e.manifest();
    let missing = m.entries.iter().filter(|x| !x.path.exists()).count();
    out.push(check(
        "Decoys",
        if m.entries.is_empty() {
            CheckStatus::Fail
        } else if missing > 0 {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        },
        format!("{} planted, {missing} missing", m.entries.len()),
    ));

    if let Some(env) = e.env() {
        let extra = match (e.user_sid(), e.uses_profile_override()) {
            (Some(sid), false) => {
                epicurus_sensor::profile::onedrive_roots(sid, &e.config().install.profile_path)
            }
            _ => Vec::new(),
        };
        let fs = RealFs::detect(env, extra);
        if fs.synced.is_empty() {
            out.push(check("Synced folders", CheckStatus::Ok, "none detected"));
        } else {
            let list: Vec<String> = fs
                .synced
                .iter()
                .map(|r| format!("{:?}: {}", r.provider, r.path.display()))
                .collect();
            out.push(check(
                "Synced folders",
                CheckStatus::Info,
                format!("excluded from planting: {}", list.join("; ")),
            ));
        }
    } else {
        out.push(check(
            "Protected profile",
            CheckStatus::Fail,
            "no user profile configured (run `epicurus install`)",
        ));
    }

    if e.mode() == ActiveMode::Audit {
        match epicurus_sensor::audit::query_file_system_policy() {
            Some(v) if v & 1 != 0 => out.push(check(
                "Audit policy",
                CheckStatus::Ok,
                "File System success auditing enabled",
            )),
            Some(_) => out.push(check(
                "Audit policy",
                CheckStatus::Fail,
                "File System success auditing is off (Group Policy may override it)",
            )),
            None => out.push(check(
                "Audit policy",
                CheckStatus::Warn,
                "could not query audit policy",
            )),
        }
    }

    let running: Vec<String> = epicurus_sensor::process_table::toolhelp()
        .into_iter()
        .map(|(_, _, n)| n.to_lowercase())
        .collect();
    let found: Vec<&str> = KNOWN_SOFTWARE
        .iter()
        .filter(|(img, _)| running.iter().any(|r| r == img))
        .map(|(_, n)| *n)
        .collect();
    out.push(if found.is_empty() {
        check("Other security software", CheckStatus::Ok, "none detected")
    } else {
        check("Other security software", CheckStatus::Info, format!("{} (usually compatible; exclude Epicurus's decoys from their remediation if they quarantine them)", found.join(", ")))
    });
    let cfa = epicurus_sensor::winutil::reg_get_dword(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
        "EnableControlledFolderAccess",
    );
    if cfa == Some(1) {
        out.push(check(
            "Controlled Folder Access",
            CheckStatus::Warn,
            "enabled; planting into Documents may be blocked",
        ));
    }

    out.push(check(
        "Process table",
        CheckStatus::Ok,
        format!("{} processes tracked", e.table_len()),
    ));
    out.push(check(
        "Data directory",
        CheckStatus::Info,
        e.data().root().display().to_string(),
    ));
    for p in e.problems().iter().rev().take(5) {
        out.push(check("Recent problem", CheckStatus::Warn, p.clone()));
    }
    out
}
