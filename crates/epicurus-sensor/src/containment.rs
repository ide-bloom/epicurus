//! Containment: suspend, resume or kill a process tree, quarantine an
//! image, block its network access and (optionally) take a minidump.
//!
//! Critical and protected processes are never touched: System, smss, csrss,
//! wininit, services, lsass (plus winlogon and our own process), and any
//! process running as a Protected Process (Light). For those Epicurus only
//! alerts.

use std::path::{Path, PathBuf};

use windows::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    MOVEFILE_COPY_ALLOWED, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows::Win32::System::Diagnostics::Debug::{
    MINIDUMP_TYPE, MiniDumpWithDataSegs, MiniDumpWithFullMemoryInfo, MiniDumpWithHandleData,
    MiniDumpWithThreadInfo, MiniDumpWithUnloadedModules, MiniDumpWriteDump,
};
use windows::Win32::System::Threading::{
    GetProcessInformation, IsProcessCritical, OpenProcess, PROCESS_PROTECTION_LEVEL_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE, PROCESS_VM_READ, ProcessProtectionLevelInfo, TerminateProcess,
    WaitForSingleObject,
};
use windows::core::PCWSTR;

use crate::error::{Result, SensorError};
use crate::process_table::{creation_time, open_limited, toolhelp};
use crate::winutil::{OwnedHandle, wide};

mod nt {
    use windows::Win32::Foundation::HANDLE;
    windows::core::link!("ntdll.dll" "system" fn NtSuspendProcess(processhandle: HANDLE) -> i32);
    windows::core::link!("ntdll.dll" "system" fn NtResumeProcess(processhandle: HANDLE) -> i32);
}

/// Image names that are never contained.
pub const CRITICAL_IMAGES: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "registry",
    "memory compression",
    "secure system",
    "lsaiso.exe",
];

const PROTECTION_LEVEL_NONE: u32 = 0xFFFF_FFFE;

/// True if a process must never be suspended or killed.
pub fn is_protected(pid: u32, image: &str) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }
    let name = image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_lowercase();
    if CRITICAL_IMAGES.contains(&name.as_str()) {
        return true;
    }
    let Some(h) = open_limited(pid) else {
        // If we cannot even query it, we will not be able to contain it either.
        return false;
    };
    let mut info = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
    // SAFETY: info buffer matches the class.
    let ppl = unsafe {
        GetProcessInformation(
            h.raw(),
            ProcessProtectionLevelInfo,
            (&mut info as *mut PROCESS_PROTECTION_LEVEL_INFORMATION).cast(),
            std::mem::size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
        )
    }
    .is_ok()
        && info.ProtectionLevel.0 != PROTECTION_LEVEL_NONE;
    if ppl {
        return true;
    }
    let mut critical = windows::core::BOOL(0);
    // SAFETY: out-parameter.
    unsafe { IsProcessCritical(h.raw(), &mut critical) }.is_ok() && critical.as_bool()
}

/// A process identified by PID and creation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcKey {
    /// PID.
    pub pid: u32,
    /// Creation time (None if unknown).
    pub create_time: Option<time::OffsetDateTime>,
}

fn open_checked(
    key: ProcKey,
    access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
) -> Result<OwnedHandle> {
    // SAFETY: plain open; handle owned.
    let h = unsafe { OpenProcess(access | PROCESS_QUERY_LIMITED_INFORMATION, false, key.pid) }
        .map_err(|e| SensorError::from_win(format!("OpenProcess({})", key.pid), &e))?;
    let h = OwnedHandle(h);
    // Refuse to act on a recycled PID.
    if let (Some(want), Some(have)) = (key.create_time, creation_time(h.raw()))
        && (want - have).abs() > time::Duration::milliseconds(50)
    {
        return Err(SensorError::Refused(format!(
            "PID {} now belongs to a different process",
            key.pid
        )));
    }
    Ok(h)
}

/// The tree rooted at `root`: the root first, then live descendants found in
/// a fresh Toolhelp snapshot (children must be younger than their parent).
pub fn process_tree(root: ProcKey) -> Vec<ProcKey> {
    let snap = toolhelp();
    let mut out = vec![root];
    let mut i = 0;
    while i < out.len() && out.len() < 256 {
        let parent = out[i];
        for (pid, ppid, _) in &snap {
            if *ppid != parent.pid || *pid == parent.pid || out.iter().any(|k| k.pid == *pid) {
                continue;
            }
            let ct = open_limited(*pid).and_then(|h| creation_time(h.raw()));
            let younger = match (ct, parent.create_time) {
                (Some(c), Some(p)) => c >= p,
                _ => true,
            };
            if younger {
                out.push(ProcKey {
                    pid: *pid,
                    create_time: ct,
                });
            }
        }
        i += 1;
    }
    out
}

fn image_of(pid: u32) -> String {
    open_limited(pid)
        .and_then(|h| crate::process_table::image_path(h.raw()))
        .unwrap_or_default()
}

/// Outcome per process.
#[derive(Debug, Clone)]
pub struct TreeResult {
    /// PIDs acted on.
    pub done: Vec<u32>,
    /// PIDs skipped or failed, with reasons.
    pub failed: Vec<(u32, String)>,
}

/// Suspends a whole tree. The root is suspended first so it cannot spawn
/// more children; then the tree is re-enumerated once to catch children
/// created during the first pass.
pub fn suspend_tree(root: ProcKey) -> TreeResult {
    let mut res = TreeResult {
        done: Vec::new(),
        failed: Vec::new(),
    };
    for _pass in 0..2 {
        for k in process_tree(root) {
            if res.done.contains(&k.pid) || res.failed.iter().any(|(p, _)| *p == k.pid) {
                continue;
            }
            match suspend_one(k) {
                Ok(()) => res.done.push(k.pid),
                Err(e) => res.failed.push((k.pid, e.to_string())),
            }
        }
    }
    res
}

fn suspend_one(k: ProcKey) -> Result<()> {
    if is_protected(k.pid, &image_of(k.pid)) {
        return Err(SensorError::Refused(format!(
            "PID {} is critical or protected",
            k.pid
        )));
    }
    let h = open_checked(k, PROCESS_SUSPEND_RESUME)?;
    // SAFETY: valid handle with PROCESS_SUSPEND_RESUME.
    let st = unsafe { nt::NtSuspendProcess(h.raw()) };
    if st < 0 {
        Err(SensorError::NtStatus {
            context: "NtSuspendProcess".into(),
            status: st as u32,
        })
    } else {
        Ok(())
    }
}

/// Resumes the given PIDs (in reverse order of suspension).
pub fn resume(keys: &[ProcKey]) -> TreeResult {
    let mut res = TreeResult {
        done: Vec::new(),
        failed: Vec::new(),
    };
    for k in keys.iter().rev() {
        let r = open_checked(*k, PROCESS_SUSPEND_RESUME).and_then(|h| {
            // SAFETY: valid handle with PROCESS_SUSPEND_RESUME.
            let st = unsafe { nt::NtResumeProcess(h.raw()) };
            if st < 0 {
                Err(SensorError::NtStatus {
                    context: "NtResumeProcess".into(),
                    status: st as u32,
                })
            } else {
                Ok(())
            }
        });
        match r {
            Ok(()) => res.done.push(k.pid),
            Err(e) => res.failed.push((k.pid, e.to_string())),
        }
    }
    res
}

/// Terminates a tree (descendants first, then the root).
pub fn kill_tree(root: ProcKey) -> TreeResult {
    let mut res = TreeResult {
        done: Vec::new(),
        failed: Vec::new(),
    };
    let tree = process_tree(root);
    for k in tree.iter().rev() {
        if is_protected(k.pid, &image_of(k.pid)) {
            res.failed.push((k.pid, "critical or protected".into()));
            continue;
        }
        let r = open_checked(*k, PROCESS_TERMINATE).and_then(|h| {
            // SAFETY: valid handle with PROCESS_TERMINATE.
            unsafe { TerminateProcess(h.raw(), 0xE91C_0001) }
                .map_err(|e| SensorError::from_win("TerminateProcess", &e))?;
            // SAFETY: waiting on our own handle.
            unsafe { WaitForSingleObject(h.raw(), 3000) };
            Ok(())
        });
        match r {
            Ok(()) => res.done.push(k.pid),
            Err(e) => res.failed.push((k.pid, e.to_string())),
        }
    }
    res
}

/// True if any thread of `pid` is suspended (used by tests and status).
pub fn is_suspended(pid: u32) -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
    };
    // SAFETY: snapshot handle owned below.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }) else {
        return false;
    };
    let snap = OwnedHandle(snap);
    let mut te = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut any = false;
    let mut all = true;
    // SAFETY: te initialized with its size.
    let mut ok = unsafe { Thread32First(snap.raw(), &mut te) }.is_ok();
    while ok {
        if te.th32OwnerProcessID == pid {
            any = true;
            // SAFETY: thread handle owned below.
            if let Ok(th) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID) } {
                let th = OwnedHandle(th);
                // Suspending returns the previous count; restore immediately.
                // SAFETY: valid thread handle.
                let prev = unsafe { SuspendThread(th.raw()) };
                if prev != u32::MAX {
                    // SAFETY: undo our own suspension.
                    unsafe { ResumeThread(th.raw()) };
                    if prev == 0 {
                        all = false;
                    }
                }
            }
        }
        // SAFETY: as above.
        ok = unsafe { Thread32Next(snap.raw(), &mut te) }.is_ok();
    }
    any && all
}

/// Moves an image into quarantine under a non-executable name with an
/// execute-deny ACL. The caller must have terminated the process first.
/// Returns the quarantine path.
pub fn quarantine_image(image: &Path, sha256: &str, quarantine_dir: &Path) -> Result<PathBuf> {
    let lower = image.to_string_lossy().to_lowercase();
    let sysroot = std::env::var("SystemRoot")
        .unwrap_or_else(|_| r"C:\Windows".into())
        .to_lowercase();
    if lower.starts_with(&sysroot) {
        return Err(SensorError::Refused(
            "will not quarantine files under %SystemRoot%".into(),
        ));
    }
    if sha256.len() != 64 || !sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(SensorError::Refused("invalid image hash".into()));
    }
    std::fs::create_dir_all(quarantine_dir)?;
    let dest = quarantine_dir.join(format!("{}.quarantine", sha256.to_lowercase()));
    let (src, dst) = (wide(image), wide(&dest));
    // Retry briefly: the image can stay locked for a moment after termination.
    let mut last = None;
    for _ in 0..20 {
        // SAFETY: NUL-terminated paths.
        match unsafe {
            MoveFileExW(
                PCWSTR(src.as_ptr()),
                PCWSTR(dst.as_ptr()),
                MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH,
            )
        } {
            Ok(()) => {
                last = None;
                break;
            }
            Err(e) => {
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
        }
    }
    if let Some(e) = last {
        return Err(SensorError::from_win("MoveFileExW", &e));
    }
    // Deny execute to everyone; only SYSTEM and Administrators can read it.
    crate::security::apply_sddl(&dest, "D:P(D;;FX;;;WD)(A;;FR;;;SY)(A;;FR;;;BA)", false)?;
    let sidecar = quarantine_dir.join(format!("{}.json", sha256.to_lowercase()));
    let meta = serde_json_like(&[
        ("original_path", &image.to_string_lossy()),
        ("sha256", sha256),
    ]);
    std::fs::write(&sidecar, meta)?;
    Ok(dest)
}

fn serde_json_like(pairs: &[(&str, &str)]) -> String {
    let body: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("  \"{k}\": \"{}\"", epicurus_core::template::json_escape(v)))
        .collect();
    format!("{{\n{}\n}}\n", body.join(",\n"))
}

/// Writes a minidump of `pid` into `dir`. Off by default in config: dumps are
/// large and contain whatever secrets the process had already read.
pub fn write_minidump(key: ProcKey, dir: &Path) -> Result<PathBuf> {
    let h = open_checked(key, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!(
        "pid{}-{}.dmp",
        key.pid,
        time::OffsetDateTime::now_utc().unix_timestamp()
    ));
    let w = wide(&path);
    // SAFETY: new file handle owned below.
    let f = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| SensorError::from_win("CreateFileW(dump)", &e))?;
    let f = OwnedHandle(f);
    let kind = MINIDUMP_TYPE(
        MiniDumpWithDataSegs.0
            | MiniDumpWithHandleData.0
            | MiniDumpWithFullMemoryInfo.0
            | MiniDumpWithThreadInfo.0
            | MiniDumpWithUnloadedModules.0,
    );
    // SAFETY: valid process and file handles.
    unsafe { MiniDumpWriteDump(h.raw(), key.pid, f.raw(), kind, None, None, None) }
        .map_err(|e| SensorError::from_win("MiniDumpWriteDump", &e))?;
    Ok(path)
}

/// Spawns a long-running child for containment tests.
#[cfg(test)]
fn spawn_sleeper() -> std::process::Child {
    std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
        .spawn()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_processes_are_protected() {
        assert!(is_protected(4, "System"));
        assert!(is_protected(0, ""));
        assert!(is_protected(1234, r"C:\Windows\System32\lsass.exe"));
        assert!(is_protected(std::process::id(), "epicurus.exe"));
    }

    #[test]
    fn suspend_resume_and_kill_a_child_tree() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let ct = open_limited(pid).and_then(|h| creation_time(h.raw()));
        let key = ProcKey {
            pid,
            create_time: ct,
        };
        let r = suspend_tree(key);
        assert!(r.done.contains(&pid), "{r:?}");
        assert!(is_suspended(pid));
        let keys: Vec<ProcKey> = r
            .done
            .iter()
            .map(|p| ProcKey {
                pid: *p,
                create_time: None,
            })
            .collect();
        let rr = resume(&keys);
        assert!(rr.done.contains(&pid));
        assert!(!is_suspended(pid));
        let k = kill_tree(key);
        assert!(k.done.contains(&pid), "{k:?}");
        let _ = child.wait();
    }

    #[test]
    fn recycled_pid_is_refused() {
        let key = ProcKey {
            pid: std::process::id(),
            create_time: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        assert!(matches!(
            open_checked(key, PROCESS_SUSPEND_RESUME),
            Err(SensorError::Refused(_))
        ));
    }

    #[test]
    fn quarantine_refuses_system_files() {
        let dir = tempfile::tempdir().unwrap();
        let r = quarantine_image(
            Path::new(r"C:\Windows\System32\notepad.exe"),
            &"a".repeat(64),
            dir.path(),
        );
        assert!(matches!(r, Err(SensorError::Refused(_))));
    }

    #[test]
    fn quarantine_moves_renames_and_denies_execute() {
        use windows::Win32::Storage::FileSystem::{FILE_EXECUTE, FILE_SHARE_READ};
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("stealer.exe");
        std::fs::write(&image, b"MZ fake image").unwrap();
        let sha = epicurus_core::manifest::sha256_file(&image).unwrap();
        let qdir = dir.path().join("quarantine");

        let dest = quarantine_image(&image, &sha, &qdir).unwrap();
        assert!(!image.exists(), "image moved away");
        assert_eq!(
            dest,
            qdir.join(format!("{sha}.quarantine")),
            "non-executable name keyed by hash"
        );
        let sidecar = std::fs::read_to_string(qdir.join(format!("{sha}.json"))).unwrap();
        assert!(sidecar.contains("stealer.exe") && sidecar.contains(&sha));

        // The DACL denies FILE_EXECUTE to Everyone, owner included.
        let w = wide(&dest);
        // SAFETY: NUL-terminated path; handle dropped immediately if opened.
        let r = unsafe {
            windows::Win32::Storage::FileSystem::CreateFileW(
                PCWSTR(w.as_ptr()),
                FILE_EXECUTE.0,
                FILE_SHARE_READ,
                None,
                windows::Win32::Storage::FileSystem::OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        match r {
            Ok(h) => {
                drop(OwnedHandle(h));
                panic!("execute access should be denied");
            }
            Err(e) => assert_eq!(e.code().0 as u32 & 0xFFFF, 5, "ERROR_ACCESS_DENIED"),
        }
        // Give ourselves full control back so the temp directory can be removed.
        let me = crate::token::current_user_sid().unwrap();
        crate::security::apply_sddl(&dest, &format!("D:P(A;;FA;;;{me})"), false).unwrap();
        std::fs::remove_file(&dest).unwrap();
    }
}
