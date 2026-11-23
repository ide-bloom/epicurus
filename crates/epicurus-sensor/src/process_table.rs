//! Live process table fed by Kernel-Process ETW and an initial snapshot.
//!
//! Entries are keyed by PID *and* creation time, so a recycled PID never
//! inherits another process's identity, and exited processes are kept for a
//! while so a short-lived stealer that exits right after its sweep can still
//! be attributed.

use std::collections::HashMap;

use time::{Duration, OffsetDateTime};
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::winutil::{OwnedHandle, filetime_to_datetime, from_wide};

/// One process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    /// PID.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Creation time.
    pub create_time: OffsetDateTime,
    /// Exit time once exited.
    pub exit_time: Option<OffsetDateTime>,
    /// DOS image path (or name if the path is unknown).
    pub image: String,
    /// Command line, captured at start while the process is alive.
    pub command_line: Option<String>,
    /// `DOMAIN\user`.
    pub user: Option<String>,
    /// User SID.
    pub user_sid: Option<String>,
    /// Integrity level.
    pub integrity: Option<String>,
    /// Session id.
    pub session: u32,
}

/// Slack when matching event timestamps against process lifetimes: ETW and
/// process timestamps come from different clocks paths.
const SLACK: Duration = Duration::seconds(2);

/// The table.
#[derive(Debug, Default)]
pub struct ProcessTable {
    by_pid: HashMap<u32, Vec<ProcEntry>>,
}

impl ProcessTable {
    /// Inserts or merges an entry (same PID and creation time = same process).
    pub fn insert(&mut self, e: ProcEntry) {
        let list = self.by_pid.entry(e.pid).or_default();
        if let Some(existing) = list
            .iter_mut()
            .find(|x| (x.create_time - e.create_time).abs() < Duration::milliseconds(20))
        {
            // Keep the richer of the two records field by field.
            if existing.command_line.is_none() {
                existing.command_line = e.command_line;
            }
            if existing.user.is_none() {
                existing.user = e.user;
            }
            if existing.user_sid.is_none() {
                existing.user_sid = e.user_sid;
            }
            if existing.integrity.is_none() {
                existing.integrity = e.integrity;
            }
            if existing.image.is_empty() || !existing.image.contains('\\') {
                existing.image = e.image;
            }
            return;
        }
        // A new process with this PID means earlier ones are gone.
        for old in list.iter_mut() {
            if old.exit_time.is_none() && old.create_time < e.create_time {
                old.exit_time = Some(e.create_time);
            }
        }
        list.push(e);
        list.sort_by_key(|x| x.create_time);
    }

    /// Records an exit.
    pub fn mark_exit(
        &mut self,
        pid: u32,
        create_time: Option<OffsetDateTime>,
        exit: OffsetDateTime,
    ) {
        if let Some(list) = self.by_pid.get_mut(&pid) {
            let target = match create_time {
                Some(ct) => list
                    .iter_mut()
                    .find(|x| (x.create_time - ct).abs() < Duration::milliseconds(20)),
                None => list.iter_mut().rev().find(|x| x.exit_time.is_none()),
            };
            if let Some(e) = target {
                e.exit_time = Some(exit);
            }
        }
    }

    /// The process that had `pid` at time `at`.
    pub fn find(&self, pid: u32, at: OffsetDateTime) -> Option<&ProcEntry> {
        self.by_pid
            .get(&pid)?
            .iter()
            .rev()
            .find(|e| e.create_time <= at + SLACK && e.exit_time.is_none_or(|x| x + SLACK >= at))
    }

    /// Exact lookup by PID and creation time.
    pub fn get(&self, pid: u32, create_time: OffsetDateTime) -> Option<&ProcEntry> {
        self.by_pid
            .get(&pid)?
            .iter()
            .find(|e| (e.create_time - create_time).abs() < Duration::milliseconds(20))
    }

    /// Live children of a process (created after it, still running).
    pub fn children(&self, pid: u32, create_time: OffsetDateTime) -> Vec<&ProcEntry> {
        self.by_pid
            .values()
            .flatten()
            .filter(|e| {
                e.ppid == pid
                    && e.create_time >= create_time
                    && e.exit_time.is_none()
                    && e.pid != pid
            })
            .collect()
    }

    /// All live descendants, breadth first.
    pub fn descendants(&self, pid: u32, create_time: OffsetDateTime) -> Vec<&ProcEntry> {
        let mut out: Vec<&ProcEntry> = Vec::new();
        let mut frontier = vec![(pid, create_time)];
        while let Some((p, ct)) = frontier.pop() {
            for c in self.children(p, ct) {
                if out.len() > 512
                    || out
                        .iter()
                        .any(|o| o.pid == c.pid && o.create_time == c.create_time)
                {
                    continue;
                }
                frontier.push((c.pid, c.create_time));
                out.push(c);
            }
        }
        out
    }

    /// Ancestors, nearest first. A parent must have been created before its
    /// child, which rules out recycled parent PIDs.
    pub fn ancestors(&self, e: &ProcEntry) -> Vec<&ProcEntry> {
        let mut out = Vec::new();
        let mut cur = e;
        while out.len() < 32 {
            let Some(parent) = self.by_pid.get(&cur.ppid).and_then(|l| {
                l.iter()
                    .rev()
                    .find(|p| p.create_time <= cur.create_time && p.pid != cur.pid)
            }) else {
                break;
            };
            out.push(parent);
            cur = parent;
        }
        out
    }

    /// Drops exited processes older than `keep`.
    pub fn prune(&mut self, now: OffsetDateTime, keep: Duration) {
        for list in self.by_pid.values_mut() {
            list.retain(|e| e.exit_time.is_none_or(|x| now - x < keep));
        }
        self.by_pid.retain(|_, l| !l.is_empty());
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.by_pid.values().map(Vec::len).sum()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

mod nt {
    use windows::Win32::Foundation::HANDLE;
    windows::core::link!("ntdll.dll" "system" fn NtQueryInformationProcess(processhandle: HANDLE, processinformationclass: u32, processinformation: *mut core::ffi::c_void, processinformationlength: u32, returnlength: *mut u32) -> i32);
}

/// `ProcessCommandLineInformation` (Windows 8.1+).
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

/// Facts read from a live process.
#[derive(Debug, Clone, Default)]
pub struct Enrichment {
    /// Image path.
    pub image: Option<String>,
    /// Command line.
    pub command_line: Option<String>,
    /// Creation time.
    pub create_time: Option<OffsetDateTime>,
    /// `DOMAIN\user`.
    pub user: Option<String>,
    /// SID.
    pub user_sid: Option<String>,
    /// Integrity.
    pub integrity: Option<String>,
}

/// Opens a process for limited query.
pub fn open_limited(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: plain open; handle owned.
    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .ok()
        .map(OwnedHandle)
}

/// Full image path of a process handle.
pub fn image_path(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    // SAFETY: buffer/length consistent.
    unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) }
        .ok()?;
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// Creation time of a process handle.
pub fn creation_time(h: HANDLE) -> Option<OffsetDateTime> {
    let (mut c, mut e, mut k, mut u) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: out-parameters.
    unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) }.ok()?;
    filetime_to_datetime(c)
}

/// Command line of a process handle.
pub fn command_line(h: HANDLE) -> Option<String> {
    let mut len = 0u32;
    // SAFETY: size query; expected to fail with a length mismatch.
    let _ = unsafe {
        nt::NtQueryInformationProcess(
            h,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    if len == 0 || len > 1 << 20 {
        return None;
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: buffer of `len` bytes, 8-aligned for the UNICODE_STRING header.
    let st = unsafe {
        nt::NtQueryInformationProcess(
            h,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    };
    if st < 0 {
        return None;
    }
    // UNICODE_STRING { Length: u16, MaximumLength: u16, Buffer: *u16 }
    let bytes_len = (buf[0] & 0xFFFF) as usize;
    let ptr = buf[1] as *const u16;
    if ptr.is_null() || bytes_len == 0 {
        return Some(String::new());
    }
    let base = buf.as_ptr() as usize;
    let end = base + buf.len() * 8;
    if (ptr as usize) < base || (ptr as usize) + bytes_len > end {
        return None;
    }
    // SAFETY: bounds verified: the string lies within our buffer.
    let s = unsafe { std::slice::from_raw_parts(ptr, bytes_len / 2) };
    Some(String::from_utf16_lossy(s))
}

/// Reads everything we can from a live process.
pub fn enrich(pid: u32) -> Enrichment {
    let Some(h) = open_limited(pid) else {
        return Enrichment::default();
    };
    let mut out = Enrichment {
        image: image_path(h.raw()),
        command_line: command_line(h.raw()),
        create_time: creation_time(h.raw()),
        ..Default::default()
    };
    let mut tok = HANDLE::default();
    // SAFETY: token handle owned below.
    if unsafe { OpenProcessToken(h.raw(), TOKEN_QUERY, &mut tok) }.is_ok() {
        let tok = OwnedHandle(tok);
        if let Some((sid, user)) = crate::token::token_user(tok.raw()) {
            out.user_sid = Some(sid);
            out.user = user;
        }
        out.integrity = crate::token::token_integrity(tok.raw());
    }
    out
}

/// Toolhelp snapshot of running processes: `(pid, ppid, exe name)`.
pub fn toolhelp() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    // SAFETY: snapshot handle owned below.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return out;
    };
    let snap = OwnedHandle(snap);
    let mut e = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: e is initialized with its size.
    let mut ok = unsafe { Process32FirstW(snap.raw(), &mut e) }.is_ok();
    while ok {
        out.push((
            e.th32ProcessID,
            e.th32ParentProcessID,
            from_wide(&e.szExeFile),
        ));
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snap.raw(), &mut e) }.is_ok();
    }
    out
}

/// Builds entries for every running process (startup snapshot).
pub fn snapshot() -> Vec<ProcEntry> {
    toolhelp()
        .into_iter()
        .filter(|(pid, _, _)| *pid != 0)
        .map(|(pid, ppid, name)| {
            let en = enrich(pid);
            ProcEntry {
                pid,
                ppid,
                create_time: en.create_time.unwrap_or(OffsetDateTime::UNIX_EPOCH),
                exit_time: None,
                image: en.image.unwrap_or(name),
                command_line: en.command_line,
                user: en.user,
                user_sid: en.user_sid,
                integrity: en.integrity,
                session: 0,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(pid: u32, ppid: u32, secs: i64) -> ProcEntry {
        ProcEntry {
            pid,
            ppid,
            create_time: OffsetDateTime::UNIX_EPOCH + Duration::seconds(secs),
            exit_time: None,
            image: format!(r"C:\p{pid}.exe"),
            command_line: None,
            user: None,
            user_sid: None,
            integrity: None,
            session: 1,
        }
    }

    fn t(secs: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(secs)
    }

    #[test]
    fn pid_reuse_is_disambiguated_by_start_time() {
        let mut tab = ProcessTable::default();
        tab.insert(e(100, 1, 10));
        tab.mark_exit(100, Some(t(10)), t(20));
        let mut reused = e(100, 1, 30);
        reused.image = r"C:\stealer.exe".into();
        tab.insert(reused);
        assert_eq!(tab.find(100, t(15)).unwrap().image, r"C:\p100.exe");
        assert_eq!(tab.find(100, t(40)).unwrap().image, r"C:\stealer.exe");
        assert!(tab.find(100, t(25)).is_none());
    }

    #[test]
    fn exited_processes_remain_attributable_until_pruned() {
        let mut tab = ProcessTable::default();
        tab.insert(e(7, 1, 100));
        tab.mark_exit(7, None, t(101));
        assert!(tab.find(7, t(101)).is_some());
        tab.prune(t(200), Duration::seconds(600));
        assert!(tab.find(7, t(101)).is_some());
        tab.prune(t(1000), Duration::seconds(600));
        assert!(tab.find(7, t(101)).is_none());
    }

    #[test]
    fn tree_navigation_ignores_recycled_parents() {
        let mut tab = ProcessTable::default();
        tab.insert(e(1, 0, 0));
        tab.insert(e(10, 1, 5));
        tab.insert(e(20, 10, 6));
        tab.insert(e(30, 20, 7));
        // A process created *before* its claimed parent is not its child.
        tab.insert(e(40, 30, 1));
        let p = tab.get(10, t(5)).unwrap().clone();
        let d: Vec<u32> = tab
            .descendants(p.pid, p.create_time)
            .iter()
            .map(|x| x.pid)
            .collect();
        assert!(d.contains(&20) && d.contains(&30));
        assert!(!d.contains(&40));
        let leaf = tab.get(30, t(7)).unwrap().clone();
        let a: Vec<u32> = tab.ancestors(&leaf).iter().map(|x| x.pid).collect();
        assert_eq!(a, vec![20, 10, 1]);
    }

    #[test]
    fn merge_keeps_richer_fields() {
        let mut tab = ProcessTable::default();
        tab.insert(e(5, 1, 50));
        let mut richer = e(5, 1, 50);
        richer.command_line = Some("x.exe --steal".into());
        tab.insert(richer);
        assert_eq!(tab.len(), 1);
        assert_eq!(
            tab.get(5, t(50)).unwrap().command_line.as_deref(),
            Some("x.exe --steal")
        );
    }

    #[test]
    fn enrich_reads_own_process() {
        let en = enrich(std::process::id());
        assert!(en.image.unwrap().to_lowercase().ends_with(".exe"));
        assert!(en.command_line.is_some());
        assert!(en.create_time.is_some());
        assert!(en.user_sid.unwrap().starts_with("S-1-"));
    }
}
