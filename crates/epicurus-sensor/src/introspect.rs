//! Process triage: everything we can learn about a process that touched a
//! decoy, live if it is still running, from the process table otherwise.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use epicurus_core::incident::{NetConnection, ProcessProfile};
use epicurus_core::paths::{EnvMap, is_within};
use time::OffsetDateTime;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::process_table::{ProcEntry, enrich};
use crate::winutil::OwnedHandle;

/// Where an image lives, for scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Location {
    /// Anywhere a standard user can write (profile, ProgramData, Public, Windows\Temp).
    pub user_writable: bool,
    /// %TEMP% or Downloads specifically.
    pub temp_or_downloads: bool,
}

/// Classifies an image path relative to the protected user's profile.
pub fn classify_location(image: &str, env: &EnvMap) -> Location {
    let p = Path::new(image);
    let mut loc = Location::default();
    let windows_root = env.get("SYSTEMROOT").unwrap_or(r"C:\Windows").to_string();
    let temp_dirs = [
        env.get("LOCALAPPDATA").map(|l| format!(r"{l}\Temp")),
        env.get("USERPROFILE").map(|u| format!(r"{u}\Downloads")),
        Some(format!(r"{windows_root}\Temp")),
    ];
    if temp_dirs
        .iter()
        .flatten()
        .any(|d| is_within(p, Path::new(d)))
    {
        loc.temp_or_downloads = true;
        loc.user_writable = true;
        return loc;
    }
    let drive = image.get(..2).unwrap_or("C:");
    let writable_roots = [
        env.get("USERPROFILE").map(str::to_string),
        Some(format!(r"{drive}\Users\Public")),
        Some(
            env.get("PROGRAMDATA")
                .unwrap_or(r"C:\ProgramData")
                .to_string(),
        ),
        Some(format!(r"{drive}\Users")),
    ];
    loc.user_writable = writable_roots
        .iter()
        .flatten()
        .any(|d| is_within(p, Path::new(d)));
    // A path at the drive root outside Windows/Program Files is writable by
    // default for authenticated users (e.g. C:\tools).
    if !loc.user_writable {
        let lower = image.to_lowercase();
        let protected = [
            windows_root.to_lowercase(),
            format!(r"{}\program files", drive.to_lowercase()),
        ];
        loc.user_writable = !protected.iter().any(|r| lower.starts_with(r.as_str()))
            && lower.len() > 3
            && lower.as_bytes().get(1) == Some(&b':');
    }
    loc
}

fn tcp_state(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn port(p: u32) -> u16 {
    u16::from_be((p & 0xFFFF) as u16)
}

/// Which IP Helper table to read.
#[derive(Clone, Copy)]
enum Kind {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

fn query(kind: Kind, buf: Option<*mut core::ffi::c_void>, size: &mut u32) -> u32 {
    // SAFETY: IP Helper writes at most `*size` bytes into `buf` (or only
    // reports the needed size when `buf` is None).
    unsafe {
        match kind {
            Kind::Tcp4 => GetExtendedTcpTable(
                buf,
                size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ),
            Kind::Tcp6 => GetExtendedTcpTable(
                buf,
                size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ),
            Kind::Udp4 => {
                GetExtendedUdpTable(buf, size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)
            }
            Kind::Udp6 => {
                GetExtendedUdpTable(buf, size, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0)
            }
        }
    }
}

fn table(kind: Kind) -> Option<Vec<u64>> {
    let f = |b, s: &mut u32| query(kind, b, s);
    let mut size = 0u32;
    let _ = f(None, &mut size);
    for _ in 0..4 {
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u64; (size as usize).div_ceil(8) + 64];
        size = (buf.len() * 8) as u32;
        if f(Some(buf.as_mut_ptr().cast()), &mut size) == 0 {
            return Some(buf);
        }
    }
    None
}

/// Rows of a MIB table: `dwNumEntries` followed by `table[]`.
///
/// # Safety
/// `buf` must hold a table of `T` rows as written by IP Helper.
unsafe fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
    let base = buf.as_ptr() as *const u8;
    // SAFETY: the first u32 is the entry count.
    let n = unsafe { *(base as *const u32) } as usize;
    let align = std::mem::align_of::<T>().max(4);
    let first = base.wrapping_add(align.max(4));
    let max = (buf.len() * 8).saturating_sub(align) / std::mem::size_of::<T>().max(1);
    // SAFETY: rows start after the count, aligned to T, and fit in the buffer.
    (0..n.min(max))
        .map(|i| unsafe { *(first as *const T).add(i) })
        .collect()
}

/// TCP and UDP endpoints owned by `pid`.
pub fn connections(pid: u32) -> Vec<NetConnection> {
    let mut out = Vec::new();
    if let Some(buf) = table(Kind::Tcp4) {
        // SAFETY: buffer holds MIB_TCPTABLE_OWNER_PID.
        for r in unsafe { rows::<MIB_TCPROW_OWNER_PID>(&buf) }
            .into_iter()
            .filter(|r| r.dwOwningPid == pid)
        {
            out.push(NetConnection {
                protocol: "tcp".into(),
                local: format!(
                    "{}:{}",
                    Ipv4Addr::from(u32::from_be(r.dwLocalAddr)),
                    port(r.dwLocalPort)
                ),
                remote: format!(
                    "{}:{}",
                    Ipv4Addr::from(u32::from_be(r.dwRemoteAddr)),
                    port(r.dwRemotePort)
                ),
                state: tcp_state(r.dwState).into(),
            });
        }
    }
    if let Some(buf) = table(Kind::Tcp6) {
        // SAFETY: buffer holds MIB_TCP6TABLE_OWNER_PID.
        for r in unsafe { rows::<MIB_TCP6ROW_OWNER_PID>(&buf) }
            .into_iter()
            .filter(|r| r.dwOwningPid == pid)
        {
            out.push(NetConnection {
                protocol: "tcp6".into(),
                local: format!(
                    "[{}]:{}",
                    Ipv6Addr::from(r.ucLocalAddr),
                    port(r.dwLocalPort)
                ),
                remote: format!(
                    "[{}]:{}",
                    Ipv6Addr::from(r.ucRemoteAddr),
                    port(r.dwRemotePort)
                ),
                state: tcp_state(r.dwState).into(),
            });
        }
    }
    if let Some(buf) = table(Kind::Udp4) {
        // SAFETY: buffer holds MIB_UDPTABLE_OWNER_PID.
        for r in unsafe { rows::<MIB_UDPROW_OWNER_PID>(&buf) }
            .into_iter()
            .filter(|r| r.dwOwningPid == pid)
        {
            out.push(NetConnection {
                protocol: "udp".into(),
                local: format!(
                    "{}:{}",
                    Ipv4Addr::from(u32::from_be(r.dwLocalAddr)),
                    port(r.dwLocalPort)
                ),
                remote: String::new(),
                state: String::new(),
            });
        }
    }
    if let Some(buf) = table(Kind::Udp6) {
        // SAFETY: buffer holds MIB_UDP6TABLE_OWNER_PID.
        for r in unsafe { rows::<MIB_UDP6ROW_OWNER_PID>(&buf) }
            .into_iter()
            .filter(|r| r.dwOwningPid == pid)
        {
            out.push(NetConnection {
                protocol: "udp6".into(),
                local: format!(
                    "[{}]:{}",
                    Ipv6Addr::from(r.ucLocalAddr),
                    port(r.dwLocalPort)
                ),
                remote: String::new(),
                state: String::new(),
            });
        }
    }
    out
}

/// Loaded module paths (bounded).
pub fn modules(pid: u32) -> Vec<String> {
    // SAFETY: handle owned below.
    let Ok(h) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) })
    else {
        return Vec::new();
    };
    let h = OwnedHandle(h);
    let mut mods = vec![HMODULE::default(); 1024];
    let mut needed = 0u32;
    // SAFETY: buffer sized in bytes.
    if unsafe {
        EnumProcessModulesEx(
            h.raw(),
            mods.as_mut_ptr(),
            (mods.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    }
    .is_err()
    {
        return Vec::new();
    }
    let n = (needed as usize / std::mem::size_of::<HMODULE>()).min(mods.len());
    mods[..n]
        .iter()
        .filter_map(|m| {
            let mut buf = [0u16; 1024];
            // SAFETY: valid process and module handles; buffer writable.
            let len = unsafe { GetModuleFileNameExW(Some(h.raw()), Some(*m), &mut buf) } as usize;
            (len > 0).then(|| String::from_utf16_lossy(&buf[..len]))
        })
        .collect()
}

/// Builds a process profile. `entry` is the process-table record for the
/// PID at the time of the touch, if any.
pub fn build_profile(pid: u32, entry: Option<&ProcEntry>, env: &EnvMap) -> ProcessProfile {
    let live = enrich(pid);
    // The live process is the same one only if its creation time matches.
    let same = match (entry, live.create_time) {
        (Some(e), Some(ct)) => (e.create_time - ct).abs() < time::Duration::milliseconds(50),
        (None, Some(_)) => true,
        _ => false,
    };
    let exited = !same;
    let image = if same {
        live.image
            .clone()
            .or_else(|| entry.map(|e| e.image.clone()))
    } else {
        entry.map(|e| e.image.clone())
    }
    .unwrap_or_default();

    let meta = std::fs::metadata(&image).ok();
    let image_created = meta
        .as_ref()
        .and_then(|m| m.created().ok())
        .map(OffsetDateTime::from);
    let image_sha256 = if image.is_empty() {
        None
    } else {
        epicurus_core::manifest::sha256_file(Path::new(&image)).ok()
    };
    let signature = if image.is_empty() || meta.is_none() {
        epicurus_core::incident::SignatureInfo::default()
    } else {
        crate::authenticode::verify(Path::new(&image))
    };
    let loc = classify_location(&image, env);
    let pick = |live_v: Option<String>, table_v: Option<&Option<String>>| -> Option<String> {
        if same {
            live_v.or_else(|| table_v.cloned().flatten())
        } else {
            table_v.cloned().flatten()
        }
    };

    ProcessProfile {
        pid,
        ppid: entry.map(|e| e.ppid).unwrap_or_default(),
        start_time: if same {
            live.create_time
        } else {
            entry.map(|e| e.create_time)
        },
        image_size: meta.as_ref().map(std::fs::Metadata::len),
        image_created,
        image_sha256,
        signature,
        command_line: pick(live.command_line, entry.map(|e| &e.command_line)),
        user: pick(live.user, entry.map(|e| &e.user)),
        user_sid: pick(live.user_sid, entry.map(|e| &e.user_sid)),
        integrity: pick(live.integrity, entry.map(|e| &e.integrity)),
        user_writable_dir: loc.user_writable,
        temp_or_downloads: loc.temp_or_downloads,
        network: if same { connections(pid) } else { Vec::new() },
        modules: if same {
            modules(pid).into_iter().take(512).collect()
        } else {
            Vec::new()
        },
        exited,
        protected: crate::containment::is_protected(pid, &image),
        image_path: image,
    }
}

/// True if the parent image is a script host or living-off-the-land binary.
pub fn is_suspicious_parent(image: &str) -> bool {
    let name = image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_lowercase();
    matches!(
        name.as_str(),
        "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "msiexec.exe"
            | "conhost.exe"
            | "bitsadmin.exe"
            | "certutil.exe"
            | "installutil.exe"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> EnvMap {
        let mut e = EnvMap::for_profile(Path::new(r"C:\Users\dev"), None, None);
        e.set("SYSTEMROOT", r"C:\Windows");
        e.set("PROGRAMDATA", r"C:\ProgramData");
        e
    }

    #[test]
    fn location_classification() {
        let e = env();
        assert_eq!(
            classify_location(r"C:\Users\dev\AppData\Local\Temp\x.exe", &e),
            Location {
                user_writable: true,
                temp_or_downloads: true
            }
        );
        assert!(classify_location(r"C:\Users\dev\Downloads\setup.exe", &e).temp_or_downloads);
        let roaming = classify_location(r"C:\Users\dev\AppData\Roaming\upd\u.exe", &e);
        assert!(roaming.user_writable && !roaming.temp_or_downloads);
        assert!(classify_location(r"C:\ProgramData\x\y.exe", &e).user_writable);
        assert!(!classify_location(r"C:\Windows\System32\notepad.exe", &e).user_writable);
        assert!(!classify_location(r"C:\Program Files\App\app.exe", &e).user_writable);
        assert!(!classify_location(r"C:\Program Files (x86)\App\app.exe", &e).user_writable);
        assert!(classify_location(r"C:\tools\t.exe", &e).user_writable);
        assert!(classify_location(r"C:\Windows\Temp\d.exe", &e).temp_or_downloads);
    }

    #[test]
    fn suspicious_parents() {
        assert!(is_suspicious_parent(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ));
        assert!(!is_suspicious_parent(r"C:\Windows\explorer.exe"));
    }

    #[test]
    fn profile_of_self() {
        let p = build_profile(std::process::id(), None, &env());
        assert!(!p.exited);
        assert!(p.image_sha256.is_some());
        assert!(!p.modules.is_empty());
        // Epicurus never contains itself.
        assert!(p.protected);
    }

    #[test]
    fn network_enumeration_finds_our_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let c = connections(std::process::id());
        assert!(
            c.iter().any(|x| x.protocol == "tcp"
                && x.local.ends_with(&format!(":{port}"))
                && x.state == "LISTEN"),
            "{c:?}"
        );
    }
}
