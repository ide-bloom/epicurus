//! Degraded fallback sensor: SACL auditing plus Security event 4663.
//!
//! Used when the Kernel-File ETW session cannot be started (for example when
//! the system's 64-session limit is exhausted, or ETW is blocked by policy).
//! Each decoy gets an audit ACE for read, write and delete by Everyone; the
//! "File System" audit subcategory is switched on for success; and a
//! subscription to the Security log delivers event 4663 ("An attempt was made
//! to access an object"), which carries the process id and image.
//!
//! Trade-offs versus ETW: Security log delivery adds latency (typically well
//! under a second), Group Policy can override the audit subcategory, and the
//! Security log can be cleared by an administrator. `epicurus doctor`
//! reports which mode is active.

use std::ffi::c_void;
use std::path::Path;
use std::sync::mpsc::Sender;

use epicurus_core::incident::SensorSource;
use epicurus_core::paths::normalize_key;
use windows::Win32::Security::Authentication::Identity::{
    AUDIT_POLICY_INFORMATION, AuditFree, AuditQuerySystemPolicy, AuditSetSystemPolicy,
};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EvtClose, EvtRender, EvtRenderEventXml, EvtSubscribe,
    EvtSubscribeActionDeliver, EvtSubscribeToFutureEvents,
};
use windows::core::{GUID, PCWSTR};

use crate::error::{Result, SensorError};
use crate::events::{SensorEvent, SharedFilter};
use crate::winutil::wide;

/// Audit subcategory "File System" (`Audit_ObjectAccess_FileSystem`).
pub const FILE_SYSTEM_SUBCATEGORY: GUID = GUID::from_u128(0x0cce921d_69ae_11d9_bed3_505054503030);
const POLICY_AUDIT_EVENT_SUCCESS: u32 = 0x1;

/// SACL applied to each decoy: audit successful read data, write data,
/// append, and delete by Everyone.
pub const DECOY_SACL: &str = "S:(AU;SA;0x10007;;;WD)";

/// Current "File System" auditing flags.
pub fn query_file_system_policy() -> Option<u32> {
    let mut p: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
    // SAFETY: output freed with AuditFree.
    let ok = unsafe { AuditQuerySystemPolicy(&[FILE_SYSTEM_SUBCATEGORY], &mut p) };
    if !ok || p.is_null() {
        return None;
    }
    // SAFETY: p points to one AUDIT_POLICY_INFORMATION.
    let v = unsafe { (*p).AuditingInformation };
    // SAFETY: freeing the buffer allocated by AuditQuerySystemPolicy.
    unsafe { AuditFree(p as *const c_void) };
    Some(v)
}

/// Sets "File System" auditing flags (requires SeSecurityPrivilege).
pub fn set_file_system_policy(flags: u32) -> Result<()> {
    let info = AUDIT_POLICY_INFORMATION {
        AuditSubCategoryGuid: FILE_SYSTEM_SUBCATEGORY,
        AuditingInformation: flags,
        AuditCategoryGuid: GUID::zeroed(),
    };
    // SAFETY: one valid policy entry.
    if unsafe { AuditSetSystemPolicy(&[info]) } {
        Ok(())
    } else {
        let code = windows::core::Error::from_thread().code().0 as u32 & 0xFFFF;
        Err(SensorError::win32("AuditSetSystemPolicy", code))
    }
}

/// Ensures success auditing is on; returns the previous flags for restoring.
pub fn enable_file_system_auditing() -> Result<u32> {
    let prev = query_file_system_policy().unwrap_or(0);
    if prev & POLICY_AUDIT_EVENT_SUCCESS == 0 {
        set_file_system_policy(prev | POLICY_AUDIT_EVENT_SUCCESS)?;
    }
    Ok(prev)
}

/// Applies the audit SACL to every decoy file.
pub fn apply_sacls<'a>(files: impl IntoIterator<Item = &'a Path>) -> Vec<(String, String)> {
    files
        .into_iter()
        .filter_map(|f| {
            crate::security::apply_sacl(f, DECOY_SACL)
                .err()
                .map(|e| (f.display().to_string(), e.to_string()))
        })
        .collect()
}

struct SubCtx {
    tx: Sender<SensorEvent>,
    filter: SharedFilter,
    own_pid: u32,
}

/// A live Security-log subscription.
pub struct AuditSubscription {
    handle: EVT_HANDLE,
    ctx: *mut SubCtx,
}

// SAFETY: the subscription handle and context are only touched by the
// owning value and the event log's callback thread pool, which the API
// synchronizes; the context is immutable apart from the channel sender,
// which is Send.
unsafe impl Send for AuditSubscription {}

impl AuditSubscription {
    /// Subscribes to future 4663 events.
    pub fn start(tx: Sender<SensorEvent>, filter: SharedFilter) -> Result<Self> {
        let ctx = Box::into_raw(Box::new(SubCtx {
            tx,
            filter,
            own_pid: std::process::id(),
        }));
        let channel = wide("Security");
        let query = wide("*[System[(EventID=4663)]]");
        // SAFETY: strings are NUL-terminated; ctx stays alive until Drop.
        let h = unsafe {
            EvtSubscribe(
                None,
                None,
                PCWSTR(channel.as_ptr()),
                PCWSTR(query.as_ptr()),
                None,
                Some(ctx as *const c_void),
                Some(on_audit_event),
                EvtSubscribeToFutureEvents.0,
            )
        };
        match h {
            Ok(handle) => Ok(Self { handle, ctx }),
            Err(e) => {
                // SAFETY: subscription failed, so no callback holds ctx.
                drop(unsafe { Box::from_raw(ctx) });
                Err(SensorError::from_win("EvtSubscribe(Security)", &e))
            }
        }
    }
}

impl Drop for AuditSubscription {
    fn drop(&mut self) {
        // SAFETY: closing the subscription waits for in-flight callbacks.
        unsafe {
            let _ = EvtClose(self.handle);
            drop(Box::from_raw(self.ctx));
        }
    }
}

unsafe extern "system" fn on_audit_event(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    user: *const c_void,
    event: EVT_HANDLE,
) -> u32 {
    if action != EvtSubscribeActionDeliver || user.is_null() {
        return 0;
    }
    // SAFETY: user is the SubCtx registered in `start`, alive until EvtClose.
    let ctx = unsafe { &*(user as *const SubCtx) };
    let Some(xml) = render_xml(event) else {
        return 0;
    };
    let Some(ev) = parse_4663(&xml) else { return 0 };
    if ev.pid == ctx.own_pid {
        return 0;
    }
    let key = normalize_key(&ev.object);
    let is_decoy = ctx
        .filter
        .read()
        .map(|f| f.is_decoy_key(&key))
        .unwrap_or(false);
    if is_decoy {
        let at = epicurus_core::timefmt::parse_rfc3339(&ev.time)
            .unwrap_or_else(time::OffsetDateTime::now_utc);
        let _ = ctx.tx.send(SensorEvent::DecoyOpen {
            at,
            pid: ev.pid,
            path: ev.object,
            read_data: ev.access_mask & 0x1 != 0,
            source: SensorSource::Audit,
            image_hint: Some(ev.process_name),
        });
    }
    0
}

fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    // SAFETY: size query.
    let _ = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut used,
            &mut props,
        )
    };
    if used == 0 || used > 1 << 20 {
        return None;
    }
    let mut buf = vec![0u16; (used as usize).div_ceil(2)];
    // SAFETY: buffer of `used` bytes.
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            (buf.len() * 2) as u32,
            Some(buf.as_mut_ptr().cast()),
            &mut used,
            &mut props,
        )
    }
    .ok()?;
    Some(crate::winutil::from_wide(&buf))
}

/// Fields of a 4663 event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit4663 {
    /// Accessing process id.
    pub pid: u32,
    /// Accessing process image.
    pub process_name: String,
    /// Object (file) path.
    pub object: String,
    /// Access mask.
    pub access_mask: u32,
    /// SystemTime attribute.
    pub time: String,
}

fn data_field(xml: &str, name: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let needle = format!("<Data Name={quote}{name}{quote}>");
        if let Some(start) = xml.find(&needle) {
            let rest = &xml[start + needle.len()..];
            let end = rest.find("</Data>")?;
            return Some(xml_unescape(&rest[..end]));
        }
    }
    None
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn parse_hex_or_dec(s: &str) -> Option<u32> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Parses the XML rendering of a 4663 event.
pub fn parse_4663(xml: &str) -> Option<Audit4663> {
    let time = xml
        .find("SystemTime=")
        .and_then(|i| {
            let rest = &xml[i + 12..];
            rest.find(['\'', '"']).map(|e| rest[..e].to_string())
        })
        .unwrap_or_default();
    Some(Audit4663 {
        pid: parse_hex_or_dec(&data_field(xml, "ProcessId")?)?,
        process_name: data_field(xml, "ProcessName").unwrap_or_default(),
        object: data_field(xml, "ObjectName")?,
        access_mask: data_field(xml, "AccessMask")
            .and_then(|m| parse_hex_or_dec(&m))
            .unwrap_or(0),
        time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4663</EventID><TimeCreated SystemTime='2026-11-23T10:00:01.1234567Z'/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1-2-3-1001</Data><Data Name='ObjectType'>File</Data><Data Name='ObjectName'>C:\Users\dev\.aws\credentials</Data><Data Name='AccessList'>%%4416</Data><Data Name='AccessMask'>0x1</Data><Data Name='ProcessId'>0x1a2c</Data><Data Name='ProcessName'>C:\Users\dev\AppData\Local\Temp\x&amp;y.exe</Data></EventData></Event>"#;

    #[test]
    fn parses_4663_xml() {
        let e = parse_4663(SAMPLE).unwrap();
        assert_eq!(e.pid, 0x1a2c);
        assert_eq!(e.object, r"C:\Users\dev\.aws\credentials");
        assert_eq!(e.access_mask, 1);
        assert_eq!(e.process_name, r"C:\Users\dev\AppData\Local\Temp\x&y.exe");
        assert_eq!(e.time, "2026-11-23T10:00:01.1234567Z");
    }

    #[test]
    fn rejects_incomplete_xml() {
        assert!(parse_4663("<Event></Event>").is_none());
    }

    #[test]
    fn sacl_sddl_parses() {
        assert!(crate::security::Sd::from_sddl(DECOY_SACL).is_ok());
    }
}
