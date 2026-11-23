//! Windows Event Log reporting under the `Epicurus` source in the
//! Application log. Event ids are documented in docs/event-ids.md; the
//! message table embedded in epicurus.exe renders each event's text.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
    REPORT_EVENT_TYPE, RegisterEventSourceW, ReportEventW,
};
use windows::core::{PCWSTR, PCWSTR as W};

use epicurus_core::scoring::Severity;

/// Event ids (stable; documented for SIEM ingestion).
pub mod ids {
    /// Service started.
    pub const SERVICE_STARTED: u32 = 1000;
    /// Service stopped.
    pub const SERVICE_STOPPED: u32 = 1001;
    /// Active file sensor mode.
    pub const SENSOR_MODE: u32 = 1002;
    /// Sensor degraded or failed.
    pub const SENSOR_DEGRADED: u32 = 1003;
    /// ETW events lost.
    pub const EVENTS_LOST: u32 = 1004;
    /// Decoys planted.
    pub const DECOYS_PLANTED: u32 = 1010;
    /// Decoys removed.
    pub const DECOYS_REMOVED: u32 = 1011;
    /// Incident created.
    pub const INCIDENT_CREATED: u32 = 2000;
    /// Incident severity escalated.
    pub const INCIDENT_ESCALATED: u32 = 2001;
    /// Containment action succeeded.
    pub const CONTAINMENT_ACTION: u32 = 2002;
    /// Containment action failed.
    pub const CONTAINMENT_FAILED: u32 = 2003;
    /// Decoy deleted, renamed or modified.
    pub const DECOY_INTEGRITY: u32 = 2010;
    /// Decoy re-planted.
    pub const DECOY_REPLANTED: u32 = 2011;
    /// Allowlisted process touched a decoy.
    pub const ALLOWLISTED_TOUCH: u32 = 2020;
    /// Oplock break without an attributable process.
    pub const UNATTRIBUTED_BREAK: u32 = 2030;
    /// Alert delivery failed.
    pub const ALERT_FAILED: u32 = 3000;
    /// Configuration changed through IPC.
    pub const CONFIG_CHANGED: u32 = 3001;
    /// Test event.
    pub const TEST: u32 = 9000;
}

/// Every id, for the build script's message table and the docs test.
pub const ALL_IDS: &[u32] = &[
    ids::SERVICE_STARTED,
    ids::SERVICE_STOPPED,
    ids::SENSOR_MODE,
    ids::SENSOR_DEGRADED,
    ids::EVENTS_LOST,
    ids::DECOYS_PLANTED,
    ids::DECOYS_REMOVED,
    ids::INCIDENT_CREATED,
    ids::INCIDENT_ESCALATED,
    ids::CONTAINMENT_ACTION,
    ids::CONTAINMENT_FAILED,
    ids::DECOY_INTEGRITY,
    ids::DECOY_REPLANTED,
    ids::ALLOWLISTED_TOUCH,
    ids::UNATTRIBUTED_BREAK,
    ids::ALERT_FAILED,
    ids::CONFIG_CHANGED,
    ids::TEST,
];

/// Level of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Information.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

impl Level {
    /// Level for an incident severity.
    pub fn for_severity(s: Severity) -> Self {
        match s {
            Severity::Info => Level::Info,
            Severity::Low | Severity::Medium => Level::Warning,
            Severity::High | Severity::Critical => Level::Error,
        }
    }

    fn raw(self) -> REPORT_EVENT_TYPE {
        match self {
            Level::Info => EVENTLOG_INFORMATION_TYPE,
            Level::Warning => EVENTLOG_WARNING_TYPE,
            Level::Error => EVENTLOG_ERROR_TYPE,
        }
    }
}

/// A registered event source.
pub struct EventLog {
    handle: HANDLE,
}

// SAFETY: event source handles may be used from any thread.
unsafe impl Send for EventLog {}
// SAFETY: ReportEventW is thread-safe.
unsafe impl Sync for EventLog {}

impl EventLog {
    /// Opens the `Epicurus` source. Works even if the source is not
    /// registered (events then show without formatted text).
    pub fn open() -> Option<Self> {
        let name: Vec<u16> = epicurus_core::PRODUCT_NAME
            .encode_utf16()
            .chain([0])
            .collect();
        // SAFETY: NUL-terminated source name.
        let h = unsafe { RegisterEventSourceW(PCWSTR::null(), W(name.as_ptr())) }.ok()?;
        Some(Self { handle: h })
    }

    /// Writes one event with a single insertion string.
    pub fn report(&self, level: Level, id: u32, message: &str) {
        // Event log strings are limited to 31,839 characters.
        let msg: String = message.chars().take(30_000).collect();
        let w: Vec<u16> = msg.encode_utf16().chain([0]).collect();
        let strings = [W(w.as_ptr())];
        // SAFETY: handle is a registered source; strings live for the call.
        let r = unsafe {
            ReportEventW(
                self.handle,
                level.raw(),
                0,
                id,
                None,
                0,
                Some(&strings),
                None,
            )
        };
        if let Err(e) = r {
            tracing::debug!(error = %e, id, "ReportEventW failed");
        }
    }
}

impl Drop for EventLog {
    fn drop(&mut self) {
        // SAFETY: handle from RegisterEventSourceW, closed once.
        unsafe {
            let _ = DeregisterEventSource(self.handle);
        }
    }
}
