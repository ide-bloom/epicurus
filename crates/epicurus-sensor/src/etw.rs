//! Real-time ETW consumer for Microsoft-Windows-Kernel-File and
//! Microsoft-Windows-Kernel-Process.
//!
//! Keywords and event ids were taken from the provider manifests
//! (`wevtutil gp Microsoft-Windows-Kernel-File /ge /gm`):
//!
//! | Provider        | Keyword                                   | Event                 |
//! |-----------------|-------------------------------------------|-----------------------|
//! | Kernel-File     | `KERNEL_FILE_KEYWORD_CREATE` 0x80          | 12 Create             |
//! | Kernel-File     | `KERNEL_FILE_KEYWORD_DELETE_PATH` 0x400    | 26 DeletePath         |
//! | Kernel-File     | `KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH` 0x800 | 27 RenamePath    |
//! | Kernel-Process  | `WINEVENT_KEYWORD_PROCESS` 0x10            | 1 ProcessStart, 2 ProcessStop |
//!
//! `KERNEL_FILE_KEYWORD_READ` (0x100) and `KERNEL_FILE_KEYWORD_FILEIO` (0x20)
//! are deliberately not enabled: they multiply event volume by orders of
//! magnitude and make buffer loss (and therefore missed Create events) far
//! more likely, while an open of a decoy is already the signal.
//!
//! Event field layouts differ between versions (ProcessStart has four), so
//! fields are decoded by name using TDH metadata, cached per
//! (provider, id, version), instead of hard-coded offsets.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Instant;

use epicurus_core::incident::SensorSource;
use epicurus_core::paths::{DeviceMap, normalize_key};
use time::OffsetDateTime;
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, WIN32_ERROR,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL,
    EVENT_TRACE_CONTROL_FLUSH, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2,
    OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, StartTraceW, TRACE_EVENT_INFO, TdhGetEventInformation, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

use crate::error::{Result, SensorError};
use crate::events::{SensorEvent, SharedFilter, SharedSensitive};
use crate::winutil::wide;

/// Microsoft-Windows-Kernel-File.
pub const KERNEL_FILE: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
/// Microsoft-Windows-Kernel-Process.
pub const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

/// `KERNEL_FILE_KEYWORD_CREATE`.
pub const KW_FILE_CREATE: u64 = 0x80;
/// `KERNEL_FILE_KEYWORD_DELETE_PATH`.
pub const KW_FILE_DELETE_PATH: u64 = 0x400;
/// `KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH`.
pub const KW_FILE_RENAME_PATH: u64 = 0x800;
/// `WINEVENT_KEYWORD_PROCESS`.
pub const KW_PROCESS: u64 = 0x10;

/// Kernel-File Create.
pub const EV_FILE_CREATE: u16 = 12;
/// Kernel-File DeletePath.
pub const EV_FILE_DELETE_PATH: u16 = 26;
/// Kernel-File RenamePath.
pub const EV_FILE_RENAME_PATH: u16 = 27;
/// Kernel-Process ProcessStart.
pub const EV_PROCESS_START: u16 = 1;
/// Kernel-Process ProcessStop.
pub const EV_PROCESS_STOP: u16 = 2;

const TRACE_LEVEL_VERBOSE: u8 = 5;
const NAME_CHARS: usize = 1024;

/// Counters shared with the engine.
#[derive(Debug, Default)]
pub struct EtwStats {
    /// Events delivered.
    pub events: AtomicU64,
    /// FILETIME of the last delivered event.
    pub last_event_ft: AtomicU64,
    /// Consumer thread alive.
    pub running: AtomicBool,
}

/// Session-level loss counters from `ControlTraceW(QUERY)`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Events lost in the session.
    pub events_lost: u64,
    /// Real-time buffers lost (consumer too slow).
    pub realtime_buffers_lost: u64,
    /// Log buffers lost.
    pub log_buffers_lost: u64,
    /// Buffers in use.
    pub buffers: u32,
}

/// `EVENT_TRACE_PROPERTIES` followed by room for the logger name, in a
/// u64-aligned allocation.
struct PropsBuf {
    buf: Vec<u64>,
}

impl PropsBuf {
    fn new() -> Self {
        let bytes = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + NAME_CHARS * 2 * 2;
        let mut buf = vec![0u64; bytes.div_ceil(8)];
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        // SAFETY: the buffer is zeroed, large enough and suitably aligned.
        unsafe {
            (*p).Wnode.BufferSize = (buf.len() * 8) as u32;
            (*p).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*p).LogFileNameOffset = 0;
        }
        Self { buf }
    }

    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }

    fn get(&self) -> &EVENT_TRACE_PROPERTIES {
        // SAFETY: the buffer always starts with an initialized structure.
        unsafe { &*(self.buf.as_ptr() as *const EVENT_TRACE_PROPERTIES) }
    }
}

fn control(
    handle: CONTROLTRACE_HANDLE,
    name: Option<&str>,
    code: EVENT_TRACE_CONTROL,
) -> (WIN32_ERROR, PropsBuf) {
    let mut props = PropsBuf::new();
    let w = name.map(wide);
    let pname = w.as_ref().map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
    // SAFETY: props is a correctly sized properties buffer; name is NUL-terminated.
    let rc = unsafe { ControlTraceW(handle, pname, props.ptr(), code) };
    (rc, props)
}

/// Stops a session by name (used to clear sessions left by a crash).
/// Returns true if a session was stopped.
pub fn stop_session_by_name(name: &str) -> bool {
    control(
        CONTROLTRACE_HANDLE::default(),
        Some(name),
        EVENT_TRACE_CONTROL_STOP,
    )
    .0 == ERROR_SUCCESS
}

fn stats_from(p: &EVENT_TRACE_PROPERTIES) -> SessionStats {
    SessionStats {
        events_lost: u64::from(p.EventsLost),
        realtime_buffers_lost: u64::from(p.RealTimeBuffersLost),
        log_buffers_lost: u64::from(p.LogBuffersLost),
        buffers: p.NumberOfBuffers,
    }
}

/// Queries a session by name; `None` if it is not running.
pub fn query_session_by_name(name: &str) -> Option<SessionStats> {
    let (rc, props) = control(
        CONTROLTRACE_HANDLE::default(),
        Some(name),
        EVENT_TRACE_CONTROL_QUERY,
    );
    (rc == ERROR_SUCCESS).then(|| stats_from(props.get()))
}

/// Everything the event callback needs. Owned by the consumer thread.
pub struct ConsumerContext {
    /// Output channel.
    pub tx: Sender<SensorEvent>,
    /// Decoy/sensitive path filter.
    pub filter: SharedFilter,
    /// Sensitive-open cache.
    pub sensitive: SharedSensitive,
    /// Device map (refreshed when a path fails to map).
    pub devmap: RwLock<DeviceMap>,
    /// Our own PID: our file activity is never a touch.
    pub own_pid: u32,
    /// Shared counters.
    pub stats: Arc<EtwStats>,
    decoder: Mutex<Decoder>,
    last_devmap_refresh: Mutex<Option<Instant>>,
}

impl ConsumerContext {
    /// Creates a context.
    pub fn new(
        tx: Sender<SensorEvent>,
        filter: SharedFilter,
        sensitive: SharedSensitive,
        stats: Arc<EtwStats>,
    ) -> Self {
        Self {
            tx,
            filter,
            sensitive,
            devmap: RwLock::new(crate::devpath::build_device_map()),
            own_pid: std::process::id(),
            stats,
            decoder: Mutex::new(Decoder::default()),
            last_devmap_refresh: Mutex::new(None),
        }
    }

    fn normalize(&self, nt: &str) -> Option<String> {
        if let Some(p) = self.devmap.read().ok()?.normalize(nt) {
            return Some(p);
        }
        // Unknown device: maybe a volume was mounted. Refresh at most every 10 s.
        let mut last = self.last_devmap_refresh.lock().ok()?;
        if last.is_none_or(|t| t.elapsed().as_secs() >= 10) {
            *last = Some(Instant::now());
            if let Ok(mut m) = self.devmap.write() {
                *m = crate::devpath::build_device_map();
                return m.normalize(nt);
            }
        }
        None
    }
}

/// A running real-time session.
pub struct EtwSession {
    name: String,
    handle: CONTROLTRACE_HANDLE,
    consumer: Option<JoinHandle<()>>,
    /// Counters.
    pub stats: Arc<EtwStats>,
}

impl EtwSession {
    /// Starts the session, enables both providers and launches the consumer.
    pub fn start(name: &str, ctx: ConsumerContext) -> Result<Self> {
        if stop_session_by_name(name) {
            tracing::warn!(
                session = name,
                "stopped a stale ETW session left by a previous run"
            );
        }
        let wname = wide(name);
        let mut props = PropsBuf::new();
        // SAFETY: props buffer is initialized by PropsBuf::new.
        unsafe {
            let p = props.ptr();
            (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            // 1 = QueryPerformanceCounter: high-resolution timestamps. The
            // consumer receives them converted to FILETIME.
            (*p).Wnode.ClientContext = 1;
            (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*p).BufferSize = 64; // KB
            (*p).MinimumBuffers = 16;
            (*p).MaximumBuffers = 128;
            // Seconds; the minimum. Oplock breaks additionally force a flush
            // so attribution does not wait for the timer.
            (*p).FlushTimer = 1;
        }
        let mut handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: valid name and properties buffer.
        let mut rc = unsafe { StartTraceW(&mut handle, PCWSTR(wname.as_ptr()), props.ptr()) };
        if rc == ERROR_ALREADY_EXISTS {
            stop_session_by_name(name);
            let mut props2 = PropsBuf::new();
            // SAFETY: copy the configured header into a fresh buffer.
            unsafe {
                std::ptr::copy_nonoverlapping(props.ptr(), props2.ptr(), 1);
            }
            // SAFETY: as above.
            rc = unsafe { StartTraceW(&mut handle, PCWSTR(wname.as_ptr()), props2.ptr()) };
        }
        if rc != ERROR_SUCCESS {
            return Err(SensorError::win32("StartTraceW", rc.0));
        }

        let enable = |guid: &GUID, kw: u64| -> Result<()> {
            // SAFETY: handle is the session we just started.
            let rc = unsafe {
                EnableTraceEx2(
                    handle,
                    guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    TRACE_LEVEL_VERBOSE,
                    kw,
                    0,
                    0,
                    None,
                )
            };
            if rc == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(SensorError::win32("EnableTraceEx2", rc.0))
            }
        };
        let enabled = enable(&KERNEL_PROCESS, KW_PROCESS).and_then(|()| {
            enable(
                &KERNEL_FILE,
                KW_FILE_CREATE | KW_FILE_DELETE_PATH | KW_FILE_RENAME_PATH,
            )
        });
        if let Err(e) = enabled {
            let _ = control(handle, None, EVENT_TRACE_CONTROL_STOP);
            return Err(e);
        }

        let stats = ctx.stats.clone();
        let consumer_name = name.to_string();
        let ctx = Box::new(ctx);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
        let consumer = std::thread::Builder::new()
            .name("etw-consumer".into())
            .spawn(move || consume(consumer_name, ctx, ready_tx))
            .map_err(SensorError::Io)?;
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = control(handle, None, EVENT_TRACE_CONTROL_STOP);
                let _ = consumer.join();
                return Err(e);
            }
            Err(_) => {
                let _ = control(handle, None, EVENT_TRACE_CONTROL_STOP);
                return Err(SensorError::Unsupported(
                    "ETW consumer thread exited".into(),
                ));
            }
        }
        Ok(Self {
            name: name.to_string(),
            handle,
            consumer: Some(consumer),
            stats,
        })
    }

    /// Forces buffered events to be delivered now.
    pub fn flush(&self) {
        let _ = control(self.handle, None, EVENT_TRACE_CONTROL_FLUSH);
    }

    /// Loss counters.
    pub fn query(&self) -> Option<SessionStats> {
        let (rc, props) = control(self.handle, None, EVENT_TRACE_CONTROL_QUERY);
        (rc == ERROR_SUCCESS).then(|| stats_from(props.get()))
    }

    /// Session name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Stops the session and joins the consumer.
    pub fn stop(&mut self) {
        let (rc, _) = control(self.handle, None, EVENT_TRACE_CONTROL_STOP);
        if rc != ERROR_SUCCESS && rc != ERROR_WMI_INSTANCE_NOT_FOUND {
            tracing::warn!(code = rc.0, "stopping ETW session failed");
        }
        if let Some(t) = self.consumer.take() {
            let _ = t.join();
        }
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        if self.consumer.is_some() {
            self.stop();
        }
    }
}

fn consume(name: String, ctx: Box<ConsumerContext>, ready: Sender<Result<()>>) {
    let stats = ctx.stats.clone();
    let raw = Box::into_raw(ctx);
    let mut wname = wide(&name);
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: PWSTR(wname.as_mut_ptr()),
        Context: raw.cast::<c_void>(),
        ..Default::default()
    };
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(on_event);
    // SAFETY: logfile is fully initialized; Context stays valid until after
    // ProcessTrace returns because we free it only below.
    let trace: PROCESSTRACE_HANDLE = unsafe { OpenTraceW(&mut logfile) };
    if trace.Value == u64::MAX {
        let code = windows::core::Error::from_thread().code().0 as u32 & 0xFFFF;
        let _ = ready.send(Err(SensorError::win32("OpenTraceW", code)));
        // SAFETY: reclaim the context we leaked above; no callback can run.
        drop(unsafe { Box::from_raw(raw) });
        return;
    }
    stats.running.store(true, Ordering::SeqCst);
    let _ = ready.send(Ok(()));
    // SAFETY: trace is a valid handle; blocks until the session stops.
    let rc = unsafe { ProcessTrace(&[trace], None, None) };
    if rc != ERROR_SUCCESS {
        tracing::warn!(code = rc.0, "ProcessTrace ended with an error");
    }
    // SAFETY: handle from OpenTraceW, closed once.
    unsafe {
        let _ = CloseTrace(trace);
    }
    stats.running.store(false, Ordering::SeqCst);
    // SAFETY: ProcessTrace has returned, so no callback can still reference
    // the context.
    drop(unsafe { Box::from_raw(raw) });
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    if rec.is_null() {
        return;
    }
    // SAFETY: ETW passes a valid record for the duration of the callback.
    let rec = unsafe { &*rec };
    if rec.UserContext.is_null() {
        return;
    }
    // SAFETY: UserContext is the Box<ConsumerContext> owned by the consumer
    // thread, alive for the whole ProcessTrace call.
    let ctx = unsafe { &*(rec.UserContext as *const ConsumerContext) };
    let h = &rec.EventHeader;
    ctx.stats.events.fetch_add(1, Ordering::Relaxed);
    ctx.stats
        .last_event_ft
        .store(h.TimeStamp as u64, Ordering::Relaxed);
    let at = epicurus_core::timefmt::from_filetime(h.TimeStamp as u64)
        .unwrap_or_else(OffsetDateTime::now_utc);
    let id = h.EventDescriptor.Id;

    if h.ProviderId == KERNEL_FILE {
        if h.ProcessId == ctx.own_pid {
            return;
        }
        let field = match id {
            EV_FILE_CREATE => "FileName",
            EV_FILE_DELETE_PATH | EV_FILE_RENAME_PATH => "FilePath",
            _ => return,
        };
        let Some(values) = decode(ctx, rec, 0) else {
            return;
        };
        let Some(nt) = values.str(field) else { return };
        let Some(path) = ctx.normalize(nt) else {
            return;
        };
        let key = normalize_key(&path);
        let (is_decoy, is_sensitive) = match ctx.filter.read() {
            Ok(f) => (f.is_decoy_key(&key), f.is_sensitive_key(&key)),
            Err(_) => return,
        };
        if is_decoy {
            let ev = if id == EV_FILE_CREATE {
                SensorEvent::DecoyOpen {
                    at,
                    pid: h.ProcessId,
                    path,
                    read_data: false,
                    source: SensorSource::Etw,
                    image_hint: None,
                }
            } else {
                SensorEvent::DecoyDeleteOrRename {
                    at,
                    pid: h.ProcessId,
                    path,
                    rename: id == EV_FILE_RENAME_PATH,
                }
            };
            let _ = ctx.tx.send(ev);
        } else if is_sensitive
            && id == EV_FILE_CREATE
            && let Ok(mut c) = ctx.sensitive.lock()
        {
            c.record(h.ProcessId, at, path);
        }
    } else if h.ProviderId == KERNEL_PROCESS {
        match id {
            EV_PROCESS_START => {
                let Some(v) = decode(ctx, rec, 1) else { return };
                let (Some(pid), Some(ct)) = (v.u64("ProcessID"), v.u64("CreateTime")) else {
                    return;
                };
                let image_nt = v.str("ImageName").unwrap_or_default();
                let image = ctx
                    .normalize(image_nt)
                    .unwrap_or_else(|| image_nt.to_string());
                let _ = ctx.tx.send(SensorEvent::ProcessStart {
                    pid: pid as u32,
                    ppid: v.u64("ParentProcessID").unwrap_or(0) as u32,
                    create_time: epicurus_core::timefmt::from_filetime(ct).unwrap_or(at),
                    image,
                    session: v.u64("SessionID").unwrap_or(0) as u32,
                });
            }
            EV_PROCESS_STOP => {
                let Some(v) = decode(ctx, rec, 1) else { return };
                let Some(pid) = v.u64("ProcessID") else {
                    return;
                };
                let _ = ctx.tx.send(SensorEvent::ProcessStop {
                    pid: pid as u32,
                    create_time: v
                        .u64("CreateTime")
                        .and_then(epicurus_core::timefmt::from_filetime),
                    exit_time: v
                        .u64("ExitTime")
                        .and_then(epicurus_core::timefmt::from_filetime)
                        .unwrap_or(at),
                });
            }
            _ => {}
        }
    }
}

fn decode(ctx: &ConsumerContext, rec: &EVENT_RECORD, provider: u8) -> Option<Values> {
    let mut dec = ctx.decoder.lock().ok()?;
    dec.decode(rec, provider)
}

// ---------------------------------------------------------------------------
// TDH-driven decoder
// ---------------------------------------------------------------------------

/// TDH in-types we can size.
mod intype {
    pub const UNICODESTRING: u16 = 1;
    pub const ANSISTRING: u16 = 2;
    pub const INT8: u16 = 3;
    pub const UINT8: u16 = 4;
    pub const INT16: u16 = 5;
    pub const UINT16: u16 = 6;
    pub const INT32: u16 = 7;
    pub const UINT32: u16 = 8;
    pub const INT64: u16 = 9;
    pub const UINT64: u16 = 10;
    pub const FLOAT: u16 = 11;
    pub const DOUBLE: u16 = 12;
    pub const BOOLEAN: u16 = 13;
    pub const BINARY: u16 = 14;
    pub const GUID: u16 = 15;
    pub const POINTER: u16 = 16;
    pub const FILETIME: u16 = 17;
    pub const SYSTEMTIME: u16 = 18;
    pub const SID: u16 = 19;
    pub const HEXINT32: u16 = 20;
    pub const HEXINT64: u16 = 21;
    pub const SIZET: u16 = 308;
}

const PROPERTY_STRUCT: i32 = 0x1;
const PROPERTY_PARAM_LENGTH: i32 = 0x2;
const PROPERTY_PARAM_COUNT: i32 = 0x4;

#[derive(Debug, Clone)]
struct Prop {
    name: String,
    intype: u16,
    length: u16,
    length_param: Option<usize>,
    unsupported: bool,
}

/// Decoded layouts per (provider, event id, version); `None` caches failures.
type LayoutCache = HashMap<(u8, u16, u8), Option<Arc<Vec<Prop>>>>;

#[derive(Default)]
struct Decoder {
    layouts: LayoutCache,
}

/// Decoded field values.
#[derive(Debug, Default)]
pub struct Values {
    fields: Vec<(String, Value)>,
}

#[derive(Debug)]
enum Value {
    U64(u64),
    Str(String),
}

impl Values {
    fn u64(&self, name: &str) -> Option<u64> {
        self.fields.iter().find_map(|(n, v)| match v {
            Value::U64(x) if n == name => Some(*x),
            _ => None,
        })
    }

    fn str(&self, name: &str) -> Option<&str> {
        self.fields.iter().find_map(|(n, v)| match v {
            Value::Str(s) if n == name => Some(s.as_str()),
            _ => None,
        })
    }
}

impl Decoder {
    fn layout(&mut self, rec: &EVENT_RECORD, provider: u8) -> Option<Arc<Vec<Prop>>> {
        let d = &rec.EventHeader.EventDescriptor;
        let key = (provider, d.Id, d.Version);
        if let Some(l) = self.layouts.get(&key) {
            return l.clone();
        }
        let layout = load_layout(rec).map(Arc::new);
        self.layouts.insert(key, layout.clone());
        layout
    }

    fn decode(&mut self, rec: &EVENT_RECORD, provider: u8) -> Option<Values> {
        let layout = self.layout(rec, provider)?;
        let ptr_size = if rec.EventHeader.Flags as u32 & EVENT_HEADER_FLAG_32_BIT_HEADER == 0 {
            8
        } else {
            4
        };
        // SAFETY: UserData points to UserDataLength bytes for the callback's duration.
        let data = unsafe {
            std::slice::from_raw_parts(rec.UserData as *const u8, usize::from(rec.UserDataLength))
        };
        Some(walk(&layout, data, ptr_size))
    }
}

fn load_layout(rec: &EVENT_RECORD) -> Option<Vec<Prop>> {
    let mut size = 0u32;
    // SAFETY: size query.
    let _ = unsafe { TdhGetEventInformation(rec, None, None, &mut size) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    let info_ptr = buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
    // SAFETY: buffer is at least `size` bytes and 8-byte aligned.
    let rc = unsafe { TdhGetEventInformation(rec, None, Some(info_ptr), &mut size) };
    if rc != 0 {
        return None;
    }
    let base = buf.as_ptr() as *const u8;
    // SAFETY: TDH wrote a TRACE_EVENT_INFO at the start of the buffer.
    let info = unsafe { &*info_ptr };
    let count = info.TopLevelPropertyCount as usize;
    let arr = info.EventPropertyInfoArray.as_ptr();
    let mut props = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: the array has TopLevelPropertyCount entries inside the buffer.
        let p: &EVENT_PROPERTY_INFO = unsafe { &*arr.add(i) };
        // SAFETY: NameOffset points to a NUL-terminated name inside the buffer.
        let name =
            unsafe { crate::winutil::from_wide_ptr(base.add(p.NameOffset as usize) as *const u16) };
        let flags = p.Flags.0;
        // SAFETY: union reads; which member is valid is determined by flags.
        let (intype, length, length_index, count_val) = unsafe {
            (
                p.Anonymous1.nonStructType.InType,
                p.Anonymous3.length,
                p.Anonymous3.lengthPropertyIndex,
                p.Anonymous2.count,
            )
        };
        let unsupported =
            flags & PROPERTY_STRUCT != 0 || flags & PROPERTY_PARAM_COUNT != 0 || count_val > 1;
        props.push(Prop {
            name,
            intype,
            length,
            length_param: (flags & PROPERTY_PARAM_LENGTH != 0).then_some(usize::from(length_index)),
            unsupported,
        });
    }
    Some(props)
}

fn read_uint(data: &[u8], off: usize, n: usize) -> Option<u64> {
    let s = data.get(off..off + n)?;
    let mut b = [0u8; 8];
    b[..n].copy_from_slice(s);
    Some(u64::from_le_bytes(b))
}

/// Walks the payload sequentially. Stops at the first field it cannot size;
/// fields before it are still returned.
fn walk(layout: &[Prop], data: &[u8], ptr_size: usize) -> Values {
    let mut out = Values::default();
    let mut ints: Vec<Option<u64>> = Vec::with_capacity(layout.len());
    let mut off = 0usize;
    for p in layout {
        if p.unsupported {
            break;
        }
        let fixed = |n: usize| Some(n);
        let size = match p.intype {
            intype::INT8 | intype::UINT8 => fixed(1),
            intype::INT16 | intype::UINT16 => fixed(2),
            intype::INT32 | intype::UINT32 | intype::HEXINT32 | intype::FLOAT | intype::BOOLEAN => {
                fixed(4)
            }
            intype::INT64
            | intype::UINT64
            | intype::HEXINT64
            | intype::DOUBLE
            | intype::FILETIME => fixed(8),
            intype::POINTER | intype::SIZET => fixed(ptr_size),
            intype::GUID | intype::SYSTEMTIME => fixed(16),
            intype::SID => data.get(off + 1).map(|&n| 8 + 4 * usize::from(n)),
            intype::BINARY => match p.length_param {
                Some(i) => ints.get(i).copied().flatten().map(|v| v as usize),
                None => fixed(usize::from(p.length)),
            },
            intype::UNICODESTRING => {
                let s = data.get(off..).unwrap_or_default();
                let mut n = 0usize;
                while n + 1 < s.len() && (s[n] != 0 || s[n + 1] != 0) {
                    n += 2;
                }
                let units: Vec<u16> = s[..n]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                out.fields
                    .push((p.name.clone(), Value::Str(String::from_utf16_lossy(&units))));
                ints.push(None);
                off += (n + 2).min(s.len());
                continue;
            }
            intype::ANSISTRING => {
                let s = data.get(off..).unwrap_or_default();
                let n = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                out.fields.push((
                    p.name.clone(),
                    Value::Str(String::from_utf8_lossy(&s[..n]).into_owned()),
                ));
                ints.push(None);
                off += (n + 1).min(s.len());
                continue;
            }
            _ => None,
        };
        let Some(size) = size else { break };
        let int = if size <= 8 && p.intype != intype::BINARY && p.intype != intype::SID {
            read_uint(data, off, size)
        } else {
            None
        };
        if let Some(v) = int {
            out.fields.push((p.name.clone(), Value::U64(v)));
        }
        ints.push(int);
        off += size;
        if off > data.len() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prop(name: &str, intype: u16) -> Prop {
        Prop {
            name: name.into(),
            intype,
            length: 0,
            length_param: None,
            unsupported: false,
        }
    }

    #[test]
    fn walks_kernel_file_create_layout() {
        // Irp(ptr) FileObject(ptr) IssuingThreadId(u32) CreateOptions(u32)
        // CreateAttributes(u32) ShareAccess(u32) FileName(wstring)
        let layout = vec![
            prop("Irp", intype::POINTER),
            prop("FileObject", intype::POINTER),
            prop("IssuingThreadId", intype::UINT32),
            prop("CreateOptions", intype::UINT32),
            prop("CreateAttributes", intype::UINT32),
            prop("ShareAccess", intype::UINT32),
            prop("FileName", intype::UNICODESTRING),
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&0x1111u64.to_le_bytes());
        data.extend_from_slice(&0xABCDu64.to_le_bytes());
        for v in [7u32, 1, 0x80, 3] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        for u in r"\Device\HarddiskVolume3\x".encode_utf16().chain([0]) {
            data.extend_from_slice(&u.to_le_bytes());
        }
        let v = walk(&layout, &data, 8);
        assert_eq!(v.u64("FileObject"), Some(0xABCD));
        assert_eq!(v.u64("ShareAccess"), Some(3));
        assert_eq!(v.str("FileName"), Some(r"\Device\HarddiskVolume3\x"));
    }

    #[test]
    fn stops_at_unsupported_but_keeps_earlier_fields() {
        let mut bad = prop("Struct", intype::UINT32);
        bad.unsupported = true;
        let layout = vec![prop("A", intype::UINT32), bad, prop("B", intype::UINT32)];
        let data = [1u8, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0];
        let v = walk(&layout, &data, 8);
        assert_eq!(v.u64("A"), Some(1));
        assert_eq!(v.u64("B"), None);
    }

    #[test]
    fn truncated_payload_is_safe() {
        let layout = vec![prop("A", intype::UINT64), prop("S", intype::UNICODESTRING)];
        let v = walk(&layout, &[1, 2, 3], 8);
        assert_eq!(v.u64("A"), None);
    }

    #[test]
    fn sid_and_binary_sizes() {
        let mut bin = prop("Bin", intype::BINARY);
        bin.length_param = Some(0);
        let layout = vec![
            prop("Len", intype::UINT16),
            bin,
            prop("Sid", intype::SID),
            prop("After", intype::UINT32),
        ];
        let mut data = vec![3u8, 0, 9, 9, 9];
        // SID with 2 sub-authorities: 8 + 8 bytes.
        data.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0, 2, 0, 0, 0]);
        data.extend_from_slice(&42u32.to_le_bytes());
        let v = walk(&layout, &data, 8);
        assert_eq!(v.u64("After"), Some(42));
    }
}
