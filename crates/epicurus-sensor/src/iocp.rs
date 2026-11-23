//! Thin I/O completion port wrapper shared by the oplock tripwire and the
//! integrity watcher.

use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED, PostQueuedCompletionStatus,
};

use crate::error::{Result, SensorError};
use crate::winutil::OwnedHandle;

/// Completion key reserved for "wake up and read your command channel".
pub const WAKE_KEY: usize = usize::MAX;

/// A completion port.
pub struct Port {
    handle: OwnedHandle,
}

/// One dequeued packet.
pub enum Packet {
    /// Nothing arrived within the timeout.
    Timeout,
    /// An I/O completed (successfully or not).
    Io {
        /// Completion key.
        key: usize,
        /// Bytes transferred.
        bytes: u32,
        /// The OVERLAPPED passed to the operation.
        overlapped: *mut OVERLAPPED,
        /// Win32 error code; 0 on success.
        error: u32,
    },
}

impl Port {
    /// Creates a port.
    pub fn new() -> Result<Self> {
        // SAFETY: creating a new, unassociated port.
        let h = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1) }
            .map_err(|e| SensorError::from_win("CreateIoCompletionPort", &e))?;
        Ok(Self {
            handle: OwnedHandle(h),
        })
    }

    /// Associates an overlapped handle with the port.
    pub fn associate(&self, h: HANDLE, key: usize) -> Result<()> {
        // SAFETY: both handles are valid; association lives as long as `h`.
        unsafe { CreateIoCompletionPort(h, Some(self.handle.raw()), key, 0) }
            .map(|_| ())
            .map_err(|e| SensorError::from_win("CreateIoCompletionPort(associate)", &e))
    }

    /// Wakes the waiting thread.
    pub fn wake(&self) {
        // SAFETY: posting a packet with no OVERLAPPED.
        let _ = unsafe { PostQueuedCompletionStatus(self.handle.raw(), 0, WAKE_KEY, None) };
    }

    /// Waits for one packet.
    pub fn wait(&self, timeout_ms: u32) -> Packet {
        let mut bytes = 0u32;
        let mut key = 0usize;
        let mut ov: *mut OVERLAPPED = std::ptr::null_mut();
        // SAFETY: out-parameters only.
        let r = unsafe {
            GetQueuedCompletionStatus(self.handle.raw(), &mut bytes, &mut key, &mut ov, timeout_ms)
        };
        match r {
            Ok(()) => Packet::Io {
                key,
                bytes,
                overlapped: ov,
                error: 0,
            },
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                if ov.is_null() {
                    // No packet dequeued: timeout (or port failure, treated alike).
                    if code != WAIT_TIMEOUT.0 {
                        tracing::debug!(code, "GetQueuedCompletionStatus failed without a packet");
                    }
                    Packet::Timeout
                } else {
                    Packet::Io {
                        key,
                        bytes,
                        overlapped: ov,
                        error: code,
                    }
                }
            }
        }
    }
}

// SAFETY: a completion port handle may be used from any thread.
unsafe impl Send for Port {}
// SAFETY: as above.
unsafe impl Sync for Port {}
