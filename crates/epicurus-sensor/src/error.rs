//! Sensor errors.

/// Result alias.
pub type Result<T, E = SensorError> = std::result::Result<T, E>;

/// Sensor failures.
#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    /// A Win32 call failed.
    #[error("{context}: Win32 error {code} ({message})")]
    Win32 {
        /// What was being attempted.
        context: String,
        /// Win32 error code.
        code: u32,
        /// System message.
        message: String,
    },
    /// An NT native call failed with an NTSTATUS.
    #[error("{context}: NTSTATUS 0x{status:08X}{}", nt_status_name(*status))]
    NtStatus {
        /// What was being attempted.
        context: String,
        /// The NTSTATUS value.
        status: u32,
    },
    /// The operation is refused by policy (e.g. protected process).
    #[error("refused: {0}")]
    Refused(String),
    /// Not supported in this environment.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Core error.
    #[error(transparent)]
    Core(#[from] epicurus_core::Error),
}

impl SensorError {
    /// Builds a Win32 error from a code.
    pub fn win32(context: impl Into<String>, code: u32) -> Self {
        let message = windows::core::HRESULT::from_win32(code).message();
        Self::Win32 {
            context: context.into(),
            code,
            message,
        }
    }

    /// Builds a Win32 error from a `windows::core::Error`.
    pub fn from_win(context: impl Into<String>, e: &windows::core::Error) -> Self {
        // HRESULT_FROM_WIN32 keeps the Win32 code in the low 16 bits.
        let code = (e.code().0 as u32) & 0xFFFF;
        Self::Win32 {
            context: context.into(),
            code,
            message: e.message(),
        }
    }
}

/// Short names for NTSTATUS values containment commonly sees.
fn nt_status_name(status: u32) -> &'static str {
    match status {
        0xC000_0022 => " (STATUS_ACCESS_DENIED)",
        0xC000_010A => " (STATUS_PROCESS_IS_TERMINATING)",
        0xC000_0008 => " (STATUS_INVALID_HANDLE)",
        0xC000_0712 => " (STATUS_PROCESS_IS_PROTECTED)",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::SensorError;

    #[test]
    fn ntstatus_is_rendered_in_hex_with_a_name() {
        let e = SensorError::NtStatus {
            context: "NtSuspendProcess".into(),
            status: 0xC000_010A,
        };
        assert_eq!(
            e.to_string(),
            "NtSuspendProcess: NTSTATUS 0xC000010A (STATUS_PROCESS_IS_TERMINATING)"
        );
    }
}
