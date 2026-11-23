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
