//! Typed errors for the service crate.

/// Result alias.
pub type Result<T, E = ServiceError> = std::result::Result<T, E>;

/// Service-level failures.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// A filesystem or pipe operation failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Core logic (config, catalog, storage) failed.
    #[error("{context}: {source}")]
    Core {
        /// What was being attempted.
        context: String,
        /// Underlying error.
        #[source]
        source: epicurus_core::Error,
    },
    /// A sensor or OS security call failed.
    #[error(transparent)]
    Sensor(#[from] epicurus_sensor::SensorError),
    /// The Service Control Manager refused an operation.
    #[error("service control manager: {0}")]
    Scm(#[from] windows_service::Error),
    /// A registry operation failed.
    #[error("{0} failed with Win32 error {1}")]
    Registry(&'static str, u32),
    /// The service did not reach the expected state.
    #[error("{0}")]
    State(String),
    /// A background task panicked or was cancelled.
    #[error("background task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

impl ServiceError {
    /// Wraps a core error with context.
    pub fn core(context: impl Into<String>, source: epicurus_core::Error) -> Self {
        Self::Core {
            context: context.into(),
            source,
        }
    }

    /// Wraps an I/O error with context.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

impl From<std::io::Error> for ServiceError {
    fn from(e: std::io::Error) -> Self {
        Self::io("I/O", e)
    }
}

impl From<tokio::time::error::Elapsed> for ServiceError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::io(
            "IPC client timed out",
            std::io::Error::from(std::io::ErrorKind::TimedOut),
        )
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(e: serde_json::Error) -> Self {
        Self::core("JSON", epicurus_core::Error::Json(e))
    }
}
