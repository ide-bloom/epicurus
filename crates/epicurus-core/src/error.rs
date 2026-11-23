//! Typed errors for the core crate.

use std::path::PathBuf;

/// Result alias used throughout `epicurus-core`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Every failure the core crate can report.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Filesystem operation failed on a specific path.
    #[error("I/O error on {path}: {source}")]
    Io {
        /// Path the operation targeted.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// I/O error without a meaningful path (pipes, sockets).
    #[error("I/O error: {0}")]
    IoBare(#[from] std::io::Error),
    /// The decoy catalog is malformed.
    #[error("catalog error: {0}")]
    Catalog(String),
    /// A template referenced an unknown placeholder or was malformed.
    #[error("template error: {0}")]
    Template(String),
    /// A generator specification was invalid.
    #[error("generator error: {0}")]
    Generator(String),
    /// Configuration could not be parsed or failed validation.
    #[error("configuration error: {0}")]
    Config(String),
    /// TOML parse failure.
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    /// TOML serialization failure.
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    /// JSON (de)serialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// SQLite failure.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    /// An environment variable needed to resolve a path was missing.
    #[error("unknown environment variable %{0}% in path template")]
    UnknownVar(String),
    /// A refused operation that would have violated a safety rule.
    #[error("safety rule violated: {0}")]
    Safety(String),
    /// IPC protocol violation.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Secret protection (DPAPI) failed.
    #[error("secret protection failed: {0}")]
    Protect(String),
    /// Entity not found.
    #[error("not found: {0}")]
    NotFound(String),
}

impl Error {
    /// Convenience constructor for path-scoped I/O errors.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
