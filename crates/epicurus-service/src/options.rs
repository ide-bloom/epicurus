//! Runtime options for the engine host.

use std::path::PathBuf;

use epicurus_core::paths::DataDir;

/// How the engine is hosted.
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// Data directory.
    pub data_dir: DataDir,
    /// Named pipe name.
    pub pipe_name: String,
    /// Overrides the ETW session name from config (test isolation).
    pub session_name: Option<String>,
    /// Overrides the protected profile root (integration tests plant into a
    /// temporary root instead of a real profile).
    pub profile_root: Option<PathBuf>,
    /// Overrides the protected user SID.
    pub user_sid: Option<String>,
    /// True when running as the Windows service (enables tray-agent launch).
    pub as_service: bool,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            data_dir: DataDir::system(),
            pipe_name: epicurus_core::DEFAULT_PIPE_NAME.to_string(),
            session_name: None,
            profile_root: None,
            user_sid: None,
            as_service: false,
        }
    }
}
