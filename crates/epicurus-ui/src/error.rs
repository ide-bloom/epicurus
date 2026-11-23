//! Typed errors for the UI crate.

/// Result alias.
pub type Result<T, E = UiError> = std::result::Result<T, E>;

/// UI failures.
#[derive(Debug, thiserror::Error)]
pub enum UiError {
    /// The egui/eframe window could not run.
    #[error("dashboard failed: {0}")]
    Window(String),
    /// A Windows or WinRT call failed.
    #[error("Windows API: {0}")]
    Windows(#[from] windows::core::Error),
    /// The tray icon could not be created.
    #[error("tray icon: {0}")]
    Tray(String),
    /// Report export failed.
    #[error("export: {0}")]
    Export(#[from] epicurus_core::Error),
    /// An expected environment variable is missing.
    #[error("environment variable {0} is not set")]
    MissingEnv(&'static str),
}

impl From<tray_icon::Error> for UiError {
    fn from(e: tray_icon::Error) -> Self {
        Self::Tray(e.to_string())
    }
}

impl From<tray_icon::menu::Error> for UiError {
    fn from(e: tray_icon::menu::Error) -> Self {
        Self::Tray(e.to_string())
    }
}
