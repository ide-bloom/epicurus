//! Epicurus user interface: the egui dashboard, the tray agent and toast
//! notifications. Everything here runs unprivileged in the user's session.

#![cfg(windows)]

pub mod client;
pub mod dashboard;
pub mod error;
pub mod icon;
pub mod toast;
pub mod tray;

pub use client::Verifier;
pub use error::{Result, UiError};

/// Opens the dashboard window (blocks until closed).
pub fn run_dashboard(
    pipe: String,
    verifier: Verifier,
    incident: Option<String>,
) -> error::Result<()> {
    let icon = eframe::egui::IconData {
        rgba: icon::shield_rgba(64, icon::Tone::Green),
        width: 64,
        height: 64,
    };
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Epicurus")
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([820.0, 520.0])
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        "Epicurus",
        options,
        Box::new(move |cc| {
            Ok(Box::new(dashboard::Dashboard::new(
                cc, pipe, verifier, incident,
            )))
        }),
    )
    .map_err(|e| error::UiError::Window(e.to_string()))
}
