//! Platform-independent heart of Epicurus.
//!
//! This crate owns everything that can be reasoned about without touching
//! kernel sensors: the decoy catalog and its generators, the planting plan and
//! its safety rules, the manifest, configuration, the allowlist, scoring, the
//! incident model, SQLite storage, report rendering and the IPC protocol.
//!
//! Keeping this logic free of live sensors is deliberate: it is where the
//! safety guarantees live ("never overwrite a file we did not create",
//! "never plant in a synced folder"), so it must be unit-testable on any
//! developer machine without administrator rights.

pub mod allowlist;
pub mod catalog;
pub mod config;
pub mod environment;
pub mod error;
pub mod generators;
pub mod glob;
pub mod incident;
pub mod ipc;
pub mod leveldb;
pub mod manifest;
pub mod paths;
pub mod plan;
pub mod plant;
pub mod protect;
pub mod report;
pub mod scoring;
pub mod seed;
pub mod shapes;
pub mod storage;
pub mod template;
pub mod timefmt;

pub use error::{Error, Result};

/// Product name used for the service, event log source and UI titles.
pub const PRODUCT_NAME: &str = "Epicurus";

/// Windows service name.
pub const SERVICE_NAME: &str = "Epicurus";

/// AppUserModelID used for toast notifications and the Start Menu shortcut.
pub const APP_USER_MODEL_ID: &str = "IdeBloom.Epicurus";

/// Default named pipe used between the service and its clients.
pub const DEFAULT_PIPE_NAME: &str = "epicurus-v1";

/// Hidden command-line flag the simulator child runs with. The engine uses it,
/// together with the image path, to tag simulated incidents.
pub const SIMULATOR_FLAG: &str = "__simulate-stealer";

/// Crate version, shared by every component so reports name the build.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
