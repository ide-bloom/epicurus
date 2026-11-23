//! Epicurus service host: the detection engine, alerting, Event Log, the
//! named-pipe IPC server and Service Control Manager integration.

#![cfg(windows)]

pub mod alerts;
pub mod correlate;
pub mod doctor;
pub mod engine;
pub mod error;
pub mod eventlog;
pub mod host;
pub mod ipc_server;
pub mod options;
pub mod scm;
pub mod session;

pub use error::{Result, ServiceError};
pub use options::RuntimeOptions;
