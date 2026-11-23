//! Tracing setup. The service and elevated commands log to a daily rolling
//! file in `%ProgramData%\Epicurus\logs`; unprivileged UI processes log to
//! `%LOCALAPPDATA%\Epicurus\logs` because they cannot write to the
//! protected data directory.

use std::path::Path;

use epicurus_core::paths::DataDir;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriterExt;

fn filter() -> EnvFilter {
    EnvFilter::try_from_env("EPICURUS_LOG").unwrap_or_else(|_| EnvFilter::new("info"))
}

fn file_writer(
    dir: &Path,
    prefix: &str,
) -> Option<(tracing_appender::non_blocking::NonBlocking, WorkerGuard)> {
    std::fs::create_dir_all(dir).ok()?;
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(prefix)
        .filename_suffix("log")
        .max_log_files(14)
        .build(dir)
        .ok()?;
    Some(tracing_appender::non_blocking(appender))
}

/// Service logging: file (and stderr in the foreground).
pub fn init_service(data: &DataDir, foreground: bool) -> Option<WorkerGuard> {
    let (writer, guard) = file_writer(&data.logs(), "service")?;
    if foreground {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_ansi(false)
            .with_writer(writer.and(std::io::stderr))
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_ansi(false)
            .with_writer(writer)
            .try_init();
    }
    Some(guard)
}

/// CLI logging: file when the data directory is writable, warnings to stderr.
pub fn init_cli(data: &DataDir) -> Option<WorkerGuard> {
    if epicurus_sensor::privileges::is_elevated()
        && let Some((writer, guard)) = file_writer(&data.logs(), "cli")
    {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_ansi(false)
            .with_writer(writer.and(std::io::stderr.with_max_level(tracing::Level::WARN)))
            .try_init();
        return Some(guard);
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("EPICURUS_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    None
}

/// UI logging to the user's local app data.
pub fn init_user() -> Option<WorkerGuard> {
    let dir =
        std::env::var_os("LOCALAPPDATA").map(|l| Path::new(&l).join("Epicurus").join("logs"))?;
    let (writer, guard) = file_writer(&dir, "ui")?;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_ansi(false)
        .with_writer(writer)
        .try_init();
    Some(guard)
}
