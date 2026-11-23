//! Hosts the engine, either inside the Windows service or in the foreground
//! (`epicurus service --foreground`, used by the integration tests).

use std::ffi::OsString;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use epicurus_sensor::events::SensorEvent;
use tokio::sync::{broadcast, mpsc, watch};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType, SessionChangeReason,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::engine::Engine;
use crate::eventlog::{EventLog, Level, ids};
use crate::options::RuntimeOptions;

/// Runs the engine until `shutdown` becomes true. `sessions` delivers
/// session ids of new logons (service mode).
pub fn run(
    opts: RuntimeOptions,
    shutdown: watch::Receiver<bool>,
    sessions: Option<std::sync::mpsc::Receiver<u32>>,
) -> crate::error::Result<()> {
    // reqwest is built without a default TLS provider; use ring.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("epicurus-rt")
        .build()?;
    let (sensor_tx, sensor_rx) = std::sync::mpsc::channel::<SensorEvent>();
    let (alerts_tx, alerts_rx) = mpsc::unbounded_channel();
    let (fail_tx, mut fail_rx) = mpsc::unbounded_channel::<String>();
    let (events_tx, _) = broadcast::channel(256);

    let mut engine = Engine::new(opts.clone(), sensor_tx, alerts_tx, events_tx.clone())?;
    engine.start_sensors();
    // Fill in any decoys that went missing while the service was down.
    if engine.has_decoys()
        && let Err(e) = engine.plant(None, false)
    {
        tracing::warn!(error = %e.message, "startup re-plant failed");
    }
    let user_sid = engine.status_user_sid();
    let engine = Arc::new(Mutex::new(engine));

    rt.spawn(crate::alerts::run_dispatcher(alerts_rx, fail_tx));
    {
        let engine = engine.clone();
        rt.spawn(async move {
            while let Some(msg) = fail_rx.recv().await {
                if let Ok(e) = engine.lock() {
                    e.report_alert_failure(&msg);
                }
            }
        });
    }
    let serve = crate::ipc_server::serve(
        opts.pipe_name.clone(),
        user_sid.clone(),
        engine.clone(),
        events_tx,
        shutdown.clone(),
    );
    let server = rt.spawn(async move {
        // Creating the first pipe instance fails if another process already
        // owns the name (squatting). Make that loud rather than silent.
        if let Err(e) = serve.await {
            tracing::error!(error = %e, "IPC server stopped");
            if let Some(log) = EventLog::open() {
                log.report(
                    Level::Error,
                    ids::SENSOR_DEGRADED,
                    &format!("Epicurus IPC server could not run (pipe name taken?): {e:#}"),
                );
            }
        }
    });

    if opts.as_service
        && let (Some(sid), Ok(exe)) = (&user_sid, std::env::current_exe())
    {
        crate::session::launch_everywhere(sid, &exe.to_string_lossy());
    }

    // Engine loop on this thread.
    loop {
        if *shutdown.borrow() {
            break;
        }
        if let (Some(rx), Some(sid)) = (&sessions, &user_sid)
            && let Ok(session) = rx.try_recv()
            && let Ok(exe) = std::env::current_exe()
        {
            crate::session::launch_tray(session, sid, &exe.to_string_lossy());
        }
        match sensor_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(ev) => {
                // Read live process facts before taking the lock.
                let enrichment = match &ev {
                    SensorEvent::ProcessStart { pid, .. } => {
                        Some(epicurus_sensor::process_table::enrich(*pid))
                    }
                    _ => None,
                };
                if let Ok(mut e) = engine.lock() {
                    e.on_sensor_event(ev, enrichment);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if let Ok(mut e) = engine.lock() {
            e.tick();
        }
    }
    if let Ok(mut e) = engine.lock() {
        e.shutdown();
    }
    server.abort();
    rt.shutdown_timeout(Duration::from_secs(3));
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

/// Entry point when started by the SCM (`epicurus service`).
pub fn run_as_service() -> crate::error::Result<()> {
    service_dispatcher::start(epicurus_core::SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_body() {
        tracing::error!(error = %e, "service failed");
        if let Some(log) = EventLog::open() {
            log.report(
                Level::Error,
                ids::SENSOR_DEGRADED,
                &format!("Epicurus service failed: {e:#}"),
            );
        }
    }
}

fn service_body() -> crate::error::Result<()> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let (session_tx, session_rx) = std::sync::mpsc::channel::<u32>();
    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::SessionChange(p) => {
                if p.reason == SessionChangeReason::SessionLogon {
                    let _ = session_tx.send(p.notification.session_id);
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status = service_control_handler::register(epicurus_core::SERVICE_NAME, handler)?;
    let set = |state: ServiceState, accept: ServiceControlAccept, code: u32| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::SESSION_CHANGE,
        0,
    )?;
    if let Some(log) = EventLog::open() {
        log.report(
            Level::Info,
            ids::SERVICE_STARTED,
            &format!("Epicurus {} service started", epicurus_core::VERSION),
        );
    }
    let opts = RuntimeOptions {
        as_service: true,
        ..RuntimeOptions::default()
    };
    let result = run(opts, stop_rx, Some(session_rx));
    if let Some(log) = EventLog::open() {
        log.report(
            Level::Info,
            ids::SERVICE_STOPPED,
            "Epicurus service stopped",
        );
    }
    set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        if result.is_ok() { 0 } else { 1 },
    )?;
    result
}
