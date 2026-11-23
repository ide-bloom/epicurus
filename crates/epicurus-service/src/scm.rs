//! Service Control Manager operations and Event Log source registration.

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW,
};
use windows::core::PCWSTR;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::error::ServiceError;
use epicurus_core::SERVICE_NAME;
use epicurus_sensor::winutil::wide;

const EVENTLOG_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application\Epicurus";

/// Service state as seen by clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not installed.
    NotInstalled,
    /// Installed and stopped.
    Stopped,
    /// Running with this PID.
    Running(u32),
    /// Transitioning.
    Pending,
}

/// Queries the service (works without elevation).
pub fn query() -> State {
    let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return State::NotInstalled;
    };
    let Ok(svc) = mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return State::NotInstalled;
    };
    match svc.query_status() {
        Ok(s) => match s.current_state {
            ServiceState::Running => State::Running(s.process_id.unwrap_or(0)),
            ServiceState::Stopped => State::Stopped,
            _ => State::Pending,
        },
        Err(_) => State::NotInstalled,
    }
}

/// Creates (or reconfigures) the service pointing at `exe`.
pub fn install(exe: &Path) -> crate::error::Result<()> {
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Epicurus Infostealer Tripwire"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;
    let svc = match mgr.open_service(SERVICE_NAME, access) {
        Ok(s) => {
            s.change_config(&info)?;
            s
        }
        Err(_) => mgr.create_service(&info, access)?,
    };
    svc.set_description("Plants decoy developer credentials and contains processes that steal them. https://github.com/ide-bloom/epicurus")?;
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ServiceAction {
                action_type: ServiceActionType::None,
                delay: Duration::from_secs(0),
            },
        ]),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

/// Starts the service and waits until it runs.
pub fn start() -> crate::error::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(
        SERVICE_NAME,
        ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    )?;
    if svc.query_status()?.current_state != ServiceState::Running {
        svc.start::<&str>(&[])?;
    }
    wait_for(&svc, ServiceState::Running, Duration::from_secs(30))
}

/// Stops the service and waits until it stops.
pub fn stop() -> crate::error::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    )?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
    }
    wait_for(&svc, ServiceState::Stopped, Duration::from_secs(30))
}

fn wait_for(
    svc: &windows_service::service::Service,
    want: ServiceState,
    timeout: Duration,
) -> crate::error::Result<()> {
    let started = Instant::now();
    let deadline = started + timeout;
    loop {
        let s = svc.query_status()?;
        if s.current_state == want {
            return Ok(());
        }
        if want == ServiceState::Running
            && s.current_state == ServiceState::Stopped
            && started.elapsed() > Duration::from_secs(3)
        {
            return Err(ServiceError::State(
                "service stopped during startup; see %ProgramData%\\Epicurus\\logs".into(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(ServiceError::State(format!(
                "timed out waiting for service state {want:?}"
            )));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Deletes the service (stopping it first).
pub fn uninstall() -> crate::error::Result<()> {
    let _ = stop();
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(
        SERVICE_NAME,
        ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;
    svc.delete()?;
    // Deletion completes once every handle to the service is closed.
    drop(svc);
    let deadline = Instant::now() + Duration::from_secs(10);
    while query() != State::NotInstalled && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

fn reg_set(
    key: HKEY,
    name: &str,
    kind: windows::Win32::System::Registry::REG_VALUE_TYPE,
    data: &[u8],
) -> crate::error::Result<()> {
    let n = wide(name);
    // SAFETY: key is open for write; data slice is valid.
    let rc = unsafe { RegSetValueExW(key, PCWSTR(n.as_ptr()), Some(0), kind, Some(data)) };
    if rc.is_err() {
        return Err(ServiceError::Registry("RegSetValueExW", rc.0));
    }
    Ok(())
}

/// Registers the `Epicurus` Event Log source with epicurus.exe as its
/// message file (the build embeds a message table resource).
pub fn register_event_source(exe: &Path) -> crate::error::Result<()> {
    let k = wide(EVENTLOG_KEY);
    let mut key = HKEY::default();
    // SAFETY: creates/opens the key; closed below.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            Some(0),
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
    };
    if rc.is_err() {
        return Err(ServiceError::Registry("RegCreateKeyExW", rc.0));
    }
    let path: Vec<u8> = wide(exe).iter().flat_map(|c| c.to_le_bytes()).collect();
    let r = reg_set(key, "EventMessageFile", REG_EXPAND_SZ, &path)
        .and_then(|()| reg_set(key, "TypesSupported", REG_DWORD, &7u32.to_le_bytes()));
    // SAFETY: key opened above.
    unsafe {
        let _ = RegCloseKey(key);
    }
    r
}

/// Removes the Event Log source registration.
pub fn unregister_event_source() {
    let k = wide(EVENTLOG_KEY);
    // SAFETY: deleting our own key tree.
    let _ = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(k.as_ptr())) };
}

/// True if the Event Log source is registered.
pub fn event_source_registered() -> bool {
    epicurus_sensor::winutil::reg_get_string(HKEY_LOCAL_MACHINE, EVENTLOG_KEY, "EventMessageFile")
        .is_some()
}
