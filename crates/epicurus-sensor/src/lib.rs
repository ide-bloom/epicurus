//! Epicurus sensors and containment (Windows only).
//!
//! * [`etw`]: Kernel-File / Kernel-Process real-time ETW, the primary
//!   attribution sensor.
//! * [`oplock`]: oplock tripwire, an early-warning sensor independent of ETW.
//! * [`integrity`]: `ReadDirectoryChangesW` watcher for deletion, rename and
//!   modification of decoys.
//! * [`audit`]: degraded fallback using SACLs and Security event 4663.
//! * [`process_table`]: PID+start-time keyed process table.
//! * [`introspect`] and [`authenticode`]: triage of the touching process.
//! * [`containment`] and [`firewall`]: suspend/kill/quarantine/block.

#![cfg(windows)]

pub mod audit;
pub mod authenticode;
pub mod containment;
pub mod devpath;
pub mod error;
pub mod etw;
pub mod events;
pub mod firewall;
pub mod integrity;
pub mod introspect;
pub mod iocp;
pub mod oplock;
pub mod privileges;
pub mod process_table;
pub mod profile;
pub mod security;
pub mod token;
pub mod winutil;

pub use error::{Result, SensorError};

/// Plant hook that hands decoy ownership to the protected user, so a decoy
/// is not given away by an `Administrators` or `SYSTEM` owner.
pub struct OwnerHook {
    /// Protected user's SID.
    pub user_sid: String,
}

impl epicurus_core::plant::PlantHooks for OwnerHook {
    fn after_create(&self, path: &std::path::Path, _is_dir: bool) -> epicurus_core::Result<()> {
        if let Err(e) = security::set_owner(path, &self.user_sid) {
            // Ownership is cosmetic plausibility; never fail planting for it.
            tracing::debug!(path = %path.display(), error = %e, "could not set decoy owner");
        }
        Ok(())
    }
}
