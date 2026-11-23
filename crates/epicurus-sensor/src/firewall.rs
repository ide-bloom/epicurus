//! Windows Firewall outbound block rules through `INetFwPolicy2`.

use std::path::Path;

use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_OUT,
    NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::core::BSTR;

use crate::error::{Result, SensorError};

/// Rule group used for every rule Epicurus creates.
pub const RULE_GROUP: &str = "Epicurus";

struct Com(bool);

impl Com {
    fn init() -> Self {
        // SAFETY: per-thread COM init; balanced in Drop when it succeeded.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        Self(hr.is_ok())
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful CoInitializeEx above.
            unsafe { CoUninitialize() };
        }
    }
}

fn policy() -> Result<INetFwPolicy2> {
    // SAFETY: COM is initialized on this thread by the caller.
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| SensorError::from_win("CoCreateInstance(NetFwPolicy2)", &e))
}

/// Adds an outbound block rule for `image`; returns the rule name.
pub fn block_outbound(image: &Path, sha256: &str) -> Result<String> {
    let _com = Com::init();
    let name = format!("Epicurus block {}", sha256.get(..12).unwrap_or(sha256));
    let policy = policy()?;
    // SAFETY: COM calls on valid interface pointers.
    unsafe {
        let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| SensorError::from_win("CoCreateInstance(NetFwRule)", &e))?;
        let wrap = |e: windows::core::Error| SensorError::from_win("INetFwRule", &e);
        rule.SetName(&BSTR::from(name.as_str())).map_err(wrap)?;
        rule.SetDescription(&BSTR::from(format!(
            "Blocked by Epicurus after a decoy credential hit. SHA-256 {sha256}"
        )))
        .map_err(wrap)?;
        rule.SetApplicationName(&BSTR::from(image.to_string_lossy().as_ref()))
            .map_err(wrap)?;
        rule.SetDirection(NET_FW_RULE_DIR_OUT).map_err(wrap)?;
        rule.SetAction(NET_FW_ACTION_BLOCK).map_err(wrap)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(wrap)?;
        rule.SetGrouping(&BSTR::from(RULE_GROUP)).map_err(wrap)?;
        rule.SetEnabled(VARIANT_TRUE).map_err(wrap)?;
        let rules = policy
            .Rules()
            .map_err(|e| SensorError::from_win("INetFwPolicy2::Rules", &e))?;
        rules
            .Add(&rule)
            .map_err(|e| SensorError::from_win("INetFwRules::Add", &e))?;
    }
    Ok(name)
}

/// Removes rules by name (used by uninstall). Returns how many were removed.
pub fn remove_rules(names: &[String]) -> u32 {
    let _com = Com::init();
    let Ok(policy) = policy() else { return 0 };
    // SAFETY: COM calls on valid interface pointers.
    let Ok(rules) = (unsafe { policy.Rules() }) else {
        return 0;
    };
    let mut n = 0;
    for name in names {
        // SAFETY: as above.
        if unsafe { rules.Remove(&BSTR::from(name.as_str())) }.is_ok() {
            n += 1;
        }
    }
    n
}
