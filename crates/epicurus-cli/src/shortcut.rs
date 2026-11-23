//! Start Menu shortcut carrying the AppUserModelID, which Windows requires
//! before an unpackaged app may raise toasts.

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::PROPERTYKEY;
use windows::Win32::System::Com::StructuredStorage::{
    PROPVARIANT, PROPVARIANT_0, PROPVARIANT_0_0, PROPVARIANT_0_0_0,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize, IPersistFile,
};
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
use windows::core::{GUID, Interface, PCWSTR, PWSTR};

use epicurus_sensor::winutil::wide;

/// `PKEY_AppUserModel_ID`.
const PKEY_APP_USER_MODEL_ID: PROPERTYKEY = PROPERTYKEY {
    fmtid: GUID::from_u128(0x9f4c2855_9f79_4b39_a8d0_e1d42de1d5f3),
    pid: 5,
};

/// All-users Start Menu location of the shortcut.
pub fn path() -> PathBuf {
    epicurus_core::paths::program_data()
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Epicurus.lnk")
}

/// Creates (or replaces) the shortcut to `exe ui`.
pub fn create(exe: &Path) -> anyhow::Result<PathBuf> {
    let dest = path();
    // SAFETY: COM initialized for this thread and released below.
    let init = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let result = (|| -> anyhow::Result<()> {
        // SAFETY: COM calls on valid interface pointers; strings outlive calls.
        unsafe {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            let wexe = wide(exe);
            link.SetPath(PCWSTR(wexe.as_ptr()))?;
            let args = wide("ui");
            link.SetArguments(PCWSTR(args.as_ptr()))?;
            let desc = wide("Epicurus dashboard");
            link.SetDescription(PCWSTR(desc.as_ptr()))?;
            link.SetIconLocation(PCWSTR(wexe.as_ptr()), 0)?;
            let store: IPropertyStore = link.cast()?;
            let mut aumid = wide(epicurus_core::APP_USER_MODEL_ID);
            let pv = PROPVARIANT {
                Anonymous: PROPVARIANT_0 {
                    Anonymous: std::mem::ManuallyDrop::new(PROPVARIANT_0_0 {
                        vt: VT_LPWSTR,
                        wReserved1: 0,
                        wReserved2: 0,
                        wReserved3: 0,
                        Anonymous: PROPVARIANT_0_0_0 {
                            pwszVal: PWSTR(aumid.as_mut_ptr()),
                        },
                    }),
                },
            };
            store.SetValue(&PKEY_APP_USER_MODEL_ID, &pv)?;
            store.Commit()?;
            // The string buffer is ours; the PROPVARIANT must not free it.
            std::mem::forget(pv);
            let file: IPersistFile = link.cast()?;
            let wdest = wide(&dest);
            file.Save(PCWSTR(wdest.as_ptr()), true)?;
        }
        Ok(())
    })();
    if init.is_ok() {
        // SAFETY: balances the successful CoInitializeEx.
        unsafe { CoUninitialize() };
    }
    result.map(|()| dest)
}

/// Removes the shortcut if present.
pub fn remove() -> bool {
    std::fs::remove_file(path()).is_ok()
}

/// Removes the per-user AppUserModelID registration that the tray agent
/// writes under `HKCU\Software\Classes\AppUserModelId`. Uninstall runs
/// elevated (possibly as another account), so the key is addressed through
/// `HKEY_USERS\<sid>`; this works while the user's hive is loaded.
pub fn remove_aumid(user_sid: &str) -> bool {
    use windows::Win32::System::Registry::{HKEY_USERS, RegDeleteTreeW};
    if !epicurus_sensor::profile::is_valid_sid_string(user_sid) {
        return false;
    }
    let key = wide(format!(
        r"{user_sid}\Software\Classes\AppUserModelId\{}",
        epicurus_core::APP_USER_MODEL_ID
    ));
    // SAFETY: deletes only Epicurus's own key; path is NUL-terminated.
    unsafe { RegDeleteTreeW(HKEY_USERS, PCWSTR(key.as_ptr())) }.is_ok()
}
