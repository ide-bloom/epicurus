//! Builds the NT-device-to-drive-letter map with `QueryDosDeviceW`.

use epicurus_core::paths::DeviceMap;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;

use crate::winutil::{from_wide, wide};

/// Queries every drive letter. Call again when volumes are mounted; the
/// sensor refreshes the map whenever a path fails to normalize.
pub fn build_device_map() -> DeviceMap {
    let mut pairs = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let name = wide(&drive);
        let mut buf = vec![0u16; 1024];
        // SAFETY: name is NUL-terminated and buf is writable for its length.
        let n = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            continue;
        }
        // The buffer is a multi-string; the first entry is the current target.
        let target = from_wide(&buf);
        if target.starts_with(r"\Device\") {
            pairs.push((target, drive));
        }
    }
    DeviceMap::new(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_drive_is_mapped() {
        let map = build_device_map();
        assert!(!map.is_empty());
        let sysdrive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        // Round-trip: find the device for the system drive and normalize it.
        let name = wide(&sysdrive);
        let mut buf = vec![0u16; 1024];
        // SAFETY: as above.
        let n = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) };
        assert!(n > 0);
        let dev = from_wide(&buf);
        assert_eq!(
            map.normalize(&format!(r"{dev}\Windows\System32"))
                .as_deref(),
            Some(format!(r"{sysdrive}\Windows\System32").as_str())
        );
    }
}
