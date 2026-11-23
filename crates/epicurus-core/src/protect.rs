//! Secrets at rest (webhook URLs, HMAC keys, ntfy tokens) are encrypted with
//! DPAPI.
//!
//! The service runs as LocalSystem and performs the encryption itself, with
//! user-scope DPAPI, so only LocalSystem can decrypt: an administrator copying
//! `config.toml` off the machine, or an unprivileged process reading it, gets
//! nothing usable.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const PREFIX: &str = "dpapi:";
/// Additional entropy binds blobs to Epicurus, so DPAPI blobs from other
/// software cannot be swapped in.
const ENTROPY: &[u8] = b"Epicurus/alert-secret/v1";

/// An encrypted secret as stored in configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct Protected(String);

impl Protected {
    /// Encrypts a plaintext secret.
    pub fn seal(plain: &str) -> Result<Self> {
        let blob = dpapi::protect(plain.as_bytes(), ENTROPY)?;
        Ok(Self(format!("{PREFIX}{}", STANDARD.encode(blob))))
    }

    /// Decrypts the secret.
    pub fn open(&self) -> Result<String> {
        let b64 = self
            .0
            .strip_prefix(PREFIX)
            .ok_or_else(|| Error::Protect("value is not a DPAPI blob".into()))?;
        let blob = STANDARD
            .decode(b64)
            .map_err(|e| Error::Protect(format!("bad base64: {e}")))?;
        let plain = dpapi::unprotect(&blob, ENTROPY)?;
        String::from_utf8(plain).map_err(|_| Error::Protect("secret is not UTF-8".into()))
    }

    /// True when no secret is stored.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(windows)]
mod dpapi {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;

    use crate::{Error, Result};

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr().cast_mut(),
        }
    }

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        if out.pbData.is_null() {
            return Vec::new();
        }
        // SAFETY: on success DPAPI returns a LocalAlloc'd buffer of exactly
        // cbData bytes; we copy it and free it once.
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        // SAFETY: the pointer came from LocalAlloc inside DPAPI and is freed
        // exactly once here.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(out.pbData.cast())));
        }
        v
    }

    pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let input = blob(data);
        let ent = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: all blobs point to live buffers for the duration of the
        // call; DPAPI does not retain them.
        unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                Some(&ent),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|e| Error::Protect(e.to_string()))?;
        Ok(take(out))
    }

    pub fn unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let input = blob(data);
        let ent = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: as in `protect`.
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&ent),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|e| Error::Protect(e.to_string()))?;
        Ok(take(out))
    }
}

#[cfg(not(windows))]
mod dpapi {
    use crate::{Error, Result};

    pub fn protect(_data: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Protect("DPAPI is only available on Windows".into()))
    }

    pub fn unprotect(_data: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Protect("DPAPI is only available on Windows".into()))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let p = Protected::seal("https://discord.com/api/webhooks/1/abc").unwrap();
        assert!(!p.0.contains("discord"));
        assert_eq!(p.open().unwrap(), "https://discord.com/api/webhooks/1/abc");
    }

    #[test]
    fn rejects_plaintext_and_tampering() {
        assert!(Protected("https://x".into()).open().is_err());
        let p = Protected::seal("secret").unwrap();
        let mut s = p.0.clone();
        s.replace_range(s.len() - 8..s.len() - 4, "AAAA");
        assert!(Protected(s).open().is_err());
    }
}
