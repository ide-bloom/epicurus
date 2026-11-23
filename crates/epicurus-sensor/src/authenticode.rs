//! Authenticode verification with `WinVerifyTrust`, including catalog
//! signatures (most inbox Windows binaries are catalog-signed, not
//! embedded-signed).
//!
//! Revocation checking is disabled (`WTD_REVOKE_NONE`) and URL retrieval is
//! cache-only: triage must be fast and must work offline, and a stealer
//! signed with a revoked certificate still gains nothing because a valid
//! signature only ever lowers the score; it never allowlists on its own.

use std::path::Path;

use epicurus_core::incident::{SignatureInfo, SignatureStatus};
use windows::Win32::Foundation::{GENERIC_READ, HWND, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALGORITHM, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::core::PCWSTR;

use crate::winutil::{OwnedHandle, from_wide, wide};

const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003_u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001_u32 as i32;

/// Verifies a file's signature (embedded first, then catalog).
pub fn verify(path: &Path) -> SignatureInfo {
    let wpath = wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..Default::default()
    };
    let mut data = new_data(WTD_CHOICE_FILE, WINTRUST_DATA_0 { pFile: &mut file });
    let status = run(&mut data);
    let mut info = SignatureInfo::default();
    if status == 0 {
        info.status = SignatureStatus::Valid;
        info.chain = signer_chain(&data);
        close(&mut data);
        return info;
    }
    let chain = signer_chain(&data);
    close(&mut data);
    if status == TRUST_E_NOSIGNATURE
        || status == TRUST_E_SUBJECT_FORM_UNKNOWN
        || status == TRUST_E_PROVIDER_UNKNOWN
    {
        if let Some(cat) = verify_catalog(path) {
            return cat;
        }
        info.status = SignatureStatus::Unsigned;
    } else {
        info.status = SignatureStatus::Invalid;
        info.chain = chain;
        info.error = Some(format!("0x{:08X}", status as u32));
    }
    info
}

fn new_data(
    choice: windows::Win32::Security::WinTrust::WINTRUST_DATA_UNION_CHOICE,
    u: WINTRUST_DATA_0,
) -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: choice,
        Anonymous: u,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    }
}

fn run(data: &mut WINTRUST_DATA) -> i32 {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and the structures it points to are alive for the call.
    unsafe {
        WinVerifyTrust(
            HWND(INVALID_HANDLE_VALUE.0),
            &mut action,
            (data as *mut WINTRUST_DATA).cast(),
        )
    }
}

fn close(data: &mut WINTRUST_DATA) {
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = run(data);
}

/// Subject names of the signer chain, leaf first.
fn signer_chain(data: &WINTRUST_DATA) -> Vec<String> {
    if data.hWVTStateData.is_invalid() || data.hWVTStateData.0.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    // SAFETY: state data is valid until WTD_STATEACTION_CLOSE; pointers
    // returned by the helpers live inside it.
    unsafe {
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if prov.is_null() {
            return out;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() {
            return out;
        }
        let sgnr = &*sgnr;
        for i in 0..sgnr.csCertChain as usize {
            let cert = &*sgnr.pasCertChain.add(i);
            if cert.pCert.is_null() {
                continue;
            }
            let mut buf = [0u16; 512];
            let n = CertGetNameStringW(
                cert.pCert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut buf),
            );
            if n > 1 {
                out.push(from_wide(&buf));
            }
        }
    }
    out
}

fn verify_catalog(path: &Path) -> Option<SignatureInfo> {
    let mut admin: isize = 0;
    // SAFETY: out-parameter; released below.
    unsafe { CryptCATAdminAcquireContext2(&mut admin, None, BCRYPT_SHA256_ALGORITHM, None, None) }
        .ok()?;
    let result = (|| {
        let wpath = wide(path);
        // SAFETY: handle owned below.
        let h = unsafe {
            CreateFileW(
                PCWSTR(wpath.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .ok()?;
        let file = OwnedHandle(h);
        let mut size = 0u32;
        // SAFETY: size query.
        let _ = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin, file.raw(), &mut size, None, None)
        };
        if size == 0 || size > 128 {
            return None;
        }
        let mut hash = vec![0u8; size as usize];
        // SAFETY: buffer of `size` bytes.
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin,
                file.raw(),
                &mut size,
                Some(hash.as_mut_ptr()),
                None,
            )
        }
        .ok()?;
        // SAFETY: hash slice valid for the call.
        let cat = unsafe { CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None) };
        if cat == 0 {
            return None;
        }
        let mut ci = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        // SAFETY: cat is a valid catalog context.
        let got = unsafe { CryptCATCatalogInfoFromContext(cat, &mut ci, 0) }.is_ok();
        let info = if got {
            let tag = wide(hex::encode_upper(&hash));
            let mut catinfo = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: PCWSTR(ci.wszCatalogFile.as_ptr()),
                pcwszMemberTag: PCWSTR(tag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(wpath.as_ptr()),
                hMemberFile: file.raw(),
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: size,
                hCatAdmin: admin,
                ..Default::default()
            };
            let mut data = new_data(
                WTD_CHOICE_CATALOG,
                WINTRUST_DATA_0 {
                    pCatalog: &mut catinfo,
                },
            );
            let status = run(&mut data);
            let chain = signer_chain(&data);
            close(&mut data);
            Some(SignatureInfo {
                status: if status == 0 {
                    SignatureStatus::Valid
                } else {
                    SignatureStatus::Invalid
                },
                chain,
                catalog_signed: true,
                error: (status != 0).then(|| format!("0x{:08X}", status as u32)),
            })
        } else {
            None
        };
        // SAFETY: releasing the context acquired by EnumCatalogFromHash.
        unsafe {
            let _ = CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        }
        info
    })();
    // SAFETY: releasing the admin context acquired above.
    unsafe {
        let _ = CryptCATAdminReleaseContext(admin, 0);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notepad_is_validly_signed_by_microsoft() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let info = verify(&Path::new(&root).join("System32").join("kernel32.dll"));
        assert_eq!(info.status, SignatureStatus::Valid, "{info:?}");
        assert!(
            info.signer().unwrap_or_default().contains("Microsoft"),
            "{info:?}"
        );
    }

    #[test]
    fn random_file_is_unsigned() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.exe");
        std::fs::write(&p, b"MZ not really").unwrap();
        assert_eq!(verify(&p).status, SignatureStatus::Unsigned);
    }
}
