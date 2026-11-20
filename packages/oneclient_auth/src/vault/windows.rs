//! DPAPI: the blob can only be decrypted by this Windows user on this machine.
//! Credential Manager is not used because its entries cap out at 2.5 KB and a
//! few accounts' worth of tokens do not fit

use std::path::PathBuf;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

use super::SecretBackend;
use crate::error::{AuthError, AuthResult};

/// Ties blobs to OneClient so another app's DPAPI data can't be swapped in
const ENTROPY: &[u8] = b"org.polyfrost.OneClient/auth-vault/v1";

pub struct DpapiFile {
    path: PathBuf,
}

impl DpapiFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl SecretBackend for DpapiFile {
    fn name(&self) -> &'static str {
        "Windows DPAPI"
    }

    fn load(&self) -> AuthResult<Option<Vec<u8>>> {
        let sealed = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(AuthError::Vault(format!("could not read vault: {err}"))),
        };
        unprotect(&sealed).map(Some)
    }

    fn store(&self, data: &[u8]) -> AuthResult<()> {
        let sealed = protect(data)?;
        let staging = self.path.with_extension("vault.tmp");
        std::fs::write(&staging, &sealed)
            .and_then(|()| std::fs::rename(&staging, &self.path))
            .map_err(|err| AuthError::Vault(format!("could not write vault: {err}")))
    }
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: DPAPI allocated `cbData` bytes at `pbData` with LocalAlloc
    unsafe {
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData.cast());
        bytes
    }
}

fn protect(data: &[u8]) -> AuthResult<Vec<u8>> {
    let input = blob(data);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: every blob points at live memory for the duration of the call
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(AuthError::Vault(format!(
            "DPAPI could not encrypt: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(take(out))
}

fn unprotect(sealed: &[u8]) -> AuthResult<Vec<u8>> {
    let input = blob(sealed);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: as above
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(AuthError::Vault(format!(
            "DPAPI could not decrypt: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(take(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trips_and_does_not_store_plaintext() {
        let dir = tempfile_dir();
        let backend = DpapiFile::new(dir.join("auth.vault"));

        backend.store(b"refresh-token-value").unwrap();

        let on_disk = std::fs::read(dir.join("auth.vault")).unwrap();
        assert!(
            !on_disk
                .windows(b"refresh-token-value".len())
                .any(|w| w == b"refresh-token-value")
        );
        assert_eq!(
            backend.load().unwrap().as_deref(),
            Some(&b"refresh-token-value"[..])
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_vault_is_empty_not_an_error() {
        let backend = DpapiFile::new(tempfile_dir().join("nope.vault"));
        assert!(backend.load().unwrap().is_none());
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oneclient-dpapi-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
