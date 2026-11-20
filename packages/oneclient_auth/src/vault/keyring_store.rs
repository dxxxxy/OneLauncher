//! macOS Keychain and the Linux Secret Service, through the `keyring` crate.
//! The whole secrets map is one item, so a launch costs one keychain lookup

use super::SecretBackend;
use crate::error::{AuthError, AuthResult};

#[cfg(not(debug_assertions))]
const SERVICE: &str = "org.polyfrost.OneClient";
#[cfg(debug_assertions)]
const SERVICE: &str = "org.polyfrost.OneClient-dev";
const ITEM: &str = "account-secrets";

pub struct KeyringItem;

impl KeyringItem {
    pub fn new() -> Self {
        Self
    }

    fn entry(&self) -> AuthResult<keyring::Entry> {
        keyring::Entry::new(SERVICE, ITEM)
            .map_err(|err| AuthError::Vault(format!("could not open the keyring: {err}")))
    }
}

impl SecretBackend for KeyringItem {
    fn name(&self) -> &'static str {
        if cfg!(target_os = "macos") {
            "macOS Keychain"
        } else {
            "Secret Service"
        }
    }

    fn load(&self) -> AuthResult<Option<Vec<u8>>> {
        match self.entry()?.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(AuthError::Vault(format!(
                "could not read the keyring: {err}"
            ))),
        }
    }

    fn store(&self, data: &[u8]) -> AuthResult<()> {
        self.entry()?
            .set_secret(data)
            .map_err(|err| AuthError::Vault(format!("could not write the keyring: {err}")))
    }
}
