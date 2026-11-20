//! Account secrets live in the operating system's credential store instead of
//! `auth.json`
//!
//! - Windows: a DPAPI blob bound to the user's logon (`auth.vault`)
//! - macOS: a Keychain item bound to the app's signature
//! - Linux: the Secret Service (GNOME Keyring, KWallet)
//!
//! When the OS store can't be reached, secrets go to a 0600 fallback file so a
//! locked keyring never signs anyone out and never wipes good tokens. The next
//! save that reaches the OS store moves them back and deletes the file.
//!
//! The vault is not a defence against code running unsandboxed as the same
//! user (DPAPI and an unlocked keyring hand secrets to any such process). It
//! removes the easy "copy one JSON file" theft and, together with the game
//! sandbox, keeps secrets out of reach of mods entirely

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AuthError, AuthResult};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod keyring_store;
#[cfg(windows)]
mod windows;

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSecrets {
    pub access_token: String,
    pub refresh_token: String,
}

impl std::fmt::Debug for AccountSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountSecrets(<redacted>)")
    }
}

impl AccountSecrets {
    pub fn is_empty(&self) -> bool {
        self.access_token.is_empty() && self.refresh_token.is_empty()
    }
}

pub type Secrets = HashMap<Uuid, AccountSecrets>;

#[derive(Serialize, Deserialize, Default)]
struct VaultFile {
    version: u32,
    secrets: Secrets,
}

const VAULT_VERSION: u32 = 1;

fn encode(secrets: &Secrets) -> AuthResult<Vec<u8>> {
    serde_json::to_vec(&VaultFile {
        version: VAULT_VERSION,
        secrets: secrets.clone(),
    })
    .map_err(|err| AuthError::Vault(format!("could not encode secrets: {err}")))
}

fn decode(bytes: &[u8]) -> AuthResult<Secrets> {
    let file: VaultFile = serde_json::from_slice(bytes)
        .map_err(|err| AuthError::Vault(format!("could not decode secrets: {err}")))?;
    Ok(file.secrets)
}

/// Where the OS keeps the secrets blob
pub trait SecretBackend: Send + Sync {
    fn name(&self) -> &'static str;
    /// `Ok(None)` when nothing was ever stored
    fn load(&self) -> AuthResult<Option<Vec<u8>>>;
    fn store(&self, data: &[u8]) -> AuthResult<()>;
}

pub struct Vault {
    primary: Option<Arc<dyn SecretBackend>>,
    fallback: PathBuf,
    /// The primary failed to load this session; writing to it could
    /// overwrite secrets we never saw
    primary_unreadable: bool,
}

impl Vault {
    pub fn for_platform(config_dir: &Path) -> Self {
        Self::new(
            platform_backend(config_dir),
            config_dir.join("auth.secrets.json"),
        )
    }

    pub fn new(primary: Option<Arc<dyn SecretBackend>>, fallback: PathBuf) -> Self {
        Self {
            primary,
            fallback,
            primary_unreadable: false,
        }
    }

    /// Fallback file first, primary on top, so the freshest copy wins
    pub async fn load(&mut self) -> Secrets {
        let mut secrets = match polyio::read(&self.fallback).await {
            Ok(bytes) => decode(&bytes).unwrap_or_else(|err| {
                tracing::warn!("ignoring unreadable fallback secrets file: {err}");
                Secrets::new()
            }),
            Err(_) => Secrets::new(),
        };

        if let Some(primary) = &self.primary {
            match run_blocking(primary.clone(), |b| b.load()).await {
                Ok(Some(bytes)) => match decode(&bytes) {
                    Ok(stored) => secrets.extend(stored),
                    Err(err) => {
                        tracing::warn!("{} holds unreadable secrets: {err}", primary.name());
                        self.primary_unreadable = true;
                    }
                },
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!("could not read secrets from {}: {err}", primary.name());
                    self.primary_unreadable = true;
                }
            }
        }

        secrets
    }

    pub async fn save(&mut self, secrets: &Secrets) -> AuthResult<()> {
        let bytes = encode(secrets)?;

        if let Some(primary) = self.primary.as_ref().filter(|_| !self.primary_unreadable) {
            let stored = {
                let bytes = bytes.clone();
                run_blocking(primary.clone(), move |b| b.store(&bytes)).await
            };
            match stored {
                Ok(()) => {
                    if polyio::try_exists(&self.fallback).await.unwrap_or(false) {
                        let _ = polyio::remove_file(&self.fallback).await;
                    }
                    return Ok(());
                }
                Err(err) => {
                    tracing::warn!(
                        "could not store secrets in {}, using the fallback file: {err}",
                        primary.name()
                    );
                }
            }
        }

        write_private(&self.fallback, &bytes).await
    }

    pub fn backend_name(&self) -> &'static str {
        match &self.primary {
            Some(primary) if !self.primary_unreadable => primary.name(),
            _ => "file",
        }
    }
}

// keychain and secret-service calls block, sometimes on a user prompt
async fn run_blocking<T: Send + 'static>(
    backend: Arc<dyn SecretBackend>,
    f: impl FnOnce(&dyn SecretBackend) -> AuthResult<T> + Send + 'static,
) -> AuthResult<T> {
    tokio::task::spawn_blocking(move || f(backend.as_ref()))
        .await
        .map_err(|err| AuthError::Vault(format!("secret store task failed: {err}")))?
}

async fn write_private(path: &Path, bytes: &[u8]) -> AuthResult<()> {
    polyio::write_atomic(path, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(windows)]
fn platform_backend(config_dir: &Path) -> Option<Arc<dyn SecretBackend>> {
    Some(Arc::new(windows::DpapiFile::new(
        config_dir.join("auth.vault"),
    )))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn platform_backend(_config_dir: &Path) -> Option<Arc<dyn SecretBackend>> {
    Some(Arc::new(keyring_store::KeyringItem::new()))
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn platform_backend(_config_dir: &Path) -> Option<Arc<dyn SecretBackend>> {
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    pub struct MemoryBackend {
        pub data: Arc<Mutex<Option<Vec<u8>>>>,
        pub fail: Arc<Mutex<bool>>,
    }

    impl SecretBackend for MemoryBackend {
        fn name(&self) -> &'static str {
            "memory"
        }

        fn load(&self) -> AuthResult<Option<Vec<u8>>> {
            if *self.fail.lock().unwrap() {
                return Err(AuthError::Vault("locked".into()));
            }
            Ok(self.data.lock().unwrap().clone())
        }

        fn store(&self, data: &[u8]) -> AuthResult<()> {
            if *self.fail.lock().unwrap() {
                return Err(AuthError::Vault("locked".into()));
            }
            *self.data.lock().unwrap() = Some(data.to_vec());
            Ok(())
        }
    }

    fn secrets(refresh: &str) -> Secrets {
        let mut map = Secrets::new();
        map.insert(
            Uuid::nil(),
            AccountSecrets {
                access_token: "access".into(),
                refresh_token: refresh.into(),
            },
        );
        map
    }

    #[tokio::test]
    async fn round_trips_through_the_primary_and_leaves_no_file() {
        let dir = polyio::tempdir().await.unwrap();
        let fallback = dir.dir_path().join("auth.secrets.json");
        let backend = MemoryBackend::default();

        let mut vault = Vault::new(Some(Arc::new(backend.clone())), fallback.clone());
        vault.save(&secrets("r1")).await.unwrap();

        assert!(!fallback.exists());
        let mut reopened = Vault::new(Some(Arc::new(backend)), fallback);
        assert_eq!(reopened.load().await, secrets("r1"));
    }

    #[tokio::test]
    async fn a_locked_store_is_never_overwritten() {
        let dir = polyio::tempdir().await.unwrap();
        let fallback = dir.dir_path().join("auth.secrets.json");
        let backend = MemoryBackend::default();
        Vault::new(Some(Arc::new(backend.clone())), fallback.clone())
            .save(&secrets("good"))
            .await
            .unwrap();

        *backend.fail.lock().unwrap() = true;
        let mut vault = Vault::new(Some(Arc::new(backend.clone())), fallback.clone());
        assert!(vault.load().await.is_empty());
        vault.save(&secrets("newer")).await.unwrap();

        // the newer secret went to the fallback, the store kept the old one
        assert!(fallback.exists());
        *backend.fail.lock().unwrap() = false;
        let stored = decode(&backend.data.lock().unwrap().clone().unwrap()).unwrap();
        assert_eq!(stored, secrets("good"));

        // once the store is back, the next session prefers it and cleans up
        let mut healed = Vault::new(Some(Arc::new(backend)), fallback.clone());
        let loaded = healed.load().await;
        healed.save(&loaded).await.unwrap();
        assert!(!fallback.exists());
    }

    #[tokio::test]
    async fn without_a_primary_secrets_live_in_the_fallback() {
        let dir = polyio::tempdir().await.unwrap();
        let fallback = dir.dir_path().join("auth.secrets.json");

        let mut vault = Vault::new(None, fallback.clone());
        vault.save(&secrets("r")).await.unwrap();

        assert_eq!(Vault::new(None, fallback).load().await, secrets("r"));
    }
}
