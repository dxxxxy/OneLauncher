use std::collections::HashMap;
use std::path::PathBuf;

use uuid::Uuid;

use oneclient_common::paths;
use oneclient_events::EventBus;

use crate::data::{AccountKind, MinecraftAccount};
use crate::error::{AuthError, AuthResult};
use crate::offline::{offline_account, validate_offline_username};
use crate::vault::{AccountSecrets, Secrets, Vault};

/// Account records persist to `auth.json`; their tokens persist to the
/// [`Vault`]. Older `auth.json` files that still hold tokens are migrated on
/// the first load
#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct CredentialsStore {
    pub users: HashMap<Uuid, MinecraftAccount>,
    pub default_user: Option<Uuid>,
    #[serde(skip)]
    backing: Backing,
}

#[derive(Default)]
struct Backing {
    /// Both unset means the default locations, resolved on first save
    file: Option<PathBuf>,
    vault: Option<Vault>,
}

impl std::fmt::Debug for Backing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backing")
            .field("file", &self.file)
            .field("vault", &self.vault.as_ref().map(Vault::backend_name))
            .finish()
    }
}

#[derive(serde::Serialize)]
struct StoredFile<'a> {
    users: HashMap<Uuid, MinecraftAccount>,
    default_user: &'a Option<Uuid>,
}

impl CredentialsStore {
    #[tracing::instrument(level = "debug")]
    pub async fn load() -> AuthResult<Self> {
        let vault = Vault::for_platform(paths::config_dir()?);
        Self::load_from(paths::auth_file()?, vault).await
    }

    pub async fn load_from(path: PathBuf, mut vault: Vault) -> AuthResult<Self> {
        let mut store = if path.exists() {
            match polyio::read_json::<Self>(&path).await {
                Ok(store) => store,
                Err(err) => {
                    tracing::warn!("failed to read auth file: {err}");
                    Self::default()
                }
            }
        } else {
            Self::default()
        };

        let secrets = vault.load().await;
        let mut migrate = false;
        for account in store.users.values_mut() {
            migrate |= !account.access_token.is_empty() || !account.refresh_token.is_empty();
            if let Some(stored) = secrets.get(&account.id).filter(|s| !s.is_empty()) {
                account.access_token = stored.access_token.clone();
                account.refresh_token = stored.refresh_token.clone();
            }
        }

        tracing::debug!(backend = vault.backend_name(), "loaded account secrets");
        store.backing = Backing {
            file: Some(path),
            vault: Some(vault),
        };

        if migrate {
            tracing::info!("moving account tokens out of auth.json into the secret store");
            store.save().await?;
        }
        Ok(store)
    }

    /// Secrets first, then the stripped records: a crash in between leaves
    /// tokens in both places rather than in neither
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn save(&mut self) -> AuthResult<()> {
        let path = match &self.backing.file {
            Some(path) => path.clone(),
            None => paths::auth_file()?,
        };
        if self.backing.vault.is_none() {
            self.backing.vault = Some(Vault::for_platform(paths::config_dir()?));
        }

        let secrets: Secrets = self
            .users
            .values()
            .map(|account| {
                (
                    account.id,
                    AccountSecrets {
                        access_token: account.access_token.clone(),
                        refresh_token: account.refresh_token.clone(),
                    },
                )
            })
            .filter(|(_, secrets)| !secrets.is_empty())
            .collect();
        if let Some(vault) = self.backing.vault.as_mut() {
            vault.save(&secrets).await?;
        }

        let stripped = StoredFile {
            users: self
                .users
                .iter()
                .map(|(id, account)| {
                    let mut account = account.clone();
                    account.access_token.clear();
                    account.refresh_token.clear();
                    (*id, account)
                })
                .collect(),
            default_user: &self.default_user,
        };
        polyio::write_json_atomic(&path, &stripped).await?;
        Ok(())
    }

    pub fn has_microsoft_account(&self) -> bool {
        self.users
            .values()
            .any(|account| account.kind == AccountKind::Microsoft)
    }

    pub fn list_accounts(&self) -> Vec<MinecraftAccount> {
        self.users.values().cloned().collect()
    }

    pub fn get_account(&self, id: Uuid) -> Option<&MinecraftAccount> {
        self.users.get(&id)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(username = %account.username))]
    pub async fn commit_account(
        &mut self,
        account: MinecraftAccount,
        events: &EventBus,
    ) -> AuthResult<MinecraftAccount> {
        self.users.insert(account.id, account.clone());

        if self.default_user.is_none() {
            self.default_user = Some(account.id);
        }

        self.save().await?;
        tracing::debug!("committed account to credentials store");
        events
            .notify("Account added")
            .body(format!("Signed in as {}", account.username))
            .send();
        Ok(account)
    }

    pub fn add_offline_account(&mut self, username: String) -> AuthResult<MinecraftAccount> {
        let account = self.insert_offline_account(username)?;
        Ok(account)
    }

    #[tracing::instrument(level = "debug", skip(self), fields(username = %username))]
    pub async fn add_offline_account_and_save(
        &mut self,
        username: String,
    ) -> AuthResult<MinecraftAccount> {
        let account = self.insert_offline_account(username)?;
        self.save().await?;
        Ok(account)
    }

    fn insert_offline_account(&mut self, username: String) -> AuthResult<MinecraftAccount> {
        if !self.has_microsoft_account() {
            return Err(AuthError::OfflineRequiresMicrosoft);
        }

        validate_offline_username(&username)?;

        if self
            .users
            .values()
            .any(|u| u.username.eq_ignore_ascii_case(&username))
        {
            return Err(AuthError::DuplicateUsername { username });
        }

        let account = offline_account(username);
        self.users.insert(account.id, account.clone());
        Ok(account)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(%account.id))]
    pub async fn commit_refreshed_account(&mut self, account: MinecraftAccount) -> AuthResult<()> {
        self.users.insert(account.id, account);
        self.save().await?;
        tracing::debug!("stored refreshed Microsoft account");
        Ok(())
    }

    /// Keeps the entry and its default slot so the UI can offer a sign-in for
    /// this exact account The refresh token is kept too Microsoft sometimes
    /// rejects a good one and the next renewal retries it
    #[tracing::instrument(level = "debug", skip(self), fields(%id))]
    pub async fn mark_signed_out(&mut self, id: Uuid) -> AuthResult<()> {
        let Some(account) = self.users.get_mut(&id) else {
            return Err(AuthError::AccountNotFound(id));
        };

        account.signed_out = true;
        account.access_token.clear();
        self.save().await?;
        Ok(())
    }

    /// Debug aid swaps in a token Microsoft will reject and backdates expiry so
    /// the next launch walks the real `invalid_grant` path
    #[tracing::instrument(level = "debug", skip(self), fields(%id))]
    pub async fn corrupt_refresh_token(&mut self, id: Uuid) -> AuthResult<()> {
        let Some(account) = self.users.get_mut(&id) else {
            return Err(AuthError::AccountNotFound(id));
        };

        account.refresh_token = "oneclient-debug-invalid-refresh-token".to_string();
        account.expires = chrono::DateTime::UNIX_EPOCH;
        self.save().await?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), fields(%id))]
    pub async fn remove_account(&mut self, id: Uuid) -> AuthResult<Option<MinecraftAccount>> {
        let removed = self.users.remove(&id);

        if self.default_user == Some(id) {
            self.default_user = self.users.keys().copied().next();
        }

        self.save().await?;
        Ok(removed)
    }

    #[tracing::instrument(level = "debug", skip(self), fields(?id))]
    pub async fn set_default_user(&mut self, id: Option<Uuid>) -> AuthResult<()> {
        if let Some(id) = id
            && !self.users.contains_key(&id)
        {
            return Err(AuthError::AccountNotFound(id));
        }

        self.default_user = id;
        self.save().await?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn resolve_default_id(&mut self) -> AuthResult<Option<Uuid>> {
        let id = self
            .default_user
            .or_else(|| self.users.keys().copied().next());

        let Some(id) = id else {
            return Ok(None);
        };

        if !self.users.contains_key(&id) {
            return Ok(None);
        }

        if self.default_user != Some(id) {
            self.default_user = Some(id);
            self.save().await?;
        }

        Ok(Some(id))
    }

    /// Never touches the network callers that need a usable token go through
    /// [`crate::AuthService::account_for_launch`]
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn default_account(&mut self) -> AuthResult<Option<MinecraftAccount>> {
        let Some(id) = self.resolve_default_id().await? else {
            return Ok(None);
        };
        let Some(account) = self.users.get(&id).cloned() else {
            return Ok(None);
        };

        if account.is_offline() && !self.has_microsoft_account() {
            return Err(AuthError::OfflineRequiresMicrosoft);
        }

        Ok(Some(account))
    }
}

/// A transient failure must keep the existing token discarding it because
/// Wi-Fi dropped would sign the user out of a working account
pub(crate) fn is_transient_auth_error(err: &AuthError) -> bool {
    matches!(
        err,
        AuthError::Minecraft(crate::error::MinecraftAuthError::RequestError { source, .. })
            if source.is_connect() || source.is_timeout()
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;

    use super::*;
    use crate::vault::tests::MemoryBackend;

    const ID: Uuid = Uuid::from_u128(7);

    fn account(refresh: &str) -> MinecraftAccount {
        MinecraftAccount {
            id: ID,
            username: "Steve".into(),
            access_token: "access-value".into(),
            refresh_token: refresh.into(),
            expires: Utc::now(),
            kind: AccountKind::Microsoft,
            signed_out: false,
        }
    }

    fn vault(dir: &std::path::Path, backend: &MemoryBackend) -> Vault {
        Vault::new(
            Some(Arc::new(backend.clone())),
            dir.join("auth.secrets.json"),
        )
    }

    #[tokio::test]
    async fn legacy_tokens_move_out_of_auth_json() {
        let dir = polyio::tempdir().await.unwrap();
        let path = dir.dir_path().join("auth.json");
        let mut legacy = HashMap::new();
        legacy.insert(ID, account("legacy-refresh"));
        polyio::write_json_atomic(
            &path,
            serde_json::json!({ "users": legacy, "default_user": null }),
        )
        .await
        .unwrap();
        let backend = MemoryBackend::default();

        let store = CredentialsStore::load_from(path.clone(), vault(dir.dir_path(), &backend))
            .await
            .unwrap();

        assert_eq!(store.users[&ID].refresh_token, "legacy-refresh");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("legacy-refresh"), "{on_disk}");
        assert!(!on_disk.contains("access-value"), "{on_disk}");

        let reloaded = CredentialsStore::load_from(path, vault(dir.dir_path(), &backend))
            .await
            .unwrap();
        assert_eq!(reloaded.users[&ID].refresh_token, "legacy-refresh");
        assert_eq!(reloaded.users[&ID].access_token, "access-value");
    }

    #[tokio::test]
    async fn removing_an_account_removes_its_secrets() {
        let dir = polyio::tempdir().await.unwrap();
        let path = dir.dir_path().join("auth.json");
        let backend = MemoryBackend::default();
        let mut store = CredentialsStore::load_from(path, vault(dir.dir_path(), &backend))
            .await
            .unwrap();
        store.users.insert(ID, account("refresh-value"));
        store.save().await.unwrap();
        let stored = String::from_utf8(backend.data.lock().unwrap().clone().unwrap()).unwrap();
        assert!(stored.contains("refresh-value"));

        store.remove_account(ID).await.unwrap();

        let stored = String::from_utf8(backend.data.lock().unwrap().clone().unwrap()).unwrap();
        assert!(!stored.contains("refresh-value"), "{stored}");
    }
}
