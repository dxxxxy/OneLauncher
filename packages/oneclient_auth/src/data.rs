use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    Microsoft,
    Offline,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MinecraftAccount {
    pub id: Uuid,
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires: DateTime<Utc>,
    #[serde(default = "default_account_kind")]
    pub kind: AccountKind,
    /// Microsoft rejected the refresh token the entry stays listed but cannot
    /// launch until the user signs in to it again
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signed_out: bool,
}

// tokens must never reach logs or panic messages through `{:?}`
impl std::fmt::Debug for MinecraftAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn redacted(token: &str) -> &'static str {
            if token.is_empty() {
                "<empty>"
            } else {
                "<redacted>"
            }
        }

        f.debug_struct("MinecraftAccount")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("access_token", &redacted(&self.access_token))
            .field("refresh_token", &redacted(&self.refresh_token))
            .field("expires", &self.expires)
            .field("kind", &self.kind)
            .field("signed_out", &self.signed_out)
            .finish()
    }
}

fn default_account_kind() -> AccountKind {
    AccountKind::Microsoft
}

impl MinecraftAccount {
    pub fn is_microsoft(&self) -> bool {
        self.kind == AccountKind::Microsoft
    }

    pub fn is_offline(&self) -> bool {
        self.kind == AccountKind::Offline
    }

    pub fn needs_sign_in(&self) -> bool {
        self.is_microsoft() && self.signed_out
    }

    pub fn is_expired(&self) -> bool {
        self.expires <= Utc::now() + chrono::TimeDelta::seconds(60)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceCodeLogin {
    pub user_code: String,
    pub device_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BrowserLogin {
    pub auth_url: String,
    pub state: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MicrosoftLoginSession {
    pub browser: BrowserLogin,
    pub device: DeviceCodeLogin,
}

impl MicrosoftLoginSession {
    pub fn dedupe_key(&self) -> &str {
        &self.browser.state
    }

    pub fn auth_url(&self) -> &str {
        &self.browser.auth_url
    }

    pub fn user_code(&self) -> &str {
        &self.device.user_code
    }

    pub fn verification_uri(&self) -> &str {
        &self.device.verification_uri
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_tokens() {
        let account = MinecraftAccount {
            id: Uuid::nil(),
            username: "Steve".to_string(),
            access_token: "secret-access".to_string(),
            refresh_token: "secret-refresh".to_string(),
            expires: Utc::now(),
            kind: AccountKind::Microsoft,
            signed_out: false,
        };

        let printed = format!("{account:?}");

        assert!(!printed.contains("secret-access"), "{printed}");
        assert!(!printed.contains("secret-refresh"), "{printed}");
        assert!(printed.contains("Steve"), "{printed}");
    }
}
