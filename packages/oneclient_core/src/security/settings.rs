use std::path::PathBuf;

use oneclient_broker::{ChangeKind, ChangeRule};
use serde::{Deserialize, Serialize};

/// Per-instance security choices. Stored in the launcher's data folder, never
/// inside the instance: a sandboxed game must not be able to switch its own
/// sandbox off
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InstanceSecurity {
    pub sandbox: bool,
    /// `None` grants it automatically when a voice chat mod is installed
    pub microphone: Option<bool>,
    pub localhost: bool,
    pub grants: Vec<FolderGrant>,
    /// What mods may change on the Minecraft profile without asking. Names
    /// are refused by default: one rename can't be undone for 30 days and
    /// frees the old name for anyone to take
    pub skin_changes: ChangeRule,
    pub name_changes: ChangeRule,
    pub cape_changes: ChangeRule,
}

impl Default for InstanceSecurity {
    fn default() -> Self {
        Self {
            sandbox: true,
            microphone: None,
            localhost: false,
            grants: Vec::new(),
            skin_changes: ChangeRule::Allow,
            name_changes: ChangeRule::Deny,
            cape_changes: ChangeRule::Allow,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderGrant {
    pub path: PathBuf,
    pub write: bool,
}

fn file(cluster_id: i64) -> oneclient_common::PathsResult<PathBuf> {
    Ok(super::security_dir()?
        .join("instances")
        .join(format!("{cluster_id}.json")))
}

impl InstanceSecurity {
    pub async fn load(cluster_id: i64) -> Self {
        let Ok(path) = file(cluster_id) else {
            return Self::default();
        };
        polyio::read_json(&path).await.unwrap_or_default()
    }

    pub async fn save(&self, cluster_id: i64) -> Result<(), String> {
        let path = file(cluster_id).map_err(|e| e.to_string())?;
        if let Some(parent) = path.parent() {
            polyio::create_dir_all(parent)
                .await
                .map_err(|e| e.to_string())?;
        }
        polyio::write_json_atomic(&path, self)
            .await
            .map_err(|e| e.to_string())
    }

    /// The rule for an account change. The rest (purchases, codes, account
    /// settings) has no setting and always asks
    pub fn change_rule(&self, kind: ChangeKind) -> ChangeRule {
        match kind {
            ChangeKind::Skin => self.skin_changes,
            ChangeKind::Name => self.name_changes,
            ChangeKind::Cape => self.cape_changes,
            _ => ChangeRule::Ask,
        }
    }

    /// Adds a folder unless it is, or holds, one rats go after
    pub fn grant(&mut self, path: PathBuf, write: bool) -> Result<(), &'static str> {
        if let Some(reason) = oneclient_sandbox::grant_refusal(&path) {
            return Err(reason);
        }
        self.grants.retain(|g| g.path != path);
        self.grants.push(FolderGrant { path, write });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandboxed_by_default_and_refuses_sensitive_grants() {
        let mut security = InstanceSecurity::default();
        assert!(security.sandbox);
        assert!(
            security
                .grant(
                    PathBuf::from(r"C:\Users\me\AppData\Local\Google\Chrome\User Data"),
                    false
                )
                .is_err()
        );
        // nor anything that holds one
        let dirs = directories::BaseDirs::new().unwrap();
        for holds in [
            dirs.home_dir(),
            dirs.home_dir().parent().unwrap(),
            dirs.config_dir(),
            std::path::Path::new(r"C:\Users\me\AppData\Local\Google"),
        ] {
            assert!(
                security.grant(holds.to_path_buf(), false).is_err(),
                "{}",
                holds.display()
            );
        }
        assert!(
            security
                .grant(PathBuf::from(r"C:\Users\me\Downloads"), false)
                .is_ok()
        );
        assert_eq!(security.grants.len(), 1);
    }

    #[test]
    fn names_are_refused_and_other_profile_changes_allowed_by_default() {
        let mut security: InstanceSecurity = serde_json::from_str(r#"{"sandbox":true}"#).unwrap();
        assert_eq!(security.change_rule(ChangeKind::Cape), ChangeRule::Allow);
        assert_eq!(security.change_rule(ChangeKind::Skin), ChangeRule::Allow);
        assert_eq!(security.change_rule(ChangeKind::Name), ChangeRule::Deny);
        assert_eq!(security.change_rule(ChangeKind::Purchases), ChangeRule::Ask);
        security.name_changes = ChangeRule::Ask;
        let saved: InstanceSecurity =
            serde_json::from_str(&serde_json::to_string(&security).unwrap()).unwrap();
        assert_eq!(saved.change_rule(ChangeKind::Name), ChangeRule::Ask);
    }
}
