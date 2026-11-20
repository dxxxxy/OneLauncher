use std::path::PathBuf;

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
}

impl Default for InstanceSecurity {
    fn default() -> Self {
        Self {
            sandbox: true,
            microphone: None,
            localhost: false,
            grants: Vec::new(),
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

    /// Adds a folder unless it is one rats go after
    pub fn grant(&mut self, path: PathBuf, write: bool) -> Result<(), &'static str> {
        if let Some(reason) = oneclient_sandbox::sensitive_reason(&path) {
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
        assert!(
            security
                .grant(PathBuf::from(r"C:\Users\me\Downloads"), false)
                .is_ok()
        );
        assert_eq!(security.grants.len(), 1);
    }
}
