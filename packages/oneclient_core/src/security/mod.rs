//! Keeps mods away from the account and the user's files
//!
//! Every launch of a Microsoft account goes through the token broker (the
//! game only ever holds a fake token) and, unless the user opted the
//! instance out, the OS sandbox (the game only sees its instance). This
//! module joins the two to the launcher: per-instance settings, the security
//! activity log, and the broker's view of the user's desktop.

mod host;
mod settings;

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneclient_broker::{Activity, PickMode, RunningBroker};
use oneclient_common::paths;

pub use host::LauncherBrokerHost;
pub use settings::{FolderGrant, InstanceSecurity};

/// What the launcher's UI provides to the security layer; set once by the app
pub trait SecurityUi: Send + Sync + 'static {
    fn open_url(&self, url: &str);
    fn open_path(&self, path: &Path);
    /// Show the native picker. `Save` returns the destination the user chose
    fn pick(
        &self,
        mode: PickMode,
        title: String,
    ) -> oneclient_broker::BoxFuture<'_, Option<PathBuf>>;
}

const ACTIVITY_LIMIT: usize = 500;

#[derive(Default)]
pub struct SecurityService {
    ui: parking_lot::RwLock<Option<Arc<dyn SecurityUi>>>,
    activity: parking_lot::Mutex<VecDeque<Activity>>,
    brokers: parking_lot::Mutex<HashMap<i64, RunningBroker>>,
    protection: parking_lot::Mutex<HashMap<i64, oneclient_sandbox::Protection>>,
}

impl SecurityService {
    pub fn set_ui(&self, ui: Arc<dyn SecurityUi>) {
        *self.ui.write() = Some(ui);
    }

    pub(crate) fn ui(&self) -> Option<Arc<dyn SecurityUi>> {
        self.ui.read().clone()
    }

    /// Newest first
    pub fn activity(&self) -> Vec<Activity> {
        self.activity.lock().iter().rev().cloned().collect()
    }

    pub fn activity_for(&self, cluster_id: i64) -> Vec<Activity> {
        self.activity
            .lock()
            .iter()
            .rev()
            .filter(|a| a.cluster_id == cluster_id)
            .cloned()
            .collect()
    }

    pub(crate) fn push(&self, activity: Activity) {
        let mut log = self.activity.lock();
        if log.len() >= ACTIVITY_LIMIT {
            log.pop_front();
        }
        log.push_back(activity.clone());
        drop(log);
        tokio::spawn(append_to_disk(activity));
    }

    /// How the running (or last) launch of an instance is protected
    pub fn protection(&self, cluster_id: i64) -> Option<oneclient_sandbox::Protection> {
        self.protection.lock().get(&cluster_id).cloned()
    }

    pub(crate) fn set_protection(
        &self,
        cluster_id: i64,
        protection: oneclient_sandbox::Protection,
    ) {
        self.protection.lock().insert(cluster_id, protection);
    }

    pub(crate) fn keep_broker(&self, cluster_id: i64, broker: RunningBroker) {
        self.brokers.lock().insert(cluster_id, broker);
    }

    pub(crate) fn drop_broker(&self, cluster_id: i64) {
        self.brokers.lock().remove(&cluster_id);
        if let Ok(path) = session_file(cluster_id) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Earlier activity survives launcher restarts
    pub async fn load_history(&self) {
        let Ok(path) = activity_file() else { return };
        let Ok(text) = polyio::read_to_string(&path).await else {
            return;
        };
        let mut log = self.activity.lock();
        for line in text
            .lines()
            .rev()
            .take(ACTIVITY_LIMIT)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            if let Ok(activity) = serde_json::from_str::<Activity>(line) {
                log.push_back(activity);
            }
        }
    }
}

/// A game that outlived the last launcher gets its broker back, on the same
/// channels and key, so its agent reconnects and it can keep joining servers
pub(crate) async fn resume_broker(
    state: &Arc<crate::state::LauncherState>,
    cluster: &oneclient_cluster::Cluster,
) {
    let Ok(path) = session_file(cluster.id) else {
        return;
    };
    let Ok(descriptor) = polyio::read_json::<oneclient_broker::LaunchDescriptor>(&path).await
    else {
        return;
    };
    let Ok(cluster_dir) = cluster.dir() else {
        return;
    };
    let host = Arc::new(LauncherBrokerHost {
        cluster_id: cluster.id,
        cluster_name: cluster.name.clone(),
        cluster_dir,
        sandboxed: InstanceSecurity::load(cluster.id).await.sandbox,
        auth: Arc::clone(&state.auth),
        events: state.services.events.clone(),
        security: Arc::clone(&state.security),
    });
    match oneclient_broker::start(&descriptor, host, state.services.requester.http().clone()) {
        Ok(running) => {
            tracing::info!(
                cluster_id = cluster.id,
                "resumed the token broker for a running game"
            );
            state.security.keep_broker(cluster.id, running);
        }
        Err(err) => tracing::warn!(
            cluster_id = cluster.id,
            "could not resume the token broker: {err}"
        ),
    }
}

pub(crate) fn security_dir() -> oneclient_common::PathsResult<PathBuf> {
    Ok(paths::data_dir()?.join("security"))
}

fn activity_file() -> oneclient_common::PathsResult<PathBuf> {
    Ok(security_dir()?.join("activity.jsonl"))
}

/// The broker's launch descriptor, kept outside every sandbox so a game
/// that outlives the launcher can be served again after a restart
pub(crate) fn session_file(cluster_id: i64) -> oneclient_common::PathsResult<PathBuf> {
    Ok(security_dir()?
        .join("sessions")
        .join(format!("{cluster_id}.json")))
}

async fn append_to_disk(activity: Activity) {
    use tokio::io::AsyncWriteExt;
    let Ok(path) = activity_file() else { return };
    if let Some(parent) = path.parent() {
        let _ = polyio::create_dir_all(parent).await;
    }
    let Ok(mut line) = serde_json::to_string(&activity) else {
        return;
    };
    line.push('\n');
    if let Ok(mut file) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
    {
        let _ = file.write_all(line.as_bytes()).await;
    }
}

/// A voice chat mod in the instance means the game legitimately needs the
/// microphone
pub(crate) async fn has_voice_mod(mods_dir: &Path) -> bool {
    let Ok(mut entries) = polyio::read_dir(mods_dir).await else {
        return false;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if name.ends_with(".jar")
            && [
                "voicechat",
                "plasmovoice",
                "plasmo-voice",
                "simple-voice-chat",
            ]
            .iter()
            .any(|id| name.contains(id))
        {
            return true;
        }
    }
    false
}
