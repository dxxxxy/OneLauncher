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

use oneclient_broker::{Activity, ConfirmPrompt, PickRequest, RunningBroker};
use oneclient_common::paths;

pub use host::LauncherBrokerHost;
pub use settings::{FolderGrant, InstanceSecurity};

/// What the launcher's UI provides to the security layer; set once by the app
pub trait SecurityUi: Send + Sync + 'static {
    fn open_url(&self, url: &str);
    fn open_path(&self, path: &Path);
    /// Show the native picker. `Save` returns the destination the user chose
    fn pick(&self, request: PickRequest) -> oneclient_broker::BoxFuture<'_, Option<PathBuf>>;
    /// Ask the user a yes/no question over everything else
    fn confirm(&self, prompt: ConfirmPrompt) -> oneclient_broker::BoxFuture<'_, bool>;
    /// Bring the launcher's window to the front
    fn focus(&self);
    /// Select a file in the file manager; by default its folder is opened
    fn reveal(&self, file: &Path) {
        if let Some(folder) = file.parent() {
            self.open_path(folder);
        }
    }
}

const ACTIVITY_LIMIT: usize = 500;

#[derive(Default)]
pub struct SecurityService {
    ui: parking_lot::RwLock<Option<Arc<dyn SecurityUi>>>,
    activity: parking_lot::Mutex<VecDeque<Activity>>,
    brokers: parking_lot::Mutex<HashMap<i64, RunningBroker>>,
    discord_relays: parking_lot::Mutex<HashMap<i64, oneclient_broker::DiscordRelay>>,
    protection: parking_lot::Mutex<HashMap<i64, oneclient_sandbox::Protection>>,
    denied_seen: parking_lot::Mutex<std::collections::HashSet<(i64, String)>>,
    /// Discord connections showing a game's own rich presence, per game
    game_presences: parking_lot::Mutex<HashMap<i64, usize>>,
    /// Counts up whenever activity or protection changes, for views that
    /// show them live
    changes: tokio::sync::watch::Sender<u64>,
}

static GLOBAL: std::sync::OnceLock<Arc<SecurityService>> = std::sync::OnceLock::new();

/// Lets code without the launcher state (the log tail) report to the service
pub(crate) fn install_global(service: Arc<SecurityService>) {
    let _ = GLOBAL.set(service);
}

/// The path in a Java "access denied" line, if the line is one
pub(crate) fn denied_path(line: &str) -> Option<String> {
    for marker in ["AccessDeniedException: ", "FileNotFoundException: "] {
        let Some(at) = line.find(marker) else {
            continue;
        };
        let rest = line[at + marker.len()..].trim();
        if marker.starts_with("FileNotFound") {
            for suffix in [
                " (Access is denied)",
                " (Permission denied)",
                " (Operation not permitted)",
            ] {
                if let Some(path) = rest.strip_suffix(suffix) {
                    return Some(path.to_string());
                }
            }
            return None;
        }
        // AccessDeniedException may carry "-> other" or a reason after the path
        let path = rest.split(" -> ").next().unwrap_or(rest);
        let path = path.split(": ").next().unwrap_or(path);
        return Some(path.to_string());
    }
    None
}

/// Called for every game log line. The log is written by the game, so this
/// only ever informs: it never grants anything by itself
pub(crate) fn observe_log_line(cluster_id: i64, line: &str, events: &oneclient_events::EventBus) {
    let Some(service) = GLOBAL.get() else { return };
    let Some(path) = denied_path(line) else {
        return;
    };
    if !service
        .denied_seen
        .lock()
        .insert((cluster_id, path.clone()))
    {
        return;
    }
    let sandboxed = service
        .protection(cluster_id)
        .is_some_and(|p| p.is_sandboxed());
    if !sandboxed {
        return;
    }
    if let Some(reason) = oneclient_sandbox::sensitive_reason(Path::new(&path)) {
        service.push(Activity::now(
            cluster_id,
            oneclient_broker::ActivityKind::SensitiveAccess {
                path: path.clone(),
                caller: String::new(),
            },
        ));
        events
            .notify("Blocked a mod from reading private files")
            .body(format!(
                "A mod tried to read {path} ({reason}). The sandbox kept it out. Mods have no reason to read this; consider removing ones you don't trust."
            ))
            .error()
            .send();
    } else if !path.contains(".oneclient") {
        events
            .notify("A mod couldn't open a file")
            .body(format!(
                "The sandbox blocked {path}. If you trust the mod, share that folder in the instance's Security settings."
            ))
            .info()
            .send();
    }
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
        self.changed();
        tokio::spawn(append_to_disk(activity));
    }

    /// Wakes whenever activity or an instance's protection changes
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// An instance's security settings were saved: what's shown follows
    pub fn settings_changed(&self) {
        self.changed();
    }

    fn changed(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
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
        self.changed();
    }

    pub(crate) fn keep_broker(&self, cluster_id: i64, broker: RunningBroker) {
        self.brokers.lock().insert(cluster_id, broker);
    }

    pub(crate) fn keep_discord_relay(
        &self,
        cluster_id: i64,
        relay: oneclient_broker::DiscordRelay,
    ) {
        self.discord_relays.lock().insert(cluster_id, relay);
    }

    /// Counts a game's Discord connections showing an activity; whether any
    /// game shows one now
    pub(crate) fn game_presence(&self, cluster_id: i64, shown: bool) -> bool {
        let mut presences = self.game_presences.lock();
        let count = presences.entry(cluster_id).or_default();
        if shown {
            *count += 1;
        } else {
            *count = count.saturating_sub(1);
        }
        presences.retain(|_, count| *count > 0);
        !presences.is_empty()
    }

    /// When the game exits: its broker and Discord relay go with it
    pub(crate) fn drop_broker(&self, cluster_id: i64) {
        self.brokers.lock().remove(&cluster_id);
        self.discord_relays.lock().remove(&cluster_id);
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
        drop(log);
        self.changed();
    }
}

/// What a running game gets from the launcher, kept outside every sandbox
/// so a launcher started again while the game runs can serve it again.
/// Holds the broker's key and fake token
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct SavedSession {
    #[serde(default)]
    pub broker: Option<oneclient_broker::LaunchDescriptor>,
    /// The Discord relay the game was pointed at: the pipe on Windows, the
    /// socket on Unix
    #[serde(default)]
    pub discord: Option<PathBuf>,
    /// Windows: the AppContainer allowed to open the relay
    #[serde(default)]
    pub app_container_sid: Option<String>,
    /// How the sandbox protects the game, for the badge after a restart
    #[serde(default)]
    pub protection: Option<oneclient_sandbox::Protection>,
}

impl SavedSession {
    pub(crate) fn is_empty(&self) -> bool {
        self.broker.is_none() && self.discord.is_none() && self.protection.is_none()
    }

    pub(crate) async fn save(&self, cluster_id: i64) -> Result<(), polyio::IOError> {
        let path = session_file(cluster_id).map_err(std::io::Error::other)?;
        if let Some(parent) = path.parent() {
            polyio::create_dir_all(parent).await?;
        }
        polyio::write_json_atomic(&path, self).await
    }

    pub(crate) async fn load(cluster_id: i64) -> Option<Self> {
        let path = session_file(cluster_id).ok()?;
        Self::from_json(polyio::read_json::<serde_json::Value>(&path).await.ok()?)
    }

    fn from_json(value: serde_json::Value) -> Option<Self> {
        // launchers before the relay was saved wrote the bare descriptor
        if value.get("key").is_some() {
            return Some(Self {
                broker: serde_json::from_value(value).ok(),
                ..Self::default()
            });
        }
        serde_json::from_value(value).ok()
    }
}

/// A game that outlived the last launcher gets its broker back, on the same
/// channels and key, so its agent reconnects and it can keep joining
/// servers, and its Discord relay at the same address
pub(crate) async fn resume_session(
    state: &Arc<crate::state::LauncherState>,
    cluster: &oneclient_cluster::Cluster,
) {
    let Some(saved) = SavedSession::load(cluster.id).await else {
        return;
    };
    if let Some(protection) = saved.protection.clone() {
        state.security.set_protection(cluster.id, protection);
    }
    let Ok(cluster_dir) = cluster.dir() else {
        return;
    };
    let sandboxed = match &saved.protection {
        Some(protection) => protection.is_sandboxed(),
        None => InstanceSecurity::load(cluster.id).await.sandbox,
    };
    let host = Arc::new(LauncherBrokerHost::new(
        state,
        cluster,
        cluster_dir,
        sandboxed,
    ));
    if let Some(descriptor) = &saved.broker {
        match oneclient_broker::start(
            descriptor,
            host.clone(),
            state.services.requester.http().clone(),
        ) {
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
    if let Some(path) = &saved.discord {
        #[cfg(windows)]
        let relay = oneclient_broker::DiscordRelay::start_at(
            cluster.id,
            host,
            saved.app_container_sid.as_deref(),
            path,
        );
        #[cfg(unix)]
        let relay = match path.parent() {
            Some(dir) => oneclient_broker::DiscordRelay::start(cluster.id, host, dir.to_path_buf()),
            None => Err(std::io::ErrorKind::InvalidInput.into()),
        };
        match relay {
            Ok(relay) => {
                tracing::info!(cluster_id = cluster.id, "resumed the Discord relay");
                state.security.keep_discord_relay(cluster.id, relay);
            }
            Err(err) => tracing::warn!(
                cluster_id = cluster.id,
                "could not resume the Discord relay: {err}"
            ),
        }
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
/// The protection to show for an instance: the running game's own, or what
/// its next launch will get
pub async fn shown_protection(
    state: &crate::state::LauncherState,
    cluster_id: i64,
    folder_name: &str,
) -> oneclient_sandbox::Protection {
    if state.games.is_running(cluster_id)
        && let Some(live) = state.security.protection(cluster_id)
    {
        return live;
    }
    predicted_protection(&InstanceSecurity::load(cluster_id).await, folder_name).await
}

/// What the next launch with `settings` will get. Takes the settings rather
/// than reading them so a view that just changed one shows the result before
/// the file is written
pub async fn predicted_protection(
    settings: &InstanceSecurity,
    folder_name: &str,
) -> oneclient_sandbox::Protection {
    let (sandbox, localhost) = (settings.sandbox, settings.localhost);
    let microphone = match settings.microphone {
        Some(choice) => choice,
        None => match paths::cluster_mods_dir(folder_name) {
            Ok(mods) => has_voice_mod(&mods).await,
            Err(_) => false,
        },
    };
    // finding bubblewrap runs it once
    tokio::task::spawn_blocking(move || {
        oneclient_sandbox::expected_protection(sandbox, localhost, microphone)
    })
    .await
    .unwrap_or_else(|_| oneclient_sandbox::Protection::Off(String::new()))
}

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

#[cfg(test)]
mod tests {
    use super::{SavedSession, SecurityService, denied_path};

    #[test]
    fn the_launcher_presence_steps_aside_while_any_game_shows_one() {
        let security = SecurityService::default();
        assert!(security.game_presence(1, true));
        assert!(security.game_presence(2, true));
        assert!(security.game_presence(1, false));
        // a stray "stopped" never goes below none
        assert!(security.game_presence(1, false));
        assert!(!security.game_presence(2, false));
    }

    #[test]
    fn sessions_from_older_launchers_still_resume() {
        let descriptor = oneclient_broker::LaunchDescriptor::new(
            3,
            uuid::Uuid::from_u128(1),
            vec![],
            Some("S-1-15-2-1".into()),
            None,
        );
        let legacy = serde_json::to_value(&descriptor).unwrap();
        let saved = SavedSession::from_json(legacy).unwrap();
        assert_eq!(saved.broker.unwrap().key, descriptor.key);
        assert_eq!(saved.discord, None);

        let current = SavedSession {
            broker: None,
            discord: Some(r"\\.\pipe\oneclient-discord-1".into()),
            app_container_sid: Some("S-1-15-2-1".into()),
            protection: Some(oneclient_sandbox::Protection::Partial(vec!["x".into()])),
        };
        let back = SavedSession::from_json(serde_json::to_value(&current).unwrap()).unwrap();
        assert!(back.broker.is_none());
        assert_eq!(back.discord, current.discord);
        assert_eq!(back.app_container_sid, current.app_container_sid);
        assert_eq!(back.protection, current.protection);
    }

    #[test]
    fn finds_the_path_in_java_access_errors() {
        assert_eq!(
            denied_path(r"java.nio.file.AccessDeniedException: C:\Users\me\Downloads\a.png")
                .as_deref(),
            Some(r"C:\Users\me\Downloads\a.png")
        );
        assert_eq!(
            denied_path("java.io.FileNotFoundException: /home/me/.ssh/id_rsa (Permission denied)")
                .as_deref(),
            Some("/home/me/.ssh/id_rsa")
        );
        assert_eq!(
            denied_path("java.io.FileNotFoundException: config/x.json"),
            None
        );
        assert_eq!(denied_path("[Render thread/INFO]: all good"), None);
    }
}
