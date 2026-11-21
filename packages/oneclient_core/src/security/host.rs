use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneclient_auth::AuthService;
use oneclient_broker::{
    Activity, ActivityKind, BoxFuture, BrokerHost, ConfirmPrompt, OpenTarget, PickMode, PickRequest,
};
use oneclient_events::EventBus;
use uuid::Uuid;

use super::SecurityService;

/// The launcher side of one game's broker
pub struct LauncherBrokerHost {
    pub(crate) cluster_id: i64,
    pub(crate) cluster_name: String,
    /// The instance's own folder; picked files are copied in here
    pub(crate) cluster_dir: PathBuf,
    pub(crate) sandboxed: bool,
    pub(crate) auth: Arc<AuthService>,
    pub(crate) events: EventBus,
    pub(crate) security: Arc<SecurityService>,
    /// The folder the user last agreed to import from, and when: dropping
    /// several files at once asks once
    recent_import: parking_lot::Mutex<Option<(PathBuf, Instant)>>,
}

/// How long the launcher waits for an answer before refusing
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);
/// Further drops from the same folder within this time don't ask again
const IMPORT_GRACE: Duration = Duration::from_secs(30);

impl LauncherBrokerHost {
    pub(crate) fn new(
        state: &Arc<crate::state::LauncherState>,
        cluster: &oneclient_cluster::Cluster,
        cluster_dir: PathBuf,
        sandboxed: bool,
    ) -> Self {
        Self {
            cluster_id: cluster.id,
            cluster_name: cluster.name.clone(),
            cluster_dir,
            sandboxed,
            auth: Arc::clone(&state.auth),
            events: state.services.events.clone(),
            security: Arc::clone(&state.security),
            recent_import: parking_lot::Mutex::new(None),
        }
    }
}

impl BrokerHost for LauncherBrokerHost {
    fn real_token(&self, account: Uuid) -> BoxFuture<'_, Result<String, String>> {
        Box::pin(async move {
            // renews when expired, so a game never loses its session mid-play
            self.auth
                .account_for_launch(account)
                .await
                .map(|account| account.access_token)
                .map_err(|e| e.to_string())
        })
    }

    fn record(&self, activity: Activity) {
        match &activity.kind {
            ActivityKind::Alarm { reason, caller, .. } => {
                tracing::warn!(cluster_id = self.cluster_id, %reason, %caller, "rat alarm");
                self.events
                    .notify(format!("Blocked a mod in {}", self.cluster_name))
                    .body(format!(
                        "{}. OneClient stopped it and your account is safe. Mod: {}. If you didn't expect this, close the game and remove mods you don't trust.",
                        capitalise(reason),
                        caller_label(caller)
                    ))
                    .error()
                    .send();
            }
            ActivityKind::SensitiveAccess { path, caller } => {
                self.events
                    .notify(format!("Blocked a mod in {}", self.cluster_name))
                    .body(format!(
                        "A mod ({}) tried to read {path}. The sandbox kept it out.",
                        caller_label(caller)
                    ))
                    .error()
                    .send();
            }
            ActivityKind::Join { caller, .. } if caller != "minecraft" => {
                self.events
                    .notify("Signed in to a mod's server")
                    .body(format!(
                        "{} verified your Minecraft account with its server.",
                        caller_label(caller)
                    ))
                    .info()
                    .send();
            }
            ActivityKind::JoinLimited { caller } => {
                self.events
                    .notify("Slowed down server sign-ins")
                    .body(format!(
                        "{} signed in to servers unusually often, so OneClient paused it.",
                        caller_label(caller)
                    ))
                    .error()
                    .send();
            }
            ActivityKind::BadHandshake => {
                tracing::warn!(
                    cluster_id = self.cluster_id,
                    "rejected a broker connection without the launch key"
                );
            }
            _ => {}
        }
        self.security.push(activity);
    }

    fn open(&self, target: OpenTarget) {
        let Some(ui) = self.security.ui() else {
            return;
        };
        match target {
            OpenTarget::Url(url) => ui.open_url(url.as_str()),
            OpenTarget::Path(path) => ui.open_path(&path),
        }
    }

    fn pick(&self, request: PickRequest) -> BoxFuture<'_, Option<PathBuf>> {
        Box::pin(async move {
            let ui = self.security.ui()?;
            let mode = request.mode;
            let chosen = ui.pick(request).await?;
            if let Some(reason) = oneclient_sandbox::sensitive_reason(&chosen) {
                self.events
                    .notify("Can't share that with the game")
                    .body(format!(
                        "That location holds {reason}, so OneClient won't give a game access to it."
                    ))
                    .error()
                    .send();
                return None;
            }
            if !self.sandboxed {
                return Some(chosen);
            }
            match mode {
                PickMode::OpenFile => self.copy_in(&chosen).await,
                PickMode::SaveFile => Some(self.export(chosen).await),
                PickMode::OpenFolder => self.share_folder(chosen).await,
            }
        })
    }

    fn confirm(&self, mut prompt: ConfirmPrompt) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            prompt.body = format!("{}\n\nInstance: {}", prompt.body, self.cluster_name);
            let Some(ui) = self.security.ui() else {
                return false;
            };
            tokio::time::timeout(CONFIRM_TIMEOUT, ui.confirm(prompt))
                .await
                .unwrap_or(false)
        })
    }

    fn import(&self, from: PathBuf, _caller: String) -> BoxFuture<'_, Option<PathBuf>> {
        Box::pin(async move {
            if !self.sandboxed || !from.is_absolute() {
                return None;
            }
            if let Some(reason) = oneclient_sandbox::sensitive_reason(&from) {
                self.events
                    .notify(format!("Blocked a mod in {}", self.cluster_name))
                    .body(format!(
                        "The game asked to copy in a file that holds {reason}. OneClient refused."
                    ))
                    .error()
                    .send();
                return None;
            }
            // only files: a folder could be the whole user profile
            if !tokio::fs::metadata(&from).await.ok()?.is_file() {
                return None;
            }
            let folder = from.parent()?.to_path_buf();
            let name = from.file_name()?.to_string_lossy().to_string();
            let recent = matches!(
                &*self.recent_import.lock(),
                Some((dir, at)) if *dir == folder && at.elapsed() < IMPORT_GRACE
            );
            if !recent {
                let allowed = self
                    .confirm(ConfirmPrompt {
                        title: format!("Copy {name} into {}?", self.cluster_name),
                        body: format!(
                            "The game says you dropped this file onto its window:\n\n{}\n\nOneClient will copy it into the instance so the game can open it. If you didn't just drag a file into the game, choose Don't allow: a mod may be trying to read your files.",
                            from.display()
                        ),
                        allow: "Copy it in".into(),
                    })
                    .await;
                if !allowed {
                    return None;
                }
            }
            *self.recent_import.lock() = Some((folder, Instant::now()));
            self.copy_in(&from).await
        })
    }
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn caller_label(caller: &str) -> String {
    if caller.is_empty() || caller == "minecraft" {
        "an unknown mod".into()
    } else {
        // a class name; the package usually names the mod
        caller.to_string()
    }
}

fn unique_in(dir: &Path, name: &std::ffi::OsStr) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let stem = Path::new(name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let ext = Path::new(name)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (1..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
}

impl LauncherBrokerHost {
    /// The sandbox can't see the user's files, so a picked file is copied
    /// into the instance and the game gets the copy
    async fn copy_in(&self, chosen: &Path) -> Option<PathBuf> {
        let dir = self.cluster_dir.join(".oneclient").join("imports");
        polyio::create_dir_all(&dir).await.ok()?;
        let target = unique_in(&dir, chosen.file_name()?);
        polyio::copy(chosen, &target).await.ok()?;
        Some(target)
    }

    /// The game writes inside the instance; once the file settles it is
    /// moved to where the user asked
    async fn export(&self, destination: PathBuf) -> PathBuf {
        let dir = self.cluster_dir.join(".oneclient").join("exports");
        let _ = polyio::create_dir_all(&dir).await;
        let staging = unique_in(&dir, destination.file_name().unwrap_or_default());
        let events = self.events.clone();
        let watch = staging.clone();
        tokio::spawn(async move {
            let mut last = None;
            for _ in 0..(30 * 60) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let size = std::fs::metadata(&watch).ok().map(|m| m.len());
                if size.is_some() && size == last {
                    if polyio::copy(&watch, &destination).await.is_ok() {
                        let _ = polyio::remove_file(&watch).await;
                        events
                            .notify("Saved from the game")
                            .body(destination.display().to_string())
                            .info()
                            .send();
                    }
                    return;
                }
                last = size;
            }
        });
        staging
    }

    async fn share_folder(&self, chosen: PathBuf) -> Option<PathBuf> {
        let mut settings = super::InstanceSecurity::load(self.cluster_id).await;
        if settings.grant(chosen.clone(), false).is_ok() {
            let _ = settings.save(self.cluster_id).await;
        }
        match oneclient_sandbox::grant_live(self.cluster_id, &chosen, false) {
            Ok(true) => Some(chosen),
            _ => {
                self.events
                    .notify("Folder shared from the next launch")
                    .body(format!(
                        "{} will be available to this instance after you restart the game.",
                        chosen.display()
                    ))
                    .info()
                    .send();
                None
            }
        }
    }
}
