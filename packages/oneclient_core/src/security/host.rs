use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneclient_auth::AuthService;
use oneclient_broker::{
    Activity, ActivityKind, BoxFuture, BrokerHost, ConfirmPrompt, GameAccount, OpenTarget,
    PickMode, PickRequest, WantedDownload,
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
    /// Watching the user's Downloads folder for a file a mod waits for
    downloads_watch: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    discord: oneclient_discord::DiscordRpc,
}

impl Drop for LauncherBrokerHost {
    fn drop(&mut self) {
        if let Some(watch) = self.downloads_watch.get_mut().take() {
            watch.abort();
        }
    }
}

/// How long the launcher waits for an answer before refusing
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);
/// Further drops from the same folder within this time don't ask again
const IMPORT_GRACE: Duration = Duration::from_secs(30);
/// How long a mod may wait for the user to download a file
const DOWNLOAD_WATCH: Duration = Duration::from_secs(15 * 60);

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
            downloads_watch: parking_lot::Mutex::new(None),
            discord: state.discord.clone(),
        }
    }
}

/// Waits for `wanted` to show up in `downloads` and copies it into `into`.
/// Only a file with exactly the size and hash the mod named is copied, so
/// the game learns nothing else about the folder
async fn watch_downloads(
    downloads: PathBuf,
    into: PathBuf,
    wanted: WantedDownload,
) -> Option<(PathBuf, PathBuf)> {
    let until = Instant::now() + DOWNLOAD_WATCH;
    // files already hashed, by name and modification time
    let mut seen = std::collections::HashSet::new();
    while Instant::now() < until {
        if let Ok(mut entries) = tokio::fs::read_dir(&downloads).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                let extension = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase());
                if extension.as_deref() != Some(wanted.extension.as_str()) {
                    continue;
                }
                let Ok(metadata) = entry.metadata().await else {
                    continue;
                };
                if !metadata.is_file() || metadata.len() != wanted.size {
                    continue;
                }
                if !seen.insert((path.clone(), metadata.modified().ok())) {
                    continue;
                }
                if polyio::sha1_file(&path).await.ok().as_deref() != Some(wanted.sha1.as_str()) {
                    continue;
                }
                let name = path.file_name()?.to_owned();
                tokio::fs::create_dir_all(&into).await.ok()?;
                // the mod watches the folder: it should only ever see the whole file
                let part = into.join(format!(".{}.part", uuid::Uuid::new_v4().simple()));
                tokio::fs::copy(&path, &part).await.ok()?;
                let copy = into.join(name);
                if tokio::fs::rename(&part, &copy).await.is_err() {
                    let _ = tokio::fs::remove_file(&part).await;
                    return None;
                }
                return Some((path, copy));
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    None
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

    fn accounts(&self) -> BoxFuture<'_, Vec<GameAccount>> {
        Box::pin(async move {
            self.auth
                .list_accounts()
                .await
                .into_iter()
                // the broker only has tokens for Microsoft accounts
                .filter(|a| a.kind == oneclient_auth::AccountKind::Microsoft && !a.signed_out)
                .map(|a| GameAccount {
                    id: a.id.to_string(),
                    name: a.username,
                })
                .collect()
        })
    }

    fn switch_account(&self, to: Uuid) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let account = self
                .auth
                .get_account(to)
                .await
                .filter(|a| a.kind == oneclient_auth::AccountKind::Microsoft && !a.signed_out)
                .ok_or("that isn't one of your OneClient accounts")?;
            // a launcher restart picks the broker back up as this account
            if let Some(mut saved) = super::SavedSession::load(self.cluster_id).await
                && let Some(descriptor) = &mut saved.broker
            {
                descriptor.account = to;
                let _ = saved.save(self.cluster_id).await;
            }
            self.events
                .notify(format!("Switched account in {}", self.cluster_name))
                .body(format!("The game now plays as {}.", account.username))
                .info()
                .send();
            Ok(())
        })
    }

    fn add_account(&self) {
        if let Some(ui) = self.security.ui() {
            ui.focus();
        }
        self.events
            .notify("Add the account in OneClient")
            .body("Open Settings, then Accounts, and sign in there. The game lists the new account right after.")
            .info()
            .send();
    }

    fn watch_downloads(&self, wanted: Option<WantedDownload>) {
        let mut slot = self.downloads_watch.lock();
        if let Some(previous) = slot.take() {
            previous.abort();
        }
        let Some(wanted) = wanted else {
            return;
        };
        if !self.sandboxed {
            return;
        }
        let Some(downloads) = directories::UserDirs::new()
            .and_then(|dirs| dirs.download_dir().map(Path::to_path_buf))
        else {
            return;
        };
        // where the mod looks: Downloads in the game's own home folder
        let into = self
            .cluster_dir
            .join(".oneclient")
            .join("home")
            .join("Downloads");
        let cluster_id = self.cluster_id;
        let cluster_name = self.cluster_name.clone();
        let events = self.events.clone();
        let security = Arc::clone(&self.security);
        *slot = Some(tokio::spawn(async move {
            let caller = wanted.caller.clone();
            let Some((from, copy)) = watch_downloads(downloads, into, wanted).await else {
                return;
            };
            let name = copy
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            events
                .notify(format!("Gave {cluster_name} your download"))
                .body(format!("{name} is in the game now."))
                .info()
                .send();
            security.push(Activity::now(
                cluster_id,
                ActivityKind::Imported {
                    from: from.display().to_string(),
                    to: Some(copy.display().to_string()),
                    caller,
                },
            ));
        }));
    }

    fn game_presence(&self, shown: bool) {
        let any = self.security.game_presence(self.cluster_id, shown);
        self.discord.set_hidden(any);
    }

    fn reveal(&self, file: PathBuf) {
        if let Some(ui) = self.security.ui() {
            ui.reveal(&file);
        }
    }

    fn trash(&self, path: PathBuf) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            // the recycle bin doesn't take `\\?\` paths
            let path = dunce::simplified(&path).to_path_buf();
            let shown = path.display().to_string();
            match tokio::task::spawn_blocking(move || trash::delete(&path)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => {
                    tracing::warn!(
                        cluster_id = self.cluster_id,
                        "couldn't trash {shown}: {err}"
                    );
                    Err(format!("couldn't move it to the trash: {err}"))
                }
                Err(err) => Err(err.to_string()),
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_the_exact_download_is_handed_over() {
        let root = std::env::temp_dir().join(format!("oneclient-downloads-{}", Uuid::new_v4()));
        let downloads = root.join("Downloads");
        let into = root.join("instance");
        std::fs::create_dir_all(&downloads).unwrap();
        // same size and extension, other content; still downloading; the one
        std::fs::write(downloads.join("decoy.zip"), b"other").unwrap();
        std::fs::write(downloads.join("pack.zip.crdownload"), b"right").unwrap();
        std::fs::write(downloads.join("Pack.ZIP"), b"right").unwrap();
        let sha1 = polyio::sha1_file(downloads.join("Pack.ZIP")).await.unwrap();

        let wanted = WantedDownload::new("zip", 5, &sha1, "resourcify".into()).unwrap();
        let (from, copy) = watch_downloads(downloads.clone(), into.clone(), wanted)
            .await
            .unwrap();
        assert_eq!(from, downloads.join("Pack.ZIP"));
        assert_eq!(copy, into.join("Pack.ZIP"));
        assert_eq!(std::fs::read(&copy).unwrap(), b"right");
        // nothing else, and no leftovers
        assert_eq!(std::fs::read_dir(&into).unwrap().count(), 1);

        let _ = std::fs::remove_dir_all(root);
    }
}
