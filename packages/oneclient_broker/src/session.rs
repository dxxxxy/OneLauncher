//! One connection from one game: authenticate the agent, then answer its
//! requests through the policy

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use url::Url;
use uuid::Uuid;

use crate::activity::{Activity, ActivityKind};
use crate::limiter::{JoinLimiter, Take};
use crate::policy::{self, AccountChange, ChangeKind, Decision, Route, TokenPlacement};
use crate::protocol::{self, GameAccount, PickFilter, PickMode, Reply, Request};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the launcher provides to a broker session
pub trait BrokerHost: Send + Sync + 'static {
    /// The account's current, refreshed access token
    fn real_token(&self, account: Uuid) -> BoxFuture<'_, Result<String, String>>;
    fn record(&self, activity: Activity);
    /// Open an already-validated `http(s)` URL or local folder for the user
    fn open(&self, target: OpenTarget);
    /// Show a native picker outside the sandbox and make the choice reachable
    /// from inside it
    fn pick(&self, request: PickRequest) -> BoxFuture<'_, Option<PathBuf>>;
    /// Ask the user, in the launcher, whether the game may do something.
    /// `false` when nobody answers
    fn confirm(&self, _prompt: ConfirmPrompt) -> BoxFuture<'_, bool> {
        Box::pin(async { false })
    }
    /// A file the user dropped on the game window: copy it somewhere the
    /// game can read, once the user agrees, and return the copy
    fn import(&self, _from: PathBuf, _caller: String) -> BoxFuture<'_, Option<PathBuf>> {
        Box::pin(async { None })
    }
    /// The user's accounts the game may switch to
    fn accounts(&self) -> BoxFuture<'_, Vec<GameAccount>> {
        Box::pin(async { Vec::new() })
    }
    /// The game now plays as `to`, one of [`Self::accounts`]; the broker
    /// answers with that account's token from here on
    fn switch_account(&self, _to: Uuid) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async { Err("switching accounts isn't available".into()) })
    }
    /// Show the launcher's own way to add an account
    fn add_account(&self) {}
    /// Select an already-validated file inside the instance in the user's
    /// file manager; by default its folder is opened
    fn reveal(&self, file: PathBuf) {
        if let Some(folder) = file.parent() {
            self.open(OpenTarget::Path(folder.to_path_buf()));
        }
    }
    /// Move an already-validated file or folder inside the instance to the
    /// user's trash
    fn trash(&self, _path: PathBuf) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async { Err("the trash isn't available".into()) })
    }
    /// Watch the user's real Downloads folder for this one file and copy it
    /// where the game waits for it; `None` stops watching
    fn watch_downloads(&self, _wanted: Option<WantedDownload>) {}
    /// One of the game's Discord connections started (`true`) or stopped
    /// showing an activity, so the launcher can step its own presence aside
    fn game_presence(&self, _shown: bool) {}
}

/// A file a mod sent the user to download in their browser. Only a file
/// with exactly this content is ever handed to the game
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WantedDownload {
    /// Lowercase, without the dot
    pub extension: String,
    pub size: u64,
    /// Lowercase hex
    pub sha1: String,
    pub caller: String,
}

impl WantedDownload {
    /// Downloads bigger than this aren't watched for
    pub const MAX_SIZE: u64 = 1024 * 1024 * 1024;

    pub fn new(extension: &str, size: u64, sha1: &str, caller: String) -> Option<Self> {
        let extension = extension.trim_start_matches('.').to_ascii_lowercase();
        let sha1 = sha1.to_ascii_lowercase();
        let valid = !extension.is_empty()
            && extension.len() <= 16
            && extension.chars().all(|c| c.is_ascii_alphanumeric())
            && sha1.len() == 40
            && sha1.chars().all(|c| c.is_ascii_hexdigit())
            && size > 0
            && size <= Self::MAX_SIZE;
        valid.then_some(Self {
            extension,
            size,
            sha1,
            caller,
        })
    }
}

/// A yes/no question for the user, shown by the launcher
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmPrompt {
    pub title: String,
    pub body: String,
    /// The label of the button that says yes; the other one always refuses
    pub allow: String,
}

/// What the game asked its picker for
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickRequest {
    pub mode: PickMode,
    pub title: String,
    pub filters: Vec<PickFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenTarget {
    Url(Url),
    Path(PathBuf),
}

#[derive(Clone)]
pub struct SessionConfig {
    pub cluster_id: i64,
    pub account: Uuid,
    pub key: String,
    pub fake_token: String,
    /// Folders the game may ask to have opened
    pub open_roots: Vec<PathBuf>,
    pub http: reqwest::Client,
}

pub(crate) struct Shared {
    pub config: SessionConfig,
    pub host: Arc<dyn BrokerHost>,
    pub joins: Mutex<JoinLimiter>,
    /// Account changes the user allowed, and when, so a wardrobe doesn't
    /// ask for every cape tried on
    allowed: Mutex<HashMap<ChangeKind, Instant>>,
    /// One question at a time: a burst of requests waits for the first answer
    asking: tokio::sync::Mutex<()>,
    /// The account the game plays as; an in-game switcher can change it
    account: Mutex<Uuid>,
}

/// How long an approval covers more changes of the same kind
const ALLOWED_FOR: Duration = Duration::from_secs(10 * 60);

impl Shared {
    pub fn new(config: SessionConfig, host: Arc<dyn BrokerHost>) -> Arc<Self> {
        Arc::new(Self {
            host,
            joins: Mutex::new(JoinLimiter::standard()),
            allowed: Mutex::new(HashMap::new()),
            asking: tokio::sync::Mutex::new(()),
            account: Mutex::new(config.account),
            config,
        })
    }

    pub fn account(&self) -> Uuid {
        self.account
            .lock()
            .map(|a| *a)
            .unwrap_or(self.config.account)
    }

    /// Runs the question for a request to `path` on the profile host
    #[cfg(test)]
    pub async fn ask_for_test(&self, method: &str, path: &str) -> bool {
        let url = Url::parse(&format!("https://api.minecraftservices.com{path}")).unwrap();
        let Decision::Confirm { change, .. } = policy::decide(method, &url) else {
            panic!("{method} {path} doesn't ask");
        };
        self.ask(&change, "").await
    }

    fn recently_allowed(&self, kind: ChangeKind) -> bool {
        kind.remembered()
            && self
                .allowed
                .lock()
                .ok()
                .and_then(|a| a.get(&kind).copied())
                .is_some_and(|at| at.elapsed() < ALLOWED_FOR)
    }

    /// Asks the user whether the game may make this change
    async fn ask(&self, change: &AccountChange, caller: &str) -> bool {
        let _one_at_a_time = self.asking.lock().await;
        if self.recently_allowed(change.kind) {
            return true;
        }
        let who = if caller.is_empty() || caller == "minecraft" {
            "Something in the game".to_string()
        } else {
            format!("Something in the game ({caller})")
        };
        let later = if change.kind.remembered() {
            " If you allow it, OneClient won't ask again about this for 10 minutes."
        } else {
            ""
        };
        let allowed = self
            .host
            .confirm(ConfirmPrompt {
                title: format!("Let the game {}?", change.what),
                body: format!(
                    "{who} wants to {}. Cosmetics and profile menus do this, but so do mods that try to take over accounts.\n\nOnly allow it if you just asked for this in the game.{later}",
                    change.what
                ),
                allow: "Allow".into(),
            })
            .await;
        if allowed
            && change.kind.remembered()
            && let Ok(mut a) = self.allowed.lock()
        {
            a.insert(change.kind, Instant::now());
        }
        allowed
    }

    fn record(&self, kind: ActivityKind) {
        self.host
            .record(Activity::now(self.config.cluster_id, kind));
    }
}

fn same_secret(a: &str, b: &str) -> bool {
    // compare digests so the time taken says nothing about the key
    Sha256::digest(a.as_bytes()) == Sha256::digest(b.as_bytes())
}

/// Serves one connection until the game closes it
pub(crate) async fn serve(
    shared: Arc<Shared>,
    mut up: impl AsyncRead + Unpin + Send,
    mut down: impl AsyncWrite + Unpin + Send + 'static,
) -> std::io::Result<()> {
    let Some(first) = protocol::read_frame(&mut up).await? else {
        return Ok(());
    };
    match protocol::decode_request(&first) {
        Ok((id, Request::Hello { key, agent_version }))
            if same_secret(&key, &shared.config.key) =>
        {
            tracing::debug!(%agent_version, "game agent connected to the broker");
            protocol::write_frame(&mut down, &protocol::encode_reply(id, &Reply::Ok)).await?;
            shared.record(ActivityKind::Connected { agent_version });
        }
        _ => {
            shared.record(ActivityKind::BadHandshake);
            return Ok(());
        }
    }

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if protocol::write_frame(&mut down, &frame).await.is_err() {
                break;
            }
        }
    });

    while let Some(frame) = protocol::read_frame(&mut up).await? {
        let (id, request) = match protocol::decode_request(&frame) {
            Ok(decoded) => decoded,
            Err(err) => {
                tracing::warn!("closing broker connection after a malformed frame: {err}");
                break;
            }
        };
        let shared = Arc::clone(&shared);
        let tx = tx.clone();
        tokio::spawn(async move {
            // a host that panics still owes the game an answer, or it waits
            // out its whole timeout
            let reply = tokio::spawn(async move { handle(&shared, request).await })
                .await
                .unwrap_or_else(|_| Reply::Error("OneClient failed to handle this request".into()));
            let _ = tx.send(protocol::encode_reply(id, &reply)).await;
        });
    }

    drop(tx);
    let _ = writer.await;
    Ok(())
}

pub(crate) async fn handle(shared: &Shared, request: Request) -> Reply {
    match request {
        Request::Hello { .. } => Reply::Error("already connected".into()),
        Request::Http {
            method,
            url,
            headers,
            body,
            caller,
        } => http(shared, method, url, headers, body, caller).await,
        Request::Open { target, caller } => open(shared, &target, caller),
        Request::Pick {
            mode,
            title,
            filters,
            caller,
        } => {
            let filters = filters
                .iter()
                .take(32)
                .filter_map(|f| PickFilter::parse(f))
                .collect();
            let picked = shared
                .host
                .pick(PickRequest {
                    mode,
                    title,
                    filters,
                })
                .await;
            shared.record(ActivityKind::Picked {
                path: picked.as_ref().map(|p| p.display().to_string()),
                caller,
            });
            Reply::Picked(picked.map(|p| p.display().to_string()))
        }
        Request::Accounts { caller: _ } => Reply::Accounts {
            active: shared.account().to_string(),
            accounts: shared.host.accounts().await,
        },
        Request::SwitchAccount { account, caller } => {
            let Ok(to) = Uuid::parse_str(&account) else {
                return Reply::Error("not an account id".into());
            };
            if to == shared.account() {
                return Reply::Ok;
            }
            let name = shared
                .host
                .accounts()
                .await
                .into_iter()
                .find(|a| Uuid::parse_str(&a.id).ok() == Some(to))
                .map(|a| a.name);
            let Some(name) = name else {
                return Reply::Error("that isn't one of your OneClient accounts".into());
            };
            match shared.host.switch_account(to).await {
                Ok(()) => {
                    if let Ok(mut current) = shared.account.lock() {
                        *current = to;
                    }
                    shared.record(ActivityKind::SwitchedAccount { to: name, caller });
                    Reply::Ok
                }
                Err(err) => Reply::Error(err),
            }
        }
        Request::AddAccount { caller: _ } => {
            shared.host.add_account();
            Reply::Ok
        }
        Request::Reveal { path, caller } => {
            match validate_instance_file(&path, &shared.config.open_roots) {
                Some(file) => {
                    shared.record(ActivityKind::Opened {
                        target: path,
                        caller,
                    });
                    shared.host.reveal(file);
                    Reply::Ok
                }
                None => {
                    shared.record(ActivityKind::OpenRefused {
                        target: path,
                        caller,
                    });
                    Reply::Error("OneClient only shows files inside this instance".into())
                }
            }
        }
        Request::WatchDownloads {
            extension,
            size,
            sha1,
            caller,
        } => {
            if sha1.is_empty() {
                shared.host.watch_downloads(None);
                return Reply::Ok;
            }
            match WantedDownload::new(&extension, size, &sha1, caller) {
                Some(wanted) => {
                    shared.host.watch_downloads(Some(wanted));
                    Reply::Ok
                }
                None => Reply::Error("not a download OneClient can watch for".into()),
            }
        }
        Request::Trash { path, caller } => {
            let result = match validate_instance_file(&path, &shared.config.open_roots) {
                Some(file) => shared.host.trash(file).await,
                None => Err("OneClient only trashes files inside this instance".into()),
            };
            shared.record(ActivityKind::Trashed {
                path,
                done: result.is_ok(),
                caller,
            });
            match result {
                Ok(()) => Reply::Ok,
                Err(err) => Reply::Error(err),
            }
        }
        Request::Import { path, caller } => {
            let copied = shared
                .host
                .import(PathBuf::from(&path), caller.clone())
                .await;
            shared.record(ActivityKind::Imported {
                from: path,
                to: copied.as_ref().map(|p| p.display().to_string()),
                caller,
            });
            Reply::Picked(copied.map(|p| p.display().to_string()))
        }
    }
}

async fn http(
    shared: &Shared,
    method: String,
    url: String,
    mut headers: protocol::Headers,
    mut body: Vec<u8>,
    caller: String,
) -> Reply {
    let Ok(parsed) = Url::parse(&url) else {
        return Reply::Error("invalid URL".into());
    };

    let placement = match policy::decide(&method, &parsed) {
        Decision::Allow(Route::Join) => {
            if !policy::join_names_account(&body, &shared.account()) {
                shared.record(ActivityKind::Alarm {
                    method,
                    url,
                    reason: "a mod tried to join a server as a different account".into(),
                    caller,
                });
                return forbidden();
            }
            let take = shared
                .joins
                .lock()
                .map(|mut l| l.try_take())
                .unwrap_or(Take::Paused { first: false });
            if let Take::Paused { first } = take {
                if first {
                    shared.record(ActivityKind::JoinLimited { caller });
                }
                return Reply::Http {
                    status: 429,
                    headers: vec![],
                    body: br#"{"error":"TooManyRequests","errorMessage":"OneClient limited how often this game can authenticate to servers"}"#.to_vec(),
                };
            }
            shared.record(ActivityKind::Join {
                server_hash: policy::join_server_hash(&body).unwrap_or_default(),
                caller,
            });
            TokenPlacement::JsonAccessToken
        }
        Decision::Allow(Route::Plain(placement)) => placement,
        Decision::Confirm { placement, change } => {
            if !shared.ask(&change, &caller).await {
                shared.record(ActivityKind::Denied {
                    method,
                    url,
                    reason: format!("you didn't let the game {}", change.what),
                    caller,
                });
                return forbidden();
            }
            shared.record(ActivityKind::Allowed {
                method: method.clone(),
                url: url.clone(),
                what: change.what,
                caller,
            });
            placement
        }
        Decision::Deny { reason, alarm } => {
            let kind = if alarm {
                ActivityKind::Alarm {
                    method,
                    url,
                    reason: reason.into(),
                    caller,
                }
            } else {
                ActivityKind::Denied {
                    method,
                    url,
                    reason: reason.into(),
                    caller,
                }
            };
            shared.record(kind);
            return forbidden();
        }
    };

    let real = if placement == TokenPlacement::None {
        String::new()
    } else {
        match shared.host.real_token(shared.account()).await {
            Ok(token) => token,
            Err(err) => {
                tracing::warn!("broker could not get a token: {err}");
                return Reply::Http {
                    status: 401,
                    headers: vec![],
                    body:
                        br#"{"error":"Unauthorized","errorMessage":"Sign in to OneClient again"}"#
                            .to_vec(),
                };
            }
        }
    };
    policy::substitute(
        placement,
        &mut headers,
        &mut body,
        &shared.config.fake_token,
        if real.is_empty() { "" } else { &real },
    );

    match forward(&shared.config.http, &method, parsed, headers, body).await {
        Ok((status, headers, body)) => {
            // responses never legitimately echo the token; make sure the real
            // one can't ride back into the game in one
            let body = if real.is_empty() {
                body
            } else {
                policy::replace_bytes(&body, real.as_bytes(), shared.config.fake_token.as_bytes())
            };
            Reply::Http {
                status,
                headers,
                body,
            }
        }
        Err(err) => Reply::Error(format!("request failed: {err}")),
    }
}

fn forbidden() -> Reply {
    Reply::Http {
        status: 403,
        headers: vec![],
        body: br#"{"error":"Forbidden","errorMessage":"OneClient blocked this request to protect your account"}"#
            .to_vec(),
    }
}

const DROPPED_REQUEST: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "accept-encoding",
    "keep-alive",
    "proxy-authorization",
    "upgrade",
];
const DROPPED_RESPONSE: &[&str] = &[
    "content-length",
    "connection",
    "transfer-encoding",
    "content-encoding",
    "keep-alive",
];

async fn forward(
    client: &reqwest::Client,
    method: &str,
    url: Url,
    headers: protocol::Headers,
    body: Vec<u8>,
) -> Result<(u16, protocol::Headers, Vec<u8>), reqwest::Error> {
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut request = client.request(method, url);
    for (name, value) in headers {
        if DROPPED_REQUEST.iter().any(|d| name.eq_ignore_ascii_case(d)) || value.is_empty() {
            continue;
        }
        request = request.header(name, value);
    }
    if !body.is_empty() {
        request = request.body(body);
    }

    let response = request.send().await?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter(|(name, _)| !DROPPED_RESPONSE.contains(&name.as_str()))
        .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
        .collect();
    let body = response.bytes().await?.to_vec();
    Ok((status, headers, body))
}

fn open(shared: &Shared, target: &str, caller: String) -> Reply {
    match validate_open(target, &shared.config.open_roots) {
        Some(validated) => {
            shared.record(ActivityKind::Opened {
                target: target.to_string(),
                caller,
            });
            shared.host.open(validated);
            Reply::Ok
        }
        None => {
            shared.record(ActivityKind::OpenRefused {
                target: target.to_string(),
                caller,
            });
            Reply::Error("OneClient only opens web links and this instance's folders".into())
        }
    }
}

/// Web links, and files or folders inside the instance. Never programs,
/// never `file:` URLs pointing elsewhere, never custom URL schemes (those can
/// launch arbitrary apps)
pub fn validate_open(target: &str, roots: &[PathBuf]) -> Option<OpenTarget> {
    if let Ok(url) = Url::parse(target) {
        match url.scheme() {
            "http" | "https" if url.host_str().is_some() => return Some(OpenTarget::Url(url)),
            "file" => {
                let path = url.to_file_path().ok()?;
                return validate_path(&path, roots);
            }
            // a one-letter "scheme" is a Windows drive letter
            scheme if scheme.len() > 1 => return None,
            _ => {}
        }
    }
    validate_path(Path::new(target), roots)
}

/// A file or folder strictly inside one of `roots`: never a root itself,
/// and nothing in the launcher's own `.oneclient` folder. A link is judged
/// by where it sits, not where it points, so trashing it only moves the link
pub fn validate_instance_file(target: &str, roots: &[PathBuf]) -> Option<PathBuf> {
    let path = Path::new(target);
    if !path.is_absolute() {
        return None;
    }
    let name = path.file_name()?;
    let file = std::fs::canonicalize(path.parent()?).ok()?.join(name);
    std::fs::symlink_metadata(&file).ok()?;
    let roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    if roots.contains(&file) {
        return None;
    }
    let relative = roots
        .iter()
        .filter_map(|root| file.strip_prefix(root).ok())
        .min_by_key(|relative| relative.components().count())?;
    if relative
        .components()
        .any(|part| part.as_os_str() == ".oneclient")
    {
        return None;
    }
    Some(file)
}

fn validate_path(path: &Path, roots: &[PathBuf]) -> Option<OpenTarget> {
    let canonical = std::fs::canonicalize(path).ok()?;
    let inside = roots.iter().any(|root| {
        std::fs::canonicalize(root)
            .map(|root| canonical.starts_with(root))
            .unwrap_or(false)
    });
    if !inside {
        return None;
    }
    // folders open in the file manager; files are only revealed, never run
    let folder = if canonical.is_dir() {
        canonical
    } else {
        canonical.parent()?.to_path_buf()
    };
    Some(OpenTarget::Path(folder))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_web_links_and_instance_folders_only() {
        let root = std::env::temp_dir().join(format!("broker-open-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("screenshots")).unwrap();
        std::fs::write(root.join("screenshots/a.png"), b"x").unwrap();
        let roots = vec![root.clone()];

        assert!(matches!(
            validate_open("https://modrinth.com/mod/sodium", &roots),
            Some(OpenTarget::Url(_))
        ));
        assert_eq!(
            validate_open(root.join("screenshots").to_str().unwrap(), &roots),
            Some(OpenTarget::Path(
                std::fs::canonicalize(root.join("screenshots")).unwrap()
            ))
        );
        // a file is revealed through its folder, never executed
        assert_eq!(
            validate_open(root.join("screenshots/a.png").to_str().unwrap(), &roots),
            Some(OpenTarget::Path(
                std::fs::canonicalize(root.join("screenshots")).unwrap()
            ))
        );

        assert_eq!(validate_open("ms-settings:privacy", &roots), None);
        assert_eq!(validate_open("javascript:alert(1)", &roots), None);
        assert_eq!(
            validate_open(std::env::temp_dir().to_str().unwrap(), &roots),
            None
        );
        assert_eq!(
            validate_open(root.join("..").to_str().unwrap(), &roots),
            None
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn trashes_and_reveals_files_inside_the_instance_only() {
        let root = std::env::temp_dir().join(format!("broker-trash-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("resourcepacks/Faithful")).unwrap();
        std::fs::create_dir_all(root.join(".oneclient")).unwrap();
        std::fs::write(root.join("resourcepacks/old.zip"), b"x").unwrap();
        std::fs::write(root.join(".oneclient/session.json"), b"x").unwrap();
        let outside = std::env::temp_dir().join(format!("broker-outside-{}", Uuid::new_v4()));
        std::fs::write(&outside, b"x").unwrap();
        let roots = vec![root.clone()];
        let canonical = std::fs::canonicalize(&root).unwrap();
        let check = |path: PathBuf| validate_instance_file(path.to_str().unwrap(), &roots);

        assert_eq!(
            check(root.join("resourcepacks/old.zip")),
            Some(canonical.join("resourcepacks").join("old.zip"))
        );
        assert_eq!(
            check(root.join("resourcepacks/Faithful")),
            Some(canonical.join("resourcepacks").join("Faithful"))
        );
        // through a `..` that stays inside
        assert_eq!(
            check(root.join("resourcepacks/Faithful/../old.zip")),
            Some(canonical.join("resourcepacks").join("old.zip"))
        );

        assert_eq!(check(root.clone()), None);
        assert_eq!(check(root.join("resourcepacks/..")), None);
        assert_eq!(check(root.join(".oneclient")), None);
        assert_eq!(check(root.join(".oneclient/session.json")), None);
        assert_eq!(check(root.join("resourcepacks/missing.zip")), None);
        assert_eq!(check(outside.clone()), None);
        assert_eq!(
            check(
                root.join("resourcepacks/../..")
                    .join(outside.file_name().unwrap())
            ),
            None
        );
        assert_eq!(
            validate_instance_file("resourcepacks/old.zip", &roots),
            None
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(outside);
    }
}
