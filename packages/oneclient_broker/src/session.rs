//! One connection from one game: authenticate the agent, then answer its
//! requests through the policy

use std::collections::{HashMap, HashSet};
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
use crate::policy::{self, AccountChange, ChangeKind, ChangeRule, Decision, Route, TokenPlacement};
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
    /// What the user chose for this kind of account change. Hosts that don't
    /// keep a choice ask every time
    fn change_rule(&self, _kind: ChangeKind) -> BoxFuture<'_, ChangeRule> {
        Box::pin(async { ChangeRule::Ask })
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

/// After the user says no, the same question isn't asked again for this
/// long: a mod repeating a request can't wear them down
const REFUSAL_HOLD: Duration = Duration::from_secs(120);
/// After this many noes to one question, it isn't asked again this launch
const REFUSALS_BEFORE_STOPPING: u32 = 3;
/// The most of a caller, link or path that is ever shown to the user
const SHOWN_LIMIT: usize = 120;

/// Why a question about a change came back no
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The user's rule for this kind of change refuses it
    Rule(String),
    /// The user was asked and said no, or didn't answer
    Answered(String),
    /// The user said no a moment ago, or kept saying no: not asked again
    Held(String),
}

impl Refusal {
    pub fn reason(&self) -> &str {
        match self {
            Self::Rule(r) | Self::Answered(r) | Self::Held(r) => r,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Refusals {
    count: u32,
    last: Instant,
}

pub(crate) struct Shared {
    pub config: SessionConfig,
    pub host: Arc<dyn BrokerHost>,
    pub joins: Mutex<JoinLimiter>,
    /// One question at a time: a burst of requests waits for the first answer
    asking: tokio::sync::Mutex<()>,
    /// The account the game plays as; an in-game switcher can change it
    account: Mutex<Uuid>,
    /// Refusals already in the activity log this launch: a mod repeating
    /// one in a loop is reported once, not once per try
    reported: Mutex<HashSet<String>>,
    /// The user's noes, per question
    refusals: Mutex<HashMap<String, Refusals>>,
    /// Sites the user agreed to have opened in their browser this launch
    approved_sites: Mutex<HashSet<String>>,
}

impl Shared {
    pub fn new(config: SessionConfig, host: Arc<dyn BrokerHost>) -> Arc<Self> {
        Arc::new(Self {
            host,
            joins: Mutex::new(JoinLimiter::standard()),
            asking: tokio::sync::Mutex::new(()),
            account: Mutex::new(config.account),
            reported: Mutex::default(),
            refusals: Mutex::default(),
            approved_sites: Mutex::default(),
            config,
        })
    }

    /// As if the hold after each refusal had run out
    #[cfg(test)]
    pub fn expire_refusals_for_test(&self) {
        for refusal in self.refusals.lock().unwrap().values_mut() {
            refusal.last = Instant::now() - REFUSAL_HOLD;
        }
    }

    /// Whether `key` is reported for the first time this launch
    fn first_report(&self, key: impl Into<String>) -> bool {
        self.reported
            .lock()
            .map(|mut seen| seen.insert(key.into()))
            .unwrap_or(true)
    }

    pub fn account(&self) -> Uuid {
        self.account
            .lock()
            .map(|a| *a)
            .unwrap_or(self.config.account)
    }

    /// Decides a change to `path` on the profile host
    #[cfg(test)]
    pub async fn permit_for_test(&self, method: &str, path: &str) -> Result<(), String> {
        let url = Url::parse(&format!("https://api.minecraftservices.com{path}")).unwrap();
        let Decision::Confirm { change, .. } = policy::decide(method, &url) else {
            panic!("{method} {path} isn't an account change");
        };
        self.permit(&change, "")
            .await
            .map(|_| ())
            .map_err(|refusal| refusal.reason().to_string())
    }

    /// Whether the game may make this change: what the user chose for it,
    /// or their answer when they chose to be asked. `Ok(true)` when the user
    /// was asked and agreed
    pub(crate) async fn permit(
        &self,
        change: &AccountChange,
        caller: &str,
    ) -> Result<bool, Refusal> {
        match self.host.change_rule(change.kind).await {
            ChangeRule::Allow => Ok(false),
            ChangeRule::Deny => Err(Refusal::Rule(format!(
                "you don't let games {}",
                change.what
            ))),
            ChangeRule::Ask => {
                let prompt = ConfirmPrompt {
                    title: format!("Let the game {}?", change.what),
                    body: format!(
                        "{} wants to {}. Cosmetics and profile menus do this, but so do mods that try to take over accounts.\n\nOnly allow it if you just asked for this in the game.",
                        who(caller),
                        change.what
                    ),
                    allow: "Allow".into(),
                };
                self.ask(&format!("{:?}", change.kind), &change.what, caller, prompt)
                    .await
                    .map(|()| true)
            }
        }
    }

    /// Asks the user, one question at a time. A question the user just said
    /// no to isn't asked again for a while, and after a few noes not again
    /// this launch: that's reported as a mod pestering them
    async fn ask(
        &self,
        key: &str,
        what: &str,
        caller: &str,
        prompt: ConfirmPrompt,
    ) -> Result<(), Refusal> {
        let _one_at_a_time = self.asking.lock().await;
        let past = self.refusals.lock().ok().and_then(|r| r.get(key).copied());
        if let Some(past) = past {
            if past.count >= REFUSALS_BEFORE_STOPPING {
                return Err(Refusal::Held(format!(
                    "you refused several times to let the game {what}"
                )));
            }
            if past.last.elapsed() < REFUSAL_HOLD {
                return Err(Refusal::Held(format!(
                    "you just refused to let the game {what}"
                )));
            }
        }
        if self.host.confirm(prompt).await {
            return Ok(());
        }
        let count = self.refusals.lock().map_or(0, |mut refusals| {
            let entry = refusals.entry(key.to_string()).or_insert(Refusals {
                count: 0,
                last: Instant::now(),
            });
            entry.count += 1;
            entry.last = Instant::now();
            entry.count
        });
        if count == REFUSALS_BEFORE_STOPPING {
            self.record(ActivityKind::Alarm {
                method: String::new(),
                url: String::new(),
                reason: format!(
                    "a mod kept asking to {what} after you said no, so OneClient stopped asking until the game restarts"
                ),
                caller: caller.to_string(),
            });
        }
        Err(Refusal::Answered(format!("you didn't let the game {what}")))
    }

    fn record(&self, kind: ActivityKind) {
        self.host
            .record(Activity::now(self.config.cluster_id, kind));
    }
}

/// "Something in the game (caller)", for questions
fn who(caller: &str) -> String {
    if caller.is_empty() || caller == "minecraft" {
        "Something in the game".to_string()
    } else {
        format!("Something in the game ({caller})")
    }
}

/// Text from the game, made safe to show: no control or direction-changing
/// characters (they could write lines of their own into a question), runs
/// of spaces folded, and no longer than `limit` characters
pub fn shown(text: &str, limit: usize) -> String {
    let invisible = |c: char| {
        matches!(c,
            '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
            | '\u{061c}')
    };
    let mut out = String::new();
    let mut count = 0;
    let mut space = false;
    for c in text.chars() {
        if invisible(c) {
            continue;
        }
        if c.is_control() || c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if count >= limit {
            out.push('…');
            break;
        }
        if space {
            out.push(' ');
            count += 1;
            space = false;
        }
        out.push(c);
        count += 1;
    }
    out
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

pub(crate) async fn handle(shared: &Shared, mut request: Request) -> Reply {
    // the game names the caller itself: never let it write the launcher's text
    if let Some(caller) = request.caller_mut() {
        *caller = shown(caller, SHOWN_LIMIT);
    }
    match request {
        Request::Hello { .. } => Reply::Error("already connected".into()),
        Request::Http {
            method,
            url,
            headers,
            body,
            caller,
        } => http(shared, method, url, headers, body, caller).await,
        Request::Open { target, caller } => open(shared, &target, caller).await,
        Request::Pick {
            mode,
            title,
            filters,
            caller,
        } => {
            let title = shown(&title, SHOWN_LIMIT);
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
            let name = shown(&name, SHOWN_LIMIT);
            // the game can act as whichever account it plays as: the user
            // picks, not a mod
            let what = format!("play as {name}");
            let prompt = ConfirmPrompt {
                title: format!("Switch the game to {name}?"),
                body: format!(
                    "{} wants to play as your account {name} from now on. Account switchers in mods do this, but a mod that switches accounts can use that account too.\n\nOnly switch if you just picked {name} in the game.",
                    who(&caller)
                ),
                allow: "Switch".into(),
            };
            if let Err(refusal) = shared
                .ask(&format!("switch:{to}"), &what, &caller, prompt)
                .await
            {
                return Reply::Error(refusal.reason().to_string());
            }
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
            // the path is shown in the question: it can't carry lines of its own
            if path.chars().any(char::is_control) {
                shared.record(ActivityKind::Imported {
                    from: shown(&path, SHOWN_LIMIT),
                    to: None,
                    caller,
                });
                return Reply::Picked(None);
            }
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
    // as parsed, so what's logged is what was decided on
    let url = shown(parsed.as_str(), 2 * SHOWN_LIMIT);
    let method = shown(&method, 16);

    let placement = match policy::decide(&method, &parsed) {
        Decision::Allow(Route::Join) => {
            if !policy::join_names_account(&body, &shared.account()) {
                if shared.first_report("alarm:join-as-other") {
                    shared.record(ActivityKind::Alarm {
                        method,
                        url,
                        reason: "a mod tried to join a server as a different account".into(),
                        caller,
                    });
                }
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
        Decision::Confirm { placement, change } => match shared.permit(&change, &caller).await {
            Ok(asked) => {
                shared.record(ActivityKind::Allowed {
                    method: method.clone(),
                    url: url.clone(),
                    what: change.what,
                    caller,
                    asked,
                });
                placement
            }
            Err(refusal) => {
                let kind = format!("{:?}", change.kind);
                match refusal {
                    // the user's own answers are always kept
                    Refusal::Answered(reason) => shared.record(ActivityKind::Denied {
                        method,
                        url,
                        reason,
                        caller,
                    }),
                    Refusal::Rule(_) if shared.first_report(format!("rule:{kind}")) => {
                        shared.record(ActivityKind::Refused {
                            method,
                            url,
                            what: change.what,
                            caller,
                        });
                    }
                    Refusal::Held(reason) if shared.first_report(format!("held:{kind}")) => {
                        shared.record(ActivityKind::Denied {
                            method,
                            url,
                            reason,
                            caller,
                        });
                    }
                    Refusal::Rule(_) | Refusal::Held(_) => {}
                }
                return forbidden();
            }
        },
        Decision::Deny { reason, alarm } => {
            if shared.first_report(format!("deny:{alarm}:{reason}")) {
                let reason = reason.to_string();
                shared.record(if alarm {
                    ActivityKind::Alarm {
                        method,
                        url,
                        reason,
                        caller,
                    }
                } else {
                    ActivityKind::Denied {
                        method,
                        url,
                        reason,
                        caller,
                    }
                });
            }
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

    // sent the way it was decided on: methods are case-sensitive on the wire
    let method = method.to_ascii_uppercase();
    match forward(&shared.config.http, &method, parsed, headers, body).await {
        Ok((status, headers, body)) => {
            // responses never legitimately echo the token; make sure the real
            // one can't ride back into the game in one
            let (body, headers) = if real.is_empty() {
                (body, headers)
            } else {
                let fake = shared.config.fake_token.as_str();
                (
                    policy::replace_bytes(&body, real.as_bytes(), fake.as_bytes()),
                    headers
                        .into_iter()
                        .map(|(name, value)| (name, value.replace(&real, fake)))
                        .collect(),
                )
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

async fn open(shared: &Shared, target: &str, caller: String) -> Reply {
    let shown_target = shown(target, 2 * SHOWN_LIMIT);
    let refused = |reason: &str| {
        shared.record(ActivityKind::OpenRefused {
            target: shown_target.clone(),
            caller: caller.clone(),
        });
        Reply::Error(reason.into())
    };
    let url = match validate_open(target, &shared.config.open_roots) {
        Some(OpenTarget::Url(url)) => url,
        // the instance's own folders open without asking
        Some(folder) => {
            shared.record(ActivityKind::Opened {
                target: shown_target,
                caller,
            });
            shared.host.open(folder);
            return Reply::Ok;
        }
        None => return refused("OneClient only opens web links and this instance's folders"),
    };

    if signs_in_to_microsoft(&url) {
        // a device code entered on Microsoft's real page hands over the
        // whole Microsoft account; no game feature sends players there
        if shared.first_report("alarm:microsoft-sign-in") {
            shared.record(ActivityKind::Alarm {
                method: "OPEN".into(),
                url: shown_target,
                reason:
                    "a mod tried to open a Microsoft sign-in page, the way account phishing starts"
                        .into(),
                caller,
            });
        }
        return Reply::Error("OneClient never opens sign-in pages for a game".into());
    }
    if is_local(&url) {
        return refused("OneClient doesn't open links to this computer or your network");
    }

    let site = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let approved = shared
        .approved_sites
        .lock()
        .is_ok_and(|sites| sites.contains(&site));
    if !approved {
        let prompt = ConfirmPrompt {
            title: format!("Open {site} in your browser?"),
            body: format!(
                "{} wants to open this link:\n\n{}\n\nOpen it only if you just clicked a link in the game. Never sign in or enter a code on a page a game opened: that's how mods take over accounts.",
                who(&caller),
                shown(url.as_str(), 2 * SHOWN_LIMIT)
            ),
            allow: "Open".into(),
        };
        if let Err(refusal) = shared
            .ask("open", "open links in your browser", &caller, prompt)
            .await
        {
            return refused(refusal.reason());
        }
        if let Ok(mut sites) = shared.approved_sites.lock() {
            sites.insert(site);
        }
    }
    shared.record(ActivityKind::Opened {
        target: shown_target,
        caller,
    });
    shared.host.open(OpenTarget::Url(url));
    Reply::Ok
}

/// Microsoft's sign-in and device-code pages
pub fn signs_in_to_microsoft(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let under = |domain: &str| host == domain || host.ends_with(&format!(".{domain}"));
    let segments: Vec<String> = url
        .path_segments()
        .map(|s| s.take(2).map(str::to_ascii_lowercase).collect())
        .unwrap_or_default();
    let first = |names: &[&str]| {
        segments
            .first()
            .is_some_and(|s| names.contains(&s.as_str()))
    };
    if [
        "live.com",
        "microsoftonline.com",
        "login.microsoft.com",
        "account.microsoft.com",
        "msauth.net",
        "msftauth.net",
        "xboxlive.com",
    ]
    .iter()
    .any(|domain| under(domain))
    {
        return true;
    }
    // Microsoft's own short links; the game itself links to its terms here
    if under("aka.ms") {
        return first(&["remoteconnect", "devicelogin", "link", "mfasetup"]);
    }
    // microsoft.com/link and /devicelogin, with or without a locale
    under("microsoft.com") && segments.iter().any(|s| s == "link" || s == "devicelogin")
}

/// This computer, the local network, or a name only it could resolve
fn is_local(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                // carrier-grade NAT, 100.64.0.0/10
                || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
        }
        Some(url::Host::Ipv6(ip)) => {
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_private())
        }
        Some(url::Host::Domain(name)) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            !name.contains('.')
                || ["localhost", "local", "internal", "lan", "home.arpa"]
                    .iter()
                    .any(|tld| name == *tld || name.ends_with(&format!(".{tld}")))
        }
        None => true,
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
    fn text_from_the_game_stays_on_one_line() {
        assert_eq!(
            shown("rat)\n\nOneClient says: it's safe.\r\n(", 120),
            "rat) OneClient says: it's safe. ("
        );
        assert_eq!(shown("a\u{202e}gpj.exe\u{200b}", 120), "agpj.exe");
        assert_eq!(shown("  spaced\tout  ", 120), "spaced out");
        assert_eq!(shown(&"x".repeat(500), 5), "xxxxx…");
    }

    #[test]
    fn microsoft_sign_in_pages_are_recognised() {
        let check = |url: &str| signs_in_to_microsoft(&Url::parse(url).unwrap());
        for url in [
            "https://login.live.com/oauth20_remoteconnect.srf",
            "https://www.microsoft.com/link",
            "https://www.microsoft.com/en-us/link?otc=ABCD",
            "https://microsoft.com/devicelogin",
            "https://login.microsoftonline.com/common/oauth2/deviceauth",
            "https://aka.ms/remoteconnect",
            "https://account.microsoft.com/",
            "https://LOGIN.LIVE.COM./",
        ] {
            assert!(check(url), "{url}");
        }
        for url in [
            // the game's own links to its terms
            "https://aka.ms/MinecraftEULA",
            "https://www.microsoft.com/en-us/privacy",
            "https://modrinth.com/mod/sodium",
            "https://login.live.com.verify-account.example/",
        ] {
            assert!(!check(url), "{url}");
        }
    }

    #[test]
    fn links_to_this_computer_and_network_are_local() {
        let check = |url: &str| is_local(&Url::parse(url).unwrap());
        for url in [
            "http://127.0.0.1:9222/json",
            "http://localhost:8080/",
            "http://192.168.1.1/",
            "http://10.0.0.5/",
            "http://169.254.169.254/",
            "http://[::1]/",
            "http://[fd00::1]/",
            "http://router/",
            "http://nas.local/",
        ] {
            assert!(check(url), "{url}");
        }
        for url in ["https://modrinth.com/", "https://8.8.8.8/"] {
            assert!(!check(url), "{url}");
        }
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
