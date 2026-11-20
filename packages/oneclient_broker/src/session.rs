//! One connection from one game: authenticate the agent, then answer its
//! requests through the policy

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use url::Url;
use uuid::Uuid;

use crate::activity::{Activity, ActivityKind};
use crate::limiter::JoinLimiter;
use crate::policy::{self, Decision, Route, TokenPlacement};
use crate::protocol::{self, PickMode, Reply, Request};

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
    fn pick(&self, mode: PickMode, title: String) -> BoxFuture<'_, Option<PathBuf>>;
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
}

impl Shared {
    pub fn new(config: SessionConfig, host: Arc<dyn BrokerHost>) -> Arc<Self> {
        Arc::new(Self {
            config,
            host,
            joins: Mutex::new(JoinLimiter::standard()),
        })
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
            let reply = handle(&shared, request).await;
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
            filters: _,
            caller,
        } => {
            let picked = shared.host.pick(mode, title).await;
            shared.record(ActivityKind::Picked {
                path: picked.as_ref().map(|p| p.display().to_string()),
                caller,
            });
            Reply::Picked(picked.map(|p| p.display().to_string()))
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
            if !policy::join_names_account(&body, &shared.config.account) {
                shared.record(ActivityKind::Alarm {
                    method,
                    url,
                    reason: "a mod tried to join a server as a different account".into(),
                    caller,
                });
                return forbidden();
            }
            let allowed = shared
                .joins
                .lock()
                .map(|mut l| l.try_take())
                .unwrap_or(false);
            if !allowed {
                shared.record(ActivityKind::JoinLimited { caller });
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
        match shared.host.real_token(shared.config.account).await {
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
}
