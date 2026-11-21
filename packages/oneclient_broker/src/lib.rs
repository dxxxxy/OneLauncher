//! The token broker: the game never sees the real Minecraft token
//!
//! Every launch gets a random fake token in place of the real one. The
//! launcher-owned `oneclient-agent.jar` routes the game's requests to account
//! hosts through a private channel to this broker, which checks each one
//! against [`policy`], swaps the fake token for the real one and sends it on.
//! A mod that grabs the session token gets a string that is worthless
//! anywhere else, and a mod that asks the broker to rename the account or
//! change its skin is refused and reported.
//!
//! Security does not depend on the agent: it runs inside the game and a mod
//! can bypass it. All it can then do is fail to talk to Mojang.

pub mod activity;
pub mod agent;
pub mod discord;
pub mod limiter;
pub mod policy;
pub mod protocol;
mod session;
pub mod transport;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use activity::{Activity, ActivityKind};
pub use discord::DiscordRelay;
pub use protocol::{GameAccount, PickFilter, PickMode};
pub use session::{BoxFuture, BrokerHost, ConfirmPrompt, OpenTarget, PickRequest, validate_open};
use session::{SessionConfig, Shared};
pub use transport::Endpoint;

/// The environment variable the agent reads its key from. Keys never go on
/// the command line, which every process on the machine can read
pub const KEY_ENV: &str = "ONECLIENT_BROKER_KEY";
/// `-D` property naming the two channels
pub const ENDPOINT_PROPERTY: &str = "oneclient.broker";

fn random_token(prefix: &str) -> String {
    let bytes: [u8; 32] = rand::random();
    format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Everything needed to serve one game, and to pick it back up after the
/// launcher restarts while the game keeps running. Holds the per-launch key
/// and fake token, so it is stored only where the sandbox can't reach
#[derive(Clone, Serialize, Deserialize)]
pub struct LaunchDescriptor {
    pub id: String,
    pub cluster_id: i64,
    pub account: Uuid,
    pub key: String,
    pub fake_token: String,
    pub open_roots: Vec<PathBuf>,
    /// Windows: the AppContainer allowed to open the pipes
    pub app_container_sid: Option<String>,
    /// Unix: where the FIFOs live
    pub fifo_dir: Option<PathBuf>,
}

impl std::fmt::Debug for LaunchDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchDescriptor")
            .field("id", &self.id)
            .field("cluster_id", &self.cluster_id)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl LaunchDescriptor {
    /// `fifo_root` is the per-instance directory the Unix sandbox exposes for
    /// broker channels; ignored on Windows
    pub fn new(
        cluster_id: i64,
        account: Uuid,
        open_roots: Vec<PathBuf>,
        app_container_sid: Option<String>,
        fifo_root: Option<PathBuf>,
    ) -> Self {
        let id = Uuid::new_v4().simple().to_string();
        let fifo_dir = fifo_root.map(|root| transport::unix_endpoint_dir(&root, &id));
        Self {
            id,
            cluster_id,
            account,
            key: random_token(""),
            fake_token: random_token("oc1_"),
            open_roots,
            app_container_sid,
            fifo_dir,
        }
    }

    pub async fn save(&self, path: &std::path::Path) -> Result<(), polyio::IOError> {
        polyio::write_json_atomic(path, self).await
    }
}

/// A broker serving one game; dropping it stops it
pub struct RunningBroker {
    endpoint: Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl RunningBroker {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// `-Doneclient.broker=…` for the JVM
    pub fn jvm_property(&self) -> String {
        format!("-D{ENDPOINT_PROPERTY}={}", self.endpoint.property())
    }
}

impl Drop for RunningBroker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn start(
    descriptor: &LaunchDescriptor,
    host: Arc<dyn BrokerHost>,
    http: reqwest::Client,
) -> std::io::Result<RunningBroker> {
    #[cfg(windows)]
    let listener =
        transport::Listener::new(&descriptor.id, descriptor.app_container_sid.as_deref())?;
    #[cfg(unix)]
    let listener = transport::Listener::new(descriptor.fifo_dir.clone().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no FIFO directory")
    })?)?;

    let endpoint = listener.endpoint().clone();
    let shared = Shared::new(
        SessionConfig {
            cluster_id: descriptor.cluster_id,
            account: descriptor.account,
            key: descriptor.key.clone(),
            fake_token: descriptor.fake_token.clone(),
            open_roots: descriptor.open_roots.clone(),
            http,
        },
        host,
    );

    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(connection) => {
                    if let Err(err) =
                        session::serve(Arc::clone(&shared), connection.up, connection.down).await
                    {
                        tracing::debug!("broker connection ended: {err}");
                    }
                }
                Err(err) => {
                    tracing::warn!("broker could not accept a connection: {err}");
                }
            }
            // a game restarting its agent reconnects; don't spin if it can't
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    Ok(RunningBroker { endpoint, task })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::protocol::{Reply, Request};

    #[derive(Default)]
    struct TestHost {
        log: Mutex<Vec<Activity>>,
        asked: Mutex<Vec<ConfirmPrompt>>,
        answer: bool,
    }

    impl BrokerHost for TestHost {
        fn real_token(&self, _account: Uuid) -> BoxFuture<'_, Result<String, String>> {
            Box::pin(async { Ok("REAL-TOKEN".to_string()) })
        }

        fn record(&self, activity: Activity) {
            self.log.lock().unwrap().push(activity);
        }

        fn open(&self, _target: OpenTarget) {}

        fn pick(&self, _request: PickRequest) -> BoxFuture<'_, Option<PathBuf>> {
            Box::pin(async { None })
        }

        fn confirm(&self, prompt: ConfirmPrompt) -> BoxFuture<'_, bool> {
            self.asked.lock().unwrap().push(prompt);
            let answer = self.answer;
            Box::pin(async move { answer })
        }
    }

    fn shared(host: Arc<TestHost>) -> Arc<Shared> {
        Shared::new(
            SessionConfig {
                cluster_id: 1,
                account: Uuid::from_u128(1),
                key: "KEY".into(),
                fake_token: "FAKE".into(),
                open_roots: vec![],
                http: reqwest::Client::new(),
            },
            host,
        )
    }

    #[test]
    fn fake_tokens_are_random_and_marked() {
        let a = LaunchDescriptor::new(1, Uuid::nil(), vec![], None, None);
        let b = LaunchDescriptor::new(1, Uuid::nil(), vec![], None, None);
        assert!(a.fake_token.starts_with("oc1_"));
        assert_ne!(a.fake_token, b.fake_token);
        assert_ne!(a.key, b.key);
        assert!(!format!("{a:?}").contains(&a.key));
    }

    #[tokio::test]
    async fn a_wrong_key_is_turned_away() {
        let host = Arc::new(TestHost::default());
        let (mut agent_up, broker_up) = tokio::io::duplex(4096);
        let (broker_down, mut agent_down) = tokio::io::duplex(4096);

        let hello = protocol::encode_request(
            1,
            &Request::Hello {
                key: "WRONG".into(),
                agent_version: "t".into(),
            },
        );
        protocol::write_frame(&mut agent_up, &hello).await.unwrap();
        drop(agent_up);

        session::serve(shared(host.clone()), broker_up, broker_down)
            .await
            .unwrap();

        assert!(
            protocol::read_frame(&mut agent_down)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(host.log.lock().unwrap()[0].kind, ActivityKind::BadHandshake);
    }

    fn rename() -> Request {
        Request::Http {
            method: "PUT".into(),
            url: "https://api.minecraftservices.com/minecraft/profile/name/Taken".into(),
            headers: vec![("Authorization".into(), "Bearer FAKE".into())],
            body: vec![],
            caller: "mods/rat.jar".into(),
        }
    }

    #[tokio::test]
    async fn account_changes_the_user_refuses_never_touch_the_network() {
        let host = Arc::new(TestHost::default());
        let reply = session::handle(&shared(host.clone()), rename()).await;

        assert!(matches!(reply, Reply::Http { status: 403, .. }));
        let log = host.log.lock().unwrap();
        assert!(
            matches!(&log[0].kind, ActivityKind::Denied { reason, .. } if reason.contains("name to Taken")),
            "{log:?}"
        );
        let asked = host.asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0]
                .title
                .contains("change your Minecraft name to Taken")
        );
        assert!(asked[0].body.contains("mods/rat.jar"));
    }

    #[tokio::test]
    async fn the_game_can_only_switch_to_the_users_own_accounts() {
        struct Accounts(Mutex<Vec<Uuid>>);
        impl BrokerHost for Accounts {
            fn real_token(&self, account: Uuid) -> BoxFuture<'_, Result<String, String>> {
                Box::pin(async move { Ok(format!("REAL-{account}")) })
            }
            fn record(&self, _activity: Activity) {}
            fn open(&self, _target: OpenTarget) {}
            fn pick(&self, _request: PickRequest) -> BoxFuture<'_, Option<PathBuf>> {
                Box::pin(async { None })
            }
            fn accounts(&self) -> BoxFuture<'_, Vec<GameAccount>> {
                Box::pin(async {
                    vec![GameAccount {
                        id: Uuid::from_u128(2).to_string(),
                        name: "Alt".into(),
                    }]
                })
            }
            fn switch_account(&self, to: Uuid) -> BoxFuture<'_, Result<(), String>> {
                self.0.lock().unwrap().push(to);
                Box::pin(async { Ok(()) })
            }
        }
        let host = Arc::new(Accounts(Mutex::new(vec![])));
        let shared = Shared::new(
            SessionConfig {
                cluster_id: 1,
                account: Uuid::from_u128(1),
                key: "KEY".into(),
                fake_token: "FAKE".into(),
                open_roots: vec![],
                http: reqwest::Client::new(),
            },
            host.clone(),
        );
        let switch = |id: u128| Request::SwitchAccount {
            account: Uuid::from_u128(id).to_string(),
            caller: String::new(),
        };

        assert!(matches!(
            session::handle(&shared, switch(9)).await,
            Reply::Error(_)
        ));
        assert_eq!(shared.account(), Uuid::from_u128(1));
        assert_eq!(session::handle(&shared, switch(2)).await, Reply::Ok);
        assert_eq!(shared.account(), Uuid::from_u128(2));
        assert_eq!(host.0.lock().unwrap().as_slice(), &[Uuid::from_u128(2)]);
    }

    #[tokio::test]
    async fn an_allowed_cape_change_covers_the_next_ones() {
        let host = Arc::new(TestHost {
            answer: true,
            ..Default::default()
        });
        let shared = shared(host.clone());
        assert!(
            shared
                .ask_for_test("PUT", "/minecraft/profile/capes/active")
                .await
        );
        assert!(
            shared
                .ask_for_test("DELETE", "/minecraft/profile/capes/active")
                .await
        );
        // names are never remembered
        assert!(
            shared
                .ask_for_test("PUT", "/minecraft/profile/name/A")
                .await
        );
        assert!(
            shared
                .ask_for_test("PUT", "/minecraft/profile/name/B")
                .await
        );
        assert_eq!(host.asked.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn joins_for_another_account_raise_the_alarm() {
        let host = Arc::new(TestHost::default());
        let reply = session::handle(
            &shared(host.clone()),
            Request::Http {
                method: "POST".into(),
                url: "https://sessionserver.mojang.com/session/minecraft/join".into(),
                headers: vec![],
                body: br#"{"accessToken":"FAKE","selectedProfile":"00000000000000000000000000000009","serverId":"x"}"#.to_vec(),
                caller: String::new(),
            },
        )
        .await;

        assert!(matches!(reply, Reply::Http { status: 403, .. }));
        assert!(host.log.lock().unwrap()[0].is_alarm());
    }

    #[tokio::test]
    async fn joins_are_rate_limited() {
        let host = Arc::new(TestHost::default());
        let shared = shared(host.clone());
        *shared.joins.lock().unwrap() = limiter::JoinLimiter::new(0, Duration::from_secs(3600));

        let reply = session::handle(
            &shared,
            Request::Http {
                method: "POST".into(),
                url: "https://sessionserver.mojang.com/session/minecraft/join".into(),
                headers: vec![],
                body: br#"{"accessToken":"FAKE","selectedProfile":"00000000000000000000000000000001","serverId":"x"}"#.to_vec(),
                caller: String::new(),
            },
        )
        .await;

        assert!(matches!(reply, Reply::Http { status: 429, .. }));
        assert!(matches!(
            host.log.lock().unwrap()[0].kind,
            ActivityKind::JoinLimited { .. }
        ));
    }
}
