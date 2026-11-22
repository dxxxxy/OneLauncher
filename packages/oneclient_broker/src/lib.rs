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
pub use policy::{ChangeKind, ChangeRule};
pub use protocol::{GameAccount, PickFilter, PickMode};
pub use session::{
    BoxFuture, BrokerHost, ConfirmPrompt, OpenTarget, PickRequest, WantedDownload, validate_open,
};
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
        broken: bool,
        rule: Option<ChangeRule>,
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

        fn add_account(&self) {
            assert!(!self.broken, "the launcher's UI isn't reachable");
        }

        fn change_rule(&self, _kind: ChangeKind) -> BoxFuture<'_, ChangeRule> {
            let rule = self.rule.unwrap_or(ChangeRule::Ask);
            Box::pin(async move { rule })
        }
    }

    impl TestHost {
        fn alarm_count(&self) -> usize {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|a| a.is_alarm())
                .count()
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

    #[tokio::test]
    async fn a_failing_host_still_answers() {
        let host = Arc::new(TestHost {
            broken: true,
            ..TestHost::default()
        });
        let (mut agent_up, broker_up) = tokio::io::duplex(4096);
        let (broker_down, mut agent_down) = tokio::io::duplex(4096);
        let broker = tokio::spawn(session::serve(shared(host), broker_up, broker_down));

        for (id, request) in [
            (
                1,
                Request::Hello {
                    key: "KEY".into(),
                    agent_version: "t".into(),
                },
            ),
            (
                2,
                Request::AddAccount {
                    caller: String::new(),
                },
            ),
        ] {
            let frame = protocol::encode_request(id, &request);
            protocol::write_frame(&mut agent_up, &frame).await.unwrap();
        }

        let mut replies = Vec::new();
        for _ in 0..2 {
            let frame = protocol::read_frame(&mut agent_down)
                .await
                .unwrap()
                .unwrap();
            replies.push(protocol::decode_reply(&frame).unwrap());
        }
        assert!(matches!(replies[0], (1, Reply::Ok)));
        assert!(matches!(&replies[1], (2, Reply::Error(e)) if e.contains("failed")));

        drop(agent_up);
        broker.await.unwrap().unwrap();
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
        struct Accounts(Mutex<Vec<Uuid>>, Mutex<Vec<String>>, bool);
        impl BrokerHost for Accounts {
            fn confirm(&self, prompt: ConfirmPrompt) -> BoxFuture<'_, bool> {
                self.1.lock().unwrap().push(prompt.title);
                let answer = self.2;
                Box::pin(async move { answer })
            }
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
        for agrees in [false, true] {
            let host = Arc::new(Accounts(Mutex::new(vec![]), Mutex::new(vec![]), agrees));
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
            assert!(
                host.1.lock().unwrap().is_empty(),
                "nobody is asked about strangers"
            );

            // the user is asked first, and the game only switches if they agree
            let reply = session::handle(&shared, switch(2)).await;
            assert_eq!(
                host.1.lock().unwrap().as_slice(),
                &["Switch the game to Alt?".to_string()]
            );
            if agrees {
                assert_eq!(reply, Reply::Ok);
                assert_eq!(shared.account(), Uuid::from_u128(2));
                assert_eq!(host.0.lock().unwrap().as_slice(), &[Uuid::from_u128(2)]);
            } else {
                assert!(matches!(reply, Reply::Error(_)), "{reply:?}");
                assert_eq!(shared.account(), Uuid::from_u128(1));
                assert!(host.0.lock().unwrap().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn account_changes_follow_the_users_choice() {
        for (rule, answer, allowed, asked) in [
            (ChangeRule::Allow, false, true, 0),
            (ChangeRule::Deny, true, false, 0),
            (ChangeRule::Ask, true, true, 2),
            // a no holds for a while, so a mod retrying isn't asked about
            (ChangeRule::Ask, false, false, 1),
        ] {
            let host = Arc::new(TestHost {
                answer,
                rule: Some(rule),
                ..Default::default()
            });
            let shared = shared(host.clone());
            // a yes covers that one change only
            for _ in 0..2 {
                let permitted = shared
                    .permit_for_test("PUT", "/minecraft/profile/capes/active")
                    .await;
                assert_eq!(permitted.is_ok(), allowed, "{rule:?}: {permitted:?}");
            }
            assert_eq!(host.asked.lock().unwrap().len(), asked, "{rule:?}");
        }
    }

    #[tokio::test]
    async fn a_mod_that_keeps_asking_is_stopped_and_reported() {
        let host = Arc::new(TestHost::default());
        let shared = shared(host.clone());
        let ask = || shared.permit_for_test("GET", "/productvoucher/X");
        for _ in 0..10 {
            assert!(ask().await.is_err());
        }
        // asked once, then held: a burst can't bury the user in questions
        assert_eq!(host.asked.lock().unwrap().len(), 1);
        assert_eq!(host.alarm_count(), 0);

        // after the hold, asked again; the third no stops it for the launch
        for _ in 0..2 {
            shared.expire_refusals_for_test();
            assert!(ask().await.is_err());
        }
        assert_eq!(host.asked.lock().unwrap().len(), 3);
        assert_eq!(host.alarm_count(), 1);
        shared.expire_refusals_for_test();
        assert!(ask().await.unwrap_err().contains("several times"));
        assert_eq!(host.asked.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_refused_request_in_a_loop_is_reported_once() {
        let host = Arc::new(TestHost::default());
        let shared = shared(host.clone());
        for _ in 0..50 {
            let reply = session::handle(
                &shared,
                Request::Http {
                    method: "POST".into(),
                    url: "https://authserver.mojang.com/authenticate".into(),
                    headers: vec![],
                    body: vec![],
                    caller: String::new(),
                },
            )
            .await;
            assert!(matches!(reply, Reply::Http { status: 403, .. }));
        }
        assert_eq!(host.log.lock().unwrap().len(), 1);
        assert_eq!(host.alarm_count(), 1);
    }

    #[tokio::test]
    async fn a_name_change_the_rules_refuse_is_recorded_as_refused() {
        let host = Arc::new(TestHost {
            rule: Some(ChangeRule::Deny),
            ..Default::default()
        });
        let reply = session::handle(&shared(host.clone()), rename()).await;
        assert!(matches!(reply, Reply::Http { status: 403, .. }));
        assert!(host.asked.lock().unwrap().is_empty());
        let log = host.log.lock().unwrap();
        assert!(
            matches!(&log[0].kind, ActivityKind::Refused { what, .. } if what.contains("name to Taken")),
            "{log:?}"
        );
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

        // a mod retrying in a loop is reported once, not on every refusal
        for _ in 0..3 {
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
        }

        let log = host.log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert!(matches!(log[0].kind, ActivityKind::JoinLimited { .. }));
    }
}
