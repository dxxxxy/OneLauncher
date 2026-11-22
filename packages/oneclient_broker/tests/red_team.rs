//! Red team: a hostile mod that read `ONECLIENT_BROKER_KEY` from its own
//! environment and talks to the real broker over the real pipes, without the
//! agent. Requests the policy lets through go to a capturing proxy, so a test
//! sees exactly what would have reached the network.
//!
//! Each test asserts the secure outcome; a failure is a finding.
#![cfg(windows)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneclient_broker::policy::{self, TokenPlacement};
use oneclient_broker::protocol::{self, Reply, Request};
use oneclient_broker::{
    Activity, ActivityKind, BoxFuture, BrokerHost, ChangeKind, ChangeRule, ConfirmPrompt,
    GameAccount, LaunchDescriptor, OpenTarget, PickRequest, RunningBroker,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use url::Url;
use uuid::Uuid;

const REAL: &str = "REAL-SECRET-TOKEN";
const ME: u128 = 1;
const ALT: u128 = 2;

/// The launcher, as far as the broker can tell: its default rules
/// (names refused, skins and capes allowed, the rest asked)
struct Host {
    answer: bool,
    log: Mutex<Vec<Activity>>,
    prompts: Mutex<Vec<ConfirmPrompt>>,
    opened: Mutex<Vec<OpenTarget>>,
    switched: Mutex<Vec<Uuid>>,
    tokens_for: Mutex<Vec<Uuid>>,
}

impl Host {
    fn new(answer: bool) -> Arc<Self> {
        Arc::new(Self {
            answer,
            log: Mutex::default(),
            prompts: Mutex::default(),
            opened: Mutex::default(),
            switched: Mutex::default(),
            tokens_for: Mutex::default(),
        })
    }

    fn log(&self) -> Vec<Activity> {
        self.log.lock().unwrap().clone()
    }

    fn alarms(&self) -> usize {
        self.log().iter().filter(|a| a.is_alarm()).count()
    }
}

impl BrokerHost for Host {
    fn real_token(&self, account: Uuid) -> BoxFuture<'_, Result<String, String>> {
        self.tokens_for.lock().unwrap().push(account);
        Box::pin(async { Ok(REAL.to_string()) })
    }
    fn record(&self, activity: Activity) {
        self.log.lock().unwrap().push(activity);
    }
    fn open(&self, target: OpenTarget) {
        self.opened.lock().unwrap().push(target);
    }
    fn pick(&self, _request: PickRequest) -> BoxFuture<'_, Option<PathBuf>> {
        Box::pin(async { None })
    }
    fn confirm(&self, prompt: ConfirmPrompt) -> BoxFuture<'_, bool> {
        self.prompts.lock().unwrap().push(prompt);
        let answer = self.answer;
        Box::pin(async move { answer })
    }
    fn change_rule(&self, kind: ChangeKind) -> BoxFuture<'_, ChangeRule> {
        let rule = match kind {
            ChangeKind::Name => ChangeRule::Deny,
            ChangeKind::Skin | ChangeKind::Cape => ChangeRule::Allow,
            _ => ChangeRule::Ask,
        };
        Box::pin(async move { rule })
    }
    fn accounts(&self) -> BoxFuture<'_, Vec<GameAccount>> {
        Box::pin(async {
            vec![
                GameAccount {
                    id: Uuid::from_u128(ME).to_string(),
                    name: "Main".into(),
                },
                GameAccount {
                    id: Uuid::from_u128(ALT).to_string(),
                    name: "ValuableAlt".into(),
                },
            ]
        })
    }
    fn switch_account(&self, to: Uuid) -> BoxFuture<'_, Result<(), String>> {
        self.switched.lock().unwrap().push(to);
        Box::pin(async { Ok(()) })
    }
}

/// A proxy that writes down where each forwarded request was headed and
/// refuses it, so nothing reaches the internet
async fn capture() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&buf);
                log.lock()
                    .unwrap()
                    .push(text.lines().next().unwrap_or_default().to_string());
                let _ = socket
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    (format!("http://{addr}"), seen)
}

struct Rat {
    up: NamedPipeClient,
    down: NamedPipeClient,
    next: u32,
    _broker: RunningBroker,
}

async fn open_pipe(name: &str, write: bool) -> NamedPipeClient {
    for _ in 0..200 {
        match ClientOptions::new().write(write).open(name) {
            Ok(pipe) => return pipe,
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    panic!("couldn't open {name}");
}

impl Rat {
    /// Starts a broker for one game and connects to it the way a mod that
    /// read the launch key could
    async fn connect(host: Arc<Host>) -> (Self, Arc<Mutex<Vec<String>>>) {
        let (proxy, seen) = capture().await;
        let http = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy).unwrap())
            .build()
            .unwrap();
        let descriptor = LaunchDescriptor::new(7, Uuid::from_u128(ME), vec![], None, None);
        let broker = oneclient_broker::start(&descriptor, host, http).unwrap();
        let endpoint = broker.endpoint().clone();
        let up = open_pipe(&endpoint.up, true).await;
        let down = open_pipe(&endpoint.down, false).await;
        let mut rat = Self {
            up,
            down,
            next: 1,
            _broker: broker,
        };
        let hello = rat
            .call(Request::Hello {
                key: descriptor.key.clone(),
                agent_version: "rat".into(),
            })
            .await;
        assert_eq!(hello, Reply::Ok);
        (rat, seen)
    }

    async fn call(&mut self, request: Request) -> Reply {
        let id = self.next;
        self.next += 1;
        protocol::write_frame(&mut self.up, &protocol::encode_request(id, &request))
            .await
            .unwrap();
        let frame = protocol::read_frame(&mut self.down).await.unwrap().unwrap();
        let (got, reply) = protocol::decode_reply(&frame).unwrap();
        assert_eq!(got, id);
        reply
    }

    async fn http(&mut self, method: &str, url: &str, body: &[u8], caller: &str) -> Reply {
        self.call(Request::Http {
            method: method.into(),
            url: url.into(),
            headers: vec![("Authorization".into(), "Bearer oc1_fake".into())],
            body: body.to_vec(),
            caller: caller.into(),
        })
        .await
    }
}

fn blocked(reply: &Reply) -> bool {
    matches!(reply, Reply::Http { status: 403, .. })
}

fn me() -> String {
    Uuid::from_u128(ME).simple().to_string()
}

// ---------------------------------------------------------------- alarms

#[tokio::test]
async fn password_logins_are_blocked_and_raise_the_alarm() {
    let host = Host::new(false);
    let (mut rat, seen) = Rat::connect(host.clone()).await;
    for path in [
        "authenticate",
        "refresh",
        "signout",
        "invalidate",
        "validate",
    ] {
        let url = format!("https://authserver.mojang.com/{path}");
        let reply = rat
            .http("POST", &url, br#"{"username":"x","password":"y"}"#, "rat")
            .await;
        assert!(blocked(&reply), "{url}: {reply:?}");
    }
    // one alarm for the attempt, not one per try
    assert_eq!(host.alarms(), 1);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn spelling_the_auth_host_differently_still_raises_the_alarm() {
    let variants = [
        "https://AUTHSERVER.Mojang.com/authenticate",
        "https://authserver.mojang.com:443/authenticate",
        "http://authserver.mojang.com/authenticate",
        "https://authserver.mojang.com./authenticate",
    ];
    let mut quiet = Vec::new();
    for url in variants {
        // a game of its own each, since an alarm is reported once a launch
        let host = Host::new(false);
        let (mut rat, seen) = Rat::connect(host.clone()).await;
        let reply = rat.http("POST", url, b"{}", "rat").await;
        assert!(blocked(&reply), "{url}: {reply:?}");
        assert!(seen.lock().unwrap().is_empty());
        if host.alarms() == 0 {
            quiet.push(url);
        }
    }
    assert!(quiet.is_empty(), "blocked without an alarm: {quiet:?}");
}

#[tokio::test]
async fn joining_as_another_account_raises_the_alarm() {
    let host = Host::new(false);
    let (mut rat, seen) = Rat::connect(host.clone()).await;
    let other = "00000000000000000000000000000009";
    let url = "https://sessionserver.mojang.com/session/minecraft/join";

    let plain =
        format!(r#"{{"accessToken":"oc1_fake","selectedProfile":"{other}","serverId":"x"}}"#);
    assert!(blocked(
        &rat.http("POST", url, plain.as_bytes(), "rat").await
    ));
    assert_eq!(host.alarms(), 1);
    assert!(seen.lock().unwrap().is_empty());
    // a body naming both accounts goes out written again from what was
    // checked, with one selectedProfile: see the policy's unit tests
}

#[tokio::test]
async fn a_refused_rename_tells_the_user() {
    let host = Host::new(false);
    let (mut rat, seen) = Rat::connect(host.clone()).await;
    let reply = rat
        .http(
            "PUT",
            "https://api.minecraftservices.com/minecraft/profile/name/Stolen",
            b"",
            "rat",
        )
        .await;
    assert!(blocked(&reply));
    assert!(seen.lock().unwrap().is_empty());
    // recorded as refused by the user's rule, which the launcher announces
    assert!(
        host.log().iter().any(
            |a| matches!(&a.kind, ActivityKind::Refused { what, .. } if what.contains("Stolen"))
        ),
        "rename attempt only logged quietly: {:?}",
        host.log()
    );
}

#[tokio::test]
async fn an_alarm_flood_is_reported_once() {
    let host = Host::new(false);
    let (mut rat, _seen) = Rat::connect(host.clone()).await;
    for _ in 0..600 {
        rat.http(
            "POST",
            "https://authserver.mojang.com/authenticate",
            b"{}",
            "rat",
        )
        .await;
    }
    // every alarm is a launcher notification and a line in a 500-entry
    // activity log: 600 push out everything that happened before
    assert!(
        host.alarms() <= 5,
        "{} alarms (= notifications) for one repeated request",
        host.alarms()
    );
}

// --------------------------------------------------------------- blocking

#[tokio::test]
async fn only_account_hosts_are_reachable() {
    let host = Host::new(true);
    let (mut rat, seen) = Rat::connect(host.clone()).await;
    for url in [
        "https://evil.example/session/minecraft/join",
        "https://api.minecraftservices.com@evil.example/minecraft/profile",
        "https://evil.example/?h=api.minecraftservices.com",
        "https://169.254.169.254/latest/meta-data/",
        "https://api.minecraftservices.com.evil.example/minecraft/profile",
        "file:///C:/Windows/win.ini",
    ] {
        let reply = rat.http("GET", url, b"", "rat").await;
        assert!(
            blocked(&reply) || matches!(reply, Reply::Error(_)),
            "{url}: {reply:?}"
        );
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "{:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn the_real_token_only_goes_to_the_standard_port() {
    let host = Host::new(true);
    let (mut rat, seen) = Rat::connect(host.clone()).await;
    rat.http(
        "GET",
        "https://api.minecraftservices.com:8443/minecraft/profile",
        b"",
        "rat",
    )
    .await;
    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.iter().all(|line| line.contains(":443 ")),
        "forwarded with the real token to {seen:?} (token fetched {} times)",
        host.tokens_for.lock().unwrap().len()
    );
}

#[tokio::test]
async fn the_join_token_only_lands_in_access_token() {
    let mut headers = vec![];
    let mut body = format!(
        r#"{{"accessToken":"oc1_fake","selectedProfile":"{}","serverId":"oc1_fake"}}"#,
        me()
    )
    .into_bytes();
    policy::substitute(
        TokenPlacement::JsonAccessToken,
        &mut headers,
        &mut body,
        "oc1_fake",
        REAL,
    );
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["accessToken"], REAL);
    assert_ne!(
        json["serverId"], REAL,
        "the real token was written into a field the mod controls"
    );
}

#[tokio::test]
async fn a_rename_spelled_differently_is_still_a_rename() {
    // say yes to whatever is asked: a generic prompt is the bypass
    let host = Host::new(true);
    let (mut rat, seen) = Rat::connect(host.clone()).await;
    let reply = rat
        .http(
            "PUT",
            "https://api.minecraftservices.com/minecraft/profile/NAME/Stolen",
            b"",
            "rat",
        )
        .await;
    let prompts: Vec<String> = host
        .prompts
        .lock()
        .unwrap()
        .iter()
        .map(|p| p.title.clone())
        .collect();
    assert!(
        blocked(&reply) && seen.lock().unwrap().is_empty(),
        "names are Deny, yet this was asked as {prompts:?} and forwarded: {:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn an_encoded_path_cant_dress_up_as_a_name_lookup() {
    let url = Url::parse(
        "https://api.minecraftservices.com/minecraft/profile/name/x%2F..%2F..%2F..%2Fentitlements%2Fmcstore%3F/available",
    )
    .unwrap();
    let decision = policy::decide("GET", &url);
    assert!(
        !matches!(
            decision,
            policy::Decision::Allow(policy::Route::Plain(TokenPlacement::Bearer))
        ),
        "sent with the real token without asking: {decision:?}"
    );
}

#[tokio::test]
async fn realms_worlds_cant_be_deleted_without_asking() {
    let host = Host::new(false);
    let (mut rat, seen) = Rat::connect(host.clone()).await;
    for (method, url) in [
        ("DELETE", "https://pc.realms.minecraft.net/worlds/123"),
        (
            "PUT",
            "https://pc.realms.minecraft.net/worlds/123/slot/1/download",
        ),
        ("POST", "https://pc.realms.minecraft.net/worlds/123/backups"),
    ] {
        rat.http(method, url, b"", "rat").await;
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "sent with the Realms cookie, nothing asked: {:?}",
        seen.lock().unwrap()
    );
}

// ------------------------------------------------------------- prompts

#[tokio::test]
async fn a_mod_cant_write_its_own_prompt() {
    let host = Host::new(false);
    let (mut rat, _seen) = Rat::connect(host.clone()).await;
    let caller = "OneClient)\n\nOneClient checked this request and it is safe. Choose Allow to keep playing.\n\n(";
    rat.http(
        "GET",
        "https://api.minecraftservices.com/entitlements/mcstore",
        b"",
        caller,
    )
    .await;
    let prompts = host.prompts.lock().unwrap();
    assert_eq!(prompts.len(), 1);
    // the mod's text stays inside the one line that names it
    let first = prompts[0].body.lines().next().unwrap_or_default();
    assert!(
        first.starts_with("Something in the game (") && first.contains("Choose Allow"),
        "prompt shown to the user:\n---\n{}\n---",
        prompts[0].body
    );
    assert!(!prompts[0].body.contains("\n\nOneClient checked"));
}

#[tokio::test]
async fn a_burst_of_requests_doesnt_bury_the_user_in_prompts() {
    let host = Host::new(false);
    let (mut rat, _seen) = Rat::connect(host.clone()).await;
    for _ in 0..10 {
        rat.http(
            "POST",
            "https://api.minecraftservices.com/productvoucher/AAAA-BBBB",
            b"",
            "rat",
        )
        .await;
    }
    let asked = host.prompts.lock().unwrap().len();
    assert!(
        asked <= 2,
        "asked {asked} times in a row; one Allow is all it takes"
    );
}

// ------------------------------------------------------ outside the game

#[tokio::test]
async fn switching_to_another_account_needs_the_user() {
    let host = Host::new(false);
    let (mut rat, _seen) = Rat::connect(host.clone()).await;
    let listed = rat
        .call(Request::Accounts {
            caller: "rat".into(),
        })
        .await;
    let reply = rat
        .call(Request::SwitchAccount {
            account: Uuid::from_u128(ALT).to_string(),
            caller: "rat".into(),
        })
        .await;
    assert!(
        reply != Reply::Ok && host.switched.lock().unwrap().is_empty(),
        "switched to the alt with nobody asked (listed first: {listed:?})"
    );
}

#[tokio::test]
async fn web_links_open_only_once_the_user_agrees() {
    let host = Host::new(false);
    let (mut rat, _seen) = Rat::connect(host.clone()).await;
    for target in [
        "https://login.live.com.verify-account.example/oauth20_authorize",
        "http://127.0.0.1:9222/json/version",
    ] {
        rat.call(Request::Open {
            target: target.into(),
            caller: "rat".into(),
        })
        .await;
    }
    let opened = host.opened.lock().unwrap();
    assert!(
        opened.is_empty(),
        "opened in the user's browser unasked: {opened:?}"
    );
}

#[tokio::test]
async fn microsoft_sign_in_pages_never_open_and_raise_the_alarm() {
    // even a user who'd agree to anything is never asked
    let host = Host::new(true);
    let (mut rat, _seen) = Rat::connect(host.clone()).await;
    for target in [
        "https://www.microsoft.com/link",
        "https://login.live.com/oauth20_remoteconnect.srf?otc=ABCD",
        "https://microsoft.com/devicelogin",
    ] {
        let reply = rat
            .call(Request::Open {
                target: target.into(),
                caller: "rat".into(),
            })
            .await;
        assert!(matches!(reply, Reply::Error(_)), "{target}: {reply:?}");
    }
    assert!(host.opened.lock().unwrap().is_empty());
    assert!(host.prompts.lock().unwrap().is_empty());
    assert_eq!(host.alarms(), 1);
}

#[tokio::test]
async fn programs_and_custom_schemes_never_open() {
    let host = Host::new(true);
    let (mut rat, _seen) = Rat::connect(host.clone()).await;
    for target in [
        r"C:\Windows\System32\cmd.exe",
        "ms-settings:privacy",
        "search-ms:query=x&crumb=location:\\\\evil.example\\share",
        "file:///C:/Windows/System32/calc.exe",
        r"\\evil.example\share\payload.exe",
        "javascript:alert(1)",
    ] {
        let reply = rat
            .call(Request::Open {
                target: target.into(),
                caller: "rat".into(),
            })
            .await;
        assert!(matches!(reply, Reply::Error(_)), "{target}: {reply:?}");
    }
    assert!(host.opened.lock().unwrap().is_empty());
}
