//! Discord rich presence for sandboxed games
//!
//! Mods show rich presence by talking to Discord's local IPC endpoint
//! (`\\.\pipe\discord-ipc-N`, or a `discord-ipc-N` socket on Unix). The
//! sandbox can't reach it, and shouldn't: the same endpoint lets any local
//! program ask Discord to sign it in to the user's account. The launcher
//! offers a relay in its place that passes on rich presence and its join
//! and spectate events, and answers every other command with an error.
//!
//! - Windows: a pipe only the game's AppContainer can open; the agent points
//!   Java IPC libraries at it (`-Doneclient.discord`)
//! - Unix: a socket the sandbox shows at the path Discord's would have

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Activity, ActivityKind, BrokerHost};

/// `-D` property naming the relay pipe for the agent (Windows)
pub const RELAY_PROPERTY: &str = "oneclient.discord";

const HANDSHAKE: u32 = 0;
const FRAME: u32 = 1;
const CLOSE: u32 = 2;
const PING: u32 = 3;
const PONG: u32 = 4;
/// Windows: pipe instances kept waiting for the game at once
#[cfg(windows)]
const LISTENERS: usize = 4;
/// Presence payloads are a few KB; anything bigger isn't rich presence
const MAX_FRAME: usize = 64 * 1024;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

type Connecting = Pin<Box<dyn Future<Output = io::Result<Box<dyn Stream>>> + Send>>;
type Connect = Arc<dyn Fn() -> Connecting + Send + Sync>;

/// What a game may ask Discord to do
fn allowed(frame: &Value) -> bool {
    let field = |name| frame.get(name).and_then(Value::as_str);
    match field("cmd") {
        Some("SET_ACTIVITY" | "SEND_ACTIVITY_JOIN_INVITE" | "CLOSE_ACTIVITY_REQUEST") => true,
        Some("SUBSCRIBE" | "UNSUBSCRIBE") => matches!(
            field("evt"),
            Some("ACTIVITY_JOIN" | "ACTIVITY_SPECTATE" | "ACTIVITY_JOIN_REQUEST")
        ),
        _ => false,
    }
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<(u32, Vec<u8>)>> {
    let mut header = [0u8; 8];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let op = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Discord frame too large",
        ));
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await?;
    Ok(Some((op, body)))
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    op: u32,
    body: &[u8],
) -> io::Result<()> {
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(&op.to_le_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Relays one game connection to Discord until either side hangs up.
/// `denied` hears each refused command once per connection
pub async fn relay<G, D>(game: G, discord: D, mut denied: impl FnMut(String)) -> io::Result<()>
where
    G: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let (mut game_read, game_write) = tokio::io::split(game);
    let (mut discord_read, mut discord_write) = tokio::io::split(discord);
    let game_write = tokio::sync::Mutex::new(game_write);
    let mut reported = HashSet::new();

    let up = async {
        while let Some((op, body)) = read_frame(&mut game_read).await? {
            match op {
                HANDSHAKE | PING | PONG => write_frame(&mut discord_write, op, &body).await?,
                CLOSE => {
                    write_frame(&mut discord_write, op, &body).await?;
                    break;
                }
                FRAME => {
                    let frame: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    if allowed(&frame) {
                        write_frame(&mut discord_write, op, &body).await?;
                        continue;
                    }
                    let command = frame
                        .get("cmd")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string();
                    if reported.insert(command.clone()) {
                        denied(command.clone());
                    }
                    let reply = json!({
                        "cmd": command,
                        "evt": "ERROR",
                        "nonce": frame.get("nonce").cloned().unwrap_or(Value::Null),
                        "data": {
                            "code": 4006,
                            "message": "OneClient only lets games set rich presence",
                        },
                    });
                    let reply = serde_json::to_vec(&reply).map_err(io::Error::other)?;
                    write_frame(&mut *game_write.lock().await, FRAME, &reply).await?;
                }
                _ => break,
            }
        }
        io::Result::Ok(())
    };
    let down = async {
        while let Some((op, body)) = read_frame(&mut discord_read).await? {
            write_frame(&mut *game_write.lock().await, op, &body).await?;
        }
        io::Result::Ok(())
    };
    tokio::select! {
        result = up => result,
        result = down => result,
    }
}

/// A relay serving one game; dropping it stops it
pub struct DiscordRelay {
    path: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
    #[cfg(unix)]
    _dir: unix::SocketDir,
}

impl Drop for DiscordRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DiscordRelay {
    /// Windows: the pipe; Unix: the socket
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// `-Doneclient.discord=…` for the agent; only Windows needs it
    pub fn jvm_property(&self) -> Option<String> {
        cfg!(windows).then(|| format!("-D{RELAY_PROPERTY}={}", self.path.display()))
    }
}

fn handle(cluster_id: i64, host: Arc<dyn BrokerHost>, connect: Connect, mut game: Box<dyn Stream>) {
    tokio::spawn(async move {
        // libraries check the pipe exists by opening and closing it; only
        // a real handshake is worth a connection to Discord
        let hello = match read_frame(&mut game).await {
            Ok(Some((HANDSHAKE, body))) => body,
            _ => return,
        };
        let mut discord = match connect().await {
            Ok(discord) => discord,
            // Discord isn't running; the game's library sees a closed pipe and retries later
            Err(err) => {
                tracing::debug!("no Discord to relay to: {err}");
                return;
            }
        };
        if let Err(err) = write_frame(&mut discord, HANDSHAKE, &hello).await {
            tracing::debug!("Discord closed the relay: {err}");
            return;
        }
        let result = relay(game, discord, |command| {
            tracing::info!(cluster_id, %command, "refused a Discord command from the game");
            host.record(Activity::now(
                cluster_id,
                ActivityKind::DiscordDenied { command },
            ));
        })
        .await;
        if let Err(err) = result {
            tracing::debug!("Discord relay connection ended: {err}");
        }
    });
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::time::Duration;

    use polyio::win_security::{SecurityDescriptor, current_user_sid};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeServer, PipeMode, ServerOptions,
    };

    use super::Stream;

    pub(super) fn create(
        name: &str,
        security: &SecurityDescriptor,
        first: bool,
    ) -> io::Result<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options
            .pipe_mode(PipeMode::Byte)
            .reject_remote_clients(true)
            .first_pipe_instance(first);
        let mut attributes = security.attributes();
        // SAFETY: attributes and the descriptor they borrow outlive the call
        unsafe { options.create_with_security_attributes_raw(name, attributes.as_mut_ptr()) }
    }

    pub(super) fn security(app_container_sid: Option<&str>) -> io::Result<SecurityDescriptor> {
        let user = current_user_sid()?;
        let mut sddl = format!("D:P(A;;GA;;;{user})");
        if let Some(sid) = app_container_sid {
            sddl.push_str(&format!("(A;;GRGW;;;{sid})"));
        }
        SecurityDescriptor::from_sddl(&sddl)
    }

    /// Discord's own pipe: the first of `discord-ipc-0..9` that answers
    pub(super) async fn discord() -> io::Result<Box<dyn Stream>> {
        const ERROR_PIPE_BUSY: i32 = 231;
        let mut last = io::Error::from(io::ErrorKind::NotFound);
        for attempt in 0..2 {
            for i in 0..10 {
                match ClientOptions::new().open(format!(r"\\.\pipe\discord-ipc-{i}")) {
                    Ok(client) => return Ok(Box::new(client)),
                    Err(err) => last = err,
                }
            }
            if attempt == 0 && last.raw_os_error() == Some(ERROR_PIPE_BUSY) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            } else {
                break;
            }
        }
        Err(last)
    }
}

#[cfg(windows)]
impl DiscordRelay {
    /// `app_container_sid` is the sandbox allowed to open the relay
    pub fn start(
        cluster_id: i64,
        host: Arc<dyn BrokerHost>,
        app_container_sid: Option<&str>,
    ) -> io::Result<Self> {
        Self::start_with(
            cluster_id,
            host,
            app_container_sid,
            Arc::new(|| Box::pin(windows::discord()) as Connecting),
        )
    }

    fn start_with(
        cluster_id: i64,
        host: Arc<dyn BrokerHost>,
        app_container_sid: Option<&str>,
        connect: Connect,
    ) -> io::Result<Self> {
        let name = format!(
            r"\\.\pipe\oneclient-discord-{}",
            uuid::Uuid::new_v4().simple()
        );
        let security = Arc::new(windows::security(app_container_sid)?);
        // the first instance claims the name; a few more wait alongside so a
        // library's existence check never leaves the pipe busy for its open
        let mut servers = vec![windows::create(&name, &security, true)?];
        for _ in 1..LISTENERS {
            servers.push(windows::create(&name, &security, false)?);
        }
        let pipe = name.clone();
        let task = tokio::spawn(async move {
            let mut listeners = tokio::task::JoinSet::new();
            for mut server in servers {
                let (pipe, security, host, connect) = (
                    pipe.clone(),
                    Arc::clone(&security),
                    Arc::clone(&host),
                    Arc::clone(&connect),
                );
                listeners.spawn(async move {
                    loop {
                        if let Err(err) = server.connect().await {
                            tracing::debug!("Discord relay could not accept: {err}");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                        let next = match windows::create(&pipe, &security, false) {
                            Ok(next) => next,
                            Err(err) => {
                                tracing::warn!("Discord relay listener stopped: {err}");
                                return;
                            }
                        };
                        let game = std::mem::replace(&mut server, next);
                        handle(
                            cluster_id,
                            Arc::clone(&host),
                            Arc::clone(&connect),
                            Box::new(game),
                        );
                    }
                });
            }
            while listeners.join_next().await.is_some() {}
        });
        Ok(Self {
            path: name.into(),
            task,
        })
    }
}

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use tokio::net::UnixStream;

    use super::Stream;

    /// Removes the relay's directory with it
    pub(super) struct SocketDir(pub(super) PathBuf);

    impl Drop for SocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(super) fn make_dir(dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }

    /// Where Discord (and its Flatpak and Snap builds) put the socket, in
    /// the order Discord's own libraries look
    fn candidates() -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = ["XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"]
            .iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .collect();
        roots.push(PathBuf::from("/tmp"));
        let mut paths = Vec::new();
        for root in roots {
            for sub in [
                "",
                "app/com.discordapp.Discord",
                "snap.discord",
                ".flatpak/dev.vencord.Vesktop/xdg-run",
            ] {
                for i in 0..10 {
                    paths.push(root.join(sub).join(format!("discord-ipc-{i}")));
                }
            }
        }
        paths
    }

    pub(super) async fn discord(own: PathBuf) -> io::Result<Box<dyn Stream>> {
        let mut last = io::Error::from(io::ErrorKind::NotFound);
        for path in candidates() {
            if path == own {
                continue;
            }
            match UnixStream::connect(&path).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(err) => last = err,
            }
        }
        Err(last)
    }
}

#[cfg(unix)]
impl DiscordRelay {
    /// Listens on `<dir>/discord-ipc-0`. `dir` is made 0700 and removed with
    /// the relay. Keep it short: socket paths are limited to about 100 bytes
    pub fn start(
        cluster_id: i64,
        host: Arc<dyn BrokerHost>,
        dir: std::path::PathBuf,
    ) -> io::Result<Self> {
        unix::make_dir(&dir)?;
        let path = dir.join("discord-ipc-0");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path)?;
        let own = path.clone();
        let connect: Connect = Arc::new(move || Box::pin(unix::discord(own.clone())) as Connecting);
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((game, _)) => handle(
                        cluster_id,
                        Arc::clone(&host),
                        Arc::clone(&connect),
                        Box::new(game),
                    ),
                    Err(err) => {
                        tracing::debug!("Discord relay could not accept: {err}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        Ok(Self {
            path,
            task,
            _dir: unix::SocketDir(dir),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn send(stream: &mut (impl AsyncWrite + Unpin), op: u32, body: Value) {
        write_frame(stream, op, &serde_json::to_vec(&body).unwrap())
            .await
            .unwrap();
    }

    async fn next(stream: &mut (impl AsyncRead + Unpin)) -> (u32, Value) {
        let (op, body) = read_frame(stream).await.unwrap().unwrap();
        (op, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn presence_passes_and_account_access_is_refused() {
        let (mut game, game_side) = tokio::io::duplex(1 << 16);
        let (relay_side, mut discord) = tokio::io::duplex(1 << 16);
        let denied = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = Arc::clone(&denied);
        let task = tokio::spawn(async move {
            relay(game_side, relay_side, move |c| log.lock().unwrap().push(c)).await
        });

        send(&mut game, HANDSHAKE, json!({"v": 1, "client_id": "1"})).await;
        assert_eq!(
            next(&mut discord).await,
            (HANDSHAKE, json!({"v": 1, "client_id": "1"}))
        );
        send(
            &mut discord,
            FRAME,
            json!({"cmd": "DISPATCH", "evt": "READY"}),
        )
        .await;
        assert_eq!(next(&mut game).await.1["evt"], "READY");

        let presence = json!({"cmd": "SET_ACTIVITY", "args": {"pid": 1, "activity": {"state": "Hypixel"}}, "nonce": "a"});
        send(&mut game, FRAME, presence.clone()).await;
        assert_eq!(next(&mut discord).await, (FRAME, presence));

        let join = json!({"cmd": "SUBSCRIBE", "evt": "ACTIVITY_JOIN", "nonce": "b"});
        send(&mut game, FRAME, join.clone()).await;
        assert_eq!(next(&mut discord).await, (FRAME, join));

        for (cmd, evt) in [
            ("AUTHORIZE", None),
            ("SUBSCRIBE", Some("MESSAGE_CREATE")),
            ("AUTHORIZE", None),
        ] {
            let mut frame =
                json!({"cmd": cmd, "args": {"client_id": "1", "scopes": ["guilds"]}, "nonce": "c"});
            if let Some(evt) = evt {
                frame["evt"] = json!(evt);
            }
            send(&mut game, FRAME, frame).await;
            let (op, reply) = next(&mut game).await;
            assert_eq!(op, FRAME);
            assert_eq!(reply["evt"], "ERROR");
            assert_eq!(reply["nonce"], "c");
        }
        assert_eq!(*denied.lock().unwrap(), ["AUTHORIZE", "SUBSCRIBE"]);

        // nothing refused ever reached Discord
        send(&mut game, PING, json!({})).await;
        assert_eq!(next(&mut discord).await.0, PING);

        drop(game);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn oversized_frames_end_the_connection() {
        let (mut game, game_side) = tokio::io::duplex(1 << 16);
        let (relay_side, _discord) = tokio::io::duplex(1 << 16);
        let mut header = FRAME.to_le_bytes().to_vec();
        header.extend_from_slice(&((MAX_FRAME + 1) as u32).to_le_bytes());
        game.write_all(&header).await.unwrap();
        let result = relay(game_side, relay_side, |_| {}).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn the_windows_relay_serves_each_connection() {
        use tokio::net::windows::named_pipe::ClientOptions;

        #[derive(Default)]
        struct Host(std::sync::Mutex<Vec<Activity>>);
        impl BrokerHost for Host {
            fn real_token(&self, _: uuid::Uuid) -> crate::BoxFuture<'_, Result<String, String>> {
                Box::pin(async { Err(String::new()) })
            }
            fn record(&self, activity: Activity) {
                self.0.lock().unwrap().push(activity);
            }
            fn open(&self, _: crate::OpenTarget) {}
            fn pick(
                &self,
                _: crate::PickMode,
                _: String,
            ) -> crate::BoxFuture<'_, Option<std::path::PathBuf>> {
                Box::pin(async { None })
            }
        }

        // a pretend Discord that echoes every frame back
        let connect: Connect = Arc::new(|| {
            Box::pin(async {
                let (ours, mut theirs) = tokio::io::duplex(1 << 16);
                tokio::spawn(async move {
                    while let Ok(Some((op, body))) = read_frame(&mut theirs).await {
                        write_frame(&mut theirs, op, &body).await.unwrap();
                    }
                });
                Ok(Box::new(ours) as Box<dyn Stream>)
            }) as Connecting
        });
        let host = Arc::new(Host::default());
        let relay = DiscordRelay::start_with(7, host.clone(), None, connect).unwrap();
        assert!(relay.jvm_property().unwrap().contains("oneclient-discord-"));

        for _ in 0..2 {
            // what File.exists() does: open and close at once
            drop(ClientOptions::new().open(relay.path()).unwrap());
            let mut game = ClientOptions::new().open(relay.path()).unwrap();
            send(&mut game, HANDSHAKE, json!({"v": 1})).await;
            assert_eq!(next(&mut game).await.0, HANDSHAKE);
            send(&mut game, FRAME, json!({"cmd": "GET_GUILDS", "nonce": "x"})).await;
            assert_eq!(next(&mut game).await.1["evt"], "ERROR");
        }
        let log = host.0.lock().unwrap();
        assert_eq!(log.len(), 2);
        assert!(
            matches!(&log[0].kind, ActivityKind::DiscordDenied { command } if command == "GET_GUILDS")
        );
    }
}
