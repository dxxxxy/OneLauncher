//! Wire format between the launcher and `oneclient-agent.jar`
//!
//! Plain length-prefixed binary so the agent can read it with nothing but
//! `DataInputStream` on Java 8. Every integer is big-endian.
//!
//! ```text
//! frame   = u32 length, payload
//! payload = u32 id, u8 kind, body
//! string  = u32 length, UTF-8
//! bytes   = u32 length, raw
//! headers = u16 count, (string name, string value)*
//! ```
//!
//! Requests come up the agent→launcher channel, replies go down the other one
//! carrying the same id. The two directions use separate pipes because Java
//! can only do blocking I/O on a pipe, and a blocked read on a synchronous
//! Windows handle would also block writes on it

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Frames bigger than this are refused, so a hostile game can't make the
/// launcher allocate unbounded memory
pub const MAX_FRAME: u32 = 8 * 1024 * 1024;

pub type Headers = Vec<(String, String)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// First frame on a connection; anything else first closes it
    Hello { key: String, agent_version: String },
    Http {
        method: String,
        url: String,
        headers: Headers,
        body: Vec<u8>,
        /// The jar the call came from, as the agent saw it on the stack.
        /// A hostile mod can fake this, so it's only shown, never trusted
        caller: String,
    },
    /// Open a link or a folder in the user's real desktop
    Open { target: String, caller: String },
    /// Show the user's file picker outside the sandbox
    Pick {
        mode: PickMode,
        title: String,
        filters: Vec<String>,
        caller: String,
    },
    /// The user dropped a file the sandbox can't read onto the game window.
    /// The game can't prove that, so the launcher asks before copying it in
    Import { path: String, caller: String },
    /// The user's accounts, for an in-game account switcher (names only)
    Accounts { caller: String },
    /// Play as another of the user's accounts from now on
    SwitchAccount { account: String, caller: String },
    /// Start adding an account in the launcher
    AddAccount { caller: String },
    /// Move a file or folder inside the instance to the user's trash
    Trash { path: String, caller: String },
    /// Select a file inside the instance in the user's file manager
    Reveal { path: String, caller: String },
}

/// One of the user's accounts as the game may see it: never a token
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameAccount {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickMode {
    OpenFile,
    OpenFolder,
    SaveFile,
}

/// One "files of this type" entry of a picker, `name|ext;ext` on the wire
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickFilter {
    pub name: String,
    /// Without the dot; `*` means any file
    pub extensions: Vec<String>,
}

impl PickFilter {
    /// `Images|png;jpg`, `*.png;*.jpg` (tinyfd) or `png` (SDL) all parse
    pub fn parse(wire: &str) -> Option<Self> {
        let (name, patterns) = match wire.rsplit_once('|') {
            Some((name, patterns)) => (name.trim(), patterns),
            None => ("", wire),
        };
        let extensions: Vec<String> = patterns
            .split([';', ',', ' '])
            .map(|p| p.trim().trim_start_matches('*').trim_start_matches('.'))
            .map(|p| if p.is_empty() { "*" } else { p })
            .filter(|p| p.len() <= 32 && !p.contains(['/', '\\']))
            .map(str::to_string)
            .collect();
        if extensions.is_empty() {
            return None;
        }
        let name = if name.is_empty() {
            extensions.join(", ")
        } else {
            name.chars().take(80).collect()
        };
        Some(Self { name, extensions })
    }
}

impl PickMode {
    fn from_byte(byte: u8) -> io::Result<Self> {
        match byte {
            0 => Ok(Self::OpenFile),
            1 => Ok(Self::OpenFolder),
            2 => Ok(Self::SaveFile),
            other => Err(invalid(format!("unknown pick mode {other}"))),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::OpenFile => 0,
            Self::OpenFolder => 1,
            Self::SaveFile => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok,
    Http {
        status: u16,
        headers: Headers,
        body: Vec<u8>,
    },
    /// The path the user picked, already reachable from inside the sandbox
    Picked(Option<String>),
    Accounts {
        active: String,
        accounts: Vec<GameAccount>,
    },
    Error(String),
}

const HELLO: u8 = 1;
const HTTP: u8 = 2;
const OPEN: u8 = 3;
const PICK: u8 = 4;
const IMPORT: u8 = 5;
const ACCOUNTS: u8 = 6;
const SWITCH_ACCOUNT: u8 = 7;
const ADD_ACCOUNT: u8 = 8;
const TRASH: u8 = 9;
const REVEAL: u8 = 10;

const OK: u8 = 0x81;
const HTTP_REPLY: u8 = 0x82;
const ERROR: u8 = 0x83;
const PICKED: u8 = 0x84;
const ACCOUNTS_REPLY: u8 = 0x85;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

struct Writer(Vec<u8>);

impl Writer {
    fn new(id: u32, kind: u8) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&id.to_be_bytes());
        buf.push(kind);
        Self(buf)
    }

    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.0.extend_from_slice(value);
    }

    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn headers(&mut self, headers: &Headers) {
        self.u16(headers.len().min(u16::MAX as usize) as u16);
        for (name, value) in headers.iter().take(u16::MAX as usize) {
            self.string(name);
            self.string(value);
        }
    }

    fn frame(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() + 4);
        out.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.0);
        out
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> io::Result<&[u8]> {
        if self.0.len() < n {
            return Err(invalid("frame ended early"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| invalid("string is not UTF-8"))
    }

    fn headers(&mut self) -> io::Result<Headers> {
        let count = self.u16()?;
        (0..count)
            .map(|_| Ok((self.string()?, self.string()?)))
            .collect()
    }
}

pub fn encode_request(id: u32, request: &Request) -> Vec<u8> {
    match request {
        Request::Hello { key, agent_version } => {
            let mut w = Writer::new(id, HELLO);
            w.string(key);
            w.string(agent_version);
            w.frame()
        }
        Request::Http {
            method,
            url,
            headers,
            body,
            caller,
        } => {
            let mut w = Writer::new(id, HTTP);
            w.string(method);
            w.string(url);
            w.headers(headers);
            w.bytes(body);
            w.string(caller);
            w.frame()
        }
        Request::Open { target, caller } => {
            let mut w = Writer::new(id, OPEN);
            w.string(target);
            w.string(caller);
            w.frame()
        }
        Request::Pick {
            mode,
            title,
            filters,
            caller,
        } => {
            let mut w = Writer::new(id, PICK);
            w.u8(mode.to_byte());
            w.string(title);
            w.u16(filters.len() as u16);
            for filter in filters {
                w.string(filter);
            }
            w.string(caller);
            w.frame()
        }
        Request::Import { path, caller } => {
            let mut w = Writer::new(id, IMPORT);
            w.string(path);
            w.string(caller);
            w.frame()
        }
        Request::Accounts { caller } => {
            let mut w = Writer::new(id, ACCOUNTS);
            w.string(caller);
            w.frame()
        }
        Request::SwitchAccount { account, caller } => {
            let mut w = Writer::new(id, SWITCH_ACCOUNT);
            w.string(account);
            w.string(caller);
            w.frame()
        }
        Request::AddAccount { caller } => {
            let mut w = Writer::new(id, ADD_ACCOUNT);
            w.string(caller);
            w.frame()
        }
        Request::Trash { path, caller } | Request::Reveal { path, caller } => {
            let kind = if matches!(request, Request::Trash { .. }) {
                TRASH
            } else {
                REVEAL
            };
            let mut w = Writer::new(id, kind);
            w.string(path);
            w.string(caller);
            w.frame()
        }
    }
}

pub fn decode_request(payload: &[u8]) -> io::Result<(u32, Request)> {
    let mut r = Reader(payload);
    let id = r.u32()?;
    let request = match r.u8()? {
        HELLO => Request::Hello {
            key: r.string()?,
            agent_version: r.string()?,
        },
        HTTP => Request::Http {
            method: r.string()?,
            url: r.string()?,
            headers: r.headers()?,
            body: r.bytes()?,
            caller: r.string()?,
        },
        OPEN => Request::Open {
            target: r.string()?,
            caller: r.string()?,
        },
        PICK => {
            let mode = PickMode::from_byte(r.u8()?)?;
            let title = r.string()?;
            let count = r.u16()?;
            let filters = (0..count).map(|_| r.string()).collect::<io::Result<_>>()?;
            Request::Pick {
                mode,
                title,
                filters,
                caller: r.string()?,
            }
        }
        IMPORT => Request::Import {
            path: r.string()?,
            caller: r.string()?,
        },
        ACCOUNTS => Request::Accounts {
            caller: r.string()?,
        },
        SWITCH_ACCOUNT => Request::SwitchAccount {
            account: r.string()?,
            caller: r.string()?,
        },
        ADD_ACCOUNT => Request::AddAccount {
            caller: r.string()?,
        },
        TRASH => Request::Trash {
            path: r.string()?,
            caller: r.string()?,
        },
        REVEAL => Request::Reveal {
            path: r.string()?,
            caller: r.string()?,
        },
        other => return Err(invalid(format!("unknown request kind {other}"))),
    };
    Ok((id, request))
}

pub fn encode_reply(id: u32, reply: &Reply) -> Vec<u8> {
    match reply {
        Reply::Ok => Writer::new(id, OK).frame(),
        Reply::Http {
            status,
            headers,
            body,
        } => {
            let mut w = Writer::new(id, HTTP_REPLY);
            w.u16(*status);
            w.headers(headers);
            w.bytes(body);
            w.frame()
        }
        Reply::Picked(path) => {
            let mut w = Writer::new(id, PICKED);
            w.u8(path.is_some() as u8);
            w.string(path.as_deref().unwrap_or_default());
            w.frame()
        }
        Reply::Accounts { active, accounts } => {
            let mut w = Writer::new(id, ACCOUNTS_REPLY);
            w.string(active);
            w.u16(accounts.len().min(u16::MAX as usize) as u16);
            for account in accounts.iter().take(u16::MAX as usize) {
                w.string(&account.id);
                w.string(&account.name);
            }
            w.frame()
        }
        Reply::Error(message) => {
            let mut w = Writer::new(id, ERROR);
            w.string(message);
            w.frame()
        }
    }
}

pub fn decode_reply(payload: &[u8]) -> io::Result<(u32, Reply)> {
    let mut r = Reader(payload);
    let id = r.u32()?;
    let reply = match r.u8()? {
        OK => Reply::Ok,
        HTTP_REPLY => Reply::Http {
            status: r.u16()?,
            headers: r.headers()?,
            body: r.bytes()?,
        },
        PICKED => {
            let some = r.u8()? != 0;
            let path = r.string()?;
            Reply::Picked(some.then_some(path))
        }
        ACCOUNTS_REPLY => {
            let active = r.string()?;
            let count = r.u16()?;
            let accounts = (0..count)
                .map(|_| {
                    Ok(GameAccount {
                        id: r.string()?,
                        name: r.string()?,
                    })
                })
                .collect::<io::Result<_>>()?;
            Reply::Accounts { active, accounts }
        }
        ERROR => Reply::Error(r.string()?),
        other => return Err(invalid(format!("unknown reply kind {other}"))),
    };
    Ok((id, reply))
}

/// `Ok(None)` on a clean end of stream between frames
pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME {
        return Err(invalid(format!("frame of {len} bytes is too large")));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

pub async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), frame: &[u8]) -> io::Result<()> {
    writer.write_all(frame).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request(request: Request) {
        let frame = encode_request(42, &request);
        let (id, decoded) = decode_request(&frame[4..]).unwrap();
        assert_eq!(id, 42);
        assert_eq!(decoded, request);
    }

    #[test]
    fn requests_survive_the_wire() {
        round_trip_request(Request::Hello {
            key: "k".into(),
            agent_version: "1".into(),
        });
        round_trip_request(Request::Http {
            method: "POST".into(),
            url: "https://sessionserver.mojang.com/session/minecraft/join".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: b"{}".to_vec(),
            caller: "mods/foo.jar".into(),
        });
        round_trip_request(Request::Open {
            target: "https://example.com".into(),
            caller: String::new(),
        });
        round_trip_request(Request::Import {
            path: r"C:\Users\me\Downloads\pack.zip".into(),
            caller: "minecraft".into(),
        });
        round_trip_request(Request::Accounts {
            caller: "polyplus".into(),
        });
        round_trip_request(Request::SwitchAccount {
            account: "00000000-0000-0000-0000-000000000002".into(),
            caller: "polyplus".into(),
        });
        round_trip_request(Request::AddAccount {
            caller: String::new(),
        });
        round_trip_request(Request::Trash {
            path: "C:\\instance\\resourcepacks\\old.zip".into(),
            caller: "polyplus".into(),
        });
        round_trip_request(Request::Reveal {
            path: "/instance/resourcepacks/old.zip".into(),
            caller: String::new(),
        });
        round_trip_request(Request::Pick {
            mode: PickMode::SaveFile,
            title: "Save".into(),
            filters: vec!["*.png".into()],
            caller: String::new(),
        });
    }

    #[test]
    fn replies_survive_the_wire() {
        for reply in [
            Reply::Ok,
            Reply::Error("nope".into()),
            Reply::Picked(None),
            Reply::Picked(Some("C:/x.png".into())),
            Reply::Accounts {
                active: "a".into(),
                accounts: vec![GameAccount {
                    id: "a".into(),
                    name: "Steve".into(),
                }],
            },
            Reply::Http {
                status: 204,
                headers: vec![("a".into(), "b".into())],
                body: vec![1, 2, 3],
            },
        ] {
            let frame = encode_reply(7, &reply);
            assert_eq!(decode_reply(&frame[4..]).unwrap(), (7, reply));
        }
    }

    #[test]
    fn truncated_and_unknown_frames_are_errors() {
        let frame = encode_request(
            1,
            &Request::Open {
                target: "x".into(),
                caller: "y".into(),
            },
        );
        assert!(decode_request(&frame[4..frame.len() - 1]).is_err());
        assert!(decode_request(&[0, 0, 0, 1, 99]).is_err());
    }

    #[tokio::test]
    async fn oversized_frames_are_refused() {
        let mut data: &[u8] = &(MAX_FRAME + 1).to_be_bytes();
        assert!(read_frame(&mut data).await.is_err());
    }

    #[test]
    fn pick_filters_parse_every_library_style() {
        let f = |s: &str| PickFilter::parse(s).unwrap();
        assert_eq!(f("Images|png;jpg").extensions, ["png", "jpg"]);
        assert_eq!(f("Images|png;jpg").name, "Images");
        assert_eq!(f("*.png *.jpg").extensions, ["png", "jpg"]);
        assert_eq!(f("*.png *.jpg").name, "png, jpg");
        assert_eq!(f("All|*").extensions, ["*"]);
        assert_eq!(f("Odd|a/b;zip").extensions, ["zip"]);
        assert!(PickFilter::parse("Bad|../x").is_none());
    }
}
