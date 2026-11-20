//! The two one-way channels between the launcher and one game
//!
//! - Windows: a pair of named pipes whose DACL admits only the game's
//!   AppContainer (or, unsandboxed, the current user)
//! - Unix: a pair of FIFOs in a 0700 directory only the game can see
//!
//! Either way the agent must also present the per-launch key, which it gets
//! from the environment, never the command line

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Where a game's agent connects, as handed to it in `-Doneclient.broker`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub up: String,
    pub down: String,
}

impl Endpoint {
    /// The value of `-Doneclient.broker`, `up|down`
    pub fn property(&self) -> String {
        format!("{}|{}", self.up, self.down)
    }
}

#[cfg(windows)]
pub use windows::*;

#[cfg(windows)]
mod windows {
    use std::io;

    use polyio::win_security::{SecurityDescriptor, current_user_sid};
    use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};

    use super::Endpoint;

    pub struct Listener {
        endpoint: Endpoint,
        security: SecurityDescriptor,
    }

    pub struct Connection {
        pub up: NamedPipeServer,
        pub down: NamedPipeServer,
    }

    impl Listener {
        /// `app_container_sid` is the sandbox the game runs in; `None` lets
        /// any process of this user in (still gated by the key)
        pub fn new(id: &str, app_container_sid: Option<&str>) -> io::Result<Self> {
            let user = current_user_sid()?;
            let mut sddl = format!("D:P(A;;GA;;;{user})");
            if let Some(sid) = app_container_sid {
                sddl.push_str(&format!("(A;;GRGW;;;{sid})"));
            }
            Ok(Self {
                endpoint: Endpoint {
                    up: format!(r"\\.\pipe\oneclient-broker-{id}-up"),
                    down: format!(r"\\.\pipe\oneclient-broker-{id}-down"),
                },
                security: SecurityDescriptor::from_sddl(&sddl)?,
            })
        }

        pub fn endpoint(&self) -> &Endpoint {
            &self.endpoint
        }

        fn create(&self, name: &str, inbound: bool) -> io::Result<NamedPipeServer> {
            let mut options = ServerOptions::new();
            options
                .pipe_mode(PipeMode::Byte)
                .reject_remote_clients(true)
                .max_instances(1)
                .access_inbound(inbound)
                .access_outbound(!inbound);
            let mut attributes = self.security.attributes();
            // SAFETY: attributes and the descriptor they borrow outlive the call
            unsafe { options.create_with_security_attributes_raw(name, attributes.as_mut_ptr()) }
        }

        /// Waits for the agent to open both pipes. Fresh instances are made for
        /// every connection so a game that restarts its agent can reconnect
        pub async fn accept(&self) -> io::Result<Connection> {
            let up = self.create(&self.endpoint.up, true)?;
            let down = self.create(&self.endpoint.down, false)?;
            up.connect().await?;
            down.connect().await?;
            Ok(Connection { up, down })
        }
    }
}

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use tokio::net::unix::pipe;

    use super::Endpoint;

    pub struct Listener {
        endpoint: Endpoint,
        dir: PathBuf,
    }

    pub struct Connection {
        pub up: pipe::Receiver,
        pub down: pipe::Sender,
    }

    fn mkfifo(path: &Path) -> io::Result<()> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has a NUL"))?;
        // SAFETY: valid NUL-terminated path
        if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::AlreadyExists {
                return Err(err);
            }
        }
        Ok(())
    }

    impl Listener {
        /// `dir` must be a directory the sandbox exposes to the game and
        /// nothing else; it is created 0700
        pub fn new(dir: PathBuf) -> io::Result<Self> {
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            let up = dir.join("up");
            let down = dir.join("down");
            mkfifo(&up)?;
            mkfifo(&down)?;
            Ok(Self {
                endpoint: Endpoint {
                    up: up.display().to_string(),
                    down: down.display().to_string(),
                },
                dir,
            })
        }

        pub fn endpoint(&self) -> &Endpoint {
            &self.endpoint
        }

        pub fn dir(&self) -> &Path {
            &self.dir
        }

        /// The agent opens `up` for writing first and sends its hello, then
        /// opens `down`; a write end can only open once a reader exists, so
        /// `down` is retried until the agent gets there
        pub async fn accept(&self) -> io::Result<Connection> {
            let up = pipe::OpenOptions::new().open_receiver(&self.endpoint.up)?;
            up.readable().await?;
            let mut attempts = 0;
            let down = loop {
                match pipe::OpenOptions::new().open_sender(&self.endpoint.down) {
                    Ok(sender) => break sender,
                    Err(err) if err.raw_os_error() == Some(libc::ENXIO) && attempts < 200 => {
                        attempts += 1;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(err) => return Err(err),
                }
            };
            Ok(Connection { up, down })
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Per-launch directory for the FIFOs on Unix
pub fn unix_endpoint_dir(runtime_root: &std::path::Path, id: &str) -> PathBuf {
    runtime_root.join(format!("broker-{id}"))
}
