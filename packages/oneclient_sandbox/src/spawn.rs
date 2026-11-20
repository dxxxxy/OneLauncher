use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};

/// Everything needed to start the game, independent of how it is sandboxed
#[derive(Debug)]
pub struct SpawnSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// The complete environment; nothing is inherited
    pub env: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
    pub stdout: Option<std::fs::File>,
    pub stderr: Option<std::fs::File>,
}

impl SpawnSpec {
    /// Takes the program, arguments and working directory from `command`,
    /// and builds a clean environment: the launcher's own environment
    /// filtered to what a game needs (see [`crate::env`]), with the
    /// command's explicit changes on top
    pub fn from_command(
        command: &std::process::Command,
        stdout: Option<std::fs::File>,
        stderr: Option<std::fs::File>,
    ) -> Self {
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(key, _)| crate::env::passes(&key.to_string_lossy()))
            .collect();
        for (key, value) in command.get_envs() {
            env.retain(|(k, _)| !crate::env::same_key(k, key));
            if let Some(value) = value {
                env.push((key.to_os_string(), value.to_os_string()));
            }
        }
        Self {
            program: PathBuf::from(command.get_program()),
            args: command.get_args().map(|a| a.to_os_string()).collect(),
            env,
            cwd: command
                .get_current_dir()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".")),
            stdout,
            stderr,
        }
    }

    pub fn set_env(&mut self, key: &str, value: impl Into<OsString>) {
        self.env
            .retain(|(k, _)| !crate::env::same_key(k, std::ffi::OsStr::new(key)));
        self.env.push((key.into(), value.into()));
    }

    /// A tokio command for the spec, optionally run through a sandbox
    /// launcher (`bwrap …`, `sandbox-exec …`) that takes the real program as
    /// its next argument
    pub(crate) fn into_tokio(
        self,
        launcher: Option<(PathBuf, Vec<OsString>)>,
    ) -> tokio::process::Command {
        let mut command = match launcher {
            Some((program, prefix)) => {
                let mut command = tokio::process::Command::new(program);
                command.args(prefix).arg(&self.program);
                command
            }
            None => tokio::process::Command::new(&self.program),
        };
        command
            .args(&self.args)
            .env_clear()
            .envs(self.env)
            .current_dir(&self.cwd)
            .stdin(Stdio::null())
            .stdout(self.stdout.map_or_else(Stdio::null, Stdio::from))
            .stderr(self.stderr.map_or_else(Stdio::null, Stdio::from));
        detach(command.as_std_mut());
        command
    }
}

/// The game outlives the launcher, so it must not share its console or get
/// the launcher's Ctrl-C
fn detach(command: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(crate::DETACHED_FLAGS);
    }
}

/// The running game, whichever way it was started
pub enum GameChild {
    Tokio(tokio::process::Child),
    #[cfg(windows)]
    Raw(crate::windows::RawChild),
}

impl GameChild {
    pub fn id(&self) -> Option<u32> {
        match self {
            Self::Tokio(child) => child.id(),
            #[cfg(windows)]
            Self::Raw(child) => Some(child.pid),
        }
    }

    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match self {
            Self::Tokio(child) => child.wait().await,
            #[cfg(windows)]
            Self::Raw(child) => child.wait().await,
        }
    }

    pub fn start_kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tokio(child) => child.start_kill(),
            #[cfg(windows)]
            Self::Raw(child) => child.kill(),
        }
    }
}

/// Unsandboxed: a normal child process
pub(crate) fn plain(spec: SpawnSpec) -> std::io::Result<GameChild> {
    spec.into_tokio(None).spawn().map(GameChild::Tokio)
}
