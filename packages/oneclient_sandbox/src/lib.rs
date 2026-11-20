//! Runs the game in an OS sandbox that can see its own instance and nothing
//! else of the user's
//!
//! - Windows: an AppContainer per instance, plus a job object
//! - macOS: a Seatbelt profile through `sandbox-exec`
//! - Linux: bubblewrap, or Landlock when bubblewrap is unavailable
//!
//! Mods share the game's process, so this can't separate one mod from
//! another; it separates every mod from the user's browser profiles, Discord,
//! wallets, other launchers and OneClient's own credentials. Whatever the
//! sandbox does not cover is reported through [`Protection`] so the UI can be
//! honest about it.

mod env;
mod sensitive;
mod spawn;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use sensitive::{is_sensitive_path, sensitive_reason};
pub use spawn::{GameChild, SpawnSpec};

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("could not set up the game sandbox: {0}")]
    Setup(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type SandboxResult<T> = Result<T, SandboxError>;

/// `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`
#[cfg(windows)]
pub(crate) const DETACHED_FLAGS: u32 = 0x0000_0008 | 0x0000_0200;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Stable per instance: Windows keys the AppContainer on it
    pub instance_id: i64,
    /// Launcher-owned files every game needs: Java, libraries, assets,
    /// natives, the content store, the agent
    pub runtime: Vec<PathBuf>,
    /// The game and instance directories
    pub read_write: Vec<PathBuf>,
    /// Folders the user granted to this instance
    pub extra_read_only: Vec<PathBuf>,
    pub extra_read_write: Vec<PathBuf>,
    /// Where `user.home`, `HOME`, `APPDATA` and temp files are redirected
    pub home: PathBuf,
    pub temp: PathBuf,
    pub microphone: bool,
    /// Windows: let the game reach servers on this machine (needs a one-time
    /// admin prompt). Elsewhere loopback always works
    pub localhost: bool,
}

/// How well the sandbox protects this launch, for the badge in the UI
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "level", content = "reasons", rename_all = "snake_case")]
pub enum Protection {
    Full,
    /// Sandboxed, with gaps the user should know about
    Partial(Vec<String>),
    /// Not sandboxed
    Off(String),
}

impl Protection {
    pub fn is_sandboxed(&self) -> bool {
        !matches!(self, Self::Off(_))
    }
}

/// A sandbox ready to start the game
pub struct Prepared {
    pub protection: Protection,
    /// Windows: grant this SID access to the broker pipes
    pub app_container_sid: Option<String>,
    inner: Backend,
}

enum Backend {
    None,
    #[cfg(windows)]
    Windows(windows::Container),
    #[cfg(target_os = "macos")]
    MacOs(macos::Profile),
    #[cfg(target_os = "linux")]
    Linux(linux::Plan),
}

/// Applies grants and builds the sandbox for one launch. Never fails the
/// launch on an unsupported system; it reports [`Protection::Off`] instead
pub async fn prepare(policy: &SandboxPolicy) -> SandboxResult<Prepared> {
    for dir in [&policy.home, &policy.temp] {
        polyio::create_dir_all(dir)
            .await
            .map_err(|e| SandboxError::Setup(e.to_string()))?;
    }

    #[cfg(windows)]
    {
        let policy = policy.clone();
        let container = tokio::task::spawn_blocking(move || windows::Container::prepare(&policy))
            .await
            .map_err(|e| SandboxError::Setup(e.to_string()))??;
        return Ok(Prepared {
            protection: container.protection(),
            app_container_sid: Some(container.sid_string().to_string()),
            inner: Backend::Windows(container),
        });
    }

    #[cfg(target_os = "macos")]
    {
        let profile = macos::Profile::build(policy)?;
        return Ok(Prepared {
            protection: profile.protection(),
            app_container_sid: None,
            inner: Backend::MacOs(profile),
        });
    }

    #[cfg(target_os = "linux")]
    {
        let plan = linux::Plan::build(policy).await?;
        return Ok(Prepared {
            protection: plan.protection(),
            app_container_sid: None,
            inner: Backend::Linux(plan),
        });
    }

    #[allow(unreachable_code)]
    Ok(unsandboxed("this system has no supported sandbox"))
}

/// For instances the user opted out of the sandbox
pub fn unsandboxed(reason: impl Into<String>) -> Prepared {
    Prepared {
        protection: Protection::Off(reason.into()),
        app_container_sid: None,
        inner: Backend::None,
    }
}

impl Prepared {
    /// Starts the game. `spec.env` should already be the full environment
    /// the game gets (see [`SpawnSpec::from_command`])
    pub fn spawn(&self, spec: SpawnSpec) -> std::io::Result<GameChild> {
        match &self.inner {
            Backend::None => spawn::plain(spec),
            #[cfg(windows)]
            Backend::Windows(container) => container.spawn(spec),
            #[cfg(target_os = "macos")]
            Backend::MacOs(profile) => profile.spawn(spec),
            #[cfg(target_os = "linux")]
            Backend::Linux(plan) => plan.spawn(spec),
        }
    }

    pub fn is_sandboxed(&self) -> bool {
        self.protection.is_sandboxed()
    }
}

/// Gives a running sandboxed game access to one more folder the user picked.
/// Only Windows can widen a running sandbox; elsewhere this returns `false`
/// and the grant applies from the next launch
pub fn grant_live(instance_id: i64, path: &std::path::Path, write: bool) -> SandboxResult<bool> {
    #[cfg(windows)]
    {
        windows::grant_live(instance_id, path, write)?;
        return Ok(true);
    }
    #[allow(unreachable_code)]
    {
        let _ = (instance_id, path, write);
        Ok(false)
    }
}

/// Takes back a folder grant. Windows applies it at once; elsewhere the
/// sandbox is rebuilt from settings at every launch, so nothing is needed
pub fn revoke_grant(instance_id: i64, path: &std::path::Path) -> SandboxResult<()> {
    #[cfg(windows)]
    windows::revoke(instance_id, path)?;
    #[cfg(not(windows))]
    let _ = (instance_id, path);
    Ok(())
}

/// Drops the per-instance sandbox identity when an instance is deleted
pub fn forget_instance(instance_id: i64) {
    #[cfg(windows)]
    windows::forget(instance_id);
    #[cfg(not(windows))]
    let _ = instance_id;
}
