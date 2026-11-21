//! macOS: a Seatbelt profile applied by `sandbox-exec`
//!
//! `sandbox-exec` is deprecated but still ships with every macOS and is what
//! Bazel, Nix and others rely on. It execs the game in place, so the PID the
//! launcher tracks is the game's.

use std::path::{Path, PathBuf};

use crate::{GameChild, Protection, SandboxPolicy, SandboxResult, SpawnSpec};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub(crate) struct Profile {
    source: Option<String>,
}

fn quote(path: &Path) -> String {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let s = real
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{s}\"")
}

/// Later rules win, so the broad deny comes before the specific allows
pub(crate) fn profile(policy: &SandboxPolicy, home: &Path) -> String {
    let mut p = String::from("(version 1)\n(allow default)\n");
    p.push_str(&format!(
        "(deny file-read* file-write* (subpath {}))\n",
        quote(home)
    ));
    p.push_str(&format!(
        "(allow file-read-metadata (literal {}))\n",
        quote(home)
    ));
    for dir in policy.runtime.iter().chain(&policy.extra_read_only) {
        p.push_str(&format!("(allow file-read* (subpath {}))\n", quote(dir)));
    }
    for dir in policy
        .read_write
        .iter()
        .chain(&policy.extra_read_write)
        .chain([&policy.home, &policy.temp])
    {
        p.push_str(&format!(
            "(allow file-read* file-write* (subpath {}))\n",
            quote(dir)
        ));
    }
    // Discord only through the launcher's relay, which passes rich presence
    // and refuses account access
    p.push_str(
        "(deny network-outbound (remote unix-socket (path-regex #\"/discord-ipc-[0-9]+$\")))\n",
    );
    if let Some(relay) = &policy.discord_socket {
        p.push_str(&format!(
            "(allow network-outbound (remote unix-socket (path-literal {})))\n",
            quote(relay)
        ));
    }
    if policy.offline {
        p.push_str("(deny network*)\n");
    }
    // other apps: no scripting them, no asking the keychain
    p.push_str("(deny appleevent-send)\n");
    p.push_str("(deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n");
    p.push_str("(deny device-camera)\n");
    if !policy.microphone {
        p.push_str("(deny device-microphone)\n");
    }
    p
}

/// What [`Profile::build`] would report, without building anything
pub(crate) fn expected() -> Protection {
    if Path::new(SANDBOX_EXEC).exists() && std::env::var_os("HOME").is_some() {
        Protection::Full
    } else {
        Protection::Off(MISSING.into())
    }
}

const MISSING: &str = "sandbox-exec is missing on this Mac";

impl Profile {
    pub(crate) fn build(policy: &SandboxPolicy) -> SandboxResult<Self> {
        if !Path::new(SANDBOX_EXEC).exists() {
            return Ok(Self { source: None });
        }
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(Self { source: None });
        };
        for dir in policy.read_write.iter().chain([&policy.home, &policy.temp]) {
            std::fs::create_dir_all(dir)?;
        }
        Ok(Self {
            source: Some(profile(policy, &home)),
        })
    }

    pub(crate) fn protection(&self) -> Protection {
        match self.source {
            Some(_) => Protection::Full,
            None => Protection::Off(MISSING.into()),
        }
    }

    pub(crate) fn spawn(&self, spec: SpawnSpec) -> std::io::Result<GameChild> {
        match &self.source {
            None => crate::spawn::plain(spec),
            Some(source) => spec
                .into_tokio(Some((
                    PathBuf::from(SANDBOX_EXEC),
                    vec!["-p".into(), source.into()],
                )))
                .spawn()
                .map(GameChild::Tokio),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_denies_home_then_allows_the_instance() {
        let policy = SandboxPolicy {
            runtime: vec![PathBuf::from("/nonexistent/runtime")],
            read_write: vec![PathBuf::from("/nonexistent/instance \"x\"")],
            ..Default::default()
        };
        let p = profile(&policy, Path::new("/Users/me"));
        let deny = p
            .find("(deny file-read* file-write* (subpath \"/Users/me\"))")
            .unwrap();
        let allow = p.find("instance \\\"x\\\"").unwrap();
        assert!(deny < allow);
        assert!(p.contains("(deny device-microphone)"));
        assert!(p.contains(
            "(deny network-outbound (remote unix-socket (path-regex #\"/discord-ipc-[0-9]+$\")))"
        ));
    }
}
