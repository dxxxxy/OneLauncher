//! Inside OneClient's own Flatpak: bubblewrap can't nest there, so the game
//! goes into a sub-sandbox through the Flatpak portal (`flatpak-spawn
//! --sandbox`), which every Flatpak app may ask for. It sees only the
//! folders passed here, and no D-Bus (so no keyring); the display, sound and
//! GPU are shared with it.
//!
//! The arguments are built on every platform so they can be tested anywhere;
//! only Linux runs them.

use std::ffi::OsString;
use std::path::Path;

use crate::SandboxPolicy;

/// Reported with every Flatpak launch
pub(crate) const GAP: &str = "Inside Flatpak the game runs in a sub-sandbox that shares OneClient's display and sound access";

/// `flatpak-spawn` options for one launch, ending before the program
pub(crate) fn spawn_args(
    policy: &SandboxPolicy,
    cwd: &Path,
    env: &[(OsString, OsString)],
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["--sandbox".into()];
    for flag in ["share-display", "share-sound", "share-gpu"] {
        args.push(format!("--sandbox-flag={flag}").into());
    }
    let expose = |args: &mut Vec<OsString>, option: &str, path: &Path| {
        let mut arg = OsString::from(format!("--{option}="));
        arg.push(path.as_os_str());
        args.push(arg);
    };
    for dir in policy
        .read_write
        .iter()
        .chain(&policy.extra_read_write)
        .chain([&policy.home, &policy.temp])
    {
        expose(&mut args, "sandbox-expose-path", dir);
    }
    for dir in policy.runtime.iter().chain(&policy.extra_read_only) {
        expose(&mut args, "sandbox-expose-path-ro", dir);
    }
    // the Discord relay: libraries find it through TMPDIR, as on macOS
    let relay_dir = policy.discord_socket.as_deref().and_then(Path::parent);
    if let Some(dir) = relay_dir {
        expose(&mut args, "sandbox-expose-path", dir);
    }
    if policy.offline {
        args.push("--no-network".into());
    }
    expose(&mut args, "directory", cwd);
    // the portal starts the game with only what it's told
    args.push("--clear-env".into());
    for (key, value) in env {
        if relay_dir.is_some() && key == "TMPDIR" {
            continue;
        }
        let mut arg = OsString::from("--env=");
        arg.push(key);
        arg.push("=");
        arg.push(value);
        args.push(arg);
    }
    if let Some(dir) = relay_dir {
        let mut arg = OsString::from("--env=TMPDIR=");
        arg.push(dir.as_os_str());
        args.push(arg);
    }
    args
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn the_game_sees_only_its_folders() {
        let policy = SandboxPolicy {
            instance_id: 1,
            runtime: vec![PathBuf::from("/data/metadata")],
            read_write: vec![PathBuf::from("/data/clusters/a")],
            extra_read_only: vec![PathBuf::from("/home/u/Pictures")],
            home: PathBuf::from("/data/clusters/a/.oneclient/home"),
            temp: PathBuf::from("/data/clusters/a/.oneclient/tmp"),
            discord_socket: Some(PathBuf::from(
                "/run/user/1/oneclient-discord-1/discord-ipc-0",
            )),
            ..Default::default()
        };
        let env = vec![
            (OsString::from("JAVA_HOME"), OsString::from("/data/java")),
            (
                OsString::from("TMPDIR"),
                OsString::from("/data/clusters/a/.oneclient/tmp"),
            ),
        ];
        let args: Vec<String> = spawn_args(&policy, Path::new("/data/clusters/a"), &env)
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "--sandbox",
                "--sandbox-flag=share-display",
                "--sandbox-flag=share-sound",
                "--sandbox-flag=share-gpu",
                "--sandbox-expose-path=/data/clusters/a",
                "--sandbox-expose-path=/data/clusters/a/.oneclient/home",
                "--sandbox-expose-path=/data/clusters/a/.oneclient/tmp",
                "--sandbox-expose-path-ro=/data/metadata",
                "--sandbox-expose-path-ro=/home/u/Pictures",
                "--sandbox-expose-path=/run/user/1/oneclient-discord-1",
                "--directory=/data/clusters/a",
                "--clear-env",
                "--env=JAVA_HOME=/data/java",
                "--env=TMPDIR=/run/user/1/oneclient-discord-1",
            ]
        );
        // never D-Bus, never the host
        assert!(
            !args
                .iter()
                .any(|a| a.contains("allow-dbus") || a == "--host")
        );
    }

    #[test]
    fn installer_runs_get_no_network() {
        let policy = SandboxPolicy {
            offline: true,
            ..Default::default()
        };
        let args = spawn_args(&policy, Path::new("/x"), &[]);
        assert!(args.contains(&OsString::from("--no-network")));
    }
}
