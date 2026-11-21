//! Linux: bubblewrap when it works here, Landlock otherwise
//!
//! bubblewrap builds a private filesystem view: system directories read-only,
//! the user's home replaced by an empty tmpfs with only the instance and the
//! launcher's runtime files bound back in, and no D-Bus session bus, so the
//! keyring can't be asked for passwords. Landlock (kernel 5.13+) restricts
//! file access without namespaces but can't hide sockets, so it is reported
//! as partial protection.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
    path_beneath_rules,
};

use crate::{GameChild, Protection, SandboxPolicy, SandboxResult, SpawnSpec};

pub(crate) enum Plan {
    Bwrap {
        program: PathBuf,
        args: Vec<OsString>,
        gaps: Vec<String>,
    },
    Landlock {
        read: Vec<PathBuf>,
        write: Vec<PathBuf>,
        gaps: Vec<String>,
    },
    Off(String),
}

const FLATPAK_OFF: &str = "Flatpak already confines OneClient; games share its permissions";
const AUDIO_GAP: &str =
    "Game audio goes through your sound server, which can't keep the microphone out on Linux";
const X11_GAP: &str = "X11 lets any window read the keyboard and screen of others; use a Wayland session for full protection";
const NO_BWRAP_GAP: &str = "bubblewrap isn't available, so the game can still reach the keyring and other apps through D-Bus; install bubblewrap for full protection";

/// What [`Plan::build`] would report, without building anything
pub(crate) fn expected(microphone: bool) -> Protection {
    if std::env::var_os("FLATPAK_ID").is_some() {
        return Protection::Off(FLATPAK_OFF.into());
    }
    if bwrap().is_none() {
        return Protection::Partial(vec![NO_BWRAP_GAP.into()]);
    }
    let mut gaps = Vec::new();
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        let sound =
            runtime_dir.join("pulse/native").exists() || runtime_dir.join("pipewire-0").exists();
        if sound && !microphone {
            gaps.push(AUDIO_GAP.into());
        }
    }
    if std::env::var_os("DISPLAY").is_some() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        gaps.push(X11_GAP.into());
    }
    if gaps.is_empty() {
        Protection::Full
    } else {
        Protection::Partial(gaps)
    }
}

fn bwrap() -> Option<&'static PathBuf> {
    static FOUND: OnceLock<Option<PathBuf>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            let candidates = [
                std::env::var_os("ONECLIENT_BWRAP").map(PathBuf::from),
                std::env::var_os("APPDIR").map(|d| PathBuf::from(d).join("usr/bin/bwrap")),
                Some(PathBuf::from("/usr/bin/bwrap")),
                Some(PathBuf::from("/usr/local/bin/bwrap")),
                Some(PathBuf::from("/run/current-system/sw/bin/bwrap")),
            ];
            candidates.into_iter().flatten().find(|path| {
                // installed is not enough: user namespaces may be blocked
                // (Ubuntu 24.04 AppArmor, hardened kernels)
                path.is_file()
                    && std::process::Command::new(path)
                        .args(["--ro-bind", "/", "/", "--", "/bin/true"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .is_ok_and(|s| s.success())
            })
        })
        .as_ref()
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn push(args: &mut Vec<OsString>, parts: &[&str]) {
    args.extend(parts.iter().map(OsString::from));
}

fn bind(args: &mut Vec<OsString>, kind: &str, path: &Path) {
    let path = canonical(path);
    args.push(kind.into());
    args.push(path.clone().into());
    args.push(path.into());
}

impl Plan {
    pub(crate) async fn build(policy: &SandboxPolicy) -> SandboxResult<Self> {
        if std::env::var_os("FLATPAK_ID").is_some() {
            return Ok(Self::Off(FLATPAK_OFF.into()));
        }

        let mut read: Vec<PathBuf> = policy
            .runtime
            .iter()
            .chain(&policy.extra_read_only)
            .cloned()
            .collect();
        let write: Vec<PathBuf> = policy
            .read_write
            .iter()
            .chain(&policy.extra_read_write)
            .chain([&policy.home, &policy.temp])
            .cloned()
            .collect();
        for dir in &write {
            std::fs::create_dir_all(dir)?;
        }

        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        let x11 =
            std::env::var_os("DISPLAY").is_some() && std::env::var_os("WAYLAND_DISPLAY").is_none();

        if let Some(program) = bwrap() {
            let mut args: Vec<OsString> = Vec::new();
            push(&mut args, &["--ro-bind", "/usr", "/usr"]);
            for dir in [
                "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/opt", "/nix",
            ] {
                push(&mut args, &["--ro-bind-try", dir, dir]);
            }
            push(
                &mut args,
                &[
                    "--proc",
                    "/proc",
                    "--dev",
                    "/dev",
                    "--ro-bind",
                    "/sys",
                    "/sys",
                ],
            );
            push(&mut args, &["--dev-bind-try", "/dev/dri", "/dev/dri"]);
            if let Ok(entries) = std::fs::read_dir("/dev") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    if name.to_string_lossy().starts_with("nvidia") {
                        bind(&mut args, "--dev-bind", &entry.path());
                    }
                }
            }
            if policy.microphone {
                push(&mut args, &["--dev-bind-try", "/dev/snd", "/dev/snd"]);
            }
            push(&mut args, &["--tmpfs", "/tmp", "--tmpfs", "/run"]);
            for dir in [
                "/run/systemd/resolve",
                "/run/NetworkManager",
                "/run/resolvconf",
                "/run/opengl-driver",
                "/run/current-system",
            ] {
                push(&mut args, &["--ro-bind-try", dir, dir]);
            }
            if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
                let home = canonical(&home);
                args.push("--tmpfs".into());
                args.push(home.into());
            }

            let mut gaps = Vec::new();
            if let Some(runtime_dir) = &runtime_dir {
                args.push("--dir".into());
                args.push(runtime_dir.clone().into());
                // the relay's folder, not its socket: a launcher started
                // again while the game runs makes a new socket there, which
                // a bind of the old one would never show
                if let Some(relay_dir) = policy.discord_socket.as_deref().and_then(Path::parent) {
                    let inside = runtime_dir.join(".oneclient-discord");
                    args.push("--bind".into());
                    args.push(relay_dir.to_path_buf().into());
                    args.push(inside.into());
                    args.push("--symlink".into());
                    args.push(".oneclient-discord/discord-ipc-0".into());
                    args.push(runtime_dir.join("discord-ipc-0").into());
                }
                if let Some(wayland) = std::env::var_os("WAYLAND_DISPLAY") {
                    bind(&mut args, "--ro-bind-try", &runtime_dir.join(wayland));
                }
                let pulse = runtime_dir.join("pulse/native");
                let pipewire = runtime_dir.join("pipewire-0");
                if pulse.exists() || pipewire.exists() {
                    bind(&mut args, "--ro-bind-try", &pulse);
                    bind(&mut args, "--ro-bind-try", &pipewire);
                    if !policy.microphone {
                        gaps.push(AUDIO_GAP.into());
                    }
                }
            }
            if x11 {
                push(
                    &mut args,
                    &["--ro-bind-try", "/tmp/.X11-unix", "/tmp/.X11-unix"],
                );
                if let Some(auth) = std::env::var_os("XAUTHORITY") {
                    bind(&mut args, "--ro-bind-try", Path::new(&auth));
                }
                gaps.push(X11_GAP.into());
            }

            for dir in &read {
                bind(&mut args, "--ro-bind-try", dir);
            }
            for dir in &write {
                bind(&mut args, "--bind", dir);
            }
            push(
                &mut args,
                &["--unshare-ipc", "--unshare-cgroup-try", "--cap-drop", "ALL"],
            );
            push(&mut args, &["--"]);

            return Ok(Self::Bwrap {
                program: program.clone(),
                args,
                gaps,
            });
        }

        // Landlock: what the system needs to run Java and draw a window
        for dir in [
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib32",
            "/lib64",
            "/etc",
            "/opt",
            "/nix",
            "/proc",
            "/sys",
            "/run",
            "/tmp/.X11-unix",
        ] {
            let dir = PathBuf::from(dir);
            if dir.exists() {
                read.push(dir);
            }
        }
        if let Some(auth) = std::env::var_os("XAUTHORITY") {
            read.push(PathBuf::from(auth));
        }
        let mut write = write;
        write.push(PathBuf::from("/dev"));

        Ok(Self::Landlock {
            read,
            write,
            gaps: vec![NO_BWRAP_GAP.into()],
        })
    }

    pub(crate) fn protection(&self) -> Protection {
        match self {
            Self::Bwrap { gaps, .. } if gaps.is_empty() => Protection::Full,
            Self::Bwrap { gaps, .. } | Self::Landlock { gaps, .. } => {
                Protection::Partial(gaps.clone())
            }
            Self::Off(reason) => Protection::Off(reason.clone()),
        }
    }

    pub(crate) fn spawn(&self, spec: SpawnSpec) -> std::io::Result<GameChild> {
        match self {
            Self::Off(_) => crate::spawn::plain(spec),
            Self::Bwrap { program, args, .. } => {
                let mut prefix = args.clone();
                // `--chdir` goes before `--`
                let dashes = prefix.len() - 1;
                prefix.insert(dashes, spec.cwd.clone().into());
                prefix.insert(dashes, "--chdir".into());
                spec.into_tokio(Some((program.clone(), prefix)))
                    .spawn()
                    .map(GameChild::Tokio)
            }
            Self::Landlock { read, write, .. } => {
                let ruleset = landlock_ruleset(read, write)
                    .map_err(|e| std::io::Error::other(format!("landlock: {e}")))?;
                let slot = Mutex::new(Some(ruleset));
                let mut command = spec.into_tokio(None);
                // SAFETY: the closure only takes a prepared ruleset out of an
                // uncontended mutex and makes the restrict syscalls; no
                // allocation happens between fork and exec
                unsafe {
                    command.pre_exec(move || {
                        let ruleset = slot.lock().ok().and_then(|mut s| s.take());
                        if let Some(ruleset) = ruleset {
                            match ruleset.restrict_self() {
                                Ok(status) if status.ruleset != RulesetStatus::NotEnforced => {}
                                Ok(_) => {
                                    return Err(std::io::Error::other("landlock not enforced"));
                                }
                                Err(_) => return Err(std::io::Error::other("landlock failed")),
                            }
                        }
                        Ok(())
                    });
                }
                command.spawn().map(GameChild::Tokio)
            }
        }
    }
}

fn landlock_ruleset(
    read: &[PathBuf],
    write: &[PathBuf],
) -> Result<landlock::RulesetCreated, landlock::RulesetError> {
    let abi = ABI::V5;
    let mut ruleset = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
    // kernels with ABI 6 also keep abstract sockets and signals inside
    ruleset = match ruleset.scope(Scope::from_all(ABI::V6)) {
        Ok(scoped) => scoped,
        Err(_) => Ruleset::default().handle_access(AccessFs::from_all(abi))?,
    };
    ruleset
        .create()?
        .add_rules(path_beneath_rules(read, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(write, AccessFs::from_all(abi)))
}
