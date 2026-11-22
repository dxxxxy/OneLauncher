#![recursion_limit = "256"]

//! Launches a real game in the sandbox and checks it, for reviewers and
//! testers:
//!
//! `cargo run -p oneclient_core --example sandbox_launch -- [version] [loader] [--seconds N] [--fresh]`
//!
//! - waits for the main menu, then (on Linux) looks at the running game from
//!   outside: its own process list, your home folder and the session bus out
//!   of sight, the display still there
//! - stops it the way the stop button does and checks nothing is left
//! - exits with 1 if any of that fails
//!
//! Files go to `target/sandbox-launch` and are reused, so only the first run
//! downloads Java and the game; `--fresh` starts over in a new folder. The
//! account is offline (no sign-in needed), so servers and skins won't work.
//! Prompts such as "Java required" are asked in the terminal; set
//! `ONECLIENT_DEV_PROMPTS=primary` to answer them on their own

use std::path::Path;
use std::time::{Duration, Instant};

use oneclient_common::domain::GameLoader;
use oneclient_core::LauncherResult;
use oneclient_core::clusters::CreateClusterOptions;
use oneclient_core::dev;

const MENU_TIMEOUT: Duration = Duration::from_secs(600);

struct Args {
    version: String,
    loader: GameLoader,
    seconds: Option<u64>,
    fresh: bool,
}

fn args() -> Args {
    let mut args = Args {
        version: "1.21.4".into(),
        loader: GameLoader::Vanilla,
        seconds: None,
        fresh: false,
    };
    let mut positional = 0;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seconds" => args.seconds = it.next().and_then(|s| s.parse().ok()),
            "--fresh" => args.fresh = true,
            _ if positional == 0 => {
                args.version = arg;
                positional += 1;
            }
            _ => {
                args.loader = arg.parse().unwrap_or_else(|_| {
                    eprintln!("unknown loader {arg}, using vanilla");
                    GameLoader::Vanilla
                });
            }
        }
    }
    args
}

#[tokio::main]
async fn main() -> LauncherResult<()> {
    let args = args();
    let target = std::env::current_dir()
        .map_err(oneclient_core::LauncherError::StdIoError)?
        .join("target");
    let root = if args.fresh {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        target.join(format!("sandbox-launch-{}", now.as_millis()))
    } else {
        target.join("sandbox-launch")
    };
    let state = dev::state_at(root.clone()).await?;

    // the store only takes offline accounts beside a Microsoft one, and a
    // launch doesn't need it stored
    let account = oneclient_auth::offline_account("Sandboxed".to_string());

    let name = format!("sandbox-{}-{}", args.version, args.loader);
    let existing = state
        .clusters
        .list()
        .await?
        .into_iter()
        .find(|c| c.name == name);
    let cluster = match existing {
        Some(cluster) => cluster,
        None => {
            let global = state.settings.read().global_game_settings.clone();
            state
                .clusters
                .create(
                    &global,
                    CreateClusterOptions::new(name, &args.version, args.loader),
                )
                .await?
        }
    };
    let cluster_dir = cluster.dir()?;

    println!(
        "\nProtection this system gives: {:?}",
        oneclient_sandbox::expected_protection(true, false, false)
    );
    println!("Instance: {}\n", cluster_dir.display());

    let game = oneclient_core::launch_cluster(&state, cluster.id, &account, true).await?;
    let Some(pid) = game.pid else {
        println!("✗ the game started without a process id");
        std::process::exit(1);
    };

    let mut failed = false;
    let log = cluster_dir.join("logs").join("latest.log");
    let started = Instant::now();
    let reached = loop {
        if !state.games.is_running(cluster.id) {
            break false;
        }
        if main_menu_reached(&log) {
            break true;
        }
        if started.elapsed() > MENU_TIMEOUT {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    if !reached {
        println!(
            "✗ the game didn't reach the main menu; see {}",
            log.display()
        );
        println!("  and {}", cluster_dir.join("cluster-output.log").display());
        state.games.kill(cluster.id);
        std::process::exit(1);
    }
    println!("✓ the game reached the main menu in the sandbox");

    #[cfg(target_os = "linux")]
    let game_pid = {
        // the window and the libraries finish loading after the first atlas
        tokio::time::sleep(Duration::from_secs(2)).await;
        let game_pid = linux::game_process(pid);
        match game_pid {
            Some(game_pid) => failed |= !linux::check_from_outside(game_pid, &root),
            None => {
                println!("✗ couldn't find the game's Java process under {pid}");
                failed = true;
            }
        }
        game_pid
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&root, pid);
        println!(
            "  (checks from outside are Linux-only here; the escape tests cover {})",
            std::env::consts::OS
        );
    }

    wait_before_stopping(&state, cluster.id, args.seconds).await;

    if state.games.is_running(cluster.id) {
        state.games.kill(cluster.id);
        let stopping = Instant::now();
        while state.games.is_running(cluster.id) && stopping.elapsed() < Duration::from_secs(10) {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if state.games.is_running(cluster.id) {
            println!("✗ the game was still running 10s after stopping it");
            failed = true;
        } else {
            println!("✓ stopping the game ended it");
        }
    } else {
        println!("  the game was closed before the stop test");
    }

    #[cfg(target_os = "linux")]
    if let Some(game_pid) = game_pid {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if Path::new(&format!("/proc/{game_pid}")).exists() {
            println!("✗ the game's Java process {game_pid} outlived the stop");
            failed = true;
        } else {
            println!("✓ no game process is left");
        }
    }

    if failed {
        std::process::exit(1);
    }
    println!("\nAll checks passed");
    Ok(())
}

fn main_menu_reached(log: &Path) -> bool {
    std::fs::read_to_string(log).is_ok_and(|text| {
        text.lines()
            .any(|l| l.contains("Created: ") && l.contains("atlas"))
    })
}

async fn wait_before_stopping(
    state: &oneclient_core::LauncherState,
    cluster_id: i64,
    seconds: Option<u64>,
) {
    use std::io::IsTerminal;

    let wait = match seconds {
        Some(seconds) => Some(Duration::from_secs(seconds)),
        None if std::io::stdin().is_terminal() => None,
        None => Some(Duration::from_secs(15)),
    };
    match wait {
        Some(wait) => {
            println!("\nStopping the game in {}s", wait.as_secs());
            let until = Instant::now() + wait;
            while Instant::now() < until && state.games.is_running(cluster_id) {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        None => {
            println!(
                "\nPlay as long as you like. Press Enter to stop the game the way the stop button does"
            );
            let enter = tokio::task::spawn_blocking(|| {
                let mut line = String::new();
                let _ = std::io::stdin().read_line(&mut line);
            });
            tokio::pin!(enter);
            loop {
                tokio::select! {
                    _ = &mut enter => break,
                    () = tokio::time::sleep(Duration::from_millis(500)) => {
                        if !state.games.is_running(cluster_id) {
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};

    fn parent_of(pid: u32) -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // the name can hold spaces and brackets: fields resume after the last ')'
        let rest = &stat[stat.rfind(')')? + 1..];
        rest.split_whitespace().nth(1)?.parse().ok()
    }

    /// The Java process under what the launcher started (bubblewrap there)
    pub fn game_process(started: u32) -> Option<u32> {
        let mut found = None;
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            if comm.trim() != "java" {
                continue;
            }
            let mut at = pid;
            while let Some(parent) = parent_of(at) {
                if parent == started || at == started {
                    found = Some(pid);
                    break;
                }
                if parent <= 1 {
                    break;
                }
                at = parent;
            }
        }
        found
    }

    fn namespace(pid: &str, kind: &str) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/ns/{kind}")).ok()
    }

    fn check(ok: bool, what: &str) -> bool {
        println!("{} {what}", if ok { "✓" } else { "✗" });
        ok
    }

    /// What the running game can see, read through `/proc/<pid>/root`
    pub fn check_from_outside(game: u32, launcher_root: &Path) -> bool {
        let pid = game.to_string();
        if namespace(&pid, "mnt") == namespace("self", "mnt") {
            println!(
                "  the game shares the system's view of files (the Landlock fallback): \
                 checks from outside don't apply, the escape tests cover it"
            );
            return true;
        }
        let inside = PathBuf::from(format!("/proc/{game}/root"));
        let seen = |path: &Path| inside.join(path.strip_prefix("/").unwrap_or(path)).exists();
        let mut ok = true;

        ok &= check(
            namespace(&pid, "pid") != namespace("self", "pid"),
            "the game has its own process list",
        );

        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            let private: Vec<PathBuf> = [
                ".ssh",
                ".gnupg",
                ".local/share/keyrings",
                ".mozilla",
                ".config/google-chrome",
                ".config/discord",
                ".minecraft",
            ]
            .iter()
            .map(|p| home.join(p))
            .filter(|p| p.exists())
            .collect();
            // one that's always there: a file made just for this check
            let canary = home.join(format!(".oneclient-sandbox-check-{}", std::process::id()));
            let planted = std::fs::write(&canary, "the game must not see this").is_ok();
            let mut leaked: Vec<_> = private.iter().filter(|p| seen(p)).cloned().collect();
            if planted && seen(&canary) {
                leaked.push(canary.clone());
            }
            let _ = std::fs::remove_file(&canary);
            let private_len = private.len() + usize::from(planted);
            ok &= check(
                leaked.is_empty(),
                &format!(
                    "your home folder is out of sight (checked {} private paths{})",
                    private_len,
                    if leaked.is_empty() {
                        String::new()
                    } else {
                        format!(", saw {leaked:?}")
                    }
                ),
            );
        }

        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        if let Some(bus) = runtime
            .as_ref()
            .map(|r| r.join("bus"))
            .filter(|b| b.exists())
        {
            ok &= check(
                !seen(&bus),
                "the session bus (keyring, other apps) is out of reach",
            );
        }

        let db = launcher_root.join("example.db");
        if db.exists() {
            ok &= check(!seen(&db), "the launcher's own database is out of sight");
        }

        if let (Some(runtime), Some(wayland)) = (&runtime, std::env::var_os("WAYLAND_DISPLAY")) {
            ok &= check(
                seen(&runtime.join(wayland)),
                "the game can reach the Wayland display",
            );
        }
        ok
    }
}
