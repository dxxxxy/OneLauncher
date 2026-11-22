//! Starts `/bin/sh` in the real sandbox (bubblewrap and Landlock on Linux,
//! Seatbelt on macOS) and checks what it can reach. Everything lives under
//! $HOME, which every backend hides except where granted. On Linux every
//! check runs on each backend this machine has: Landlock is what users
//! without bubblewrap get

#![cfg(unix)]

use std::path::{Path, PathBuf};

use oneclient_sandbox::{Prepared, Protection, SandboxPolicy, SpawnSpec};

/// Runs `script` in the sandbox; whether it succeeded, and what it printed.
/// The output goes to a file inside the instance: a sandbox may refuse
/// writes to an inherited file anywhere else, as Seatbelt does
async fn sh(prepared: &Prepared, cwd: &Path, script: &str) -> (bool, String) {
    let out_path = cwd.join(format!(".out-{}.txt", uuid_ish()));
    let out = std::fs::File::create(&out_path).unwrap();
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", script]).current_dir(cwd);
    let spec = SpawnSpec::from_command(&command, Some(out.try_clone().unwrap()), Some(out));
    let status = prepared.spawn(spec).unwrap().wait().await.unwrap();
    let output = std::fs::read_to_string(&out_path).unwrap_or_default();
    let _ = std::fs::remove_file(out_path);
    (status.success(), output)
}

fn uuid_ish() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn quoted(path: &Path) -> String {
    format!("'{}'", path.display())
}

/// What the canary in the real home holds, so a read is told apart from an
/// error message that names the file
const CANARY: &str = "the real home folder, which no game may read";

/// A folder layout under the real $HOME, removed on drop
struct Layout {
    root: PathBuf,
    instance: PathBuf,
    runtime: PathBuf,
    other: PathBuf,
    canary: PathBuf,
}

impl Layout {
    fn new(name: &str) -> Self {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let root = home.join(format!(".oneclient-escape-{name}-{}", std::process::id()));
        let instance = root.join("instance");
        let runtime = root.join("runtime");
        let other = root.join("other-instance");
        for dir in [&instance, &runtime, &other] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(runtime.join("lib.txt"), "runtime").unwrap();
        std::fs::write(other.join("secret.txt"), "other").unwrap();
        let canary = home.join(format!(".oneclient-canary-{name}-{}", std::process::id()));
        std::fs::write(&canary, CANARY).unwrap();
        Self {
            root,
            instance,
            runtime,
            other,
            canary,
        }
    }

    fn policy(&self, offline: bool) -> SandboxPolicy {
        SandboxPolicy {
            instance_id: 1,
            runtime: vec![self.runtime.clone()],
            read_write: vec![self.instance.clone()],
            home: self.instance.join(".oneclient/home"),
            temp: self.instance.join(".oneclient/tmp"),
            offline,
            ..Default::default()
        }
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_file(&self.canary);
    }
}

fn bwrap_installed() -> bool {
    cfg!(target_os = "linux")
        && ["/usr/bin/bwrap", "/usr/local/bin/bwrap"]
            .iter()
            .any(|p| Path::new(p).exists())
}

/// Every sandbox backend this machine has, by name
async fn backends(policy: &SandboxPolicy) -> Vec<(&'static str, Prepared)> {
    let mut found = Vec::new();
    let default = oneclient_sandbox::prepare(policy).await.unwrap();
    eprintln!("default protection: {:?}", default.protection);
    if let Protection::Off(reason) = &default.protection {
        eprintln!("no sandbox here ({reason})");
    } else {
        let name = if cfg!(target_os = "macos") {
            "seatbelt"
        } else if bwrap_installed() {
            "bubblewrap"
        } else {
            "landlock"
        };
        found.push((name, default));
    }
    #[cfg(target_os = "linux")]
    if bwrap_installed() {
        match oneclient_sandbox::prepare_landlock(policy).await {
            Ok(landlock) => {
                eprintln!("landlock protection: {:?}", landlock.protection);
                found.push(("landlock", landlock));
            }
            Err(err) => eprintln!("no landlock here: {err}"),
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread")]
async fn the_game_only_reaches_what_it_was_granted() {
    let layout = Layout::new("files");
    let backends = backends(&layout.policy(false)).await;
    if backends.is_empty() {
        eprintln!("skipping: no sandbox here");
        return;
    }
    let mut failures = Vec::new();
    for (name, prepared) in &backends {
        let checks = [
            (
                "read the runtime",
                true,
                format!("cat {}", quoted(&layout.runtime.join("lib.txt"))),
            ),
            (
                "write the instance",
                true,
                format!("echo x > {}", quoted(&layout.instance.join("new.txt"))),
            ),
            (
                "read the real home",
                false,
                format!("cat {}", quoted(&layout.canary)),
            ),
            (
                "read another instance",
                false,
                format!("cat {}", quoted(&layout.other.join("secret.txt"))),
            ),
            (
                "write the runtime",
                false,
                format!("echo x > {}", quoted(&layout.runtime.join("new.txt"))),
            ),
        ];
        for (what, expected, script) in checks {
            let (ok, output) = sh(prepared, &layout.instance, &script).await;
            if ok != expected {
                let could = if ok { "could" } else { "couldn't" };
                failures.push(format!("{name}: {could} {what}: {output}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Other processes of the same user: their environment and their view of
/// the filesystem (`/proc/<pid>/root`) must stay out of reach, and under
/// bubblewrap they aren't even listed, since command lines can hold secrets
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn other_processes_stay_out_of_reach() {
    let layout = Layout::new("proc");
    let backends = backends(&layout.policy(false)).await;
    if backends.is_empty() {
        eprintln!("skipping: no sandbox here");
        return;
    }
    let mut victim = std::process::Command::new("sleep")
        .arg("300")
        .env("ONECLIENT_TEST_SECRET", "hunter2")
        .spawn()
        .unwrap();
    let pid = victim.id();

    let mut failures = Vec::new();
    for (name, prepared) in &backends {
        let environ = sh(
            prepared,
            &layout.instance,
            &format!("tr '\\0' '\\n' < /proc/{pid}/environ"),
        )
        .await;
        if environ.1.contains("hunter2") {
            failures.push(format!("{name}: read another process's environment"));
        }
        let root = sh(
            prepared,
            &layout.instance,
            &format!("cat /proc/{pid}/root{}", layout.canary.display()),
        )
        .await;
        if root.0 || root.1.contains(CANARY) {
            failures.push(format!("{name}: read the home through /proc/{pid}/root"));
        }
        if *name == "bubblewrap" {
            let listed = sh(prepared, &layout.instance, &format!("test -e /proc/{pid}")).await;
            if listed.0 {
                failures.push(format!("{name}: other processes are listed in /proc"));
            }
        }
    }
    let _ = victim.kill();
    let _ = victim.wait();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The session bus reaches the keyring and every app the user runs; only
/// bubblewrap can hide it (Landlock reports that as a gap)
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn bubblewrap_hides_the_session_bus() {
    let Some(bus) = std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("bus"))
    else {
        eprintln!("skipping: no XDG_RUNTIME_DIR");
        return;
    };
    if !bus.exists() || !bwrap_installed() {
        eprintln!("skipping: no session bus or no bubblewrap here");
        return;
    }
    let layout = Layout::new("bus");
    let prepared = oneclient_sandbox::prepare(&layout.policy(false))
        .await
        .unwrap();
    let (reachable, _) = sh(
        &prepared,
        &layout.instance,
        &format!("test -e {}", quoted(&bus)),
    )
    .await;
    assert!(!reachable, "the session bus is reachable in the sandbox");
}

/// Installer processors run offline; bubblewrap takes the network away
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn offline_sandboxes_have_no_network() {
    let curl = Path::new("/usr/bin/curl");
    if !curl.exists() || !bwrap_installed() {
        eprintln!("skipping: no curl or no bubblewrap here");
        return;
    }
    let layout = Layout::new("net");
    let fetch = |offline: bool| {
        let policy = layout.policy(offline);
        let instance = layout.instance.clone();
        async move {
            let prepared = oneclient_sandbox::prepare(&policy).await.unwrap();
            sh(
                &prepared,
                &instance,
                "/usr/bin/curl -sS -o /dev/null -m 10 https://example.com/",
            )
            .await
        }
    };
    let host_online = std::process::Command::new(curl)
        .args(["-sS", "-o", "/dev/null", "-m", "10", "https://example.com/"])
        .status()
        .is_ok_and(|status| status.success());
    if !host_online {
        eprintln!("skipping: no network here");
        return;
    }
    // games play online: the sandbox must keep DNS and the network working
    let online = fetch(false).await;
    assert!(
        online.0,
        "a sandboxed game couldn't reach the internet: {online:?}"
    );
    let offline = fetch(true).await;
    assert!(
        !offline.0,
        "an offline sandbox reached the network: {offline:?}"
    );
}

/// Killing the PID the launcher holds stops the game, not just bubblewrap
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn killing_the_sandbox_stops_the_game() {
    if !bwrap_installed() {
        eprintln!("skipping: no bubblewrap here");
        return;
    }
    let layout = Layout::new("kill");
    let prepared = oneclient_sandbox::prepare(&layout.policy(false))
        .await
        .unwrap();
    // a sleep long and odd enough that only this test runs it
    let marker = format!("sleep 31{}", std::process::id());
    let mut command = std::process::Command::new("/bin/sh");
    command
        .args(["-c", &format!("exec {marker}")])
        .current_dir(&layout.instance);
    let spec = SpawnSpec::from_command(&command, None, None);
    let mut child = prepared.spawn(spec).unwrap();
    // `-x`: the game itself, not bwrap, whose own command line names it too
    let pgrep = |flags: &str| {
        std::process::Command::new("pgrep")
            .args([flags, &marker])
            .output()
            .is_ok_and(|out| out.status.success())
    };
    for _ in 0..100 {
        if pgrep("-xf") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(pgrep("-xf"), "the game never started");
    child.start_kill().unwrap();
    let _ = child.wait().await;
    // nothing left: neither the game nor any part of bwrap
    for _ in 0..50 {
        if !pgrep("-f") {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let left = std::process::Command::new("ps")
        .args(["-eo", "pid,ppid,pgid,stat,args"])
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|line| line.contains(&marker))
                .collect::<Vec<_>>()
                .join(
                    "
",
                )
        })
        .unwrap_or_default();
    let _ = std::process::Command::new("pkill")
        .args(["-f", &marker])
        .status();
    panic!(
        "the game kept running after the sandbox was killed:
{left}"
    );
}
