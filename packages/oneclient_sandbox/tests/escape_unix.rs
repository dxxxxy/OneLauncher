//! Starts `/bin/sh` in the real sandbox (bubblewrap or Landlock on Linux,
//! Seatbelt on macOS) and checks what it can reach. Everything lives under
//! $HOME, which every backend hides except where granted

#![cfg(unix)]

use std::path::{Path, PathBuf};

use oneclient_sandbox::{Protection, SandboxPolicy, SpawnSpec};

async fn sh(
    prepared: &oneclient_sandbox::Prepared,
    cwd: &Path,
    out_dir: &Path,
    script: &str,
) -> (bool, String) {
    let out_path = out_dir.join("out.txt");
    let out = std::fs::File::create(&out_path).unwrap();
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", script]).current_dir(cwd);
    let spec = SpawnSpec::from_command(&command, Some(out.try_clone().unwrap()), Some(out));
    let status = prepared.spawn(spec).unwrap().wait().await.unwrap();
    (
        status.success(),
        std::fs::read_to_string(out_path).unwrap_or_default(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_game_only_reaches_what_it_was_granted() {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    let root = home.join(format!(".oneclient-escape-{}", std::process::id()));
    let instance = root.join("instance");
    let runtime = root.join("runtime");
    let other = root.join("other-instance");
    let outside = root.join("outside");
    for dir in [&instance, &runtime, &other, &outside] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(runtime.join("lib.txt"), "runtime").unwrap();
    std::fs::write(other.join("secret.txt"), "other").unwrap();
    let canary = home.join(format!(".oneclient-canary-{}", std::process::id()));
    std::fs::write(&canary, "canary").unwrap();

    let policy = SandboxPolicy {
        instance_id: 1,
        runtime: vec![runtime.clone()],
        read_write: vec![instance.clone()],
        home: instance.join(".oneclient/home"),
        temp: instance.join(".oneclient/tmp"),
        ..Default::default()
    };
    let prepared = oneclient_sandbox::prepare(&policy).await.unwrap();
    eprintln!("protection: {:?}", prepared.protection);
    if let Protection::Off(reason) = &prepared.protection {
        eprintln!("skipping: no sandbox here ({reason})");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&canary);
        return;
    }

    let p = |path: &Path| format!("'{}'", path.display());
    let canary_read = sh(
        &prepared,
        &instance,
        &outside,
        &format!("cat {}", p(&canary)),
    )
    .await;
    let other_read = sh(
        &prepared,
        &instance,
        &outside,
        &format!("cat {}", p(&other.join("secret.txt"))),
    )
    .await;
    let runtime_read = sh(
        &prepared,
        &instance,
        &outside,
        &format!("cat {}", p(&runtime.join("lib.txt"))),
    )
    .await;
    let runtime_write = sh(
        &prepared,
        &instance,
        &outside,
        &format!("echo x > {}", p(&runtime.join("new.txt"))),
    )
    .await;
    let instance_write = sh(
        &prepared,
        &instance,
        &outside,
        &format!("echo x > {}", p(&instance.join("new.txt"))),
    )
    .await;

    let _ = std::fs::remove_file(&canary);

    assert!(
        runtime_read.0,
        "could not read the runtime: {runtime_read:?}"
    );
    assert!(
        instance_write.0,
        "could not write the instance: {instance_write:?}"
    );
    assert!(!canary_read.0, "read the real home: {canary_read:?}");
    assert!(!other_read.0, "read another instance: {other_read:?}");
    assert!(!runtime_write.0, "wrote the runtime: {runtime_write:?}");

    let _ = std::fs::remove_dir_all(&root);
}
