//! Starts a real process in the real sandbox and checks what it can reach

#![cfg(windows)]

use std::path::PathBuf;

use oneclient_sandbox::{SandboxPolicy, SpawnSpec};

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "oneclient-sandbox-escape-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn the_game_only_reaches_what_it_was_granted() {
    let root = scratch();
    let instance = root.join("instance");
    let runtime = root.join("runtime");
    let other = root.join("other-instance");
    for dir in [&instance, &runtime, &other, &instance.join("mods")] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(runtime.join("lib.txt"), "runtime").unwrap();
    std::fs::write(runtime.join("store.jar"), "original").unwrap();
    std::fs::hard_link(runtime.join("store.jar"), instance.join("mods/store.jar")).unwrap();
    std::fs::write(other.join("secret.txt"), "other").unwrap();

    let home = std::env::var_os("USERPROFILE").map(PathBuf::from).unwrap();
    let canary = home.join(format!("oneclient-canary-{}.txt", std::process::id()));
    std::fs::write(&canary, "canary").unwrap();

    let instance_id = 9_000_000 + i64::from(std::process::id() % 100_000);
    let policy = SandboxPolicy {
        instance_id,
        runtime: vec![runtime.clone()],
        read_write: vec![instance.clone()],
        home: instance.join(".oneclient/home"),
        temp: instance.join(".oneclient/tmp"),
        ..Default::default()
    };
    let prepared = oneclient_sandbox::prepare(&policy).await.unwrap();
    assert!(prepared.is_sandboxed());

    // one plain command per check: cmd.exe's batch and `dir` path searches
    // probe parent folders the sandbox rightly can't list
    let run = |line: String| {
        let prepared = &prepared;
        let root = root.clone();
        let instance = instance.clone();
        async move {
            let out_path = root.join("out.txt");
            let out = std::fs::File::create(&out_path).unwrap();
            let mut command = std::process::Command::new(r"C:\Windows\System32\cmd.exe");
            command
                .args(["/d", "/c"])
                .args(line.split(' '))
                .current_dir(&instance);
            let spec = SpawnSpec::from_command(&command, Some(out.try_clone().unwrap()), Some(out));
            let status = prepared.spawn(spec).unwrap().wait().await.unwrap();
            let output = std::fs::read_to_string(&out_path).unwrap_or_default();
            (status.success(), output)
        }
    };
    let p = |path: PathBuf| path.display().to_string();

    let canary_read = run(format!("type {}", p(canary.clone()))).await;
    let other_read = run(format!("type {}", p(other.join("secret.txt")))).await;
    let runtime_read = run(format!("type {}", p(runtime.join("lib.txt")))).await;
    let runtime_write = run(format!("echo x> {}", p(runtime.join("new.txt")))).await;
    let instance_write = run(format!("echo x> {}", p(instance.join("new.txt")))).await;
    let link_write = run(format!(
        "echo x>> {}",
        p(instance.join("mods").join("store.jar"))
    ))
    .await;

    let _ = std::fs::remove_file(&canary);
    oneclient_sandbox::forget_instance(instance_id);

    assert!(
        runtime_read.0,
        "could not read the runtime: {runtime_read:?}"
    );
    assert!(
        instance_write.0,
        "could not write the instance: {instance_write:?}"
    );
    assert!(!canary_read.0, "read the user profile: {canary_read:?}");
    assert!(!other_read.0, "read another instance: {other_read:?}");
    assert!(!runtime_write.0, "wrote the runtime: {runtime_write:?}");
    assert!(
        !link_write.0,
        "wrote a store file through a hardlink: {link_write:?}"
    );
    assert_eq!(
        std::fs::read_to_string(runtime.join("store.jar")).unwrap(),
        "original"
    );

    let _ = std::fs::remove_dir_all(root);
}

/// Installer processors run offline: the same program reaches the web from
/// a normal sandbox and not from an offline one
#[tokio::test(flavor = "multi_thread")]
async fn offline_sandboxes_have_no_network() {
    let curl = PathBuf::from(r"C:\Windows\System32\curl.exe");
    if !curl.is_file() {
        eprintln!("skipping: no curl.exe");
        return;
    }
    let root = scratch();
    let fetch = |offline: bool| {
        let root = root.clone();
        let curl = curl.clone();
        async move {
            let dir = root.join(if offline { "offline" } else { "online" });
            std::fs::create_dir_all(&dir).unwrap();
            let instance_id =
                9_100_000 + i64::from(std::process::id() % 100_000) * 2 + i64::from(offline);
            let policy = SandboxPolicy {
                instance_id,
                read_write: vec![dir.clone()],
                home: dir.join("home"),
                temp: dir.join("tmp"),
                offline,
                ..Default::default()
            };
            let prepared = oneclient_sandbox::prepare(&policy).await.unwrap();
            let out = std::fs::File::create(dir.join("out.txt")).unwrap();
            let mut command = std::process::Command::new(&curl);
            command
                .args(["-sS", "-o", "NUL", "-m", "10", "https://example.com/"])
                .current_dir(&dir);
            let spec = SpawnSpec::from_command(&command, Some(out.try_clone().unwrap()), Some(out));
            let status = prepared.spawn(spec).unwrap().wait().await.unwrap();
            oneclient_sandbox::forget_instance(instance_id);
            status.success()
        }
    };
    if !fetch(false).await {
        eprintln!("skipping: no network here");
        let _ = std::fs::remove_dir_all(root);
        return;
    }
    assert!(!fetch(true).await, "an offline sandbox reached the network");
    let _ = std::fs::remove_dir_all(root);
}
