//! Runs one command in the sandbox for manual checks:
//! `cargo run -p oneclient_sandbox --example probe -- <instance dir> <program> [args...]`
//! Set `PROBE_RUNTIME` to grant one read-only runtime folder (a JDK, say)
use std::path::PathBuf;
#[tokio::main]
async fn main() {
    let mut args = std::env::args_os().skip(1);
    let instance = PathBuf::from(args.next().unwrap());
    let program = args.next().unwrap();
    let rest: Vec<_> = args.collect();
    let policy = oneclient_sandbox::SandboxPolicy {
        instance_id: 9_999_999,
        read_write: vec![instance.clone()],
        runtime: std::env::var_os("PROBE_RUNTIME")
            .map(|r| vec![PathBuf::from(r)])
            .unwrap_or_default(),
        home: instance.join(".oneclient/home"),
        temp: instance.join(".oneclient/tmp"),
        ..Default::default()
    };
    let prepared = oneclient_sandbox::prepare(&policy).await.unwrap();
    let out = instance.join("probe-out.txt");
    let file = std::fs::File::create(&out).unwrap();
    let mut command = std::process::Command::new(program);
    command.args(rest).current_dir(&instance);
    let spec = oneclient_sandbox::SpawnSpec::from_command(
        &command,
        Some(file.try_clone().unwrap()),
        Some(file),
    );
    let status = prepared.spawn(spec).unwrap().wait().await.unwrap();
    println!("{status:?}\n{}", std::fs::read_to_string(out).unwrap());
}
