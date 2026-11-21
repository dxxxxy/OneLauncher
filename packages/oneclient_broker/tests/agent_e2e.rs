//! A real JVM with the real agent talking to a real broker over real pipes.
//! Needs Java 11+ (`ONECLIENT_TEST_JAVA` or `java` on PATH); skipped without

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use oneclient_broker::{
    Activity, ActivityKind, BoxFuture, BrokerHost, LaunchDescriptor, OpenTarget, PickMode,
};
use uuid::Uuid;

#[derive(Default)]
struct Host {
    log: Mutex<Vec<Activity>>,
    opened: Mutex<Vec<OpenTarget>>,
}

impl BrokerHost for Host {
    fn real_token(&self, _account: Uuid) -> BoxFuture<'_, Result<String, String>> {
        Box::pin(async { Ok("REAL".to_string()) })
    }

    fn record(&self, activity: Activity) {
        self.log.lock().unwrap().push(activity);
    }

    fn open(&self, target: OpenTarget) {
        self.opened.lock().unwrap().push(target);
    }

    fn pick(&self, _mode: PickMode, _title: String) -> BoxFuture<'_, Option<PathBuf>> {
        Box::pin(async { Some(PathBuf::from("picked.png")) })
    }
}

const PROBE: &str = r#"
import java.net.*;
public class Probe {
    public static void main(String[] args) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(
            "https://api.minecraftservices.com/minecraft/profile/name/Stolen").openConnection();
        c.setRequestMethod("PUT");
        c.setRequestProperty("Authorization", "Bearer " + args[0]);
        System.out.println("status=" + c.getResponseCode());

        String opener = System.getProperty("os.name").startsWith("Windows") ? "rundll32" : "xdg-open";
        Process p = opener.equals("rundll32")
            ? new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", "https://modrinth.com").start()
            : new ProcessBuilder("xdg-open", "https://modrinth.com").start();
        System.out.println("opened=" + p.waitFor());

        // 1.8.9's "Open resource pack folder": one string, split on spaces
        String folder = args[1];
        Process q = System.getProperty("os.name").startsWith("Windows")
            ? Runtime.getRuntime().exec(String.format("cmd.exe /C start \"Open file\" \"%s\"", folder))
            : Runtime.getRuntime().exec(new String[] {"/usr/bin/open", folder});
        System.out.println("folder=" + q.waitFor());
    }
}
"#;

fn java() -> Option<String> {
    let java = std::env::var("ONECLIENT_TEST_JAVA").unwrap_or_else(|_| "java".into());
    std::process::Command::new(&java)
        .arg("-version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| java)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_routes_account_requests_through_the_broker() {
    let Some(java) = java() else {
        eprintln!("skipping: no java");
        return;
    };

    let dir = std::env::temp_dir().join(format!("oneclient-broker-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Probe.java"), PROBE).unwrap();
    // a space, as in most real paths, so the split string has to be re-read
    let packs = dir.join("resource packs");
    std::fs::create_dir_all(&packs).unwrap();
    let jar = oneclient_broker::agent::install(&dir.join("agent"))
        .await
        .unwrap();

    let descriptor = LaunchDescriptor::new(
        1,
        Uuid::from_u128(1),
        vec![dir.clone()],
        None,
        Some(dir.join("run")),
    );
    let host = Arc::new(Host::default());
    let broker =
        oneclient_broker::start(&descriptor, host.clone(), reqwest::Client::new()).unwrap();

    let mut command = tokio::process::Command::new(&java);
    command
        .args(oneclient_broker::agent::jvm_arguments(&jar, &broker))
        .arg("-Doneclient.sandboxed=true")
        .arg(dir.join("Probe.java"))
        .arg(&descriptor.fake_token)
        .arg(&packs)
        .env(oneclient_broker::KEY_ENV, &descriptor.key)
        .current_dir(&dir);
    let output = tokio::time::timeout(std::time::Duration::from_secs(60), command.output())
        .await
        .expect("probe timed out")
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("status=403"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    for line in ["opened=0", "folder=0"] {
        assert!(
            stdout.contains(line),
            "stdout: {stdout}\nstderr: {stderr}"
        );
    }

    let log = host.log.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|a| matches!(a.kind, ActivityKind::Connected { .. })),
        "{log:?}"
    );
    assert!(log.iter().any(Activity::is_alarm), "{log:?}");
    assert_eq!(
        host.opened.lock().unwrap().as_slice(),
        &[
            OpenTarget::Url("https://modrinth.com".parse().unwrap()),
            OpenTarget::Path(std::fs::canonicalize(&packs).unwrap()),
        ]
    );

    drop(broker);
    let _ = std::fs::remove_dir_all(dir);
}
