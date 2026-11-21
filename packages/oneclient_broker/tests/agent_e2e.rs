//! A real JVM with the real agent talking to a real broker over real pipes.
//! Needs Java 11+ (`ONECLIENT_TEST_JAVA` or `java` on PATH); skipped without

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use oneclient_broker::{
    Activity, ActivityKind, BoxFuture, BrokerHost, ConfirmPrompt, GameAccount, LaunchDescriptor,
    OpenTarget, PickRequest, WantedDownload,
};
use uuid::Uuid;

#[derive(Default)]
struct Host {
    log: Mutex<Vec<Activity>>,
    opened: Mutex<Vec<OpenTarget>>,
    imported: Mutex<Vec<PathBuf>>,
    switched: Mutex<Vec<Uuid>>,
    asked: Mutex<Vec<String>>,
    revealed: Mutex<Vec<PathBuf>>,
    trashed: Mutex<Vec<PathBuf>>,
    watched: Mutex<Vec<Option<WantedDownload>>>,
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

    fn pick(&self, _request: PickRequest) -> BoxFuture<'_, Option<PathBuf>> {
        Box::pin(async { Some(PathBuf::from("picked.png")) })
    }

    fn import(&self, from: PathBuf, _caller: String) -> BoxFuture<'_, Option<PathBuf>> {
        self.imported.lock().unwrap().push(from);
        Box::pin(async { Some(PathBuf::from("imported.zip")) })
    }

    fn accounts(&self) -> BoxFuture<'_, Vec<GameAccount>> {
        Box::pin(async {
            vec![
                GameAccount {
                    id: Uuid::from_u128(1).to_string(),
                    name: "Main".into(),
                },
                GameAccount {
                    id: Uuid::from_u128(2).to_string(),
                    name: "Alt".into(),
                },
            ]
        })
    }

    fn confirm(&self, prompt: ConfirmPrompt) -> BoxFuture<'_, bool> {
        self.asked.lock().unwrap().push(prompt.title);
        Box::pin(async { false })
    }

    fn switch_account(&self, to: Uuid) -> BoxFuture<'_, Result<(), String>> {
        self.switched.lock().unwrap().push(to);
        Box::pin(async { Ok(()) })
    }

    fn reveal(&self, file: PathBuf) {
        self.revealed.lock().unwrap().push(file);
    }

    fn trash(&self, path: PathBuf) -> BoxFuture<'_, Result<(), String>> {
        self.trashed.lock().unwrap().push(path);
        Box::pin(async { Ok(()) })
    }

    fn watch_downloads(&self, wanted: Option<WantedDownload>) {
        self.watched.lock().unwrap().push(wanted);
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

        // Java 11's client, as newer mods use it
        java.net.http.HttpResponse<String> r = java.net.http.HttpClient.newHttpClient().send(
            java.net.http.HttpRequest.newBuilder(URI.create(
                "https://api.minecraftservices.com/minecraft/profile/skins/active"))
                .header("Authorization", "Bearer " + args[0])
                .DELETE().build(),
            java.net.http.HttpResponse.BodyHandlers.ofString());
        System.out.println("modern=" + r.statusCode());
        int async = java.net.http.HttpClient.newHttpClient().sendAsync(
            java.net.http.HttpRequest.newBuilder(URI.create(
                "https://api.minecraftservices.com/minecraft/profile/name/Async"))
                .PUT(java.net.http.HttpRequest.BodyPublishers.ofString("{}")).build(),
            java.net.http.HttpResponse.BodyHandlers.ofByteArray()).get().statusCode();
        System.out.println("async=" + async);

        // AWT's file dialog (a waypoint mod's fallback): the launcher picks instead
        if (!java.awt.GraphicsEnvironment.isHeadless()) {
            java.awt.FileDialog fd = new java.awt.FileDialog((java.awt.Frame) null, "Pick", java.awt.FileDialog.LOAD);
            fd.setVisible(true);
            System.out.println("filedialog=" + fd.getFile() + "," + fd.getFiles().length);
        }

        // GLFW's drop callback, compiled here as a stub and patched like the
        // real one: a dropped file the game can't read gets copied in
        java.nio.file.Path stubs = java.nio.file.Paths.get(args[2]);
        java.nio.file.Path source = stubs.resolve("org/lwjgl/glfw/GLFWDropCallback.java");
        java.nio.file.Files.createDirectories(source.getParent());
        java.nio.file.Files.write(source, ("package org.lwjgl.glfw; public class GLFWDropCallback {"
            + " public static String getName(long names, int index) {"
            + " return \"/oneclient-e2e-missing/pack\" + index + \".zip\"; } }").getBytes("UTF-8"));
        javax.tools.ToolProvider.getSystemJavaCompiler().run(null, null, null, "-d", stubs.toString(), source.toString());
        URLClassLoader stubLoader = new URLClassLoader(new URL[] {stubs.toUri().toURL()});
        Object dropped = stubLoader.loadClass("org.lwjgl.glfw.GLFWDropCallback")
            .getMethod("getName", long.class, int.class).invoke(null, 0L, 3);
        System.out.println("dropped=" + dropped);

        // Poly+'s account switcher, stubbed the same way: it gets the
        // launcher's accounts with the fake token, and switching remaps
        String pp = "org/polyfrost/polyplus/client/launcher/";
        java.nio.file.Path ppSource = stubs.resolve(pp + "LauncherAccountStore.java");
        java.nio.file.Files.createDirectories(ppSource.getParent());
        java.nio.file.Files.write(ppSource, ("package org.polyfrost.polyplus.client.launcher;"
            + " public class LauncherAccountStore {"
            + " public static class StoredAccount { final String id, name, token;"
            + "  public StoredAccount(String id, String name, String token, String refresh, String expires, String kind) {"
            + "   this.id = id; this.name = name; this.token = token; }"
            + "  public String getId() { return id; } public String toString() { return name + ':' + token; } }"
            + " public static class CredentialsStore { public final java.util.Map<String, StoredAccount> users; public final String active;"
            + "  public CredentialsStore(java.util.Map<String, StoredAccount> users, String active) { this.users = users; this.active = active; }"
            + "  public String toString() { return users.values() + \" active \" + active; } }"
            + " public CredentialsStore load() { return null; } }").getBytes("UTF-8"));
        java.nio.file.Path switchSource = stubs.resolve(pp + "AccountSwitch.java");
        java.nio.file.Files.write(switchSource, ("package org.polyfrost.polyplus.client.launcher;"
            + " public class AccountSwitch { public boolean apply(LauncherAccountStore.StoredAccount a) { return true; } }")
            .getBytes("UTF-8"));
        javax.tools.ToolProvider.getSystemJavaCompiler().run(null, null, null, "-d", stubs.toString(),
            ppSource.toString(), switchSource.toString());
        Class<?> store = stubLoader.loadClass("org.polyfrost.polyplus.client.launcher.LauncherAccountStore");
        Object credentials = store.getMethod("load").invoke(store.getConstructor().newInstance());
        System.out.println("accounts=" + credentials);
        Object alt = ((java.util.Map<?, ?>) credentials.getClass().getField("users").get(credentials))
            .get("00000000-0000-0000-0000-000000000002");
        Class<?> switcher = stubLoader.loadClass("org.polyfrost.polyplus.client.launcher.AccountSwitch");
        System.out.println("switched=" + switcher.getMethod("apply", alt.getClass())
            .invoke(switcher.getConstructor().newInstance(), alt));

        // Poly+'s pack screen: trash through PowerShell (refused here, the
        // stub says no) and "show in Explorer", both through the launcher
        java.nio.file.Path old = java.nio.file.Paths.get(args[1], "old.zip");
        java.nio.file.Files.write(old, new byte[] {1});
        String packsPackage = "org/polyfrost/polyplus/client/gui/screens/packs/";
        java.nio.file.Path packSource = stubs.resolve(packsPackage + "PackFiles.java");
        java.nio.file.Files.createDirectories(packSource.getParent());
        java.nio.file.Files.write(packSource, ("package org.polyfrost.polyplus.client.gui.screens.packs;"
            + " public class PackFiles { private boolean toTrash(java.nio.file.Path p) { return false; }"
            + " public boolean trash(java.nio.file.Path p) { return toTrash(p); }"
            + " public int reveal(java.nio.file.Path p) throws Exception {"
            + "  return new ProcessBuilder(\"explorer.exe\", \"/select,\" + p.toAbsolutePath()).start().waitFor(); } }")
            .getBytes("UTF-8"));
        javax.tools.ToolProvider.getSystemJavaCompiler().run(null, null, null, "-d", stubs.toString(),
            packSource.toString());
        Class<?> packFiles = stubLoader.loadClass("org.polyfrost.polyplus.client.gui.screens.packs.PackFiles");
        Object files = packFiles.getConstructor().newInstance();
        System.out.println("trashed=" + packFiles.getMethod("trash", java.nio.file.Path.class).invoke(files, old));
        System.out.println("revealed=" + packFiles.getMethod("reveal", java.nio.file.Path.class).invoke(files, old));

        // Resourcify's manual download: the screen ticks twice, then closes
        String rf = "dev/dediamondpro/resourcify/gui/";
        java.nio.file.Path rfSource = stubs.resolve(rf + "DownloadWatcherScreen.java");
        java.nio.file.Files.createDirectories(rfSource.getParent());
        java.nio.file.Files.write(rfSource, ("package dev.dediamondpro.resourcify.gui;"
            + " public class DownloadWatcherScreen { private final String extension = \"zip\";"
            + " private final long size = 1234; private final String sha1 = \"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709\";"
            + " public static final Companion Companion = new Companion();"
            + " public static class Companion { public boolean isUsable() {"
            + "  return new java.io.File(System.getProperty(\"user.home\"), \"Downloads\").isDirectory(); } }"
            + " public void tick() {} public void onClose() {} }").getBytes("UTF-8"));
        javax.tools.ToolProvider.getSystemJavaCompiler().run(null, null, null, "-d", stubs.toString(),
            rfSource.toString());
        Class<?> watcher = stubLoader.loadClass("dev.dediamondpro.resourcify.gui.DownloadWatcherScreen");
        Object companion = watcher.getField("Companion").get(null);
        System.out.println("usable=" + companion.getClass().getMethod("isUsable").invoke(companion));
        Object screen = watcher.getConstructor().newInstance();
        watcher.getMethod("tick").invoke(screen);
        watcher.getMethod("tick").invoke(screen);
        watcher.getMethod("onClose").invoke(screen);

        // jagrosh-style Discord IPC: the pipe opened as a file
        if (System.getProperty("os.name").startsWith("Windows")) {
            java.io.RandomAccessFile pipe = new java.io.RandomAccessFile("\\\\?\\pipe\\discord-ipc-0", "rw");
            pipe.write("hello".getBytes("UTF-8"));
            System.out.println("discord=" + (char) pipe.read());
            pipe.close();
        }
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
    // stands in for the launcher's Discord relay
    #[cfg(windows)]
    let discord_pipe = format!(
        r"\\.\pipe\oneclient-test-discord-{}",
        Uuid::new_v4().simple()
    );
    #[cfg(windows)]
    let discord = {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&discord_pipe)
            .unwrap();
        tokio::spawn(async move {
            server.connect().await.unwrap();
            let mut hello = [0u8; 5];
            server.read_exact(&mut hello).await.unwrap();
            server.write_all(b"k").await.unwrap();
            hello
        })
    };

    let host = Arc::new(Host::default());
    let broker =
        oneclient_broker::start(&descriptor, host.clone(), reqwest::Client::new()).unwrap();

    let mut command = tokio::process::Command::new(&java);
    command
        .args(oneclient_broker::agent::jvm_arguments(&jar, &broker))
        .arg("-Doneclient.sandboxed=true");
    #[cfg(windows)]
    command.arg(format!("-Doneclient.discord={discord_pipe}"));
    command
        .arg(dir.join("Probe.java"))
        .arg(&descriptor.fake_token)
        .arg(&packs)
        .arg(dir.join("stubs"))
        // as Minecraft gets it; the agent reads the fake token from here
        .arg("--accessToken")
        .arg(&descriptor.fake_token)
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
    let mut expected = vec![
        "opened=0",
        "folder=0",
        "modern=403",
        "async=403",
        "dropped=imported.zip",
        "switched=true",
        "trashed=true",
        "revealed=0",
        "usable=true",
    ];
    if cfg!(windows) {
        expected.push("discord=k");
        expected.push("filedialog=picked.png,1");
    }
    for line in expected {
        assert!(stdout.contains(line), "stdout: {stdout}\nstderr: {stderr}");
    }

    let log = host.log.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|a| matches!(a.kind, ActivityKind::Connected { .. })),
        "{log:?}"
    );
    // account changes ask the user; this host says no to all three
    assert_eq!(log.iter().filter(|a| a.is_alarm()).count(), 0, "{log:?}");
    assert_eq!(
        log.iter()
            .filter(|a| matches!(&a.kind, ActivityKind::Denied { reason, .. } if reason.starts_with("you didn't let")))
            .count(),
        3,
        "{log:?}"
    );
    #[cfg(windows)]
    assert_eq!(&discord.await.unwrap(), b"hello");
    assert_eq!(
        host.opened.lock().unwrap().as_slice(),
        &[
            OpenTarget::Url("https://modrinth.com".parse().unwrap()),
            OpenTarget::Path(std::fs::canonicalize(&packs).unwrap()),
        ]
    );

    let accounts = format!(
        "accounts=[Main:{fake}, Alt:{fake}] active 00000000-0000-0000-0000-000000000001",
        fake = descriptor.fake_token
    );
    assert!(
        stdout.contains(&accounts),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        host.switched.lock().unwrap().as_slice(),
        &[Uuid::from_u128(2)]
    );
    let old = std::fs::canonicalize(&packs).unwrap().join("old.zip");
    assert_eq!(host.trashed.lock().unwrap().as_slice(), &[old.clone()]);
    assert_eq!(host.revealed.lock().unwrap().as_slice(), &[old]);
    // one watch for the screen however often it ticks, stopped on close
    assert_eq!(
        host.watched.lock().unwrap().as_slice(),
        &[
            WantedDownload::new(
                "zip",
                1234,
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "dev.dediamondpro.resourcify.gui.DownloadWatcherScreen".into()
            ),
            None
        ]
    );
    assert_eq!(
        host.imported.lock().unwrap().as_slice(),
        &[PathBuf::from("/oneclient-e2e-missing/pack3.zip")]
    );

    drop(broker);
    let _ = std::fs::remove_dir_all(dir);
}

/// Poly+'s shaded Ktor client, driven from Java the way Kotlin would
const KTOR_PROBE: &str = r#"
import java.lang.reflect.*;
import java.util.concurrent.*;
public class KtorProbe {
    static final String K = "org.polyfrost.polyplus.libs.ktor.";
    interface Suspend { Object call(Object continuation) throws Exception; }

    /** Runs a suspend call to the end */
    static Object await(Suspend f) throws Exception {
        CompletableFuture<Object> result = new CompletableFuture<>();
        Object context = Class.forName("kotlin.coroutines.EmptyCoroutineContext").getField("INSTANCE").get(null);
        Object continuation = Proxy.newProxyInstance(KtorProbe.class.getClassLoader(),
            new Class<?>[] {Class.forName("kotlin.coroutines.Continuation")}, (p, m, a) -> {
                if (m.getName().equals("getContext")) return context;
                if (m.getName().equals("resumeWith")) result.complete(a[0]);
                return null;
            });
        Method marker = Class.forName("kotlin.coroutines.intrinsics.IntrinsicsKt").getMethod("getCOROUTINE_SUSPENDED");
        marker.setAccessible(true);
        Object suspended = marker.invoke(null);
        Object value = f.call(continuation);
        if (value == suspended) value = result.get(60, TimeUnit.SECONDS);
        if (value != null && value.getClass().getName().equals("kotlin.Result$Failure")) {
            throw new RuntimeException((Throwable) value.getClass().getField("exception").get(value));
        }
        return value;
    }

    static Object request(Object client, String method, String url, Object body) throws Exception {
        Class<?> builderClass = Class.forName(K + "client.request.HttpRequestBuilder");
        Object builder = builderClass.getConstructor().newInstance();
        Class.forName(K + "client.request.HttpRequestKt").getMethod("url", builderClass, String.class).invoke(null, builder, url);
        Object methods = Class.forName(K + "http.HttpMethod").getField("Companion").get(null);
        builderClass.getMethod("setMethod", Class.forName(K + "http.HttpMethod"))
            .invoke(builder, methods.getClass().getMethod("get" + method).invoke(methods));
        Object headers = builderClass.getMethod("getHeaders").invoke(builder);
        headers.getClass().getMethod("append", String.class, String.class)
            .invoke(headers, "Authorization", "Bearer " + System.getProperty("fake"));
        if (body != null) builderClass.getMethod("setBody", Object.class).invoke(builder, body);
        Class<?> statementClass = Class.forName(K + "client.statement.HttpStatement");
        Object statement = statementClass.getConstructor(builderClass, Class.forName(K + "client.HttpClient"))
            .newInstance(builder, client);
        Class<?> continuation = Class.forName("kotlin.coroutines.Continuation");
        Object response = await(c -> statementClass.getMethod("execute", continuation).invoke(statement, c));
        Object status = response.getClass().getMethod("getStatus").invoke(response);
        Object text = await(c -> Class.forName(K + "client.statement.HttpResponseKt")
            .getMethod("bodyAsText", Class.forName(K + "client.statement.HttpResponse"),
                java.nio.charset.Charset.class, continuation)
            .invoke(null, response, java.nio.charset.StandardCharsets.UTF_8, c));
        return status.getClass().getMethod("getValue").invoke(status) + " " + text;
    }

    public static void main(String[] args) throws Exception {
        Object cio = Class.forName(K + "client.engine.cio.CIO").getField("INSTANCE").get(null);
        Object configure = Proxy.newProxyInstance(KtorProbe.class.getClassLoader(),
            new Class<?>[] {Class.forName("kotlin.jvm.functions.Function1")}, (p, m, a) ->
                m.getName().equals("invoke") ? Class.forName("kotlin.Unit").getField("INSTANCE").get(null) : null);
        Object client = Class.forName(K + "client.HttpClientKt").getMethod("HttpClient",
            Class.forName(K + "client.engine.HttpClientEngineFactory"), Class.forName("kotlin.jvm.functions.Function1"))
            .invoke(null, cio, configure);
        Class<?> contentType = Class.forName(K + "http.ContentType");

        Object json = Class.forName(K + "http.ContentType$Application").getField("INSTANCE").get(null);
        Object cape = Class.forName(K + "http.content.TextContent")
            .getConstructor(String.class, contentType, Class.forName(K + "http.HttpStatusCode"))
            .newInstance("{}", json.getClass().getMethod("getJson").invoke(json), null);
        System.out.println("cape=" + request(client, "Put",
            "https://api.minecraftservices.com/minecraft/profile/capes/active", cape));

        Object headersCompanion = Class.forName(K + "http.Headers").getField("Companion").get(null);
        Object noHeaders = headersCompanion.getClass().getMethod("getEmpty").invoke(headersCompanion);
        Class<?> formPart = Class.forName(K + "client.request.forms.FormPart");
        Object part = formPart.getConstructor(String.class, Object.class, Class.forName(K + "http.Headers"))
            .newInstance("file", "pretend-png", noHeaders);
        Object partsArray = Array.newInstance(formPart, 1);
        Array.set(partsArray, 0, part);
        Object parts = Class.forName(K + "client.request.forms.FormDslKt")
            .getMethod("formData", partsArray.getClass()).invoke(null, partsArray);
        Object multipart = Class.forName(K + "http.ContentType$MultiPart").getField("INSTANCE").get(null);
        Object form = Class.forName(K + "client.request.forms.MultiPartFormDataContent")
            .getConstructor(java.util.List.class, String.class, contentType)
            .newInstance(parts, "oneclientboundary", multipart.getClass().getMethod("getFormData").invoke(multipart));
        System.out.println("skin=" + request(client, "Post",
            "https://api.minecraftservices.com/minecraft/profile/skins", form));
        System.exit(0);
    }
}
"#;

/// Needs Poly+ and its Kotlin libraries: `ONECLIENT_TEST_POLYPLUS_CP` is a
/// class path holding polyplus.jar, kotlin-stdlib and kotlinx-coroutines
#[tokio::test(flavor = "multi_thread")]
async fn poly_plus_ktor_requests_go_through_the_broker() {
    let Some(java) = java() else {
        eprintln!("skipping: no java");
        return;
    };
    let Ok(classpath) = std::env::var("ONECLIENT_TEST_POLYPLUS_CP") else {
        eprintln!("skipping: ONECLIENT_TEST_POLYPLUS_CP not set");
        return;
    };

    let dir = std::env::temp_dir().join(format!("oneclient-broker-ktor-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("KtorProbe.java"), KTOR_PROBE).unwrap();
    let jar = oneclient_broker::agent::install(&dir.join("agent"))
        .await
        .unwrap();
    let descriptor =
        LaunchDescriptor::new(1, Uuid::from_u128(1), vec![], None, Some(dir.join("run")));
    let host = Arc::new(Host::default());
    let broker =
        oneclient_broker::start(&descriptor, host.clone(), reqwest::Client::new()).unwrap();

    let mut command = tokio::process::Command::new(&java);
    command
        .args(oneclient_broker::agent::jvm_arguments(&jar, &broker))
        .arg(format!("-Dfake={}", descriptor.fake_token))
        .arg("-cp")
        .arg(&classpath)
        .arg(dir.join("KtorProbe.java"))
        .env(oneclient_broker::KEY_ENV, &descriptor.key)
        .current_dir(&dir);
    let output = tokio::time::timeout(std::time::Duration::from_secs(90), command.output())
        .await
        .expect("probe timed out")
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // this host refuses every account change, so both come back 403 from the
    // broker without touching the network; the multipart body still had to
    // be read in full to get there
    for line in ["cape=403 ", "skin=403 ", "OneClient blocked"] {
        assert!(stdout.contains(line), "stdout: {stdout}\nstderr: {stderr}");
    }
    let asked = host.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert!(asked[0].contains("change your cape"), "{asked:?}");
    assert!(asked[1].contains("change your skin"), "{asked:?}");

    drop(broker);
    let _ = std::fs::remove_dir_all(dir);
}

/// java-discord-rpc as mods ship it, over stand-ins for JNA (the agent
/// answers `Native.loadLibrary("discord-rpc", ...)` itself)
#[cfg(windows)]
const RPC_PROBE: &str = r#"
import java.net.*;
import java.nio.file.*;
public class RpcProbe {
    static void write(Path root, String path, String source) throws Exception {
        Path file = root.resolve(path);
        Files.createDirectories(file.getParent());
        Files.write(file, source.getBytes("UTF-8"));
    }

    public static void main(String[] args) throws Exception {
        Path stubs = Paths.get(args[0]);
        write(stubs, "com/sun/jna/Library.java", "package com.sun.jna; public interface Library {}");
        write(stubs, "com/sun/jna/Callback.java", "package com.sun.jna; public interface Callback {}");
        write(stubs, "com/sun/jna/Structure.java", "package com.sun.jna; public abstract class Structure {}");
        write(stubs, "com/sun/jna/Native.java", "package com.sun.jna; public class Native {"
            + " public static Object loadLibrary(String name, Class<?> type) { throw new UnsatisfiedLinkError(name); } }");
        String rpc = "club/minnced/discord/rpc/";
        String pkg = "package club.minnced.discord.rpc; ";
        write(stubs, rpc + "DiscordUser.java", pkg + "public class DiscordUser extends com.sun.jna.Structure {"
            + " public String userId, username, discriminator, avatar; }");
        write(stubs, rpc + "DiscordRichPresence.java", pkg + "public class DiscordRichPresence extends com.sun.jna.Structure {"
            + " public String state, details; public long startTimestamp, endTimestamp;"
            + " public String largeImageKey, largeImageText, smallImageKey, smallImageText, partyId;"
            + " public int partySize, partyMax; public String matchSecret, joinSecret, spectateSecret; public byte instance; }");
        write(stubs, rpc + "DiscordEventHandlers.java", pkg + "public class DiscordEventHandlers extends com.sun.jna.Structure {"
            + " public interface OnReady extends com.sun.jna.Callback { void accept(DiscordUser user); }"
            + " public interface OnStatus extends com.sun.jna.Callback { void accept(int code, String message); }"
            + " public interface OnGameUpdate extends com.sun.jna.Callback { void accept(String secret); }"
            + " public interface OnJoinRequest extends com.sun.jna.Callback { void accept(DiscordUser user); }"
            + " public OnReady ready; public OnStatus disconnected, errored; public OnGameUpdate joinGame, spectateGame;"
            + " public OnJoinRequest joinRequest; }");
        write(stubs, rpc + "DiscordRPC.java", pkg + "public interface DiscordRPC extends com.sun.jna.Library {"
            + " DiscordRPC INSTANCE = (DiscordRPC) com.sun.jna.Native.loadLibrary(\"discord-rpc\", DiscordRPC.class);"
            + " void Discord_Initialize(String id, DiscordEventHandlers handlers, boolean register, String steam);"
            + " void Discord_Shutdown(); void Discord_RunCallbacks(); void Discord_UpdatePresence(DiscordRichPresence p);"
            + " void Discord_ClearPresence(); void Discord_Respond(String user, int reply); }");
        write(stubs, rpc + "Driver.java", pkg + "public class Driver { public static String run() throws Exception {"
            + " final StringBuilder log = new StringBuilder();"
            + " DiscordEventHandlers handlers = new DiscordEventHandlers();"
            + " handlers.ready = u -> log.append(\"ready=\").append(u.username).append(' ');"
            + " handlers.joinGame = s -> log.append(\"join=\").append(s).append(' ');"
            + " DiscordRPC lib = DiscordRPC.INSTANCE;"
            + " lib.Discord_Initialize(\"123\", handlers, true, null);"
            + " DiscordRichPresence p = new DiscordRichPresence();"
            + " p.state = \"Hypixel\"; p.details = \"Bed \\\"Wars\\\"\"; p.startTimestamp = 1700000000L;"
            + " p.largeImageKey = \"logo\"; p.partySize = 2; p.partyMax = 4;"
            + " lib.Discord_UpdatePresence(p);"
            + " long until = System.currentTimeMillis() + 20000;"
            + " while (log.indexOf(\"join=\") < 0 && System.currentTimeMillis() < until) {"
            + "  lib.Discord_RunCallbacks(); Thread.sleep(20); }"
            + " lib.Discord_ClearPresence(); Thread.sleep(500); lib.Discord_Shutdown();"
            + " return log.toString().trim(); } }");

        java.util.List<String> sources = new java.util.ArrayList<>();
        try (java.util.stream.Stream<Path> files = Files.walk(stubs)) {
            files.filter(f -> f.toString().endsWith(".java")).forEach(f -> sources.add(f.toString()));
        }
        sources.add(0, stubs.toString());
        sources.add(0, "-d");
        javax.tools.ToolProvider.getSystemJavaCompiler().run(null, null, null, sources.toArray(new String[0]));
        URLClassLoader loader = new URLClassLoader(new URL[] {stubs.toUri().toURL()});
        Object result = loader.loadClass("club.minnced.discord.rpc.Driver").getMethod("run").invoke(null);
        System.out.println("rpc=" + result);
        System.exit(0);
    }
}
"#;

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn java_discord_rpc_reaches_discord_through_the_relay() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn read(pipe: &mut (impl AsyncReadExt + Unpin)) -> (u32, serde_json::Value) {
        let mut header = [0u8; 8];
        pipe.read_exact(&mut header).await.unwrap();
        let op = u32::from_le_bytes(header[..4].try_into().unwrap());
        let len = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        let mut body = vec![0; len];
        pipe.read_exact(&mut body).await.unwrap();
        (op, serde_json::from_slice(&body).unwrap())
    }
    async fn write(pipe: &mut (impl AsyncWriteExt + Unpin), body: serde_json::Value) {
        let body = serde_json::to_vec(&body).unwrap();
        let mut frame = 1u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(&body);
        pipe.write_all(&frame).await.unwrap();
    }

    let Some(java) = java() else {
        eprintln!("skipping: no java");
        return;
    };
    let dir = std::env::temp_dir().join(format!("oneclient-broker-rpc-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("RpcProbe.java"), RPC_PROBE).unwrap();
    let jar = oneclient_broker::agent::install(&dir.join("agent"))
        .await
        .unwrap();

    // stands in for the launcher's relay, with Discord behind it
    let pipe = format!(r"\\.\pipe\oneclient-test-rpc-{}", Uuid::new_v4().simple());
    let mut server = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe)
        .unwrap();
    let discord = tokio::spawn(async move {
        server.connect().await.unwrap();
        let (op, hello) = read(&mut server).await;
        assert_eq!((op, &hello["client_id"]), (0, &serde_json::json!("123")));
        write(
            &mut server,
            serde_json::json!({"cmd": "DISPATCH", "evt": "READY",
                "data": {"user": {"id": "1", "username": "steve", "discriminator": "0", "avatar": null}}}),
        )
        .await;
        let mut frames = Vec::new();
        loop {
            let (_, frame) = read(&mut server).await;
            let shows = frame["cmd"] == "SET_ACTIVITY" && frame["args"]["activity"].is_object();
            frames.push(frame);
            if shows {
                break;
            }
        }
        write(
            &mut server,
            serde_json::json!({"cmd": "DISPATCH", "evt": "ACTIVITY_JOIN", "data": {"secret": "s3cret"}}),
        )
        .await;
        loop {
            let (_, frame) = read(&mut server).await;
            let cleared = frame["cmd"] == "SET_ACTIVITY" && frame["args"].get("activity").is_none();
            frames.push(frame);
            if cleared {
                return frames;
            }
        }
    });

    let output = tokio::process::Command::new(&java)
        .arg(format!("-javaagent:{}", jar.display()))
        .arg("-Doneclient.sandboxed=true")
        .arg(format!("-Doneclient.discord={pipe}"))
        .arg(dir.join("RpcProbe.java"))
        .arg(dir.join("stubs"))
        .current_dir(&dir)
        .output();
    let output = tokio::time::timeout(std::time::Duration::from_secs(60), output)
        .await
        .expect("probe timed out")
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("rpc=ready=steve join=s3cret"),
        "stdout: {stdout}\nstderr: {stderr}"
    );

    let frames = tokio::time::timeout(std::time::Duration::from_secs(10), discord)
        .await
        .unwrap()
        .unwrap();
    let subscribed: Vec<_> = frames
        .iter()
        .filter(|f| f["cmd"] == "SUBSCRIBE")
        .map(|f| f["evt"].as_str().unwrap())
        .collect();
    assert_eq!(
        subscribed,
        [
            "ACTIVITY_JOIN",
            "ACTIVITY_SPECTATE",
            "ACTIVITY_JOIN_REQUEST"
        ]
    );
    let presence = frames
        .iter()
        .find(|f| f["args"]["activity"].is_object())
        .unwrap();
    assert_eq!(
        presence["args"]["activity"],
        serde_json::json!({
            "state": "Hypixel",
            "details": "Bed \"Wars\"",
            "timestamps": {"start": 1700000000},
            "assets": {"large_image": "logo"},
            "party": {"size": [2, 4]},
            // as the native library sends it
            "instance": false,
        })
    );
    assert!(presence["args"]["pid"].as_u64().unwrap() > 0);

    let _ = std::fs::remove_dir_all(dir);
}
