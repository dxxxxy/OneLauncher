package org.polyfrost.oneclient.agent.boot;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.polyfrost.oneclient.agent.boot.Patcher.Kind;
import org.polyfrost.oneclient.agent.boot.Patcher.Target;

/**
 * Patches the handful of JDK and library methods that need the launcher:
 * account requests through {@code java.net.http} always, and the rest only
 * when sandboxed.
 */
final class Transformer implements ClassFileTransformer {
    private static final List<Target> PROCESS_BUILDER = Arrays.asList(
            new Target("start", "()Ljava/lang/Process;", false, 1, "start", Kind.OBJECT, "java/lang/Process"));

    private static final List<Target> DESKTOP = Arrays.asList(
            new Target("browse", "(Ljava/net/URI;)V", false, 2, "browse", Kind.VOID_BOOL, null),
            new Target("open", "(Ljava/io/File;)V", false, 2, "openFile", Kind.VOID_BOOL, null));

    private static final List<Target> CHOOSER = Arrays.asList(
            new Target("showOpenDialog", "(Ljava/awt/Component;)I", false, 1, "chooserOpen", Kind.INT, null),
            new Target("showSaveDialog", "(Ljava/awt/Component;)I", false, 1, "chooserSave", Kind.INT, null),
            new Target("showDialog", "(Ljava/awt/Component;Ljava/lang/String;)I", false, 1, "chooserShow",
                    Kind.INT, null));

    private static final List<Target> TINYFD = Arrays.asList(
            new Target("tinyfd_openFileDialog", ")Ljava/lang/String;", true, 1, "tinyOpen", Kind.OBJECT,
                    "java/lang/String"),
            new Target("tinyfd_saveFileDialog", ")Ljava/lang/String;", true, 1, "tinySave", Kind.OBJECT,
                    "java/lang/String"),
            new Target("tinyfd_selectFolderDialog", ")Ljava/lang/String;", true, 1, "tinyFolder", Kind.OBJECT,
                    "java/lang/String"));

    private static final List<Target> RANDOM_ACCESS_FILE = Arrays.asList(
            new Target("<init>", "(Ljava/io/File;Ljava/lang/String;)V", false, 1, "discordPipe", Kind.REWRITE,
                    "java/io/File"),
            new Target("<init>", "(Ljava/lang/String;Ljava/lang/String;)V", false, 1, "discordPipeName",
                    Kind.REWRITE, "java/lang/String"));

    private static final List<Target> FILE = Arrays.asList(
            new Target("<init>", "(Ljava/lang/String;)V", false, 1, "discordPipeName", Kind.REWRITE,
                    "java/lang/String"));

    private static final List<Target> LWJGL2_DISPLAY = Arrays.asList(
            new Target("switchDisplayMode", "(Lorg/lwjgl/opengl/DisplayMode;)V", false, 2, "lwjglSwitchMode",
                    Kind.VOID_BOOL, null));

    private static final List<Target> HTTP_CLIENT = Arrays.asList(
            new Target("send", "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)"
                    + "Ljava/net/http/HttpResponse;", false, 3, "httpSend", Kind.OBJECT, "java/net/http/HttpResponse"),
            new Target("sendAsync", "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)"
                    + "Ljava/util/concurrent/CompletableFuture;", false, 3, "httpSendAsync", Kind.OBJECT,
                    "java/util/concurrent/CompletableFuture"),
            new Target("sendAsync", "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;"
                    + "Ljava/net/http/HttpResponse$PushPromiseHandler;)Ljava/util/concurrent/CompletableFuture;",
                    false, 3, "httpSendAsync", Kind.OBJECT, "java/util/concurrent/CompletableFuture"));

    /** Patched classes outside the JDK that may live in a named module. */
    private static final ConcurrentLinkedQueue<Object[]> toFix = new ConcurrentLinkedQueue<Object[]>();

    public byte[] transform(ClassLoader loader, String name, Class<?> redefined, ProtectionDomain domain,
            byte[] bytes) {
        if (name == null) return null;
        try {
            List<Target> targets;
            if (name.equals("jdk/internal/net/http/HttpClientFacade")) {
                return Patcher.patch(bytes, HTTP_CLIENT);
            }
            if (!Hooks.sandboxed) return null;
            if (name.equals("java/io/RandomAccessFile")) {
                return Hooks.discordRelay == null ? null : Patcher.patch(bytes, RANDOM_ACCESS_FILE);
            }
            if (name.equals("java/io/File")) {
                return Hooks.discordRelay == null ? null : Patcher.patch(bytes, FILE);
            }
            if (name.equals("org/lwjgl/opengl/WindowsDisplay")) return Patcher.patch(bytes, LWJGL2_DISPLAY);
            if (name.equals("java/lang/ProcessBuilder")) targets = PROCESS_BUILDER;
            else if (name.equals("java/awt/Desktop")) targets = DESKTOP;
            else if (name.equals("javax/swing/JFileChooser")) targets = CHOOSER;
            else if (name.equals("org/lwjgl/util/tinyfd/TinyFileDialogs")) targets = TINYFD;
            else return null;

            byte[] patched = Patcher.patch(bytes, targets);
            if (patched != null && loader != null) {
                toFix.add(new Object[] {loader, name.replace('/', '.')});
            }
            return patched;
        } catch (Throwable t) {
            Main.log("left " + name + " unpatched: " + t);
            return null;
        }
    }

    /**
     * LWJGL can sit in a named module that doesn't read ours; grant that as
     * soon as the patched class exists (pickers are only used much later).
     */
    static void startModuleFixer() {
        Thread fixer = new Thread(new Runnable() {
            public void run() {
                List<Object[]> waiting = new ArrayList<Object[]>();
                while (true) {
                    Object[] next;
                    while ((next = toFix.poll()) != null) waiting.add(next);
                    for (java.util.Iterator<Object[]> it = waiting.iterator(); it.hasNext(); ) {
                        Object[] entry = it.next();
                        try {
                            Class<?> c = Class.forName((String) entry[1], false, (ClassLoader) entry[0]);
                            Main.letRead(c);
                            it.remove();
                        } catch (Throwable notYet) {
                            // defined a moment later
                        }
                    }
                    try {
                        Thread.sleep(250);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
        }, "OneClient module fixer");
        fixer.setDaemon(true);
        fixer.start();
    }
}
