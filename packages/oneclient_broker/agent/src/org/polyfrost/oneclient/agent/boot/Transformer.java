package org.polyfrost.oneclient.agent.boot;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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

    /** 26.1+ file dialogs (OneConfig, Flashback, waypoint mods): asynchronous, answered by callback */
    private static final List<Target> SDL_DIALOG = Arrays.asList(
            new Target("nSDL_ShowOpenFileDialog", "(JJJJIJZ)V", false, 0, "sdlOpenFileDialog", Kind.TYPED, null),
            new Target("nSDL_ShowSaveFileDialog", "(JJJJIJ)V", false, 0, "sdlSaveFileDialog", Kind.TYPED, null),
            new Target("nSDL_ShowOpenFolderDialog", "(JJJJZ)V", false, 0, "sdlOpenFolderDialog", Kind.TYPED, null),
            new Target("nSDL_ShowFileDialogWithProperties", "(IJJI)V", false, 0, "sdlFileDialogWithProperties",
                    Kind.TYPED, null));

    /** AWT's FileDialog: Dialog.setVisible(true) and the old show() both end here */
    private static final List<Target> AWT_DIALOG = Arrays.asList(
            new Target("show", "()V", false, 1, "dialogShow", Kind.VOID_BOOL, null));

    /** Returns a boolean, which the JVM treats as an int */
    private static final List<Target> SDL_MISC = Arrays.asList(
            new Target("SDL_OpenURL", "(Ljava/lang/CharSequence;)Z", false, 1, "sdlOpenUrl", Kind.INT, null));

    /** Exclusive fullscreen on 26.1+: the mode argument becomes null (desktop mode) */
    private static final List<Target> SDL_VIDEO = Arrays.asList(
            new Target("SDL_SetWindowFullscreenMode", "(JLorg/lwjgl/sdl/SDL_DisplayMode;)Z", false, 2,
                    "sdlFullscreenMode", Kind.REWRITE, "org/lwjgl/sdl/SDL_DisplayMode"));

    /** Exclusive fullscreen before 26.1: always at the monitor's current mode */
    private static final List<Target> GLFW = Arrays.asList(
            new Target("nglfwCreateWindow", "(IIJJJ)J", false, 0, "glfwCreateWindow", Kind.TYPED, null),
            new Target("glfwSetWindowMonitor", "(JJIIIII)V", false, 0, "glfwSetWindowMonitor", Kind.TYPED, null));

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

    private static final List<Target> WINDOWS_PATH = Arrays.asList(
            new Target("toRealPath", "([Ljava/nio/file/LinkOption;)Lsun/nio/fs/WindowsPath;", false, 2, "realPath",
                    Kind.OBJECT, "sun/nio/fs/WindowsPath"));

    private static final List<Target> WINDOWS_PROVIDER = Arrays.asList(
            new Target("checkAccess", "(Ljava/nio/file/Path;[Ljava/nio/file/AccessMode;)V", false, 3, "checkAccess",
                    Kind.VOID_BOOL, null));

    private static final List<Target> WINDOWS_IO = Arrays.asList(
            new Target("getNameMax", "(Ljava/lang/String;)I", false, 2, "nameMax", Kind.INT, null));

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

    /**
     * The loader of each patched library class, so hooks can reach that
     * library's other classes (LWJGL's MemoryUtil, a mod's response types)
     * by reflection; the agent itself can't see them.
     */
    private static final Map<String, ClassLoader> loaders = new ConcurrentHashMap<String, ClassLoader>();

    /** The loader that defined the patched class {@code name} (dotted), or null. */
    static ClassLoader loaderOf(String name) {
        return loaders.get(name);
    }

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
            if (name.equals("sun/nio/fs/WindowsPath")) return Patcher.patch(bytes, WINDOWS_PATH);
            if (name.equals("sun/nio/fs/WindowsFileSystemProvider")) return Patcher.patch(bytes, WINDOWS_PROVIDER);
            if (name.equals("java/io/WinNTFileSystem")) return Patcher.patch(bytes, WINDOWS_IO);
            if (name.equals("java/lang/ProcessBuilder")) targets = PROCESS_BUILDER;
            else if (name.equals("java/awt/Desktop")) targets = DESKTOP;
            else if (name.equals("javax/swing/JFileChooser")) targets = CHOOSER;
            else if (name.equals("org/lwjgl/util/tinyfd/TinyFileDialogs")) targets = TINYFD;
            else if (name.equals("org/lwjgl/sdl/SDLMisc")) targets = SDL_MISC;
            else if (name.equals("org/lwjgl/sdl/SDLVideo")) targets = SDL_VIDEO;
            else if (name.equals("org/lwjgl/sdl/SDLDialog")) targets = SDL_DIALOG;
            else if (name.equals("java/awt/Dialog")) targets = AWT_DIALOG;
            else if (name.equals("org/lwjgl/glfw/GLFW")) targets = GLFW;
            else return null;

            byte[] patched = Patcher.patch(bytes, targets);
            if (patched != null && loader != null) {
                String dotted = name.replace('/', '.');
                loaders.put(dotted, loader);
                toFix.add(new Object[] {loader, dotted});
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
