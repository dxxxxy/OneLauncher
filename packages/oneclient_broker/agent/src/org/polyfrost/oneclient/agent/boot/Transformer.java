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

    /** Files dropped on the window: 26.1+ (SDL) and 1.13 to 1.21 (GLFW) */
    private static final List<Target> SDL_DROP = Arrays.asList(
            new Target("dataString", "()Ljava/lang/String;", false, 1, "sdlDropData", Kind.OBJECT,
                    "java/lang/String"));

    private static final List<Target> GLFW_DROP = Arrays.asList(
            new Target("getName", "(JI)Ljava/lang/String;", false, 0, "glfwDropName", Kind.TYPED, null));

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

    /** java-discord-rpc's native library, answered by DiscordRpcShim */
    private static final List<Target> JNA_NATIVE = Arrays.asList(
            new Target("loadLibrary", "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;", false, 2, "jnaLoad",
                    Kind.OBJECT, "java/lang/Object"),
            new Target("load", "(Ljava/lang/String;Ljava/lang/Class;)Lcom/sun/jna/Library;", false, 2, "jnaLoad",
                    Kind.OBJECT, "com/sun/jna/Library"));

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

    private static final String PP = "org/polyfrost/polyplus/client/launcher/";
    private static final String PP_STORED = "L" + PP + "LauncherAccountStore$StoredAccount;";

    /** Poly+'s account switcher, relayed to the launcher (see PolyPlus) */
    private static final List<Target> PP_STORE = Arrays.asList(
            new Target("load", "()L" + PP + "LauncherAccountStore$CredentialsStore;", false, 1, "ppLoad",
                    Kind.OBJECT, PP + "LauncherAccountStore$CredentialsStore"),
            new Target("save", "(L" + PP + "LauncherAccountStore$CredentialsStore;)V", false, 2, "ppSave",
                    Kind.VOID_BOOL, null));

    private static final List<Target> PP_SWITCH = Arrays.asList(
            new Target("apply", "(" + PP_STORED + ")Z", false, 2, "ppSwitch", Kind.INT, null));

    private static final List<Target> PP_ACCOUNTS = Arrays.asList(
            new Target("remove", "(Ljava/util/UUID;)Z", false, 2, "ppRemove", Kind.INT, null),
            new Target("addOffline", "(Ljava/lang/String;)L" + PP + "OneLauncherAccounts$Account;", false, 2,
                    "ppAddOffline", Kind.OBJECT, PP + "OneLauncherAccounts$Account"),
            new Target("beginLogin", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, 2,
                    "ppBeginLogin", Kind.OBJECT, "java/lang/Object"),
            new Target("refresh", "(Ljava/util/UUID;ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;", false, 0,
                    "ppRefresh", Kind.TYPED, null));

    private static final List<Target> PP_REFRESH = Arrays.asList(
            new Target("refreshAfterSwitch$org_polyfrost_polyplus", "(" + PP_STORED + ")V", false, 2,
                    "ppNoRefresh", Kind.VOID_BOOL, null),
            new Target("refreshAfterRejection", "()Z", false, 0, "ppRefreshAfterRejection", Kind.INT, null),
            new Target("startRefreshIfExpired", "()V", false, 1, "ppSkip", Kind.VOID_BOOL, null));

    /** Poly+'s pack screen moves packs to the trash with programs the sandbox can't run */
    private static final String PP_PACK_FILES = "org/polyfrost/polyplus/client/gui/screens/packs/PackFiles";
    private static final List<Target> PP_PACKS = Arrays.asList(
            new Target("toTrash", "(Ljava/nio/file/Path;)Z", false, 2, "ppTrash", Kind.INT, null));

    /**
     * Resourcify's manual downloads wait for a file in ~/Downloads, which in
     * the sandbox is the game's own empty home (see Hooks#rfWatch). The tick
     * is the first point the screen knows what it waits for; 1.8.9 calls it
     * updateScreen, by its SRG name at runtime
     */
    private static final String RF_SCREEN = "dev/dediamondpro/resourcify/gui/DownloadWatcherScreen";
    private static final List<Target> RF_WATCHER = Arrays.asList(
            new Target("tick", "()V", false, 1, "rfWatch", Kind.VOID_BOOL, null),
            new Target("updateScreen", "()V", false, 1, "rfWatch", Kind.VOID_BOOL, null),
            new Target("func_73876_c", "()V", false, 1, "rfWatch", Kind.VOID_BOOL, null),
            new Target("onClose", "()V", false, 1, "rfStop", Kind.VOID_BOOL, null),
            new Target("onGuiClosed", "()V", false, 1, "rfStop", Kind.VOID_BOOL, null),
            new Target("func_146281_b", "()V", false, 1, "rfStop", Kind.VOID_BOOL, null));
    private static final List<Target> RF_COMPANION = Arrays.asList(
            new Target("isUsable", "()Z", false, 1, "rfUsable", Kind.INT, null));

    /** Poly+'s shaded Ktor CIO engine, which does its own TLS (see Ktor) */
    private static final String PP_CIO = "org/polyfrost/polyplus/libs/ktor/client/engine/cio/CIOEngine";
    private static final List<Target> KTOR_CIO = Arrays.asList(
            new Target("execute", "Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", true, 3, "ktorExecute",
                    Kind.OBJECT, "java/lang/Object"));

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
            if (name.startsWith(PP) && Bridge.INSTANCE.configured()) {
                // with the broker, whether sandboxed or not: real tokens stay out
                if (name.equals(PP + "LauncherAccountStore")) targets = PP_STORE;
                else if (name.equals(PP + "AccountSwitch")) targets = PP_SWITCH;
                else if (name.equals(PP + "OneLauncherAccounts")) targets = PP_ACCOUNTS;
                else if (name.equals(PP + "SessionRefresh")) targets = PP_REFRESH;
                else return null;
                return remember(loader, name, Patcher.patch(bytes, targets));
            }
            if (name.equals(PP_CIO) && Bridge.INSTANCE.configured()) {
                return remember(loader, name, Patcher.patch(bytes, KTOR_CIO));
            }
            if (!Hooks.sandboxed) return null;
            if (name.equals("java/io/RandomAccessFile")) {
                return Hooks.discordRelay == null ? null : Patcher.patch(bytes, RANDOM_ACCESS_FILE);
            }
            if (name.equals("java/io/File")) {
                return Hooks.discordRelay == null ? null : Patcher.patch(bytes, FILE);
            }
            if (name.equals("com/sun/jna/Native")) {
                return Hooks.discordRelay == null ? null : remember(loader, name, Patcher.patch(bytes, JNA_NATIVE));
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
            else if (name.equals("org/lwjgl/sdl/SDL_DropEvent")) targets = SDL_DROP;
            else if (name.equals("org/lwjgl/glfw/GLFWDropCallback")) targets = GLFW_DROP;
            else if (name.equals("java/awt/Dialog")) targets = AWT_DIALOG;
            else if (name.equals("org/lwjgl/glfw/GLFW")) targets = GLFW;
            else if (name.equals(PP_PACK_FILES)) targets = PP_PACKS;
            else if (name.equals(RF_SCREEN)) targets = RF_WATCHER;
            else if (name.equals(RF_SCREEN + "$Companion")) targets = RF_COMPANION;
            else return null;

            return remember(loader, name, Patcher.patch(bytes, targets));
        } catch (Throwable t) {
            Main.log("left " + name + " unpatched: " + t);
            return null;
        }
    }

    private static byte[] remember(ClassLoader loader, String name, byte[] patched) {
        if (patched != null && loader != null) {
            String dotted = name.replace('/', '.');
            loaders.put(dotted, loader);
            toFix.add(new Object[] {loader, dotted});
        }
        return patched;
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
