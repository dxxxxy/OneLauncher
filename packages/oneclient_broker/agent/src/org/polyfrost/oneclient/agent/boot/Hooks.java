package org.polyfrost.oneclient.agent.boot;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Locale;

/**
 * Called from the first instructions of patched JDK and LWJGL methods (see
 * {@link Transformer}). Inside the sandbox the game can't start a browser,
 * a file manager or a file picker that sees the user's files, so these hand
 * the request to the launcher. Outside it, every hook passes.
 */
public final class Hooks {
    /** Returned by object hooks to mean "run the original method". */
    public static final Object PASS = new Object();

    static volatile boolean sandboxed;
    /** Windows: the launcher's Discord relay pipe, from {@code -Doneclient.discord} */
    static volatile String discordRelay;

    private Hooks() {}

    /**
     * A class of the library that {@code patched} (a class the agent patched,
     * dotted name) belongs to, loaded by the same loader.
     */
    static Class<?> libraryClass(String patched, String name) throws ClassNotFoundException {
        ClassLoader loader = Transformer.loaderOf(patched);
        return Class.forName(name, true, loader != null ? loader : ClassLoader.getSystemClassLoader());
    }

    // ---- java.io.File(String) and RandomAccessFile: Discord IPC

    /**
     * Java Discord IPC libraries open {@code \\?\pipe\discord-ipc-N} as a file,
     * usually after checking {@code new File(path).exists()}. The sandbox
     * can't reach Discord's own pipe, so the name becomes the launcher's
     * relay, which passes on rich presence and nothing else. Runs on every
     * File and RandomAccessFile, so it stays cheap and never throws.
     */
    public static Object discordPipe(Object file) {
        String relay = discordRelay;
        if (relay == null || !(file instanceof File) || !isDiscordPipe(((File) file).getPath())) return file;
        return new File(relay);
    }

    /** The same for constructors that take the name as a string. */
    public static Object discordPipeName(Object name) {
        String relay = discordRelay;
        if (relay == null || !(name instanceof String) || !isDiscordPipe((String) name)) return name;
        return relay;
    }

    /**
     * {@code \\?\pipe\discord-ipc-N} or {@code \\.\pipe\discord-ipc-N}, with
     * either slash and any number of them (CraftPresence doubles every one).
     */
    static boolean isDiscordPipe(String path) {
        int length = path.length();
        if (length < 20 || length > 64) return false;
        char last = path.charAt(length - 1);
        if (last < '0' || last > '9') return false; // nearly every path ends in a letter
        StringBuilder clean = new StringBuilder(length);
        boolean separator = false;
        for (int i = 0; i < length; i++) {
            char c = path.charAt(i);
            if (c == '/' || c == '\\') {
                if (!separator) clean.append('\\');
                separator = true;
            } else {
                clean.append(Character.toLowerCase(c));
                separator = false;
            }
        }
        String name = clean.toString();
        String rest;
        if (name.startsWith("\\?\\pipe\\discord-ipc-") || name.startsWith("\\.\\pipe\\discord-ipc-")) {
            rest = name.substring(20);
        } else {
            return false;
        }
        if (rest.isEmpty() || rest.length() > 2) return false;
        for (int i = 0; i < rest.length(); i++) {
            if (!Character.isDigit(rest.charAt(i))) return false;
        }
        return true;
    }

    // ---- sun.nio.fs.WindowsPath#toRealPath

    private static final ThreadLocal<Boolean> inRealPath = new ThreadLocal<Boolean>();

    /**
     * On Windows, toRealPath looks up every path component in its parent,
     * which needs permission to list that parent. A sandboxed game can't list
     * C:\Users or the user's folder, so the call fails for every file under
     * them, even ones the game may read. Java 24+ does this at startup for its
     * own java.security file and can't start at all. When the file is
     * reachable and only the lookup was refused, this answers with the
     * absolute path instead: the right file, minus case and link resolution.
     */
    public static Object realPath(Object path, Object options) throws java.io.IOException {
        if (!sandboxed || inRealPath.get() != null) return PASS;
        java.nio.file.Path p = (java.nio.file.Path) path;
        inRealPath.set(Boolean.TRUE);
        try {
            return p.toRealPath((java.nio.file.LinkOption[]) options);
        } catch (java.nio.file.AccessDeniedException denied) {
            java.nio.file.Path absolute = p.toAbsolutePath().normalize();
            if (java.nio.file.Files.exists(absolute)) return absolute;
            throw denied;
        } finally {
            inRealPath.remove();
        }
    }

    // ---- sun.nio.fs.WindowsFileSystemProvider#checkAccess

    private static final ThreadLocal<Boolean> inCheckAccess = new ThreadLocal<Boolean>();

    /**
     * Java asks Windows whether a file is writable with AccessCheck on a
     * security descriptor read without its integrity label, and Windows then
     * assumes the default label: medium, no writing up. The sandbox runs at
     * low integrity, so the answer is always no, even in the game's own folder.
     * Files.isWritable fails everywhere (and File.canWrite on JetBrains
     * Runtime), and JNA refuses to unpack itself. When that check refuses a
     * write, this tries one instead: the file opened for writing, or a
     * temporary file made and removed in a folder. The kernel's answer stands.
     */
    public static boolean checkAccess(Object provider, Object path, Object modes) throws java.io.IOException {
        if (!sandboxed || inCheckAccess.get() != null) return false;
        java.nio.file.AccessMode[] wanted = (java.nio.file.AccessMode[]) modes;
        java.util.List<java.nio.file.AccessMode> others = new java.util.ArrayList<java.nio.file.AccessMode>();
        boolean write = false;
        for (java.nio.file.AccessMode mode : wanted) {
            if (mode == java.nio.file.AccessMode.WRITE) write = true;
            else others.add(mode);
        }
        if (!write) return false;
        java.nio.file.spi.FileSystemProvider fs = (java.nio.file.spi.FileSystemProvider) provider;
        java.nio.file.Path p = (java.nio.file.Path) path;
        inCheckAccess.set(Boolean.TRUE);
        try {
            try {
                fs.checkAccess(p, wanted);
            } catch (java.nio.file.AccessDeniedException denied) {
                fs.checkAccess(p, others.toArray(new java.nio.file.AccessMode[0]));
                if (!canWrite(p)) throw denied;
            }
            return true;
        } finally {
            inCheckAccess.remove();
        }
    }

    private static boolean canWrite(java.nio.file.Path p) throws java.io.IOException {
        try {
            java.nio.file.attribute.DosFileAttributes attributes =
                    java.nio.file.Files.readAttributes(p, java.nio.file.attribute.DosFileAttributes.class);
            if (attributes.isDirectory()) {
                java.nio.file.Path probe = java.nio.file.Files.createTempFile(p, ".oneclient-", ".tmp");
                try {
                    java.nio.file.Files.delete(probe);
                } catch (java.io.IOException leftBehind) {
                    // could create but not delete: still writable
                }
            } else {
                if (attributes.isReadOnly()) return false;
                java.nio.channels.FileChannel.open(p, java.nio.file.StandardOpenOption.WRITE).close();
            }
            return true;
        } catch (java.nio.file.AccessDeniedException denied) {
            return false;
        } catch (java.nio.file.NoSuchFileException gone) {
            return false;
        } catch (java.nio.file.FileSystemException inUse) {
            // allowed, but another program holds the file open
            return true;
        }
    }

    // ---- java.io.WinNTFileSystem#getNameMax

    private static final Integer NAME_MAX = Integer.valueOf(255);

    /**
     * Java 25's File.createTempFile asks the volume for its longest file name,
     * and an AppContainer may not query volume information, so every temporary
     * file failed with "Access is denied" (JNA could not unpack itself). Every
     * Windows file system in use (NTFS, ReFS, exFAT, FAT32 long names) allows
     * 255, which is all createTempFile needs to trim its prefix.
     */
    public static Object nameMax(Object fileSystem, Object path) {
        return sandboxed ? NAME_MAX : PASS;
    }

    // ---- LWJGL 2 fullscreen (Windows)

    /**
     * Windows never lets an AppContainer change the display mode, so LWJGL 2's
     * exclusive fullscreen fails ("Failed to set display mode") and 1.8.9
     * crashes. Skipping the switch leaves LWJGL's fullscreen window, a
     * borderless one the size of the mode, which covers the screen for the
     * desktop mode Minecraft asks for. {@code mode_set} stays false, so
     * leaving fullscreen doesn't try to reset a mode that never changed.
     */
    public static boolean lwjglSwitchMode(Object display, Object mode) {
        if (!sandboxed) return false;
        try {
            java.lang.reflect.Field current = display.getClass().getDeclaredField("current_mode");
            current.setAccessible(true);
            current.set(display, mode);
            return true;
        } catch (Throwable t) {
            Main.log("left LWJGL's display mode switch alone: " + t);
            return false;
        }
    }

    // ---- LWJGL 3 fullscreen

    /**
     * The same limit for 26.1+, which goes through SDL: with no mode, SDL
     * makes the window fullscreen at the desktop mode, a borderless window
     * over the whole screen, instead of failing to switch.
     */
    public static Object sdlFullscreenMode(Object mode) {
        return sandboxed ? null : mode;
    }

    private static final int GLFW_REFRESH_RATE = 0x2100F;
    private static final ThreadLocal<Boolean> inGlfw = new ThreadLocal<Boolean>();

    /** The monitor's current mode as {width, height, refresh rate}, or null. */
    private static int[] currentMode(Class<?> glfw, long monitor) throws Exception {
        Object mode = glfw.getMethod("glfwGetVideoMode", long.class).invoke(null, Long.valueOf(monitor));
        if (mode == null) return null;
        Class<?> c = mode.getClass();
        return new int[] {
            ((Integer) c.getMethod("width").invoke(mode)).intValue(),
            ((Integer) c.getMethod("height").invoke(mode)).intValue(),
            ((Integer) c.getMethod("refreshRate").invoke(mode)).intValue(),
        };
    }

    /**
     * GLFW (1.13 to 1.21) switches the display mode when a fullscreen window
     * asks for another resolution, which the sandbox can't. At the monitor's
     * current mode GLFW skips the switch and just covers the monitor, so
     * fullscreen windows are made at that mode instead.
     */
    public static Object glfwCreateWindow(int width, int height, long title, long monitor, long share)
            throws Throwable {
        if (!sandboxed || monitor == 0L || inGlfw.get() != null) return PASS;
        Class<?> glfw = libraryClass("org.lwjgl.glfw.GLFW", "org.lwjgl.glfw.GLFW");
        int[] mode = currentMode(glfw, monitor);
        if (mode == null || (mode[0] == width && mode[1] == height)) return PASS;
        glfw.getMethod("glfwWindowHint", int.class, int.class)
                .invoke(null, Integer.valueOf(GLFW_REFRESH_RATE), Integer.valueOf(mode[2]));
        inGlfw.set(Boolean.TRUE);
        try {
            return glfw.getMethod("nglfwCreateWindow", int.class, int.class, long.class, long.class, long.class)
                    .invoke(null, Integer.valueOf(mode[0]), Integer.valueOf(mode[1]), Long.valueOf(title),
                            Long.valueOf(monitor), Long.valueOf(share));
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw e.getCause();
        } finally {
            inGlfw.remove();
        }
    }

    /** Switching an existing window to fullscreen, the same way. */
    public static Object glfwSetWindowMonitor(long window, long monitor, int x, int y, int width, int height,
            int refresh) throws Throwable {
        if (!sandboxed || monitor == 0L || inGlfw.get() != null) return PASS;
        Class<?> glfw = libraryClass("org.lwjgl.glfw.GLFW", "org.lwjgl.glfw.GLFW");
        int[] mode = currentMode(glfw, monitor);
        if (mode == null || (mode[0] == width && mode[1] == height && mode[2] == refresh)) return PASS;
        inGlfw.set(Boolean.TRUE);
        try {
            glfw.getMethod("glfwSetWindowMonitor", long.class, long.class, int.class, int.class, int.class,
                    int.class, int.class).invoke(null, Long.valueOf(window), Long.valueOf(monitor),
                    Integer.valueOf(x), Integer.valueOf(y), Integer.valueOf(mode[0]), Integer.valueOf(mode[1]),
                    Integer.valueOf(mode[2]));
            return Boolean.TRUE; // any non-PASS value: void
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw e.getCause();
        } finally {
            inGlfw.remove();
        }
    }

    // ---- java.net.http (Java 11+)

    private static volatile HttpRelay modern;
    private static volatile boolean modernLoaded;

    /** {@code client} is the JDK's own client; its loader can see {@code java.net.http}. */
    private static HttpRelay modern(Object client) {
        if (!modernLoaded) {
            synchronized (Hooks.class) {
                if (!modernLoaded) {
                    try {
                        ClassLoader loader = new ModuleLoader(client.getClass().getClassLoader(),
                                "org.polyfrost.oneclient.agent.http");
                        modern = (HttpRelay) Class.forName("org.polyfrost.oneclient.agent.http.ModernHttp", true, loader)
                                .getConstructor().newInstance();
                    } catch (Throwable t) {
                        Main.log("java.net.http requests can't reach OneClient: " + t);
                    }
                    modernLoaded = true;
                }
            }
        }
        return modern;
    }

    public static Object httpSend(Object client, Object request, Object handler) throws Exception {
        HttpRelay relay = modern(client);
        return relay == null ? PASS : relay.send(request, handler);
    }

    public static Object httpSendAsync(Object client, Object request, Object handler) {
        HttpRelay relay = modern(client);
        return relay == null ? PASS : relay.sendAsync(request, handler);
    }

    private static boolean open(final String target) {
        if (target == null || target.isEmpty()) return false;
        final String caller = Bridge.caller();
        try {
            Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.OPEN, new Bridge.Body() {
                public void write(DataOutputStream out) throws IOException {
                    Bridge.writeString(out, target);
                    Bridge.writeString(out, caller);
                }
            }, 15000);
            String error = reply.error();
            if (error != null) Main.log("OneClient did not open " + target + ": " + error);
        } catch (IOException e) {
            Main.log("could not ask OneClient to open " + target + ": " + e.getMessage());
        }
        // handled either way: inside the sandbox the original would fail anyway
        return true;
    }

    // ---- java.awt.Desktop

    public static boolean browse(Object desktop, Object uri) {
        return sandboxed && open(String.valueOf(uri));
    }

    public static boolean openFile(Object desktop, Object file) {
        return sandboxed && file instanceof File && open(((File) file).getAbsolutePath());
    }

    // ---- org.lwjgl.sdl.SDLMisc#SDL_OpenURL

    /**
     * 26.1+ opens links and folders (the resource pack folder, say) through
     * SDL, which asks the shell directly; that never works in the sandbox. The
     * launcher opens them instead, under the same rules as everything else.
     */
    public static Object sdlOpenUrl(Object url) {
        if (!sandboxed || url == null) return PASS;
        open(url.toString());
        return Integer.valueOf(1);
    }

    // ---- java.lang.ProcessBuilder#start

    public static Object start(Object builder) {
        if (!sandboxed || !(builder instanceof ProcessBuilder)) return PASS;
        String target = openerTarget(((ProcessBuilder) builder).command());
        if (target == null) return PASS;
        open(target);
        return new FinishedProcess();
    }

    /** The URL or path an "open this" helper was asked to open, or null for any other program. */
    static String openerTarget(List<String> command) {
        if (command == null || command.isEmpty()) return null;
        String program = new File(command.get(0)).getName().toLowerCase(Locale.ROOT);
        if (program.endsWith(".exe")) program = program.substring(0, program.length() - 4);
        String last = command.get(command.size() - 1);
        if (program.equals("rundll32")) {
            for (String arg : command) {
                String a = arg.toLowerCase(Locale.ROOT);
                if (a.contains("url.dll") || a.contains("shell32.dll")) return command.size() > 2 ? last : null;
            }
            return null;
        }
        if (program.equals("explorer") || program.equals("xdg-open") || program.equals("open")
                || program.equals("kde-open") || program.equals("gnome-open")) {
            return command.size() > 1 ? last : null;
        }
        if (program.equals("gio") && command.size() > 2 && command.get(1).equals("open")) return last;
        if (program.equals("cmd")) return startTarget(command);
        return null;
    }

    /**
     * The target of {@code cmd /c start ["title"] [/options] target}. Callers
     * often pass one string to {@code Runtime.exec}, which splits on spaces
     * and keeps the quotes (1.8.9's "Open resource pack folder" sends
     * {@code cmd.exe /C start "Open file" "<path>"}), so the words after
     * {@code start} are joined back and re-read the way cmd reads them.
     */
    static String startTarget(List<String> command) {
        int start = -1;
        for (int i = 1; i < command.size(); i++) {
            if (command.get(i).equalsIgnoreCase("start")) {
                start = i;
                break;
            }
        }
        if (start < 0) return null;
        StringBuilder rest = new StringBuilder();
        for (int i = start + 1; i < command.size(); i++) {
            if (rest.length() > 0) rest.append(' ');
            rest.append(command.get(i));
        }
        List<String> words = new java.util.ArrayList<String>();
        List<Boolean> quoted = new java.util.ArrayList<Boolean>();
        String line = rest.toString();
        int i = 0;
        while (i < line.length()) {
            char c = line.charAt(i);
            if (c == ' ') {
                i++;
            } else if (c == '"') {
                int end = line.indexOf('"', i + 1);
                if (end < 0) end = line.length();
                words.add(line.substring(i + 1, end));
                quoted.add(Boolean.TRUE);
                i = end + 1;
            } else {
                int end = line.indexOf(' ', i);
                if (end < 0) end = line.length();
                words.add(line.substring(i, end));
                quoted.add(Boolean.FALSE);
                i = end;
            }
        }
        int at = 0;
        // a first quoted word is the window title when something follows it
        if (words.size() > 1 && quoted.get(0).booleanValue()) at = 1;
        while (at < words.size() && !quoted.get(at).booleanValue() && words.get(at).startsWith("/")) at++;
        if (at >= words.size()) return null;
        String target = words.get(at);
        return target.isEmpty() ? null : target;
    }

    // ---- pickers

    private static final byte OPEN_FILE = 0, OPEN_FOLDER = 1, SAVE_FILE = 2;

    private static String pick(final byte mode, final String title) {
        final String caller = Bridge.caller();
        try {
            Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.PICK, new Bridge.Body() {
                public void write(DataOutputStream out) throws IOException {
                    out.writeByte(mode);
                    Bridge.writeString(out, title);
                    out.writeShort(0);
                    Bridge.writeString(out, caller);
                }
            }, 30L * 60L * 1000L);
            if (reply.kind != Bridge.PICKED) return null;
            boolean some = reply.body.readUnsignedByte() != 0;
            String path = Bridge.readString(reply.body);
            return some ? path : null;
        } catch (IOException e) {
            Main.log("file picker unavailable: " + e.getMessage());
            return null;
        }
    }

    private static String title(Object value) {
        return value instanceof CharSequence ? value.toString() : "";
    }

    public static Object tinyOpen(Object title) {
        return sandboxed ? pick(OPEN_FILE, title(title)) : PASS;
    }

    public static Object tinySave(Object title) {
        return sandboxed ? pick(SAVE_FILE, title(title)) : PASS;
    }

    public static Object tinyFolder(Object title) {
        return sandboxed ? pick(OPEN_FOLDER, title(title)) : PASS;
    }

    // javax.swing.JFileChooser: result codes APPROVE_OPTION = 0, CANCEL_OPTION = 1

    public static Object chooserOpen(Object chooser) {
        return chooser(chooser, false);
    }

    public static Object chooserSave(Object chooser) {
        return chooser(chooser, true);
    }

    public static Object chooserShow(Object chooser) {
        try {
            int type = (Integer) chooser.getClass().getMethod("getDialogType").invoke(chooser);
            return chooser(chooser, type == 1);
        } catch (Exception e) {
            return chooser(chooser, false);
        }
    }

    private static Object chooser(Object chooser, boolean save) {
        if (!sandboxed) return PASS;
        try {
            Class<?> c = chooser.getClass();
            String title = String.valueOf(c.getMethod("getDialogTitle").invoke(chooser));
            int selection = (Integer) c.getMethod("getFileSelectionMode").invoke(chooser);
            byte mode = save ? SAVE_FILE : selection == 1 ? OPEN_FOLDER : OPEN_FILE;
            String path = pick(mode, "null".equals(title) ? "" : title);
            if (path == null) return Integer.valueOf(1);
            Method set = c.getMethod("setSelectedFile", File.class);
            set.invoke(chooser, new File(path));
            return Integer.valueOf(0);
        } catch (Exception e) {
            Main.log("could not relay a file chooser: " + e);
            return Integer.valueOf(1);
        }
    }
}
