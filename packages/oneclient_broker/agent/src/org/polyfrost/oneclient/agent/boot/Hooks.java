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
        List<String> command = ((ProcessBuilder) builder).command();
        String revealed = revealTarget(command);
        if (revealed != null) {
            fileRequest(Bridge.REVEAL, revealed);
            return new FinishedProcess();
        }
        String target = openerTarget(command);
        if (target == null) return PASS;
        open(target);
        return new FinishedProcess();
    }

    /**
     * The file a "show in folder" helper was asked to select:
     * {@code explorer /select,<path>} or {@code open -R <path>}. Null for
     * anything else.
     */
    static String revealTarget(List<String> command) {
        if (command == null || command.size() < 2) return null;
        String program = new File(command.get(0)).getName().toLowerCase(Locale.ROOT);
        if (program.endsWith(".exe")) program = program.substring(0, program.length() - 4);
        if (program.equals("explorer")) {
            // one argument or several: explorer reads its command line whole
            StringBuilder joined = new StringBuilder();
            for (int i = 1; i < command.size(); i++) {
                if (i > 1) joined.append(' ');
                joined.append(command.get(i));
            }
            String args = joined.toString().trim();
            if (!args.toLowerCase(Locale.ROOT).startsWith("/select,")) return null;
            String path = args.substring("/select,".length()).trim();
            if (path.length() >= 2 && path.startsWith("\"") && path.endsWith("\"")) {
                path = path.substring(1, path.length() - 1);
            }
            return path.isEmpty() ? null : path;
        }
        if (program.equals("open") && command.size() > 2 && command.get(1).equals("-R")) {
            return command.get(command.size() - 1);
        }
        return null;
    }

    /** Asks the launcher to reveal or trash an instance file; whether it did */
    private static boolean fileRequest(final byte kind, final String path) {
        final String caller = Bridge.caller();
        try {
            Bridge.Reply reply = Bridge.INSTANCE.call(kind, new Bridge.Body() {
                public void write(DataOutputStream out) throws IOException {
                    Bridge.writeString(out, path);
                    Bridge.writeString(out, caller);
                }
            }, 30000);
            String error = reply.error();
            if (error == null) return true;
            Main.log("OneClient refused " + (kind == Bridge.TRASH ? "to trash " : "to show ") + path + ": " + error);
        } catch (IOException e) {
            Main.log("could not reach OneClient for " + path + ": " + e.getMessage());
        }
        return false;
    }

    // ---- Resourcify's manual downloads (DownloadWatcherScreen)

    private static final java.util.Map<Object, Boolean> watching =
            java.util.Collections.synchronizedMap(new java.util.WeakHashMap<Object, Boolean>());

    /** The game's own Downloads folder exists, so Resourcify offers the manual download */
    public static Object rfUsable(Object companion) {
        new File(System.getProperty("user.home"), "Downloads").mkdirs();
        return PASS;
    }

    /**
     * The first tick of a watcher screen: the launcher watches the user's
     * real Downloads folder for this exact file (extension, size and SHA-1)
     * and copies it into the game's, where Resourcify is looking.
     */
    public static boolean rfWatch(Object screen) {
        if (watching.put(screen, Boolean.TRUE) != null) return false;
        try {
            final String extension = (String) field(screen, "extension");
            final long size = ((Long) field(screen, "size")).longValue();
            final String sha1 = (String) field(screen, "sha1");
            watchDownloads(extension, size, sha1);
        } catch (Exception e) {
            Main.log("could not watch downloads for Resourcify: " + e);
        }
        return false;
    }

    public static boolean rfStop(Object screen) {
        if (watching.remove(screen) != null) {
            try {
                watchDownloads("", 0, "");
            } catch (IOException ignored) {
                // the launcher gives up by itself
            }
        }
        return false;
    }

    private static Object field(Object owner, String name) throws Exception {
        java.lang.reflect.Field f = owner.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(owner);
    }

    private static void watchDownloads(final String extension, final long size, final String sha1)
            throws IOException {
        final String caller = Bridge.caller();
        Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.WATCH_DOWNLOADS, new Bridge.Body() {
            public void write(DataOutputStream out) throws IOException {
                Bridge.writeString(out, extension);
                out.writeLong(size);
                Bridge.writeString(out, sha1);
                Bridge.writeString(out, caller);
            }
        }, 15000);
        String error = reply.error();
        if (error != null) Main.log("OneClient won't watch downloads: " + error);
    }

    // ---- Poly+'s pack screen (PackFiles#toTrash)

    /**
     * Poly+ trashes packs with PowerShell, osascript or gio, none of which the
     * sandbox lets it run; the launcher moves the file to the user's trash,
     * but only if it's inside the instance.
     */
    public static Object ppTrash(Object packFiles, Object path) {
        if (!(path instanceof java.nio.file.Path)) return PASS;
        String absolute = ((java.nio.file.Path) path).toAbsolutePath().toString();
        return Integer.valueOf(fileRequest(Bridge.TRASH, absolute) ? 1 : 0);
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
        return pick(mode, title, java.util.Collections.<String>emptyList());
    }

    /** {@code filters}: {@code name|ext;ext} each, see {@code PickFilter} */
    static String pick(final byte mode, final String title, final List<String> filters) {
        final String caller = Bridge.caller();
        try {
            Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.PICK, new Bridge.Body() {
                public void write(DataOutputStream out) throws IOException {
                    out.writeByte(mode);
                    Bridge.writeString(out, title);
                    out.writeShort(filters.size());
                    for (String filter : filters) Bridge.writeString(out, filter);
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

    // ---- org.lwjgl.sdl.SDLDialog (26.1+)

    private static final String SDL_DIALOG = "org.lwjgl.sdl.SDLDialog";

    public static Object sdlOpenFileDialog(long callback, long userdata, long window, long filters, int count,
            long location, boolean many) throws Exception {
        if (!sandboxed) return PASS;
        sdlDialog(OPEN_FILE, "", sdlFilters(filters, count), callback, userdata);
        return Boolean.TRUE;
    }

    public static Object sdlSaveFileDialog(long callback, long userdata, long window, long filters, int count,
            long location) throws Exception {
        if (!sandboxed) return PASS;
        sdlDialog(SAVE_FILE, "", sdlFilters(filters, count), callback, userdata);
        return Boolean.TRUE;
    }

    public static Object sdlOpenFolderDialog(long callback, long userdata, long window, long location, boolean many)
            throws Exception {
        if (!sandboxed) return PASS;
        sdlDialog(OPEN_FOLDER, "", java.util.Collections.<String>emptyList(), callback, userdata);
        return Boolean.TRUE;
    }

    /** SDL_FILEDIALOG_OPENFILE = 0, SAVEFILE = 1, OPENFOLDER = 2; everything else is in {@code props} */
    public static Object sdlFileDialogWithProperties(int type, long callback, long userdata, int props)
            throws Exception {
        if (!sandboxed) return PASS;
        byte mode = type == 1 ? SAVE_FILE : type == 2 ? OPEN_FOLDER : OPEN_FILE;
        Class<?> dialog = libraryClass(SDL_DIALOG, SDL_DIALOG);
        Class<?> properties = libraryClass(SDL_DIALOG, "org.lwjgl.sdl.SDLProperties");
        Integer id = Integer.valueOf(props);
        // read now: the caller may destroy the properties as soon as this returns
        Object title = properties.getMethod("SDL_GetStringProperty", int.class, CharSequence.class, CharSequence.class)
                .invoke(null, id, dialog.getField("SDL_PROP_FILE_DIALOG_TITLE_STRING").get(null), null);
        long filters = ((Long) properties.getMethod("SDL_GetPointerProperty", int.class, CharSequence.class, long.class)
                .invoke(null, id, dialog.getField("SDL_PROP_FILE_DIALOG_FILTERS_POINTER").get(null),
                        Long.valueOf(0L))).longValue();
        long count = ((Long) properties.getMethod("SDL_GetNumberProperty", int.class, CharSequence.class, long.class)
                .invoke(null, id, dialog.getField("SDL_PROP_FILE_DIALOG_NFILTERS_NUMBER").get(null),
                        Long.valueOf(0L))).longValue();
        List<String> wanted = mode == OPEN_FOLDER ? java.util.Collections.<String>emptyList()
                : sdlFilters(filters, (int) Math.min(count, 32L));
        sdlDialog(mode, title(title), wanted, callback, userdata);
        return Boolean.TRUE;
    }

    /** An array of {@code SDL_DialogFileFilter {const char *name, *pattern}} as {@code name|pattern} */
    private static List<String> sdlFilters(long filters, int count) throws Exception {
        List<String> out = new java.util.ArrayList<String>();
        if (filters == 0L || count <= 0) return out;
        Class<?> filter = libraryClass(SDL_DIALOG, "org.lwjgl.sdl.SDL_DialogFileFilter");
        int size = filter.getField("SIZEOF").getInt(null);
        Method name = filter.getMethod("nnameString", long.class);
        Method pattern = filter.getMethod("npatternString", long.class);
        for (int i = 0; i < Math.min(count, 32); i++) {
            Long at = Long.valueOf(filters + (long) i * size);
            Object n = name.invoke(null, at);
            Object p = pattern.invoke(null, at);
            if (p != null) out.add((n == null ? "" : n) + "|" + p);
        }
        return out;
    }

    /**
     * SDL dialogs return at once and report through the callback, from any
     * thread; so does this, once the launcher's picker closes. The list is
     * null-terminated UTF-8 paths, with no paths for cancel, as SDL does.
     */
    private static void sdlDialog(final byte mode, final String title, final List<String> filters,
            final long callback, final long userdata) {
        Thread t = new Thread(new Runnable() {
            public void run() {
                String path = pick(mode, title, filters);
                try {
                    answerSdlDialog(path, callback, userdata);
                } catch (Throwable e) {
                    Main.log("could not answer a file dialog: " + e);
                }
            }
        }, "OneClient file dialog");
        t.setDaemon(true);
        t.start();
    }

    private static void answerSdlDialog(String path, long callback, long userdata) throws Exception {
        Class<?> memory = libraryClass(SDL_DIALOG, "org.lwjgl.system.MemoryUtil");
        int pointer = libraryClass(SDL_DIALOG, "org.lwjgl.system.Pointer").getField("POINTER_SIZE").getInt(null);
        Method alloc = memory.getMethod("nmemAllocChecked", long.class);
        Method put = memory.getMethod("memPutAddress", long.class, long.class);
        Method free = memory.getMethod("nmemFree", long.class);
        long list = ((Long) alloc.invoke(null, Long.valueOf(2L * pointer))).longValue();
        long text = 0L;
        try {
            if (path != null) {
                byte[] utf8 = path.getBytes(Bridge.UTF8);
                text = ((Long) alloc.invoke(null, Long.valueOf(utf8.length + 1))).longValue();
                Method putByte = memory.getMethod("memPutByte", long.class, byte.class);
                for (int i = 0; i < utf8.length; i++) {
                    putByte.invoke(null, Long.valueOf(text + i), Byte.valueOf(utf8[i]));
                }
                putByte.invoke(null, Long.valueOf(text + utf8.length), Byte.valueOf((byte) 0));
            }
            put.invoke(null, Long.valueOf(list), Long.valueOf(text));
            put.invoke(null, Long.valueOf(list + pointer), Long.valueOf(0L));
            Class<?> cb = libraryClass(SDL_DIALOG, "org.lwjgl.sdl.SDL_DialogFileCallback");
            Object function = cb.getMethod("create", long.class).invoke(null, Long.valueOf(callback));
            cb.getMethod("invoke", long.class, long.class, int.class)
                    .invoke(function, Long.valueOf(userdata), Long.valueOf(list), Integer.valueOf(-1));
        } finally {
            if (text != 0L) free.invoke(null, Long.valueOf(text));
            free.invoke(null, Long.valueOf(list));
        }
    }

    // ---- Poly+'s Ktor client (see Ktor)

    public static Object ktorExecute(Object engine, Object request, Object continuation) throws Throwable {
        return Ktor.execute(engine, request, continuation);
    }

    // ---- Poly+ accounts (see PolyPlus)

    public static Object ppLoad(Object store) throws Exception {
        return PolyPlus.load();
    }

    /** Nothing to save: the launcher owns the accounts */
    public static boolean ppSave(Object store, Object credentials) {
        return true;
    }

    public static Object ppSwitch(Object accountSwitch, Object stored) throws Exception {
        return PolyPlus.switchTo(stored) ? PASS : Integer.valueOf(0);
    }

    /** Accounts are removed in the launcher, not from the game */
    public static Object ppRemove(Object accounts, Object id) {
        return Integer.valueOf(0);
    }

    public static Object ppAddOffline(Object accounts, Object name) {
        throw new IllegalStateException("Add offline accounts in OneClient");
    }

    public static Object ppBeginLogin(Object accounts, Object continuation) {
        throw PolyPlus.addAccount();
    }

    public static Object ppRefresh(Object accounts, Object id, boolean force, Object continuation)
            throws Exception {
        return PolyPlus.refreshed(accounts, id);
    }

    public static boolean ppNoRefresh(Object refresh, Object stored) {
        return true;
    }

    /** A rejected session can't be fixed from the game: the broker's token is already fresh */
    public static Object ppRefreshAfterRejection() {
        return Integer.valueOf(0);
    }

    public static boolean ppSkip(Object refresh) {
        return true;
    }

    // ---- drag and drop

    private static final ThreadLocal<Boolean> inDrop = new ThreadLocal<Boolean>();

    /** 26.1+: SDL_DropEvent#dataString, a dropped file's path */
    public static Object sdlDropData(Object event) throws Throwable {
        if (!sandboxed || inDrop.get() != null) return PASS;
        inDrop.set(Boolean.TRUE);
        try {
            return dropped((String) event.getClass().getMethod("dataString").invoke(event));
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw e.getCause();
        } finally {
            inDrop.remove();
        }
    }

    /** 1.13 to 1.21: GLFWDropCallback#getName(names, index) */
    public static Object glfwDropName(long names, int index) throws Throwable {
        if (!sandboxed || inDrop.get() != null) return PASS;
        inDrop.set(Boolean.TRUE);
        try {
            Class<?> callback = libraryClass("org.lwjgl.glfw.GLFWDropCallback", "org.lwjgl.glfw.GLFWDropCallback");
            return dropped((String) callback.getMethod("getName", long.class, int.class)
                    .invoke(null, Long.valueOf(names), Integer.valueOf(index)));
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw e.getCause();
        } finally {
            inDrop.remove();
        }
    }

    /**
     * Windows hands the game the dropped file's real path (Downloads, say),
     * which the sandbox can't read, so dropping a pack or a world on the
     * game did nothing. The launcher asks the user and copies the file into
     * the instance; the game gets the copy. Paths it can already read, and
     * anything the launcher refuses, pass through unchanged.
     */
    private static String dropped(final String path) {
        if (path == null || path.isEmpty() || readable(path)) return path;
        final String caller = Bridge.caller();
        try {
            Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.IMPORT, new Bridge.Body() {
                public void write(DataOutputStream out) throws IOException {
                    Bridge.writeString(out, path);
                    Bridge.writeString(out, caller);
                }
            }, 2L * 60L * 1000L);
            if (reply.kind != Bridge.PICKED) return path;
            boolean some = reply.body.readUnsignedByte() != 0;
            String copy = Bridge.readString(reply.body);
            return some ? copy : path;
        } catch (IOException e) {
            Main.log("could not import a dropped file: " + e.getMessage());
            return path;
        }
    }

    /** Folders count as readable: only files are imported */
    private static boolean readable(String path) {
        File file = new File(path);
        if (file.isDirectory()) return true;
        try {
            new java.io.FileInputStream(file).close();
            return true;
        } catch (IOException denied) {
            return false;
        }
    }

    // ---- java.awt.FileDialog

    /** Shows nothing: the launcher's picker runs instead and its answer goes into the dialog. */
    public static boolean dialogShow(Object dialog) {
        if (!sandboxed || !(dialog instanceof java.awt.FileDialog)) return false;
        java.awt.FileDialog fd = (java.awt.FileDialog) dialog;
        String path = pick(fd.getMode() == java.awt.FileDialog.SAVE ? SAVE_FILE : OPEN_FILE, title(fd.getTitle()));
        File picked = path == null ? null : new File(path);
        fd.setDirectory(picked == null ? null : picked.getParent());
        fd.setFile(picked == null ? null : picked.getName());
        try {
            java.lang.reflect.Field files = java.awt.FileDialog.class.getDeclaredField("files");
            files.setAccessible(true);
            files.set(fd, picked == null ? null : new File[] {picked});
        } catch (Throwable notOpen) {
            // getFiles() stays empty; getFile() and getDirectory() still answer
        }
        return true;
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
