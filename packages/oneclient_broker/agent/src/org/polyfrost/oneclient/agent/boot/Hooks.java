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

    private Hooks() {}

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
