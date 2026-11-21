package org.polyfrost.oneclient.agent.boot;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * java-discord-rpc ({@code club.minnced.discord.rpc.DiscordRPC}, often
 * shaded) binds Discord's native discord-rpc library with JNA, and that
 * library opens Discord's own pipe, which the Windows sandbox can't reach.
 * Its {@code Native.loadLibrary("discord-rpc", ...)} gets this instead: the
 * same interface, speaking Discord IPC over the launcher's relay pipe, with
 * callbacks fired from {@code Discord_RunCallbacks} as the native library
 * does. Linux and macOS need none of this: the relay sits where the native
 * library looks for Discord.
 */
final class DiscordRpcShim implements InvocationHandler {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int HANDSHAKE = 0, FRAME = 1, CLOSE = 2, PING = 3, PONG = 4;

    private final String pipe;
    private final ConcurrentLinkedQueue<Runnable> callbacks = new ConcurrentLinkedQueue<Runnable>();
    private volatile Object handlers;
    private volatile String applicationId;
    private volatile boolean running;
    private volatile RandomAccessFile file;
    private volatile boolean ready;
    /** The last SET_ACTIVITY, sent again once connected */
    private volatile String presence;
    private int nonce;

    private DiscordRpcShim(String pipe) {
        this.pipe = pipe;
    }

    static Object create(Class<?> type, String pipe) {
        return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, new DiscordRpcShim(pipe));
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String name = method.getName();
        if (method.getDeclaringClass() == Object.class) {
            if (name.equals("hashCode")) return Integer.valueOf(System.identityHashCode(proxy));
            if (name.equals("equals")) return Boolean.valueOf(proxy == args[0]);
            return "OneClient Discord RPC";
        }
        if (name.equals("Discord_Initialize")) initialize((String) args[0], args[1]);
        else if (name.equals("Discord_Shutdown")) shutdown();
        else if (name.equals("Discord_RunCallbacks")) runCallbacks();
        else if (name.equals("Discord_UpdatePresence")) updatePresence(args[0]);
        else if (name.equals("Discord_ClearPresence")) send(activity(null));
        else if (name.equals("Discord_Respond")) respond((String) args[0], ((Integer) args[1]).intValue());
        else if (name.equals("Discord_UpdateHandlers")) handlers = args[0];
        // Discord_UpdateConnection, Discord_Register*: nothing to do
        return null;
    }

    private synchronized void initialize(String id, Object handlers) {
        this.handlers = handlers;
        if (running) return;
        applicationId = id;
        running = true;
        Thread thread = new Thread(new Runnable() {
            public void run() {
                connectLoop();
            }
        }, "OneClient Discord RPC");
        thread.setDaemon(true);
        thread.start();
    }

    private synchronized void shutdown() {
        running = false;
        presence = null;
        closeQuietly();
        callbacks.clear();
    }

    private void runCallbacks() {
        for (Runnable callback; (callback = callbacks.poll()) != null; ) {
            try {
                callback.run();
            } catch (Throwable t) {
                Main.log("a Discord callback failed: " + t);
            }
        }
    }

    // ---- the connection

    private void connectLoop() {
        while (running) {
            try {
                RandomAccessFile opened = new RandomAccessFile(pipe, "rw");
                file = opened;
                write(opened, HANDSHAKE, "{\"v\":1,\"client_id\":" + Json.quote(applicationId) + "}");
                readLoop(opened);
            } catch (IOException e) {
                // Discord isn't running, or went away; the game sees a disconnect
            } catch (InterruptedException e) {
                return;
            }
            boolean wasReady = ready;
            ready = false;
            closeQuietly();
            if (wasReady) fire("disconnected", Integer.valueOf(0), "Discord disconnected");
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    /**
     * Reads only what's already there: a blocked read on a synchronous
     * Windows pipe would block every write on it too
     */
    private void readLoop(RandomAccessFile in) throws IOException, InterruptedException {
        byte[] header = new byte[8];
        while (running && in == file) {
            if (in.length() < 8) {
                Thread.sleep(50);
                continue;
            }
            in.readFully(header);
            int op = littleEndian(header, 0);
            int length = littleEndian(header, 4);
            if (length < 0 || length > 64 * 1024) throw new IOException("Discord frame too large");
            byte[] body = new byte[length];
            for (int waited = 0; in.length() < length; waited += 10) {
                if (waited > 5000) throw new IOException("Discord frame never arrived");
                Thread.sleep(10);
            }
            in.readFully(body);
            String text = new String(body, UTF8);
            if (op == PING) {
                write(in, PONG, text);
            } else if (op == CLOSE) {
                Object frame = Json.parse(text);
                fire("disconnected", Integer.valueOf(Json.number(Json.get(frame, "code"))),
                        Json.string(Json.get(frame, "message")));
                throw new IOException("Discord closed the connection");
            } else if (op == FRAME) {
                dispatch(Json.parse(text));
            }
        }
    }

    private void dispatch(Object frame) throws IOException {
        String event = Json.string(Json.get(frame, "evt"));
        Object data = Json.get(frame, "data");
        if ("READY".equals(event)) {
            ready = true;
            fire("ready", user(Json.get(data, "user")));
            for (String subscribe : new String[] {"ACTIVITY_JOIN", "ACTIVITY_SPECTATE", "ACTIVITY_JOIN_REQUEST"}) {
                send("{\"cmd\":\"SUBSCRIBE\",\"evt\":\"" + subscribe + "\",\"nonce\":\"" + nextNonce() + "\"}");
            }
            String last = presence;
            if (last != null) send(last);
        } else if ("ACTIVITY_JOIN".equals(event)) {
            fire("joinGame", Json.string(Json.get(data, "secret")));
        } else if ("ACTIVITY_SPECTATE".equals(event)) {
            fire("spectateGame", Json.string(Json.get(data, "secret")));
        } else if ("ACTIVITY_JOIN_REQUEST".equals(event)) {
            fire("joinRequest", user(Json.get(data, "user")));
        } else if ("ERROR".equals(event) && !ready) {
            fire("errored", Integer.valueOf(Json.number(Json.get(data, "code"))),
                    Json.string(Json.get(data, "message")));
        }
    }

    private void send(String frame) {
        if (frame.contains("SET_ACTIVITY")) presence = frame;
        RandomAccessFile out = file;
        if (out == null || !ready) return;
        try {
            write(out, FRAME, frame);
        } catch (IOException e) {
            closeQuietly();
        }
    }

    private static void write(RandomAccessFile out, int op, String body) throws IOException {
        byte[] bytes = body.getBytes(UTF8);
        byte[] frame = new byte[8 + bytes.length];
        putLittleEndian(frame, 0, op);
        putLittleEndian(frame, 4, bytes.length);
        System.arraycopy(bytes, 0, frame, 8, bytes.length);
        synchronized (out) {
            out.write(frame);
        }
    }

    private synchronized void closeQuietly() {
        RandomAccessFile open = file;
        file = null;
        if (open != null) {
            try {
                open.close();
            } catch (IOException ignored) {
                // already gone
            }
        }
    }

    // ---- commands

    private synchronized String nextNonce() {
        return Integer.toString(++nonce);
    }

    private void updatePresence(Object rich) throws Exception {
        if (rich == null) {
            send(activity(null));
            return;
        }
        Map<String, Object> activity = new LinkedHashMap<String, Object>();
        put(activity, "state", field(rich, "state"));
        put(activity, "details", field(rich, "details"));
        Map<String, Object> timestamps = new LinkedHashMap<String, Object>();
        putNumber(timestamps, "start", field(rich, "startTimestamp"));
        putNumber(timestamps, "end", field(rich, "endTimestamp"));
        put(activity, "timestamps", timestamps);
        Map<String, Object> assets = new LinkedHashMap<String, Object>();
        put(assets, "large_image", field(rich, "largeImageKey"));
        put(assets, "large_text", field(rich, "largeImageText"));
        put(assets, "small_image", field(rich, "smallImageKey"));
        put(assets, "small_text", field(rich, "smallImageText"));
        put(activity, "assets", assets);
        Map<String, Object> party = new LinkedHashMap<String, Object>();
        put(party, "id", field(rich, "partyId"));
        Object size = field(rich, "partySize");
        Object max = field(rich, "partyMax");
        if (size instanceof Number && max instanceof Number && ((Number) size).intValue() > 0) {
            List<Object> both = new ArrayList<Object>();
            both.add(size);
            both.add(max);
            party.put("size", both);
        }
        put(activity, "party", party);
        Map<String, Object> secrets = new LinkedHashMap<String, Object>();
        put(secrets, "match", field(rich, "matchSecret"));
        put(secrets, "join", field(rich, "joinSecret"));
        put(secrets, "spectate", field(rich, "spectateSecret"));
        put(activity, "secrets", secrets);
        Object instance = field(rich, "instance");
        if (instance instanceof Number) activity.put("instance", Boolean.valueOf(((Number) instance).intValue() != 0));
        send(activity(activity));
    }

    private String activity(Map<String, Object> activity) {
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("pid", Long.valueOf(pid()));
        if (activity != null) args.put("activity", activity);
        Map<String, Object> frame = new LinkedHashMap<String, Object>();
        frame.put("cmd", "SET_ACTIVITY");
        frame.put("args", args);
        frame.put("nonce", nextNonce());
        return Json.write(frame);
    }

    private void respond(String userId, int reply) {
        Map<String, Object> args = new LinkedHashMap<String, Object>();
        args.put("user_id", userId);
        Map<String, Object> frame = new LinkedHashMap<String, Object>();
        // DISCORD_REPLY_YES is 1; no and ignore both close the request
        frame.put("cmd", reply == 1 ? "SEND_ACTIVITY_JOIN_INVITE" : "CLOSE_ACTIVITY_REQUEST");
        frame.put("args", args);
        frame.put("nonce", nextNonce());
        send(Json.write(frame));
    }

    private static long pid() {
        String name = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
        int at = name.indexOf('@');
        try {
            return Long.parseLong(at > 0 ? name.substring(0, at) : name);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void put(Map<String, Object> map, String key, Object value) {
        if (value instanceof String && !((String) value).isEmpty()) map.put(key, value);
        if (value instanceof Map && !((Map<?, ?>) value).isEmpty()) map.put(key, value);
    }

    private static void putNumber(Map<String, Object> map, String key, Object value) {
        if (value instanceof Number && ((Number) value).longValue() != 0) map.put(key, value);
    }

    private static Object field(Object owner, String name) {
        try {
            Field f = owner.getClass().getField(name);
            return f.get(owner);
        } catch (Exception e) {
            return null;
        }
    }

    // ---- callbacks, through the game's own DiscordEventHandlers

    /** Queues {@code handlers.<name>.accept(args)} for the next RunCallbacks */
    private void fire(final String name, final Object... args) {
        final Object current = handlers;
        if (current == null) return;
        final Object callback = field(current, name);
        if (callback == null) return;
        callbacks.add(new Runnable() {
            public void run() {
                for (Method method : callback.getClass().getMethods()) {
                    if (!method.getName().equals("accept") || method.getParameterTypes().length != args.length) {
                        continue;
                    }
                    try {
                        method.setAccessible(true);
                        method.invoke(callback, args);
                    } catch (Exception e) {
                        Main.log("a Discord callback failed: " + e);
                    }
                    return;
                }
            }
        });
    }

    /** A DiscordUser of the game's own copy of the library */
    private Object user(Object json) {
        Object current = handlers;
        Object ready = current == null ? null : field(current, "ready");
        if (ready == null) ready = current == null ? null : field(current, "joinRequest");
        if (ready == null) return null;
        for (Method method : ready.getClass().getMethods()) {
            if (!method.getName().equals("accept") || method.getParameterTypes().length != 1) continue;
            try {
                Object user = method.getParameterTypes()[0].getConstructor().newInstance();
                set(user, "userId", Json.string(Json.get(json, "id")));
                set(user, "username", Json.string(Json.get(json, "username")));
                set(user, "discriminator", Json.string(Json.get(json, "discriminator")));
                set(user, "avatar", Json.string(Json.get(json, "avatar")));
                return user;
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    private static void set(Object owner, String name, Object value) {
        try {
            owner.getClass().getField(name).set(owner, value);
        } catch (Exception ignored) {
            // an older copy without the field
        }
    }

    private static int littleEndian(byte[] b, int at) {
        return (b[at] & 0xff) | (b[at + 1] & 0xff) << 8 | (b[at + 2] & 0xff) << 16 | (b[at + 3] & 0xff) << 24;
    }

    private static void putLittleEndian(byte[] b, int at, int value) {
        b[at] = (byte) value;
        b[at + 1] = (byte) (value >>> 8);
        b[at + 2] = (byte) (value >>> 16);
        b[at + 3] = (byte) (value >>> 24);
    }

    /** Just enough JSON for Discord's frames */
    static final class Json {
        private final String text;
        private int at;

        private Json(String text) {
            this.text = text;
        }

        static Object parse(String text) {
            try {
                return new Json(text).value();
            } catch (RuntimeException e) {
                return null;
            }
        }

        static Object get(Object object, String key) {
            return object instanceof Map ? ((Map<?, ?>) object).get(key) : null;
        }

        static String string(Object value) {
            return value instanceof String ? (String) value : null;
        }

        static int number(Object value) {
            return value instanceof Number ? ((Number) value).intValue() : 0;
        }

        private void skip() {
            while (at < text.length() && Character.isWhitespace(text.charAt(at))) at++;
        }

        private Object value() {
            skip();
            char c = text.charAt(at);
            if (c == '{') {
                at++;
                Map<String, Object> map = new LinkedHashMap<String, Object>();
                skip();
                if (text.charAt(at) == '}') {
                    at++;
                    return map;
                }
                while (true) {
                    skip();
                    String key = (String) value();
                    skip();
                    at++; // :
                    map.put(key, value());
                    skip();
                    if (text.charAt(at++) == '}') return map;
                }
            }
            if (c == '[') {
                at++;
                List<Object> list = new ArrayList<Object>();
                skip();
                if (text.charAt(at) == ']') {
                    at++;
                    return list;
                }
                while (true) {
                    list.add(value());
                    skip();
                    if (text.charAt(at++) == ']') return list;
                }
            }
            if (c == '"') {
                at++;
                StringBuilder out = new StringBuilder();
                while (true) {
                    char d = text.charAt(at++);
                    if (d == '"') return out.toString();
                    if (d != '\\') {
                        out.append(d);
                        continue;
                    }
                    char e = text.charAt(at++);
                    if (e == 'n') out.append('\n');
                    else if (e == 't') out.append('\t');
                    else if (e == 'r') out.append('\r');
                    else if (e == 'b') out.append('\b');
                    else if (e == 'f') out.append('\f');
                    else if (e == 'u') {
                        out.append((char) Integer.parseInt(text.substring(at, at + 4), 16));
                        at += 4;
                    } else out.append(e);
                }
            }
            if (text.startsWith("true", at)) {
                at += 4;
                return Boolean.TRUE;
            }
            if (text.startsWith("false", at)) {
                at += 5;
                return Boolean.FALSE;
            }
            if (text.startsWith("null", at)) {
                at += 4;
                return null;
            }
            int start = at;
            while (at < text.length() && "+-0123456789.eE".indexOf(text.charAt(at)) >= 0) at++;
            String number = text.substring(start, at);
            if (number.isEmpty()) throw new IllegalArgumentException("not JSON");
            return number.indexOf('.') >= 0 || number.indexOf('e') >= 0 || number.indexOf('E') >= 0
                    ? (Object) Double.valueOf(number)
                    : (Object) Long.valueOf(number);
        }

        static String write(Object value) {
            StringBuilder out = new StringBuilder();
            write(out, value);
            return out.toString();
        }

        private static void write(StringBuilder out, Object value) {
            if (value instanceof Map) {
                out.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                    if (!first) out.append(',');
                    first = false;
                    out.append(quote(String.valueOf(entry.getKey()))).append(':');
                    write(out, entry.getValue());
                }
                out.append('}');
            } else if (value instanceof List) {
                out.append('[');
                boolean first = true;
                for (Object item : (List<?>) value) {
                    if (!first) out.append(',');
                    first = false;
                    write(out, item);
                }
                out.append(']');
            } else if (value instanceof String) {
                out.append(quote((String) value));
            } else {
                out.append(String.valueOf(value));
            }
        }

        static String quote(String value) {
            if (value == null) return "null";
            StringBuilder out = new StringBuilder(value.length() + 2).append('"');
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c == '"' || c == '\\') out.append('\\').append(c);
                else if (c < 0x20) out.append(String.format("\\u%04x", Integer.valueOf(c)));
                else out.append(c);
            }
            return out.append('"').toString();
        }
    }
}
