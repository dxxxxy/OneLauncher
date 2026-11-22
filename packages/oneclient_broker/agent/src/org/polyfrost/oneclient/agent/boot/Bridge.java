package org.polyfrost.oneclient.agent.boot;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Client for the launcher's broker. Wire format matches
 * {@code oneclient_broker::protocol}: big-endian, length-prefixed frames, one
 * pipe per direction.
 */
final class Bridge {
    static final Bridge INSTANCE = new Bridge();
    static final Charset UTF8 = Charset.forName("UTF-8");

    static final byte HELLO = 1, HTTP = 2, OPEN = 3, PICK = 4, IMPORT = 5, ACCOUNTS = 6, SWITCH_ACCOUNT = 7,
            ADD_ACCOUNT = 8, TRASH = 9, REVEAL = 10, WATCH_DOWNLOADS = 11;
    static final int OK = 0x81, HTTP_REPLY = 0x82, ERROR = 0x83, PICKED = 0x84, ACCOUNTS_REPLY = 0x85;

    private final String up;
    private final String down;
    private final String key;

    private DataOutputStream out;
    private final Map<Integer, Slot> pending = new ConcurrentHashMap<Integer, Slot>();
    private final AtomicInteger ids = new AtomicInteger(1);

    private Bridge() {
        String endpoint = System.getProperty("oneclient.broker", "");
        int bar = endpoint.indexOf('|');
        this.up = bar < 0 ? null : endpoint.substring(0, bar);
        this.down = bar < 0 ? null : endpoint.substring(bar + 1);
        this.key = System.getenv("ONECLIENT_BROKER_KEY");
    }

    boolean configured() {
        return up != null && key != null;
    }

    void connectInBackground() {
        if (!configured()) return;
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    ensureConnected();
                } catch (IOException e) {
                    Main.log("broker not reachable yet: " + e.getMessage());
                }
            }
        }, "OneClient broker connect");
        t.setDaemon(true);
        t.start();
    }

    static final class Reply {
        final int kind;
        final DataInputStream body;

        Reply(int kind, DataInputStream body) {
            this.kind = kind;
            this.body = body;
        }

        String error() throws IOException {
            return kind == ERROR ? readString(body) : null;
        }
    }

    private static final class Slot {
        final CountDownLatch done = new CountDownLatch(1);
        volatile Reply reply;
        volatile IOException failure;
    }

    interface Body {
        void write(DataOutputStream out) throws IOException;
    }

    /** Sends one request and waits for its reply. */
    Reply call(byte kind, Body body, long timeoutMillis) throws IOException {
        if (!configured()) throw new IOException("OneClient broker is not configured for this game");
        int id = ids.getAndIncrement();
        byte[] frame = frame(id, kind, body);
        Slot slot = new Slot();
        pending.put(id, slot);
        try {
            for (int attempt = 0; ; attempt++) {
                DataOutputStream stream = ensureConnected();
                try {
                    synchronized (this) {
                        stream.write(frame);
                        stream.flush();
                    }
                    break;
                } catch (IOException e) {
                    dropConnection(e);
                    if (attempt >= 2) throw e;
                }
            }
            if (!slot.done.await(timeoutMillis, TimeUnit.MILLISECONDS)) {
                throw new IOException("OneClient did not answer in time");
            }
            if (slot.failure != null) throw slot.failure;
            return slot.reply;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted waiting for OneClient");
        } finally {
            pending.remove(id);
        }
    }

    private static byte[] frame(int id, byte kind, Body body) throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(payload);
        data.writeInt(id);
        data.writeByte(kind);
        if (body != null) body.write(data);
        data.flush();
        ByteArrayOutputStream framed = new ByteArrayOutputStream(payload.size() + 4);
        DataOutputStream f = new DataOutputStream(framed);
        f.writeInt(payload.size());
        payload.writeTo(f);
        f.flush();
        return framed.toByteArray();
    }

    private synchronized DataOutputStream ensureConnected() throws IOException {
        if (out != null) return out;

        IOException last = null;
        // about 2s in all: long enough for the launcher to recreate its pipes,
        // short enough that a closed launcher fails a join quickly
        for (int attempt = 0; attempt < 10; attempt++) {
            DataOutputStream o = null;
            try {
                // up first: on Unix a FIFO's write end only opens once the
                // launcher holds the read end, which it always does
                o = new DataOutputStream(new BufferedOutputStream(openUp()));
                o.write(frame(0, HELLO, new Body() {
                    public void write(DataOutputStream d) throws IOException {
                        writeString(d, key);
                        writeString(d, Main.VERSION);
                    }
                }));
                o.flush();
                final DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(down)));
                int length = in.readInt();
                byte[] payload = new byte[length];
                in.readFully(payload);
                DataInputStream r = new DataInputStream(new java.io.ByteArrayInputStream(payload));
                r.readInt();
                if (r.readUnsignedByte() != OK) throw new IOException("OneClient refused the agent");
                out = o;
                startReader(in);
                return o;
            } catch (IOException e) {
                last = e;
                // a half-open attempt would hold the launcher's only pipe instance
                if (o != null) {
                    try {
                        o.close();
                    } catch (IOException ignored) {
                        // already broken
                    }
                }
                try {
                    Thread.sleep(100L + attempt * 20L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        throw last != null ? last : new IOException("could not reach OneClient");
    }

    /**
     * JetBrains Runtime's FileOutputStream reads a file's DOS attributes
     * before opening it. On a named pipe that read is itself a connection, so
     * it takes the pipe's only instance and the real open then fails with
     * "All pipe instances are busy". RandomAccessFile opens directly; the
     * launcher makes the up pipe duplex so read-write access is allowed.
     */
    private OutputStream openUp() throws IOException {
        if (!up.startsWith("\\\\.\\pipe\\")) return new FileOutputStream(up);
        final RandomAccessFile pipe = new RandomAccessFile(up, "rw");
        return new OutputStream() {
            public void write(int b) throws IOException {
                pipe.write(b);
            }

            public void write(byte[] b, int off, int len) throws IOException {
                pipe.write(b, off, len);
            }

            public void close() throws IOException {
                pipe.close();
            }
        };
    }

    private void startReader(final DataInputStream in) {
        Thread reader = new Thread(new Runnable() {
            public void run() {
                try {
                    while (true) {
                        int length = in.readInt();
                        if (length < 5 || length > 8 * 1024 * 1024) throw new IOException("bad frame");
                        byte[] payload = new byte[length];
                        in.readFully(payload);
                        DataInputStream r = new DataInputStream(new java.io.ByteArrayInputStream(payload));
                        int id = r.readInt();
                        int kind = r.readUnsignedByte();
                        Slot slot = pending.get(id);
                        if (slot != null) {
                            slot.reply = new Reply(kind, r);
                            slot.done.countDown();
                        }
                    }
                } catch (IOException e) {
                    dropConnection(e);
                }
            }
        }, "OneClient broker reader");
        reader.setDaemon(true);
        reader.start();
    }

    private synchronized void dropConnection(IOException cause) {
        if (out != null) {
            try {
                out.close();
            } catch (IOException ignored) {
                // already gone
            }
        }
        out = null;
        for (Slot slot : pending.values()) {
            slot.failure = new IOException("lost connection to OneClient", cause);
            slot.done.countDown();
        }
    }

    static void writeString(DataOutputStream out, String value) throws IOException {
        byte[] bytes = (value == null ? "" : value).getBytes(UTF8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    static void writeBytes(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }

    static String readString(DataInputStream in) throws IOException {
        return new String(readBytes(in), UTF8);
    }

    static byte[] readBytes(DataInputStream in) throws IOException {
        int length = in.readInt();
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return bytes;
    }

    static List<String[]> readHeaders(DataInputStream in) throws IOException {
        int count = in.readUnsignedShort();
        List<String[]> headers = new ArrayList<String[]>(count);
        for (int i = 0; i < count; i++) {
            headers.add(new String[] {readString(in), readString(in)});
        }
        return headers;
    }

    /** Best-effort: the first class on the stack that isn't the JDK, the game or a loader. */
    static String caller() {
        for (StackTraceElement frame : new Throwable().getStackTrace()) {
            String c = frame.getClassName();
            if (c.startsWith("java.") || c.startsWith("javax.") || c.startsWith("sun.") || c.startsWith("jdk.")
                    || c.startsWith("com.sun.") || c.startsWith("org.polyfrost.oneclient.agent")
                    || c.startsWith("com.mojang.") || c.startsWith("net.minecraft.")
                    || c.startsWith("net.minecraftforge.") || c.startsWith("net.neoforged.")
                    || c.startsWith("net.fabricmc.") || c.startsWith("org.quiltmc.")
                    || c.startsWith("cpw.mods.") || c.startsWith("org.spongepowered.")
                    || c.startsWith("com.google.") || c.startsWith("org.apache.")
                    || c.startsWith("org.lwjgl.") || c.startsWith("io.netty.")) {
                continue;
            }
            return c;
        }
        return "minecraft";
    }
}
