package org.polyfrost.oneclient.agent.boot;

import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * What {@code org.polyfrost.oneclient.agent.api.OneClientSandbox} offers mods,
 * on top of the launcher bridge. Public only so that class can reach it.
 */
public final class SandboxApi {
    private SandboxApi() {}

    public static boolean sandboxed() {
        return Hooks.sandboxed;
    }

    public static boolean brokered() {
        return Bridge.INSTANCE.configured();
    }

    /** The active account's id, then {id, name} for each account the game may switch to */
    public static String[][] accounts() throws IOException {
        final String caller = Bridge.caller();
        Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.ACCOUNTS, new Bridge.Body() {
            public void write(DataOutputStream out) throws IOException {
                Bridge.writeString(out, caller);
            }
        }, 15000);
        String error = reply.error();
        if (error != null) throw new IOException(error);
        if (reply.kind != Bridge.ACCOUNTS_REPLY) throw new IOException("unexpected reply " + reply.kind);
        String active = Bridge.readString(reply.body);
        int count = reply.body.readUnsignedShort();
        String[][] out = new String[count + 1][];
        out[0] = new String[] {active};
        for (int i = 0; i < count; i++) {
            out[i + 1] = new String[] {Bridge.readString(reply.body), Bridge.readString(reply.body)};
        }
        return out;
    }

    /** Null when the launcher switched, otherwise why it didn't */
    public static String switchAccount(final String id) throws IOException {
        final String caller = Bridge.caller();
        Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.SWITCH_ACCOUNT, new Bridge.Body() {
            public void write(DataOutputStream out) throws IOException {
                Bridge.writeString(out, id);
                Bridge.writeString(out, caller);
            }
        }, 30000);
        return reply.error();
    }

    public static void addAccount() throws IOException {
        final String caller = Bridge.caller();
        Bridge.INSTANCE.call(Bridge.ADD_ACCOUNT, new Bridge.Body() {
            public void write(DataOutputStream out) throws IOException {
                Bridge.writeString(out, caller);
            }
        }, 15000);
    }

    /** {@code kind}: open, folder or save; null when the user cancelled */
    public static String pick(String kind, String title, String[] filters) {
        byte mode = "folder".equals(kind) ? Hooks.OPEN_FOLDER
                : "save".equals(kind) ? Hooks.SAVE_FILE : Hooks.OPEN_FILE;
        List<String> list = filters == null ? new ArrayList<String>() : Arrays.asList(filters);
        return Hooks.pick(mode, title == null ? "" : title, list);
    }

    public static boolean reveal(String path) {
        return Hooks.fileRequest(Bridge.REVEAL, path);
    }

    public static boolean trash(String path) {
        return Hooks.fileRequest(Bridge.TRASH, path);
    }
}
