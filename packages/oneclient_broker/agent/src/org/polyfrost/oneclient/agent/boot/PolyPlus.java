package org.polyfrost.oneclient.agent.boot;

import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Poly+'s account switcher reads the launcher's account file and keeps real
 * tokens in the game: it signs in, refreshes and switches with them itself.
 * Under OneClient's broker the game must only ever hold the fake token, so
 * the switcher is fed the user's accounts by name from the launcher, each
 * with the game's fake token, and a switch asks the launcher to answer for
 * the other account from then on. Signing in happens in the launcher.
 */
final class PolyPlus {
    static final String PACKAGE = "org.polyfrost.polyplus.client.launcher.";
    private static final String STORE = PACKAGE + "LauncherAccountStore";
    /** Never expires, so Poly+ never tries to refresh; the broker always has a fresh token */
    private static final String NEVER = "2999-12-31T00:00:00Z";

    private PolyPlus() {}

    /** The fake token the game was started with, from its own command line */
    static String fakeToken() {
        String command = System.getProperty("sun.java.command", "");
        String[] words = command.split(" ");
        for (int i = 0; i + 1 < words.length; i++) {
            if (words[i].equals("--accessToken")) return words[i + 1];
        }
        return "";
    }

    /** LauncherAccountStore#load: the user's accounts from the launcher, no real tokens */
    static Object load() throws Exception {
        Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.ACCOUNTS, new Bridge.Body() {
            public void write(DataOutputStream out) throws IOException {
                Bridge.writeString(out, "polyplus");
            }
        }, 15000);
        String error = reply.error();
        if (error != null) throw new IOException(error);
        if (reply.kind != Bridge.ACCOUNTS_REPLY) throw new IOException("unexpected reply " + reply.kind);
        String active = Bridge.readString(reply.body);
        int count = reply.body.readUnsignedShort();

        Class<?> stored = Hooks.libraryClass(STORE, STORE + "$StoredAccount");
        Class<?> credentials = Hooks.libraryClass(STORE, STORE + "$CredentialsStore");
        Constructor<?> account = stored.getConstructor(String.class, String.class, String.class, String.class,
                String.class, String.class);
        String token = fakeToken();
        Map<String, Object> users = new LinkedHashMap<String, Object>();
        for (int i = 0; i < count; i++) {
            String id = Bridge.readString(reply.body);
            String name = Bridge.readString(reply.body);
            users.put(id, account.newInstance(id, name, token, "", NEVER, "microsoft"));
        }
        return credentials.getConstructor(Map.class, String.class).newInstance(users, active);
    }

    /** AccountSwitch#apply: the launcher remaps the session first; false if it refuses */
    static boolean switchTo(Object storedAccount) throws Exception {
        final String id = (String) storedAccount.getClass().getMethod("getId").invoke(storedAccount);
        Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.SWITCH_ACCOUNT, new Bridge.Body() {
            public void write(DataOutputStream out) throws IOException {
                Bridge.writeString(out, id);
                Bridge.writeString(out, "polyplus");
            }
        }, 30000);
        String error = reply.error();
        if (error != null) {
            Main.log("OneClient did not switch accounts: " + error);
            return false;
        }
        return true;
    }

    /** MicrosoftAuth sign-in from the game: the launcher's own flow instead */
    static IllegalStateException addAccount() {
        try {
            Bridge.INSTANCE.call(Bridge.ADD_ACCOUNT, new Bridge.Body() {
                public void write(DataOutputStream out) throws IOException {
                    Bridge.writeString(out, "polyplus");
                }
            }, 15000);
        } catch (IOException e) {
            Main.log("could not reach OneClient to add an account: " + e.getMessage());
        }
        return new IllegalStateException(
                "Sign in from the OneClient window. The new account shows up here afterwards.");
    }

    /** OneLauncherAccounts#refresh: nothing to refresh, so the account as it is */
    static Object refreshed(Object accounts, Object id) throws Exception {
        List<?> list = (List<?>) accounts.getClass().getMethod("list").invoke(accounts);
        for (Object account : list) {
            if (id.equals(account.getClass().getMethod("getId").invoke(account))) return account;
        }
        throw new IllegalStateException("That account isn't in OneClient any more");
    }
}
