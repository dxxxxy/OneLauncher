package org.polyfrost.oneclient.agent.api;

import java.io.IOException;

import org.polyfrost.oneclient.agent.boot.SandboxApi;

/**
 * For mods that want to work with OneClient's sandbox and token broker
 * directly instead of through the agent's hooks. It's on the boot class
 * path of every game OneClient starts with its agent, and only there, so
 * call it by reflection after checking it exists:
 *
 * <pre>{@code
 * Class<?> api = Class.forName("org.polyfrost.oneclient.agent.api.OneClientSandbox");
 * boolean sandboxed = (Boolean) api.getMethod("isSandboxed").invoke(null);
 * }</pre>
 *
 * Every method is static, takes and returns only JDK types, and works on
 * Java 8. Methods that talk to the launcher block until it answers (a
 * picker until the user chooses), so call them off the render thread.
 */
public final class OneClientSandbox {
    private OneClientSandbox() {}

    /** Whether the game runs in OneClient's sandbox (it sees only its instance) */
    public static boolean isSandboxed() {
        return SandboxApi.sandboxed();
    }

    /**
     * Whether OneClient's token broker serves this game: it holds a fake
     * access token, and Mojang requests made through Java's HTTP clients,
     * OkHttp, Apache HttpClient or Ktor CIO get the real one on the way out
     */
    public static boolean isBrokered() {
        return SandboxApi.brokered();
    }

    /**
     * The user's OneClient accounts the game may switch to, as {id, name}
     * pairs; never a token
     */
    public static String[][] accounts() throws IOException {
        String[][] all = SandboxApi.accounts();
        String[][] accounts = new String[all.length - 1][];
        System.arraycopy(all, 1, accounts, 0, accounts.length);
        return accounts;
    }

    /** The id of the account the game plays as now */
    public static String activeAccount() throws IOException {
        return SandboxApi.accounts()[0][0];
    }

    /**
     * Plays as another of {@link #accounts()} from now on: the broker answers
     * with that account's token. The game keeps its fake token; refresh the
     * session (profile, skin) afterwards. Throws with the launcher's reason
     * when it refuses
     */
    public static void switchAccount(String id) throws IOException {
        String refused = SandboxApi.switchAccount(id);
        if (refused != null) throw new IOException(refused);
    }

    /** Brings up OneClient so the user can sign in another account there */
    public static void addAccount() throws IOException {
        SandboxApi.addAccount();
    }

    /**
     * The launcher's file picker, which can see the user's files. {@code kind}
     * is "open", "folder" or "save"; {@code filters} are {@code "Images|png;jpg"}
     * entries. Returns a path the game can use (a copy inside the instance for
     * a picked file), or null when the user cancelled
     */
    public static String pickFile(String kind, String title, String[] filters) {
        return SandboxApi.pick(kind, title, filters);
    }

    /** Selects a file inside the instance in the user's file manager */
    public static boolean reveal(String path) {
        return SandboxApi.reveal(path);
    }

    /** Moves a file or folder inside the instance to the user's trash */
    public static boolean trash(String path) {
        return SandboxApi.trash(path);
    }
}
