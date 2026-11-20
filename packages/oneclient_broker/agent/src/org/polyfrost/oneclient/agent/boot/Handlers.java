package org.polyfrost.oneclient.agent.boot;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/** Shared logic of the http and https protocol handlers. */
public final class Handlers {
    private static final String[] BROKERED = {
        "sessionserver.mojang.com",
        "api.minecraftservices.com",
        "api.mojang.com",
        "authserver.mojang.com",
        "pc.realms.minecraft.net",
        "java.frontendlegacy.realms.minecraft-services.net",
    };

    private static volatile URLStreamHandler http;
    private static volatile URLStreamHandler https;

    private Handlers() {}

    static boolean brokered(URL url) {
        String host = url.getHost();
        if (host == null) return false;
        host = host.toLowerCase(java.util.Locale.ROOT);
        for (String b : BROKERED) {
            if (host.equals(b)) return Bridge.INSTANCE.configured();
        }
        return false;
    }

    private static URLStreamHandler builtin(boolean secure) throws IOException {
        URLStreamHandler cached = secure ? https : http;
        if (cached != null) return cached;
        try {
            String name = secure ? "sun.net.www.protocol.https.Handler" : "sun.net.www.protocol.http.Handler";
            URLStreamHandler handler = (URLStreamHandler) Class.forName(name).getConstructor().newInstance();
            if (secure) https = handler;
            else http = handler;
            return handler;
        } catch (Exception e) {
            throw new IOException("no built-in handler for " + (secure ? "https" : "http"), e);
        }
    }

    public static URLConnection open(URL url, Proxy proxy, boolean secure) throws IOException {
        if (brokered(url)) return new BrokeredConnection(url);
        URL direct = new URL(null, url.toExternalForm(), builtin(secure));
        return proxy == null ? direct.openConnection() : direct.openConnection(proxy);
    }
}
