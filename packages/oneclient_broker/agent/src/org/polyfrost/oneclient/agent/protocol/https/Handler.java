package org.polyfrost.oneclient.agent.protocol.https;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

import org.polyfrost.oneclient.agent.boot.Handlers;

/** Found through {@code java.protocol.handler.pkgs}; see {@link Handlers}. */
public final class Handler extends URLStreamHandler {
    @Override
    protected URLConnection openConnection(URL url) throws IOException {
        return Handlers.open(url, null, true);
    }

    @Override
    protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
        return Handlers.open(url, proxy, true);
    }

    @Override
    protected int getDefaultPort() {
        return 443;
    }
}
