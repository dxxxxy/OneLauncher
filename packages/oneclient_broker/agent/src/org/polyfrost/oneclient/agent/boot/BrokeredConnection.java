package org.polyfrost.oneclient.agent.boot;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

/**
 * An HTTP request to an account host, answered by the launcher instead of the
 * network. Behaves like the JDK's own connection for everything authlib,
 * Realms and mods rely on.
 */
final class BrokeredConnection extends HttpsURLConnection {
    private final Map<String, List<String>> requestHeaders = new LinkedHashMap<String, List<String>>();
    private ByteArrayOutputStream requestBody;

    private boolean answered;
    private int status = -1;
    private final List<String[]> responseHeaders = new ArrayList<String[]>();
    private byte[] responseBody = new byte[0];

    BrokeredConnection(URL url) {
        super(url);
    }

    @Override
    public void connect() {
        connected = true;
    }

    @Override
    public void disconnect() {
        // nothing held open
    }

    @Override
    public boolean usingProxy() {
        return false;
    }

    @Override
    public void setRequestProperty(String key, String value) {
        if (key == null) return;
        List<String> values = new ArrayList<String>();
        values.add(value);
        requestHeaders.put(key, values);
    }

    @Override
    public void addRequestProperty(String key, String value) {
        if (key == null) return;
        List<String> values = requestHeaders.get(key);
        if (values == null) {
            values = new ArrayList<String>();
            requestHeaders.put(key, values);
        }
        values.add(value);
    }

    @Override
    public String getRequestProperty(String key) {
        for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(key) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    @Override
    public Map<String, List<String>> getRequestProperties() {
        return Collections.unmodifiableMap(requestHeaders);
    }

    @Override
    public OutputStream getOutputStream() {
        if (requestBody == null) requestBody = new ByteArrayOutputStream();
        if ("GET".equals(method)) method = "POST";
        return requestBody;
    }

    private synchronized void answer() throws IOException {
        if (answered) return;
        answered = true;
        connected = true;
        byte[] body = requestBody == null ? new byte[0] : requestBody.toByteArray();
        List<String[]> headers = new ArrayList<String[]>();
        for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {
            for (String value : entry.getValue()) headers.add(new String[] {entry.getKey(), value});
        }
        Exchange.Response response =
                Exchange.send(method, url.toExternalForm(), headers, body, Bridge.caller(), getReadTimeout());
        status = response.status;
        responseHeaders.addAll(response.headers);
        responseBody = response.body;
    }

    @Override
    public int getResponseCode() throws IOException {
        answer();
        return status;
    }

    @Override
    public String getResponseMessage() throws IOException {
        answer();
        return status >= 200 && status < 300 ? "OK" : "HTTP " + status;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        answer();
        if (status == 404 || status == 410) throw new FileNotFoundException(url.toString());
        if (status >= 400) throw new IOException("Server returned HTTP response code: " + status + " for URL: " + url);
        return new ByteArrayInputStream(responseBody);
    }

    @Override
    public InputStream getErrorStream() {
        return answered && status >= 400 ? new ByteArrayInputStream(responseBody) : null;
    }

    private void answerQuietly() {
        try {
            answer();
        } catch (IOException ignored) {
            // header getters can't throw; callers see nulls like with a dead socket
        }
    }

    @Override
    public String getHeaderField(String name) {
        answerQuietly();
        if (name == null) return "HTTP/1.1 " + status;
        String found = null;
        for (String[] header : responseHeaders) {
            if (header[0].equalsIgnoreCase(name)) found = header[1];
        }
        return found;
    }

    @Override
    public String getHeaderFieldKey(int n) {
        answerQuietly();
        return n == 0 ? null : n <= responseHeaders.size() ? responseHeaders.get(n - 1)[0] : null;
    }

    @Override
    public String getHeaderField(int n) {
        answerQuietly();
        if (n == 0) return "HTTP/1.1 " + status;
        return n <= responseHeaders.size() ? responseHeaders.get(n - 1)[1] : null;
    }

    @Override
    public Map<String, List<String>> getHeaderFields() {
        answerQuietly();
        Map<String, List<String>> fields = new LinkedHashMap<String, List<String>>();
        fields.put(null, Collections.singletonList("HTTP/1.1 " + status));
        for (String[] header : responseHeaders) {
            List<String> values = fields.get(header[0]);
            if (values == null) {
                values = new ArrayList<String>();
                fields.put(header[0], values);
            }
            values.add(header[1]);
        }
        return fields;
    }

    @Override
    public String getCipherSuite() {
        return "TLS_ONECLIENT_BROKER";
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return null;
    }

    @Override
    public Certificate[] getServerCertificates() {
        return new Certificate[0];
    }
}
