package org.polyfrost.oneclient.agent.boot;

import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * One HTTP request to an account host, answered by the launcher. Shared by
 * every HTTP client the agent handles ({@link BrokeredConnection} for
 * {@code HttpURLConnection}, and {@code java.net.http} on Java 11+).
 */
public final class Exchange {
    private Exchange() {}

    public static final class Response {
        public final int status;
        /** {name, value} pairs in the order the server sent them */
        public final List<String[]> headers;
        public final byte[] body;

        Response(int status, List<String[]> headers, byte[] body) {
            this.status = status;
            this.headers = headers;
            this.body = body;
        }
    }

    /** Whether requests to {@code host} go to the launcher instead of the network. */
    public static boolean brokered(String host) {
        return Handlers.brokeredHost(host);
    }

    /** The mod on the calling thread's stack, for the activity log; see {@link Bridge#caller()}. */
    public static String caller() {
        return Bridge.caller();
    }

    public static Response send(final String method, final String url, final List<String[]> headers,
            final byte[] body, final String caller, int timeoutMillis) throws IOException {
        Bridge.Reply reply = Bridge.INSTANCE.call(Bridge.HTTP, new Bridge.Body() {
            public void write(DataOutputStream out) throws IOException {
                Bridge.writeString(out, method);
                Bridge.writeString(out, url);
                out.writeShort(headers.size());
                for (String[] header : headers) {
                    Bridge.writeString(out, header[0]);
                    Bridge.writeString(out, header[1]);
                }
                Bridge.writeBytes(out, body == null ? new byte[0] : body);
                Bridge.writeString(out, caller);
            }
        }, Math.max(timeoutMillis, 30000));

        if (reply.kind != Bridge.HTTP_REPLY) {
            String error = reply.error();
            throw new IOException(error != null ? error : "OneClient could not complete the request");
        }
        int status = reply.body.readUnsignedShort();
        List<String[]> responseHeaders = new ArrayList<String[]>(Bridge.readHeaders(reply.body));
        byte[] responseBody = Bridge.readBytes(reply.body);
        return new Response(status, responseHeaders, responseBody);
    }
}
