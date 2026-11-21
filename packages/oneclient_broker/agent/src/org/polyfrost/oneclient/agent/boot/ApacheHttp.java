package org.polyfrost.oneclient.agent.boot;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Apache HttpClient 4 opens its own TLS sockets, so account requests made
 * with it would carry the fake token to Mojang. The exec chain's last step
 * ({@code MainClientExec} or {@code MinimalClientExec}) is answered here for
 * brokered hosts: it runs after the request interceptors have added their
 * headers and before a connection is leased. The reply comes back as the
 * client's own CloseableHttpResponse.
 */
final class ApacheHttp {
    private ApacheHttp() {}

    private static Object call(Object target, String name) throws Exception {
        Method m = target.getClass().getMethod(name);
        m.setAccessible(true);
        return m.invoke(target);
    }

    static Object execute(Object exec, Object route, Object request) throws Throwable {
        try {
            Object target = call(route, "getTargetHost");
            if (!Exchange.brokered((String) call(target, "getHostName"))) return Hooks.PASS;
            ClassLoader loader = exec.getClass().getClassLoader();

            Object line = call(request, "getRequestLine");
            String method = (String) call(line, "getMethod");
            URI uri = URI.create((String) call(line, "getUri"));
            if (!uri.isAbsolute()) uri = URI.create(call(target, "toURI") + uri.toString());

            List<String[]> headers = new ArrayList<String[]>();
            for (Object header : (Object[]) call(request, "getAllHeaders")) {
                headers.add(new String[] {(String) call(header, "getName"), (String) call(header, "getValue")});
            }
            byte[] body = new byte[0];
            Class<?> enclosing = Class.forName("org.apache.http.HttpEntityEnclosingRequest", false, loader);
            if (enclosing.isInstance(request)) {
                Object entity = call(request, "getEntity");
                if (entity != null) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    Method writeTo = entity.getClass().getMethod("writeTo", java.io.OutputStream.class);
                    writeTo.setAccessible(true);
                    writeTo.invoke(entity, out);
                    body = out.toByteArray();
                    Object type = call(entity, "getContentType");
                    if (type != null && !has(headers, "content-type")) {
                        headers.add(new String[] {"Content-Type", (String) call(type, "getValue")});
                    }
                }
            }

            Exchange.Response response = Exchange.send(method, uri.toString(), headers, body, Exchange.caller(),
                    90000);
            return response(loader, response);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private static boolean has(List<String[]> headers, String name) {
        for (String[] header : headers) {
            if (header[0].equalsIgnoreCase(name)) return true;
        }
        return false;
    }

    private static Object response(ClassLoader loader, Exchange.Response response) throws Exception {
        Class<?> version = Class.forName("org.apache.http.HttpVersion", true, loader);
        Class<?> protocol = Class.forName("org.apache.http.ProtocolVersion", false, loader);
        Class<?> statusLine = Class.forName("org.apache.http.message.BasicStatusLine", true, loader);
        Object status = statusLine.getConstructor(protocol, int.class, String.class)
                .newInstance(version.getField("HTTP_1_1").get(null), Integer.valueOf(response.status),
                        OkHttp.reason(response.status));
        Class<?> basic = Class.forName("org.apache.http.message.BasicHttpResponse", true, loader);
        Object plain = basic.getConstructor(Class.forName("org.apache.http.StatusLine", false, loader))
                .newInstance(status);
        Method addHeader = basic.getMethod("addHeader", String.class, String.class);
        String contentType = null;
        for (String[] header : response.headers) {
            // the body is already whole and decoded
            if (header[0].equalsIgnoreCase("content-length") || header[0].equalsIgnoreCase("transfer-encoding")
                    || header[0].equalsIgnoreCase("content-encoding")) {
                continue;
            }
            if (header[0].equalsIgnoreCase("content-type")) contentType = header[1];
            addHeader.invoke(plain, header[0], header[1]);
        }
        addHeader.invoke(plain, "Content-Length", String.valueOf(response.body.length));
        Class<?> entityClass = Class.forName("org.apache.http.entity.ByteArrayEntity", true, loader);
        Object entity = entityClass.getConstructor(byte[].class).newInstance((Object) response.body);
        if (contentType != null) entityClass.getMethod("setContentType", String.class).invoke(entity, contentType);
        basic.getMethod("setEntity", Class.forName("org.apache.http.HttpEntity", false, loader))
                .invoke(plain, entity);

        // the exec chain hands back a CloseableHttpResponse; with no
        // connection behind it, closing it has nothing to release
        Class<?> proxy = Class.forName("org.apache.http.impl.execchain.HttpResponseProxy", true, loader);
        Constructor<?> wrap = proxy.getDeclaredConstructor(Class.forName("org.apache.http.HttpResponse", false, loader),
                Class.forName("org.apache.http.impl.execchain.ConnectionHolder", false, loader));
        wrap.setAccessible(true);
        return wrap.newInstance(plain, null);
    }
}
