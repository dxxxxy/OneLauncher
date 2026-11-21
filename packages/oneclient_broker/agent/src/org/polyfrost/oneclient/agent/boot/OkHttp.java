package org.polyfrost.oneclient.agent.boot;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * OkHttp 3 and 4 do their own TLS over plain sockets, so account requests
 * made with them never reach the protocol handlers and would carry the fake
 * token to Mojang. {@code ConnectInterceptor.intercept} is answered here for
 * brokered hosts: it runs after the mod's own interceptors (so the request
 * has every header they add) and before any connection is opened. The reply
 * comes back as OkHttp's own Response.
 */
final class OkHttp {
    private OkHttp() {}

    private static Object call(Object target, String name) throws Exception {
        Method m = target.getClass().getMethod(name);
        m.setAccessible(true);
        return m.invoke(target);
    }

    static Object intercept(Object interceptor, Object chain) throws Throwable {
        try {
            Object request = call(chain, "request");
            Object url = call(request, "url");
            if (!Exchange.brokered((String) call(url, "host"))) return Hooks.PASS;
            ClassLoader loader = interceptor.getClass().getClassLoader();

            List<String[]> headers = new ArrayList<String[]>();
            Object requestHeaders = call(request, "headers");
            Method name = requestHeaders.getClass().getMethod("name", int.class);
            Method value = requestHeaders.getClass().getMethod("value", int.class);
            name.setAccessible(true);
            value.setAccessible(true);
            int count = ((Integer) call(requestHeaders, "size")).intValue();
            for (int i = 0; i < count; i++) {
                Integer index = Integer.valueOf(i);
                headers.add(new String[] {(String) name.invoke(requestHeaders, index),
                        (String) value.invoke(requestHeaders, index)});
            }
            byte[] body = new byte[0];
            Object requestBody = call(request, "body");
            if (requestBody != null) {
                Object type = call(requestBody, "contentType");
                if (type != null && !has(headers, "content-type")) {
                    headers.add(new String[] {"Content-Type", type.toString()});
                }
                Object buffer = Class.forName("okio.Buffer", true, loader).getConstructor().newInstance();
                Class<?> sink = Class.forName("okio.BufferedSink", false, loader);
                Method writeTo = requestBody.getClass().getMethod("writeTo", sink);
                writeTo.setAccessible(true);
                writeTo.invoke(requestBody, buffer);
                body = (byte[]) call(buffer, "readByteArray");
            }

            Exchange.Response response = Exchange.send((String) call(request, "method"), url.toString(), headers,
                    body, Exchange.caller(), 90000);
            return response(loader, request, response);
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

    private static Object response(ClassLoader loader, Object request, Exchange.Response response) throws Exception {
        List<String> pairs = new ArrayList<String>();
        String contentType = null;
        for (String[] header : response.headers) {
            // the body is already whole and decoded
            if (header[0].equalsIgnoreCase("content-length") || header[0].equalsIgnoreCase("transfer-encoding")
                    || header[0].equalsIgnoreCase("content-encoding")) {
                continue;
            }
            if (header[0].equalsIgnoreCase("content-type")) contentType = header[1];
            pairs.add(header[0]);
            pairs.add(header[1]);
        }
        pairs.add("Content-Length");
        pairs.add(String.valueOf(response.body.length));

        Class<?> headersClass = Class.forName("okhttp3.Headers", true, loader);
        Object headers = headersClass.getMethod("of", String[].class)
                .invoke(null, (Object) pairs.toArray(new String[0]));
        Class<?> mediaType = Class.forName("okhttp3.MediaType", true, loader);
        Object type = contentType == null ? null : mediaType.getMethod("parse", String.class).invoke(null, contentType);
        Class<?> bodyClass = Class.forName("okhttp3.ResponseBody", true, loader);
        Object body = bodyClass.getMethod("create", mediaType, byte[].class).invoke(null, type, response.body);
        Class<?> protocol = Class.forName("okhttp3.Protocol", true, loader);

        Class<?> builderClass = Class.forName("okhttp3.Response$Builder", true, loader);
        Object builder = builderClass.getConstructor().newInstance();
        long now = System.currentTimeMillis();
        builderClass.getMethod("request", Class.forName("okhttp3.Request", false, loader)).invoke(builder, request);
        builderClass.getMethod("protocol", protocol).invoke(builder, protocol.getField("HTTP_1_1").get(null));
        builderClass.getMethod("code", int.class).invoke(builder, Integer.valueOf(response.status));
        builderClass.getMethod("message", String.class).invoke(builder, reason(response.status));
        builderClass.getMethod("headers", headersClass).invoke(builder, headers);
        builderClass.getMethod("body", bodyClass).invoke(builder, body);
        builderClass.getMethod("sentRequestAtMillis", long.class).invoke(builder, Long.valueOf(now));
        builderClass.getMethod("receivedResponseAtMillis", long.class).invoke(builder, Long.valueOf(now));
        return builderClass.getMethod("build").invoke(builder);
    }

    static String reason(int status) {
        switch (status) {
            case 200: return "OK";
            case 204: return "No Content";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 429: return "Too Many Requests";
            default: return status < 400 ? "OK" : "Error";
        }
    }
}
