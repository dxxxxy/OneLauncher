package org.polyfrost.oneclient.agent.boot;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Ktor's CIO engine, as shaded into Poly+, speaks TLS itself over a plain
 * socket, so account requests made with it (Poly+'s wardrobe changing a
 * cape or a skin) never reach the protocol handlers. Its {@code execute} is
 * answered here instead for brokered hosts: the request goes to the launcher
 * and the reply is handed back as Ktor's own response data, which a suspend
 * function may return directly.
 */
final class Ktor {
    private Ktor() {}

    /** {@code engine}'s package prefix, e.g. {@code org.polyfrost.polyplus.libs.ktor.} */
    private static String prefix(Object engine) {
        String name = engine.getClass().getName();
        return name.substring(0, name.indexOf("client.engine.cio."));
    }

    /**
     * A public static method of a Kotlin file facade. Facades for multifile
     * classes inherit it from a package-private class, so reflection needs
     * to be told it may call it.
     */
    private static Method function(String owner, ClassLoader loader, String name, Class<?>... types)
            throws Exception {
        Method m = Class.forName(owner, true, loader).getMethod(name, types);
        m.setAccessible(true);
        return m;
    }

    private static Object call(Object target, String name) throws Exception {
        Method m = target.getClass().getMethod(name);
        m.setAccessible(true);
        return m.invoke(target);
    }

    static Object execute(Object engine, Object data, Object continuation) throws Throwable {
        // a suspended execute() resumes by being called again with its
        // arguments nulled: that is CIO's own request carrying on
        if (data == null) return Hooks.PASS;
        Object url = call(data, "getUrl");
        if (!Exchange.brokered((String) call(url, "getHost"))) return Hooks.PASS;
        String k = prefix(engine);
        ClassLoader loader = engine.getClass().getClassLoader();
        try {
            String method = (String) call(call(data, "getMethod"), "getValue");
            List<String[]> headers = new ArrayList<String[]>();
            addAll(headers, call(data, "getHeaders"));
            Object body = call(data, "getBody");
            Object type = call(body, "getContentType");
            if (type != null) headers.add(new String[] {"Content-Type", type.toString()});
            addAll(headers, call(body, "getHeaders"));
            byte[] bytes = bodyBytes(k, loader, body);

            Exchange.Response response = Exchange.send(method, url.toString(), headers, bytes, Exchange.caller(),
                    90000);
            return responseData(k, loader, response, data, continuation);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    /** Ktor's Headers (StringValues): entries() is a set of name to list of values */
    private static void addAll(List<String[]> out, Object values) throws Exception {
        for (Object entry : (Set<?>) call(values, "entries")) {
            Map.Entry<?, ?> e = (Map.Entry<?, ?>) entry;
            for (Object value : (List<?>) e.getValue()) out.add(new String[] {(String) e.getKey(), (String) value});
        }
    }

    private static byte[] bodyBytes(String k, ClassLoader loader, Object body) throws Exception {
        String content = k + "http.content.OutgoingContent$";
        if (Class.forName(content + "ByteArrayContent", false, loader).isInstance(body)) {
            return (byte[]) body.getClass().getMethod("bytes").invoke(body);
        }
        if (Class.forName(content + "NoContent", false, loader).isInstance(body)) return new byte[0];
        if (Class.forName(content + "ReadChannelContent", false, loader).isInstance(body)) {
            return drain(k, loader, call(body, "readFrom"));
        }
        if (Class.forName(content + "WriteChannelContent", false, loader).isInstance(body)) {
            return written(k, loader, body);
        }
        throw new IOException("can't send a " + body.getClass().getName() + " body through OneClient");
    }

    /** A ByteReadChannel read to the end, as a blocking stream */
    private static byte[] drain(String k, ClassLoader loader, Object channel) throws Exception {
        Class<?> readChannel = Class.forName(k + "utils.io.ByteReadChannel", false, loader);
        Class<?> job = Class.forName(k.replace("ktor.", "coroutines.Job"), false, loader);
        InputStream in = (InputStream) function(k + "utils.io.jvm.javaio.BlockingKt", loader, "toInputStream",
                readChannel, job).invoke(null, channel, null);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            for (int n; (n = in.read(buffer)) > 0; ) {
                out.write(buffer, 0, n);
                if (out.size() > 16 * 1024 * 1024) throw new IOException("request body too large");
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    /**
     * Multipart forms (skin uploads) write themselves into a channel with a
     * suspend function: run it on its own thread, closing the channel when
     * it finishes, and read the other end here.
     */
    private static byte[] written(String k, ClassLoader loader, final Object body) throws Exception {
        final Class<?> channelClass = Class.forName(k + "utils.io.ByteChannel", true, loader);
        final Object channel = channelClass.getConstructor(boolean.class).newInstance(Boolean.TRUE);
        final Class<?> writeChannel = Class.forName(k + "utils.io.ByteWriteChannel", false, loader);
        final Method writeTo = body.getClass().getMethod("writeTo", writeChannel,
                Class.forName("kotlin.coroutines.Continuation", false, loader));
        final Method close = channelClass.getMethod("close");
        final Object done = continuation(loader, new Runnable() {
            public void run() {
                try {
                    close.invoke(channel);
                } catch (Exception ignored) {
                    // the reader sees the end either way
                }
            }
        });
        final Object suspended = suspendedMarker(loader);
        Thread writer = new Thread(new Runnable() {
            public void run() {
                try {
                    Object result = writeTo.invoke(body, channel, done);
                    if (result != suspended) close.invoke(channel);
                } catch (Throwable t) {
                    try {
                        channelClass.getMethod("cancel", Throwable.class).invoke(channel, t);
                    } catch (Exception ignored) {
                        // nothing more to do
                    }
                }
            }
        }, "OneClient request body");
        writer.setDaemon(true);
        writer.start();
        return drain(k, loader, channel);
    }

    /** A Continuation that runs {@code onResume} once the suspend call completes */
    private static Object continuation(ClassLoader loader, final Runnable onResume) throws Exception {
        final Class<?> type = Class.forName("kotlin.coroutines.Continuation", false, loader);
        final Object context = Class.forName("kotlin.coroutines.EmptyCoroutineContext", true, loader)
                .getField("INSTANCE").get(null);
        return Proxy.newProxyInstance(loader, new Class<?>[] {type}, new InvocationHandler() {
            public Object invoke(Object proxy, Method method, Object[] args) {
                String name = method.getName();
                if (name.equals("getContext")) return context;
                if (name.equals("resumeWith")) {
                    onResume.run();
                    return null;
                }
                if (name.equals("hashCode")) return Integer.valueOf(System.identityHashCode(proxy));
                if (name.equals("equals")) return Boolean.valueOf(proxy == args[0]);
                if (name.equals("toString")) return "OneClient continuation";
                return null;
            }
        });
    }

    private static Object suspendedMarker(ClassLoader loader) throws Exception {
        return function("kotlin.coroutines.intrinsics.IntrinsicsKt", loader, "getCOROUTINE_SUSPENDED").invoke(null);
    }

    /** HttpResponseData(status, requestTime, headers, version, body, callContext) */
    private static Object responseData(String k, ClassLoader loader, Exchange.Response response, Object request,
            Object continuation) throws Exception {
        Class<?> statusClass = Class.forName(k + "http.HttpStatusCode", true, loader);
        Object companion = statusClass.getField("Companion").get(null);
        Object status = companion.getClass().getMethod("fromValue", int.class)
                .invoke(companion, Integer.valueOf(response.status));

        Object now = function(k + "util.date.DateJvmKt", loader, "GMTDate", Long.class).invoke(null, (Object) null);

        Class<?> builderClass = Class.forName(k + "http.HeadersBuilder", true, loader);
        Object builder = builderClass.getConstructor().newInstance();
        Method append = builderClass.getMethod("append", String.class, String.class);
        for (String[] header : response.headers) {
            // the body is already whole and decoded
            if (header[0].equalsIgnoreCase("content-length") || header[0].equalsIgnoreCase("transfer-encoding")
                    || header[0].equalsIgnoreCase("content-encoding")) {
                continue;
            }
            append.invoke(builder, header[0], header[1]);
        }
        append.invoke(builder, "Content-Length", String.valueOf(response.body.length));
        Object headers = builderClass.getMethod("build").invoke(builder);

        Class<?> versionClass = Class.forName(k + "http.HttpProtocolVersion", true, loader);
        Object versions = versionClass.getField("Companion").get(null);
        Object version = versions.getClass().getMethod("getHTTP_1_1").invoke(versions);

        Object body = function(k + "utils.io.ByteChannelCtorKt", loader, "ByteReadChannel", byte[].class, int.class,
                int.class).invoke(null, response.body, Integer.valueOf(0), Integer.valueOf(response.body.length));

        // as CIO does: the call gets its own job under the request's, which
        // Ktor completes once the response has been read
        Class<?> jobClass = Class.forName(k.replace("ktor.", "coroutines.Job"), false, loader);
        Object job = function(k.replace("ktor.", "coroutines.JobKt"), loader, "Job", jobClass)
                .invoke(null, call(request, "getExecutionContext"));
        Class<?> contextClass = Class.forName("kotlin.coroutines.CoroutineContext", false, loader);
        Object outer = continuation.getClass().getMethod("getContext").invoke(continuation);
        Method plus = contextClass.getMethod("plus", contextClass);
        Object context = plus.invoke(outer, job);
        Class<?> data = Class.forName(k + "client.request.HttpResponseData", true, loader);
        return data.getConstructor(statusClass, Class.forName(k + "util.date.GMTDate", false, loader),
                Class.forName(k + "http.Headers", false, loader), versionClass, Object.class, contextClass)
                .newInstance(status, now, headers, version, body, context);
    }
}
