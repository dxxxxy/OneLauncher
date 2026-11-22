package org.polyfrost.oneclient.agent.http;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSession;

import org.polyfrost.oneclient.agent.boot.Exchange;
import org.polyfrost.oneclient.agent.boot.Hooks;
import org.polyfrost.oneclient.agent.boot.HttpRelay;

/**
 * {@code java.net.http.HttpClient} requests to account hosts, answered by the
 * launcher like {@code HttpURLConnection} ones. Without this they would reach
 * Mojang with the fake token and fail.
 */
public final class ModernHttp implements HttpRelay {
    public Object send(Object request, Object handler) throws Exception {
        HttpRequest r = (HttpRequest) request;
        if (!brokered(r)) return Hooks.PASS;
        try {
            return answer(r, (HttpResponse.BodyHandler<?>) handler, Exchange.caller());
        } catch (java.io.IOException | InterruptedException e) {
            throw e;
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause();
            throw cause instanceof java.io.IOException ? (java.io.IOException) cause : new java.io.IOException(cause);
        } catch (Exception e) {
            // send only declares IOException and InterruptedException
            throw new java.io.IOException(e);
        }
    }

    public Object sendAsync(Object request, Object handler) {
        final HttpRequest r = (HttpRequest) request;
        if (!brokered(r)) return Hooks.PASS;
        final HttpResponse.BodyHandler<?> h = (HttpResponse.BodyHandler<?>) handler;
        final String caller = Exchange.caller();
        CompletableFuture<HttpResponse<?>> future = new CompletableFuture<>();
        Thread worker = new Thread(() -> {
            try {
                future.complete(answer(r, h, caller));
            } catch (Throwable t) {
                future.completeExceptionally(t);
            }
        }, "OneClient HTTP");
        worker.setDaemon(true);
        worker.start();
        return future;
    }

    private static boolean brokered(HttpRequest request) {
        URI uri = request.uri();
        String scheme = uri.getScheme();
        return ("https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme)) && Exchange.brokered(uri.getHost());
    }

    private static <T> HttpResponse<T> answer(HttpRequest request, HttpResponse.BodyHandler<T> handler, String caller)
            throws Exception {
        List<String[]> headers = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : request.headers().map().entrySet()) {
            for (String value : entry.getValue()) headers.add(new String[] {entry.getKey(), value});
        }
        long timeout = request.timeout().map(d -> d.toMillis()).orElse(30000L);
        Exchange.Response reply = Exchange.send(request.method(), request.uri().toString(), headers,
                body(request), caller, (int) Math.min(timeout, Integer.MAX_VALUE));

        Map<String, List<String>> map = new LinkedHashMap<>();
        for (String[] header : reply.headers) {
            map.computeIfAbsent(header[0], k -> new ArrayList<>()).add(header[1]);
        }
        HttpHeaders responseHeaders = HttpHeaders.of(map, (a, b) -> true);
        int status = reply.status;
        HttpResponse.ResponseInfo info = new HttpResponse.ResponseInfo() {
            public int statusCode() {
                return status;
            }

            public HttpHeaders headers() {
                return responseHeaders;
            }

            public HttpClient.Version version() {
                return HttpClient.Version.HTTP_1_1;
            }
        };
        HttpResponse.BodySubscriber<T> subscriber = handler.apply(info);
        deliver(subscriber, reply.body);
        T body = subscriber.getBody().toCompletableFuture().get(timeout, TimeUnit.MILLISECONDS);
        return new Response<>(request, status, responseHeaders, body);
    }

    /** The request body, collected from its publisher. */
    private static byte[] body(HttpRequest request) throws Exception {
        Optional<HttpRequest.BodyPublisher> publisher = request.bodyPublisher();
        if (publisher.isEmpty()) return new byte[0];
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        CompletableFuture<byte[]> done = new CompletableFuture<>();
        publisher.get().subscribe(new Flow.Subscriber<ByteBuffer>() {
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            public void onNext(ByteBuffer item) {
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                synchronized (out) {
                    out.write(chunk, 0, chunk.length);
                }
            }

            public void onError(Throwable error) {
                done.completeExceptionally(error);
            }

            public void onComplete() {
                synchronized (out) {
                    done.complete(out.toByteArray());
                }
            }
        });
        return done.get(30, TimeUnit.SECONDS);
    }

    private static <T> void deliver(HttpResponse.BodySubscriber<T> subscriber, byte[] body) {
        subscriber.onSubscribe(new Flow.Subscription() {
            private boolean sent;

            public synchronized void request(long n) {
                if (sent || n <= 0) return;
                sent = true;
                if (body.length > 0) subscriber.onNext(List.of(ByteBuffer.wrap(body)));
                subscriber.onComplete();
            }

            public synchronized void cancel() {
                sent = true;
            }
        });
    }

    private static final class Response<T> implements HttpResponse<T> {
        private final HttpRequest request;
        private final int status;
        private final HttpHeaders headers;
        private final T body;

        Response(HttpRequest request, int status, HttpHeaders headers, T body) {
            this.request = request;
            this.status = status;
            this.headers = headers;
            this.body = body;
        }

        public int statusCode() {
            return status;
        }

        public HttpRequest request() {
            return request;
        }

        public Optional<HttpResponse<T>> previousResponse() {
            return Optional.empty();
        }

        public HttpHeaders headers() {
            return headers;
        }

        public T body() {
            return body;
        }

        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        public URI uri() {
            return request.uri();
        }

        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }

        @Override
        public String toString() {
            return "(" + request.method() + " " + request.uri() + ") " + status;
        }
    }
}
