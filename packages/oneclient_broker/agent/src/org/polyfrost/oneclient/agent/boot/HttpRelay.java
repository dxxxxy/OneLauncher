package org.polyfrost.oneclient.agent.boot;

/**
 * Answers {@code java.net.http} requests to account hosts through the
 * launcher. Implemented in {@code src11} (compiled for Java 11, where that
 * client exists) and loaded by name, so this jar still runs on Java 8.
 */
public interface HttpRelay {
    /** The {@code HttpResponse}, or {@link Hooks#PASS} for hosts the launcher doesn't handle. */
    Object send(Object request, Object handler) throws Exception;

    /** A {@code CompletableFuture<HttpResponse>}, or {@link Hooks#PASS}. */
    Object sendAsync(Object request, Object handler);
}
