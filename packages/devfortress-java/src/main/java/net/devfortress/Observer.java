package net.devfortress;

import java.util.Map;

/**
 * Shared "classify this request/response, queue an event for it" logic for
 * every Java framework adapter (the Spring Boot filter in
 * devfortress-spring-boot, and any future one), the same way the Go SDK's
 * Observe/ObserveAndFlush is shared by its net/http and gin adapters, and
 * the Ruby SDK's DevFortress::Observer is shared by its Rack adapter.
 *
 * <p><b>{@link #observeAndFlush} is what adapters should call, not
 * {@link #observe}</b>: {@code observe} only queues the event. Under sparse
 * traffic (fewer requests than the client's batch size between flushes), a
 * queued-only event can sit undelivered indefinitely unless something else
 * flushes it (a configured flush interval, an explicit flush/close
 * elsewhere, or the next batch filling up). This is the exact gap the Go
 * SDK's gin adapter and {@code demos/go-non-agentic} shipped with
 * originally — fixed after the fact there, ported correctly here from the
 * start so the Spring Boot adapter never has it.
 */
public final class Observer {
    private Observer() {
    }

    /** Input {@link #observe}/{@link #observeAndFlush} need, filled in from the adapter's own request type. */
    public record Input(
            String method,
            String path,
            String rawQuery,
            int statusCode,
            int latencyMs,
            String userAgent,
            String forwardedFor,
            String realIp,
            String remoteAddr,
            String userId
    ) {
    }

    /**
     * Classifies and queues an event on the client's detached observer
     * executor, so delivery never delays the response. Only queues — see
     * the class doc for why adapters should prefer {@link #observeAndFlush}.
     */
    public static void observe(Client client, Input input) {
        queue(client, input, false);
    }

    /**
     * Behaves like {@link #observe}, but also flushes the queue once the
     * event has been classified and queued, on that same detached task — so
     * a single event is delivered even under sparse traffic, with no
     * separate task racing the enqueue. This is what every adapter should
     * call.
     */
    public static void observeAndFlush(Client client, Input input) {
        queue(client, input, true);
    }

    private static void queue(Client client, Input input, boolean flush) {
        String ip = ClientIp.resolve(input.forwardedFor(), input.realIp(), remoteHost(input.remoteAddr()));
        var classify = new Classifier.ClassifyInput(
                ip, input.method(), input.path(), input.statusCode(), input.latencyMs(),
                input.userAgent(), input.rawQuery(), input.userId());

        client.runDetached(() -> {
            Map<String, Object> event = Classifier.buildEvent(classify);
            if (event == null) {
                return;
            }
            client.trackEvent(event);
            if (flush) {
                client.flush();
            }
        });
    }

    /** Strips the port from a "host:port" remote address, or returns remoteAddr unchanged. */
    private static String remoteHost(String remoteAddr) {
        if (remoteAddr == null) {
            return null;
        }
        int lastColon = remoteAddr.lastIndexOf(':');
        if (lastColon == -1) {
            return remoteAddr;
        }
        // IPv6 literals ("::1", "[::1]:port") contain multiple colons; only strip a
        // trailing ":port" when the remainder before it isn't itself bare IPv6.
        String hostPart = remoteAddr.substring(0, lastColon);
        String portPart = remoteAddr.substring(lastColon + 1);
        if (!portPart.chars().allMatch(Character::isDigit) || portPart.isEmpty()) {
            return remoteAddr;
        }
        if (hostPart.startsWith("[") && hostPart.endsWith("]")) {
            return hostPart.substring(1, hostPart.length() - 1);
        }
        if (hostPart.contains(":")) {
            // Bare IPv6 with no brackets and a trailing ":port" is ambiguous; Go's
            // net.SplitHostPort requires brackets for this case too, so leave it as-is.
            return remoteAddr;
        }
        return hostPart;
    }
}
