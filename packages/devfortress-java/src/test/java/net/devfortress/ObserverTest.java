package net.devfortress;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves the sparse-traffic delivery guarantee at the point it actually
 * matters: {@link Observer#observeAndFlush} delivers a single observed
 * request even though the client's batch size (25) is never reached, while
 * {@link Observer#observe} alone leaves it sitting queued — the exact gap
 * the Go SDK's gin adapter originally shipped with. Every framework
 * adapter (the Spring Boot filter included) must call observeAndFlush, not
 * observe, for exactly this reason.
 */
class ObserverTest {
    private static Observer.Input input(int statusCode) {
        return new Observer.Input("GET", "/login", "", statusCode, 5, "curl/8.0",
                "", "", "203.0.113.7", null);
    }

    @Test
    void observeAndFlushDeliversASingleSparseEventWithoutWaitingForBatchSize() throws InterruptedException {
        RecordingTransport transport = new RecordingTransport();
        try (Client client = Client.builder("test-key").transport(transport).batchSize(25).build()) {
            Observer.observeAndFlush(client, input(401)); // auth_failure: classified, not dropped

            waitUntil(() -> transport.callCount() >= 1, Duration.ofSeconds(2));
            assertEquals(1, transport.callCount(), "a single sparse request must be delivered, not held for batch size 25");
            assertEquals(0, client.pendingEvents());
        }
    }

    @Test
    void observeAloneOnlyQueuesAndDoesNotDeliver() throws InterruptedException {
        RecordingTransport transport = new RecordingTransport();
        try (Client client = Client.builder("test-key").transport(transport).batchSize(25).build()) {
            Observer.observe(client, input(401));

            // Give the detached task every chance to run; it must enqueue but not flush.
            waitUntil(() -> client.pendingEvents() >= 1, Duration.ofSeconds(2));
            TimeUnit.MILLISECONDS.sleep(200);
            assertEquals(0, transport.callCount(), "observe() alone must not deliver under sparse traffic");
            assertEquals(1, client.pendingEvents());
        }
    }

    @Test
    void observeAndFlushSkipsNonSecurityRelevantRequests() throws InterruptedException {
        RecordingTransport transport = new RecordingTransport();
        try (Client client = Client.builder("test-key").transport(transport).batchSize(25).build()) {
            Observer.observeAndFlush(client, input(200));

            TimeUnit.MILLISECONDS.sleep(200);
            assertEquals(0, transport.callCount());
            assertEquals(0, client.pendingEvents());
        }
    }

    private static void waitUntil(java.util.function.BooleanSupplier condition, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition not met within " + timeout);
            }
            TimeUnit.MILLISECONDS.sleep(10);
        }
    }
}
