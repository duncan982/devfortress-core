package net.devfortress;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientTest {
    private static Map<String, Object> event(String path) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("eventType", "custom");
        e.put("ip", "203.0.113.7");
        e.put("method", "GET");
        e.put("path", path);
        e.put("severity", "LOW");
        return e;
    }

    @Test
    void queuesUntilBatchSizeThenAutoFlushes() {
        RecordingTransport transport = new RecordingTransport();
        try (Client client = Client.builder("test-key").transport(transport).batchSize(3).retries(1).build()) {
            client.trackEvent(event("/a"));
            client.trackEvent(event("/b"));
            assertEquals(0, transport.callCount(), "should not flush before batch size is reached");
            assertEquals(2, client.pendingEvents());

            client.trackEvent(event("/c"));
            assertEquals(1, transport.callCount(), "should auto-flush once batch size is reached");
            assertEquals(0, client.pendingEvents());
        }
    }

    @Test
    void explicitFlushSendsWhateverIsQueued() {
        RecordingTransport transport = new RecordingTransport();
        try (Client client = Client.builder("test-key").transport(transport).batchSize(25).retries(1).build()) {
            client.trackEvent(event("/a"));
            List<DeliveryResult> results = client.flush();
            assertEquals(1, results.size());
            assertTrue(results.get(0).ok);
            assertEquals(1, transport.callCount());
        }
    }

    @Test
    void retriesOn5xxWithExponentialBackoffThenSucceeds() {
        RecordingTransport transport = new RecordingTransport()
                .respond(500, "{}")
                .respond(500, "{}")
                .respond(200, "{\"ok\":true}");
        List<Duration> sleeps = new java.util.concurrent.CopyOnWriteArrayList<>();
        try (Client client = Client.builder("test-key").transport(transport).retries(3)
                .backoffBase(Duration.ofMillis(1)).build()) {
            client.trackEvent(event("/a"));
            DeliveryResult result = client.flush().get(0);
            assertTrue(result.ok);
            assertEquals(3, result.attempts);
            assertEquals(3, transport.callCount());
        }
    }

    @Test
    void neverRetriesA4xx() {
        RecordingTransport transport = new RecordingTransport().respond(400, "{\"error\":\"bad\"}");
        try (Client client = Client.builder("test-key").transport(transport).retries(3)
                .backoffBase(Duration.ofMillis(1)).build()) {
            client.trackEvent(event("/a"));
            DeliveryResult result = client.flush().get(0);
            assertFalse(result.ok);
            assertEquals(400, result.statusCode);
            assertEquals(1, transport.callCount(), "a 4xx must not be retried");
        }
    }

    @Test
    void exhaustsRetriesOnPersistent5xxAndNeverThrows() {
        RecordingTransport transport = new RecordingTransport()
                .respond(503, "{}").respond(503, "{}").respond(503, "{}");
        try (Client client = Client.builder("test-key").transport(transport).retries(3)
                .backoffBase(Duration.ofMillis(1)).build()) {
            client.trackEvent(event("/a"));
            DeliveryResult result = client.flush().get(0);
            assertFalse(result.ok);
            assertEquals(3, result.attempts);
            assertEquals(3, transport.callCount());
        }
    }

    @Test
    void closeFlushesWhateverIsStillQueued() {
        RecordingTransport transport = new RecordingTransport();
        Client client = Client.builder("test-key").transport(transport).batchSize(25).build();
        client.trackEvent(event("/a"));
        assertEquals(0, transport.callCount());
        client.close();
        assertEquals(1, transport.callCount(), "close() must flush pending events");
    }

    @Test
    void everyAttemptIsSignedWithAFreshNonce() {
        RecordingTransport transport = new RecordingTransport().respond(500, "{}").respond(200, "{}");
        try (Client client = Client.builder("test-key").transport(transport).retries(2)
                .backoffBase(Duration.ofMillis(1)).build()) {
            client.trackEvent(event("/a"));
            client.flush();
            assertEquals(2, transport.calls.size());
            String nonce1 = transport.calls.get(0).headers().get(Signer.NONCE_HEADER);
            String nonce2 = transport.calls.get(1).headers().get(Signer.NONCE_HEADER);
            assertFalse(nonce1.equals(nonce2), "a retry must not reuse the previous attempt's nonce");
        }
    }

    @Test
    void strictPrivacyHashesIpAndDropsUserAgent() {
        RecordingTransport transport = new RecordingTransport();
        try (Client client = Client.builder("test-key").transport(transport).privacy("strict").build()) {
            Map<String, Object> e = event("/a");
            e.put("userAgent", "curl/8.0");
            client.trackEvent(e);
            client.flush();
            String body = new String(transport.calls.get(0).body(), java.nio.charset.StandardCharsets.UTF_8);
            assertFalse(body.contains("203.0.113.7"), "strict privacy must not send the raw IP");
            assertFalse(body.contains("curl/8.0"), "strict privacy must drop the user agent");
        }
    }
}
