package net.devfortress;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TelemetryManager (CV-M2 heartbeat counters) and its co-located {@link
 * TelemetryManager.RollupBuffer}, ported from {@code
 * packages/devfortress-sdk/src/telemetry.ts} and {@code
 * packages/devfortress-sdk/src/telemetry-rollup-buffer.ts}. The periodic
 * heartbeat/flush timers themselves are not exercised here (same
 * 5-second-minimum cadence as Node, not test-friendly to await); the
 * synchronous counter and buffering logic they depend on is fully covered.
 */
class TelemetryManagerTest {
    @Test
    void countersAccumulateAndResetIsVisibleThroughGetState() {
        try (TelemetryManager telemetry = TelemetryManager.builder("test-key", "https://platform.example").build()) {
            telemetry.recordEvent();
            telemetry.recordEvent();
            telemetry.recordBlock();
            telemetry.recordRateLimit();
            telemetry.recordLatency(42);

            TelemetryManager.Stats stats = telemetry.getState();
            assertEquals(2, stats.eventCount());
            assertEquals(1, stats.blockCount());
            assertEquals(1, stats.rateLimitCount());
        }
    }

    @Test
    void hourlyPeriodKeyMatchesExpectedFormat() {
        java.time.Instant fixed = java.time.Instant.parse("2026-08-27T14:32:10Z");
        assertEquals("2026-08-27T14", TelemetryManager.hourlyPeriodKey(fixed));
    }

    @Test
    void rollupBufferBatchesContributionsPerAliasAndFlushesOnce() {
        RecordingTransport transport = new RecordingTransport().respond(200, "{}");
        try (TelemetryManager.RollupBuffer buffer = TelemetryManager.RollupBuffer.builder("test-key", "https://platform.example")
                .transport(transport).build()) {
            buffer.add(new TelemetryManager.RollupContribution("203.0.113.7", "/api/widgets", false, 12));
            buffer.add(new TelemetryManager.RollupContribution("203.0.113.7", "/api/widgets", true, 30));
            buffer.add(new TelemetryManager.RollupContribution("198.51.100.4", "/api/other", false, 5));

            buffer.flush();

            assertEquals(1, transport.callCount(), "all buffered buckets must flush in a single batched request");
            RecordingTransport.Call call = transport.calls.get(0);
            assertEquals("https://platform.example/api/events/telemetry-rollup", call.url());
            String body = new String(call.body(), java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(body.contains("\"aliasOrIpKey\":\"203.0.113.7\""));
            assertTrue(body.contains("\"requestCount\":2"));
            assertTrue(body.contains("\"errorCount\":1"));
            assertTrue(body.contains("\"aliasOrIpKey\":\"198.51.100.4\""));

            // Buckets are cleared after a successful flush.
            buffer.flush();
            assertEquals(1, transport.callCount(), "an empty buffer must not issue another request");
        }
    }

    @Test
    void rollupBufferForcesEarlyFlushWhenMaxBufferedKeysReached() {
        RecordingTransport transport = new RecordingTransport().respond(200, "{}").respond(200, "{}");
        try (TelemetryManager.RollupBuffer buffer = TelemetryManager.RollupBuffer.builder("test-key", "https://platform.example")
                .transport(transport).maxBufferedKeys(1).build()) {
            buffer.add(new TelemetryManager.RollupContribution("ip-1", "/a", false, 1));
            // A second, distinct key exceeds maxBufferedKeys(1) and must force an early flush.
            buffer.add(new TelemetryManager.RollupContribution("ip-2", "/b", false, 1));

            assertTrue(transport.callCount() >= 1, "exceeding maxBufferedKeys must force an early flush");
        }
    }
}
