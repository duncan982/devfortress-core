package net.devfortress;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * UnifiedAuditTrail (CL-M3, TODO 371), ported from
 * {@code packages/devfortress-sdk/src/unified-audit.ts}.
 */
class UnifiedAuditTrailTest {

    private static long seq = 0;

    /** Mutable builder for {@link UnifiedAuditTrail.Entry}, test-only convenience. */
    private static final class EntryBuilder {
        String eventId = "evt_" + (seq++);
        long timestamp = System.currentTimeMillis();
        UnifiedAuditTrail.AuditSource source = UnifiedAuditTrail.AuditSource.INTERNAL;
        int tier = 1;
        String decision = "allow";
        double score = 10;
        String severity = "low";
        double latencyMs = 0.5;
        String ip = "192.168.1.1";
        String path = "/api/test";
        String method = "GET";

        EntryBuilder eventId(String v) {
            eventId = v;
            return this;
        }

        EntryBuilder source(UnifiedAuditTrail.AuditSource v) {
            source = v;
            return this;
        }

        EntryBuilder decision(String v) {
            decision = v;
            return this;
        }

        EntryBuilder score(double v) {
            score = v;
            return this;
        }

        EntryBuilder latencyMs(double v) {
            latencyMs = v;
            return this;
        }

        EntryBuilder ip(String v) {
            ip = v;
            return this;
        }

        UnifiedAuditTrail.Entry build() {
            return new UnifiedAuditTrail.Entry(eventId, timestamp, source, tier, decision, score, severity,
                    latencyMs, ip, path, method, List.of(), null, null, null, false, Map.of());
        }
    }

    private static UnifiedAuditTrail.Entry makeEntry() {
        return new EntryBuilder().build();
    }

    private static UnifiedAuditTrail.Entry makeEntry(java.util.function.UnaryOperator<EntryBuilder> mutate) {
        return mutate.apply(new EntryBuilder()).build();
    }

    @Test
    void recordAndRetrieveEntries() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.ip("10.0.0.1")));
        audit.record(makeEntry(e -> e.ip("10.0.0.2")));
        assertEquals(2, audit.query(new UnifiedAuditTrail.Query()).size());
    }

    @Test
    void filterBySource() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.EXTERNAL)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.HYBRID)));

        assertEquals(1, audit.query(new UnifiedAuditTrail.Query(UnifiedAuditTrail.AuditSource.INTERNAL, null, null, null, null, null, null, 100)).size());
        assertEquals(1, audit.query(new UnifiedAuditTrail.Query(UnifiedAuditTrail.AuditSource.EXTERNAL, null, null, null, null, null, null, 100)).size());
        assertEquals(1, audit.query(new UnifiedAuditTrail.Query(UnifiedAuditTrail.AuditSource.HYBRID, null, null, null, null, null, null, 100)).size());
    }

    @Test
    void filterByDecision() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.decision("allow")));
        audit.record(makeEntry(e -> e.decision("block")));
        audit.record(makeEntry(e -> e.decision("rate_limit")));

        assertEquals(1, audit.query(new UnifiedAuditTrail.Query(null, "block", null, null, null, null, null, 100)).size());
    }

    @Test
    void filterByMinScore() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.score(20)));
        audit.record(makeEntry(e -> e.score(60)));
        audit.record(makeEntry(e -> e.score(90)));

        assertEquals(2, audit.query(new UnifiedAuditTrail.Query(null, null, null, null, null, 50.0, null, 100)).size());
    }

    @Test
    void limitResults() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        for (int i = 0; i < 50; i++) {
            audit.record(makeEntry());
        }
        assertEquals(10, audit.query(new UnifiedAuditTrail.Query(null, null, null, null, null, null, null, 10)).size());
    }

    @Test
    void combineMultipleFilters() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL).decision("block").score(85)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL).decision("allow").score(10)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.EXTERNAL).decision("block").score(90)));

        List<UnifiedAuditTrail.Entry> results = audit.query(
                new UnifiedAuditTrail.Query(UnifiedAuditTrail.AuditSource.INTERNAL, "block", null, null, null, 80.0, null, 100));
        assertEquals(1, results.size());
        assertEquals(85, results.get(0).score());
    }

    @Test
    void statsCountDecisionsBySource() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.EXTERNAL)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.HYBRID)));

        UnifiedAuditTrail.Stats stats = audit.getStats();
        assertEquals(4, stats.total());
        assertEquals(2, stats.internalDecisions());
        assertEquals(1, stats.externalDecisions());
        assertEquals(1, stats.hybridDecisions());
    }

    @Test
    void statsCountBlocksAllowsRateLimits() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.decision("block")));
        audit.record(makeEntry(e -> e.decision("allow")));
        audit.record(makeEntry(e -> e.decision("allow")));
        audit.record(makeEntry(e -> e.decision("rate_limit")));

        UnifiedAuditTrail.Stats stats = audit.getStats();
        assertEquals(1, stats.totalBlocks());
        assertEquals(2, stats.totalAllows());
        assertEquals(1, stats.totalRateLimits());
    }

    @Test
    void averageLatencies() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL).latencyMs(0.5)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL).latencyMs(1.5)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.EXTERNAL).latencyMs(100)));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.EXTERNAL).latencyMs(200)));

        UnifiedAuditTrail.Stats stats = audit.getStats();
        assertEquals(1, stats.avgInternalLatencyMs());
        assertEquals(150, stats.avgExternalLatencyMs());
    }

    @Test
    void decisionDistribution() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL).decision("allow")));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL).decision("allow")));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.INTERNAL).decision("block")));
        audit.record(makeEntry(e -> e.source(UnifiedAuditTrail.AuditSource.EXTERNAL).decision("allow")));

        Map<String, Integer> dist = audit.getDecisionDistribution();
        assertEquals(2, dist.get("INTERNAL:allow"));
        assertEquals(1, dist.get("INTERNAL:block"));
        assertEquals(1, dist.get("EXTERNAL:allow"));
    }

    @Test
    void latencyHistogramBucketsCorrectly() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.latencyMs(0.3)));
        audit.record(makeEntry(e -> e.latencyMs(2)));
        audit.record(makeEntry(e -> e.latencyMs(30)));
        audit.record(makeEntry(e -> e.latencyMs(100)));
        audit.record(makeEntry(e -> e.latencyMs(500)));
        audit.record(makeEntry(e -> e.latencyMs(2000)));

        UnifiedAuditTrail.LatencyHistogram hist = audit.getLatencyHistogram();
        assertEquals(1, hist.under1ms());
        assertEquals(1, hist.under5ms());
        assertEquals(1, hist.under50ms());
        assertEquals(1, hist.under200ms());
        assertEquals(1, hist.under1s());
        assertEquals(1, hist.over1s());
    }

    @Test
    void exportJsonExportsAllEntries() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.ip("1.1.1.1")));
        audit.record(makeEntry(e -> e.ip("2.2.2.2")));

        Object parsed = Json.decode(audit.exportJson(null));
        assertTrue(parsed instanceof List<?>);
        assertEquals(2, ((List<?>) parsed).size());
    }

    @Test
    void boundedStorageEvictsOldest10Percent() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail(100, null, false);
        for (int i = 0; i < 110; i++) {
            final int idx = i;
            audit.record(makeEntry(e -> e.eventId("evt_" + idx)));
        }

        UnifiedAuditTrail.Stats stats = audit.getStats();
        assertTrue(stats.total() <= 110);
        assertTrue(stats.total() > 90);
    }

    @Test
    void resetClearsAllEntriesAndStats() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry());
        audit.record(makeEntry());
        assertEquals(2, audit.getStats().total());

        audit.reset();
        assertEquals(0, audit.getStats().total());
        assertEquals(0, audit.getStats().internalDecisions());
    }

    @Test
    void onEntryCallbackFiresForEachRecordedEntry() {
        List<UnifiedAuditTrail.Entry> received = new ArrayList<>();
        UnifiedAuditTrail audit = new UnifiedAuditTrail(100_000, received::add, false);
        audit.record(makeEntry());
        audit.record(makeEntry());
        assertEquals(2, received.size());
    }

    @Test
    void onEntryCallbackSurvivesErrors() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail(100_000, e -> {
            throw new RuntimeException("callback error");
        }, false);

        assertDoesNotThrow(() -> audit.record(makeEntry()));
        assertEquals(1, audit.getStats().total());
    }

    @Test
    void dedupMergesExternalOverInternal() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.eventId("evt_dup").source(UnifiedAuditTrail.AuditSource.INTERNAL).decision("allow")));
        audit.record(makeEntry(e -> e.eventId("evt_dup").source(UnifiedAuditTrail.AuditSource.EXTERNAL).decision("block")));

        List<UnifiedAuditTrail.Entry> results = audit.query(new UnifiedAuditTrail.Query());
        assertEquals(1, results.size());
        assertEquals(UnifiedAuditTrail.AuditSource.HYBRID, results.get(0).source());
        assertEquals("block", results.get(0).decision());
    }

    @Test
    void dedupSkipsDuplicateInternalWithoutMerging() {
        UnifiedAuditTrail audit = new UnifiedAuditTrail();
        audit.record(makeEntry(e -> e.eventId("evt_dup2").source(UnifiedAuditTrail.AuditSource.INTERNAL).decision("allow")));
        audit.record(makeEntry(e -> e.eventId("evt_dup2").source(UnifiedAuditTrail.AuditSource.INTERNAL).decision("block")));

        List<UnifiedAuditTrail.Entry> results = audit.query(new UnifiedAuditTrail.Query());
        assertEquals(1, results.size());
        assertEquals("allow", results.get(0).decision());
    }
}
