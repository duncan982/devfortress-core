package net.devfortress;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * DevFortress SDK — Unified Audit Trail (CL-M3). Mirrors
 * {@code packages/devfortress-sdk/src/unified-audit.ts}.
 *
 * <p>Merges internal and external closed-loop audit events into a single
 * in-memory timeline with consistent fields regardless of source.
 *
 * <p><b>NOTE on tamper-evidence:</b> this is an in-memory log only — it is
 * not cryptographically signed or hash-chained, and neither is Node's own
 * {@code UnifiedAuditTrail}. The HMAC-signed, hash-chained tamper-evident
 * audit trail (TODO 265/266/272) is a separate, server-side Next.js module
 * ({@code lib/audit-trail-signer.ts}) operating directly on the
 * {@code LiveThreatEvent} Postgres table. It has no SDK-side analog in any
 * language, including Node, so this port does not and cannot provide
 * tamper-evidence either.
 *
 * <p>Safe for concurrent use.
 */
public final class UnifiedAuditTrail {

    private static final long DEDUP_WINDOW_MS = 5_000;
    private static final int DEDUP_MAP_CAP = 10_000;
    private static final int DEFAULT_MAX_ENTRIES = 100_000;

    /** Source of an audit decision. */
    public enum AuditSource { INTERNAL, EXTERNAL, HYBRID }

    /** One audit record, from any source. */
    public record Entry(
            String eventId,
            long timestamp,
            AuditSource source,
            int tier,
            String decision,
            double score,
            String severity,
            double latencyMs,
            String ip,
            String path,
            String method,
            List<String> matchedRules,
            String userId,
            String agentId,
            String sessionId,
            boolean fallbackMode,
            Map<String, Object> meta) {

        /** Returns a copy of this entry with source replaced. */
        Entry withSource(AuditSource newSource) {
            return new Entry(eventId, timestamp, newSource, tier, decision, score, severity, latencyMs, ip, path,
                    method, matchedRules, userId, agentId, sessionId, fallbackMode, meta);
        }
    }

    /** Filters for {@link #query}; a null field is not applied. */
    public record Query(
            AuditSource source,
            String decision,
            String ip,
            String userId,
            String agentId,
            Double minScore,
            Long since,
            int limit) {

        public Query() {
            this(null, null, null, null, null, null, null, 100);
        }
    }

    /** The result of {@link #getStats}. */
    public record Stats(
            int total,
            int internalDecisions,
            int externalDecisions,
            int hybridDecisions,
            int fallbackEvents,
            int totalBlocks,
            int totalAllows,
            int totalRateLimits,
            long avgInternalLatencyMs,
            long avgExternalLatencyMs) {
    }

    /** The result of {@link #getLatencyHistogram}. */
    public record LatencyHistogram(
            int under1ms, int under5ms, int under50ms, int under200ms, int under1s, int over1s) {
    }

    private final Object lock = new Object();
    private final List<Entry> entries = new ArrayList<>();
    private final Map<String, Long> recentEventIds = new LinkedHashMap<>();

    private final int maxEntries;
    private final Consumer<Entry> onEntry;
    private final boolean debug;

    private int internalDecisions, externalDecisions, hybridDecisions;
    private int fallbackEvents, totalBlocks, totalAllows, totalRateLimits;
    private double internalLatencySum, externalLatencySum;

    public UnifiedAuditTrail() {
        this(DEFAULT_MAX_ENTRIES, null, false);
    }

    public UnifiedAuditTrail(int maxEntries, Consumer<Entry> onEntry, boolean debug) {
        this.maxEntries = maxEntries > 0 ? maxEntries : DEFAULT_MAX_ENTRIES;
        this.onEntry = onEntry;
        this.debug = debug;
    }

    /**
     * Records an audit entry from any source. S27: the same eventId
     * within the 5s dedup window is merged (external overrides internal),
     * not duplicated.
     */
    public void record(Entry entry) {
        Entry fired = null;

        synchronized (lock) {
            long now = System.currentTimeMillis();
            Long existing = recentEventIds.get(entry.eventId());
            if (existing != null && (now - existing) < DEDUP_WINDOW_MS) {
                if (entry.source() == AuditSource.EXTERNAL) {
                    for (int i = 0; i < entries.size(); i++) {
                        Entry e = entries.get(i);
                        if (e.eventId().equals(entry.eventId()) && e.source() == AuditSource.INTERNAL) {
                            entries.set(i, entry.withSource(AuditSource.HYBRID));
                            if (debug) {
                                System.out.println("[DF Audit] DEDUP: merged " + entry.eventId()
                                        + " (external overrides internal)");
                            }
                            break;
                        }
                    }
                }
                return;
            }

            recentEventIds.put(entry.eventId(), now);
            if (recentEventIds.size() > DEDUP_MAP_CAP) {
                long cutoff = now - DEDUP_WINDOW_MS;
                recentEventIds.entrySet().removeIf(e -> e.getValue() < cutoff);
            }

            if (entries.size() >= maxEntries) {
                int evict = (int) (maxEntries * 0.1);
                entries.subList(0, Math.min(evict, entries.size())).clear();
            }
            entries.add(entry);
            updateStats(entry);
            fired = entry;
        }

        if (fired != null && onEntry != null) {
            try {
                onEntry.accept(fired);
            } catch (RuntimeException ignored) {
                // Callback errors must not break the audit trail.
            }
        }

        if (debug && fired != null) {
            System.out.printf("[DF Audit] %s:tier%d %s score=%s %s %s %s (%sms)%n",
                    entry.source(), entry.tier(), entry.decision(), entry.score(), entry.ip(), entry.method(),
                    entry.path(), entry.latencyMs());
        }
    }

    /** Queries audit entries matching q, most recent last, capped at q.limit() (default 100). */
    public List<Entry> query(Query q) {
        List<Entry> result;
        synchronized (lock) {
            result = new ArrayList<>(entries);
        }

        if (q.source() != null) {
            result.removeIf(e -> e.source() != q.source());
        }
        if (q.decision() != null) {
            result.removeIf(e -> !q.decision().equals(e.decision()));
        }
        if (q.ip() != null) {
            result.removeIf(e -> !q.ip().equals(e.ip()));
        }
        if (q.userId() != null) {
            result.removeIf(e -> !q.userId().equals(e.userId()));
        }
        if (q.agentId() != null) {
            result.removeIf(e -> !q.agentId().equals(e.agentId()));
        }
        if (q.minScore() != null) {
            result.removeIf(e -> e.score() < q.minScore());
        }
        if (q.since() != null) {
            result.removeIf(e -> e.timestamp() < q.since());
        }

        int limit = q.limit() > 0 ? q.limit() : 100;
        if (result.size() > limit) {
            result = new ArrayList<>(result.subList(result.size() - limit, result.size()));
        }
        return result;
    }

    /** Returns aggregated statistics. */
    public Stats getStats() {
        synchronized (lock) {
            long avgInternal = internalDecisions > 0 ? Math.round(internalLatencySum / internalDecisions) : 0;
            long avgExternal = externalDecisions > 0 ? Math.round(externalLatencySum / externalDecisions) : 0;
            return new Stats(entries.size(), internalDecisions, externalDecisions, hybridDecisions, fallbackEvents,
                    totalBlocks, totalAllows, totalRateLimits, avgInternal, avgExternal);
        }
    }

    /** Returns source:decision counts, for dashboard visualization. */
    public Map<String, Integer> getDecisionDistribution() {
        List<Entry> snapshot;
        synchronized (lock) {
            snapshot = new ArrayList<>(entries);
        }
        Map<String, Integer> dist = new LinkedHashMap<>();
        for (Entry e : snapshot) {
            String key = e.source() + ":" + e.decision();
            dist.merge(key, 1, Integer::sum);
        }
        return dist;
    }

    /** Returns latency histogram buckets. */
    public LatencyHistogram getLatencyHistogram() {
        List<Entry> snapshot;
        synchronized (lock) {
            snapshot = new ArrayList<>(entries);
        }
        int under1ms = 0, under5ms = 0, under50ms = 0, under200ms = 0, under1s = 0, over1s = 0;
        for (Entry e : snapshot) {
            double ms = e.latencyMs();
            if (ms < 1) {
                under1ms++;
            } else if (ms < 5) {
                under5ms++;
            } else if (ms < 50) {
                under50ms++;
            } else if (ms < 200) {
                under200ms++;
            } else if (ms < 1000) {
                under1s++;
            } else {
                over1s++;
            }
        }
        return new LatencyHistogram(under1ms, under5ms, under50ms, under200ms, under1s, over1s);
    }

    /** Exports entries as JSON (for compliance/archival). */
    public String exportJson(Long since) {
        List<Entry> snapshot;
        synchronized (lock) {
            snapshot = new ArrayList<>(entries);
        }
        if (since != null) {
            snapshot.removeIf(e -> e.timestamp() < since);
        }

        List<Object> encoded = new ArrayList<>();
        for (Entry e : snapshot) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("eventId", e.eventId());
            m.put("timestamp", e.timestamp());
            m.put("source", e.source().toString());
            m.put("tier", e.tier());
            m.put("decision", e.decision());
            m.put("score", e.score());
            m.put("severity", e.severity());
            m.put("latencyMs", e.latencyMs());
            m.put("ip", e.ip());
            m.put("path", e.path());
            m.put("method", e.method());
            m.put("matchedRules", e.matchedRules());
            m.put("userId", e.userId());
            m.put("agentId", e.agentId());
            m.put("sessionId", e.sessionId());
            m.put("fallbackMode", e.fallbackMode());
            encoded.add(m);
        }
        return Json.encode(encoded);
    }

    /** Resets the audit trail (for testing). */
    public void reset() {
        synchronized (lock) {
            entries.clear();
            recentEventIds.clear();
            internalDecisions = externalDecisions = hybridDecisions = 0;
            fallbackEvents = totalBlocks = totalAllows = totalRateLimits = 0;
            internalLatencySum = externalLatencySum = 0;
        }
    }

    /** Must be called with {@code lock} held. */
    private void updateStats(Entry entry) {
        switch (entry.source()) {
            case INTERNAL -> {
                internalDecisions++;
                internalLatencySum += entry.latencyMs();
            }
            case EXTERNAL -> {
                externalDecisions++;
                externalLatencySum += entry.latencyMs();
            }
            default -> {
                hybridDecisions++;
                if (entry.tier() > 0) {
                    internalLatencySum += entry.latencyMs();
                } else {
                    externalLatencySum += entry.latencyMs();
                }
            }
        }

        if (entry.fallbackMode()) {
            fallbackEvents++;
        }

        switch (entry.decision()) {
            case "block" -> totalBlocks++;
            case "allow" -> totalAllows++;
            case "rate_limit" -> totalRateLimits++;
            default -> { }
        }
    }
}
