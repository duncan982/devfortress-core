package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * DevFortress SDK — Telemetry Heartbeat (CV-M2). Mirrors
 * {@code packages/devfortress-sdk/src/telemetry.ts}.
 *
 * <p>Sends anonymised usage telemetry to the platform every 5 minutes. No
 * PII is transmitted — only aggregate counts and operational metadata.
 *
 * <p>If the heartbeat stops, the platform dashboard shows: "SDK offline —
 * upgrade to Hybrid for guaranteed visibility."
 *
 * <p>{@link RollupBuffer} and {@link #hourlyPeriodKey} also live in this
 * file (one file per module, matching this SDK's own Client/Signer/Json
 * split and the brief's one-file-per-language convention for this pillar),
 * porting {@code packages/devfortress-sdk/src/telemetry-rollup-buffer.ts}.
 */
public final class TelemetryManager implements AutoCloseable {
    private static final long DEFAULT_HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
    private static final Duration HEARTBEAT_TIMEOUT = Duration.ofSeconds(5);
    private static final int MAX_LATENCY_SAMPLES = 100;

    /** One heartbeat payload. Mirrors Node's {@code TelemetrySnapshot}. */
    public record TelemetrySnapshot(int eventCount, int blockCount, int rateLimitCount, String clMode, String tier,
                                     String sdkVersion, boolean modelExpired, boolean licenseDegraded,
                                     String integrityHash, long uptimeSeconds, long p99LatencyMs) {
    }

    /**
     * Live state supplied by the caller to enrich the next heartbeat.
     * Mirrors Node's {@code Partial<TelemetrySnapshot>} enrichment callback
     * — every field is optional (null means "use the default").
     */
    public static final class Enrichment {
        public String clMode;
        public String tier;
        public String sdkVersion;
        public Boolean modelExpired;
        public Boolean licenseDegraded;
        public String integrityHash;
    }

    /** Diagnostics snapshot, returned by {@link #getState}. */
    public record Stats(int eventCount, int blockCount, int rateLimitCount, long uptimeSeconds) {
    }

    /** Configures a {@link TelemetryManager}. */
    public static final class Builder {
        private final String apiKey;
        private final String endpoint;
        private long heartbeatIntervalMs = DEFAULT_HEARTBEAT_INTERVAL_MS;
        private boolean debug;
        private Transport transport;
        private Logger logger;

        private Builder(String apiKey, String endpoint) {
            this.apiKey = apiKey;
            this.endpoint = endpoint;
        }

        public Builder heartbeatIntervalMs(long heartbeatIntervalMs) {
            this.heartbeatIntervalMs = heartbeatIntervalMs;
            return this;
        }

        public Builder debug(boolean debug) {
            this.debug = debug;
            return this;
        }

        /** Replaces the HTTP transport, e.g. with a recording transport in tests. */
        public Builder transport(Transport transport) {
            this.transport = transport;
            return this;
        }

        public Builder logger(Logger logger) {
            this.logger = logger;
            return this;
        }

        public TelemetryManager build() {
            return new TelemetryManager(this);
        }
    }

    public static Builder builder(String apiKey, String endpoint) {
        return new Builder(apiKey, endpoint);
    }

    private final String endpoint;
    private final long heartbeatIntervalMs;
    private final boolean debug;
    private final Transport transport;
    private final Logger logger;
    private final Signer signer;

    // Counters (reset after each successful heartbeat)
    private volatile int eventCount = 0;
    private volatile int blockCount = 0;
    private volatile int rateLimitCount = 0;

    // Latency tracking (sampled)
    private final List<Long> latencies = Collections.synchronizedList(new ArrayList<>());

    private volatile long startedAt = System.currentTimeMillis();
    private ScheduledExecutorService heartbeatExecutor;
    private ScheduledFuture<?> heartbeatTask;
    private volatile Supplier<Enrichment> snapshotProvider;

    private TelemetryManager(Builder b) {
        if (b.apiKey == null || b.apiKey.isEmpty()) {
            throw new IllegalArgumentException("devfortress: an API key is required");
        }
        this.endpoint = b.endpoint;
        this.heartbeatIntervalMs = b.heartbeatIntervalMs;
        this.debug = b.debug;
        this.transport = b.transport == null ? new HttpTransport() : b.transport;
        this.logger = b.logger;
        this.signer = new Signer(b.apiKey);
    }

    /** Start sending periodic heartbeats (no enrichment callback). */
    public void start() {
        start(null);
    }

    /**
     * Start sending periodic heartbeats.
     *
     * @param snapshotProvider optional supplier to enrich telemetry with live state
     */
    public synchronized void start(Supplier<Enrichment> snapshotProvider) {
        if (heartbeatExecutor != null) {
            return; // Already started
        }

        this.snapshotProvider = snapshotProvider;
        this.startedAt = System.currentTimeMillis();

        heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "devfortress-telemetry-heartbeat");
            t.setDaemon(true); // mirrors Node's timer.unref(): never blocks process exit
            return t;
        });

        // Send first heartbeat after a short delay (don't block init), then periodically.
        heartbeatTask = heartbeatExecutor.scheduleAtFixedRate(
                this::sendHeartbeat, 5, heartbeatIntervalMs / 1000, TimeUnit.SECONDS);

        log("info", "Telemetry heartbeat started (interval: " + (heartbeatIntervalMs / 1000) + "s)");
    }

    /** Record an observed event. */
    public void recordEvent() {
        eventCount++;
    }

    /** Record a blocked event. */
    public void recordBlock() {
        blockCount++;
    }

    /** Record a rate-limited event. */
    public void recordRateLimit() {
        rateLimitCount++;
    }

    /** Record observe latency for p99 calculation. */
    public void recordLatency(long ms) {
        synchronized (latencies) {
            if (latencies.size() >= MAX_LATENCY_SAMPLES) {
                // Reservoir sampling: replace random element
                int idx = ThreadLocalRandom.current().nextInt(latencies.size());
                latencies.set(idx, ms);
            } else {
                latencies.add(ms);
            }
        }
    }

    /**
     * Send a heartbeat to the platform. Fire-and-forget — failures are
     * logged visibly (never silent, matching TODO 321's fix intent), not
     * thrown into the caller.
     */
    private void sendHeartbeat() {
        try {
            Enrichment enriched = snapshotProvider != null ? snapshotProvider.get() : null;

            TelemetrySnapshot snapshot = new TelemetrySnapshot(
                    eventCount,
                    blockCount,
                    rateLimitCount,
                    enriched != null && enriched.clMode != null ? enriched.clMode : "external",
                    enriched != null && enriched.tier != null ? enriched.tier : "starter",
                    enriched != null && enriched.sdkVersion != null ? enriched.sdkVersion : Client.VERSION,
                    enriched != null && enriched.modelExpired != null && enriched.modelExpired,
                    enriched != null && enriched.licenseDegraded != null && enriched.licenseDegraded,
                    enriched != null && enriched.integrityHash != null ? enriched.integrityHash : "",
                    Math.floorDiv(System.currentTimeMillis() - startedAt, 1000),
                    computeP99());

            String url = endpoint + "/api/sdk/heartbeat";
            String requestTarget = Signer.requestTargetFromUrl(url);

            Map<String, Object> bodyMap = new LinkedHashMap<>();
            bodyMap.put("timestamp", System.currentTimeMillis());
            bodyMap.put("eventCount", snapshot.eventCount());
            bodyMap.put("blockCount", snapshot.blockCount());
            bodyMap.put("rateLimitCount", snapshot.rateLimitCount());
            bodyMap.put("clMode", snapshot.clMode());
            bodyMap.put("tier", snapshot.tier());
            bodyMap.put("sdkVersion", snapshot.sdkVersion());
            bodyMap.put("modelExpired", snapshot.modelExpired());
            bodyMap.put("licenseDegraded", snapshot.licenseDegraded());
            bodyMap.put("integrityHash", snapshot.integrityHash());
            bodyMap.put("uptimeSeconds", snapshot.uptimeSeconds());
            bodyMap.put("p99LatencyMs", snapshot.p99LatencyMs());
            String body = Json.encode(bodyMap);

            Map<String, String> headers = new LinkedHashMap<>(signer.sign("POST", requestTarget, body, null, null));
            headers.put("Content-Type", "application/json");

            transport.send("POST", url, headers, body.getBytes(StandardCharsets.UTF_8), HEARTBEAT_TIMEOUT);

            log("debug", "Heartbeat sent: events=" + snapshot.eventCount() + ", blocks=" + snapshot.blockCount()
                    + ", uptime=" + snapshot.uptimeSeconds() + "s");

            // Reset counters after successful send
            eventCount = 0;
            blockCount = 0;
            rateLimitCount = 0;
            latencies.clear();
        } catch (Exception error) {
            // Fire-and-forget: don't throw, just log visibly.
            log("debug", "Heartbeat failed: " + (error.getMessage() != null ? error.getMessage() : "Unknown error"));
        }
    }

    /** Compute p99 latency from sampled observations. */
    private long computeP99() {
        List<Long> sorted;
        synchronized (latencies) {
            if (latencies.isEmpty()) {
                return 0;
            }
            sorted = new ArrayList<>(latencies);
        }
        Collections.sort(sorted);
        int idx = (int) Math.floor(sorted.size() * 0.99);
        return sorted.get(Math.min(idx, sorted.size() - 1));
    }

    /** Get current telemetry state (for diagnostics). */
    public Stats getState() {
        return new Stats(eventCount, blockCount, rateLimitCount,
                Math.floorDiv(System.currentTimeMillis() - startedAt, 1000));
    }

    /** Stop sending heartbeats and clean up. */
    public synchronized void destroy() {
        if (heartbeatTask != null) {
            heartbeatTask.cancel(false);
            heartbeatTask = null;
        }
        if (heartbeatExecutor != null) {
            heartbeatExecutor.shutdown();
            heartbeatExecutor = null;
        }
    }

    @Override
    public void close() {
        destroy();
    }

    private void log(String level, String message) {
        if (!debug && "debug".equals(level)) {
            return;
        }
        String prefix = "[DevFortress:Telemetry]";
        if (logger != null) {
            try {
                logger.log(level, prefix + " " + message, Map.of());
                return;
            } catch (RuntimeException ignored) {
                // A panicking Logger must not reach the host application either.
            }
        }
        switch (level) {
            case "warn", "error" -> System.err.println(prefix + " " + message);
            default -> System.out.println(prefix + " " + message);
        }
    }

    // ── Anomaly-Gated Metering: Aggregate Telemetry Rollup Buffer ──────────
    //
    // Option B (2026-08-27): CLEAN/unflagged traffic no longer gets a full,
    // billed event row per request. Instead this buffer accumulates
    // lightweight per-alias/IP-per-hour counters in memory (request count,
    // unique endpoints seen, error count, latency sum) and flushes them as a
    // small number of upsert-increment rows to `/api/events/telemetry-rollup`
    // on a short interval — not per request. Mirrors
    // packages/devfortress-sdk/src/telemetry-rollup-buffer.ts.

    /** Hour-bucket period key, e.g. "2026-08-27T14" — matches the Node helper and AliasTelemetryRollup.periodKey. */
    public static String hourlyPeriodKey(Instant instant) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH").withZone(ZoneOffset.UTC).format(instant);
    }

    /** {@link #hourlyPeriodKey(Instant)} for the current instant. */
    public static String hourlyPeriodKey() {
        return hourlyPeriodKey(Instant.now());
    }

    /** One clean (non-flagged) request's contribution, buffered by {@link RollupBuffer#add}. */
    public record RollupContribution(String aliasOrIpKey, String endpoint, boolean isError, long latencyMs) {
    }

    /**
     * Composite (aliasOrIpKey, periodKey) bucket key. Node's implementation
     * concatenates the two strings with an embedded NUL byte as a
     * collision-proof separator (since either field may itself contain any
     * other delimiter character); this record is the Java-idiomatic
     * equivalent — a proper immutable value type with structural {@code
     * equals()}/{@code hashCode()}, so collision-freedom comes from field
     * identity rather than a separator character at all.
     */
    private record BucketKey(String aliasOrIpKey, String periodKey) {
    }

    private static final class RollupBucket {
        final String aliasOrIpKey;
        final String periodKey;
        int requestCount;
        final java.util.Set<String> endpoints = new java.util.LinkedHashSet<>();
        int errorCount;
        long latencySumMs;
        long windowStart;
        long windowEnd;

        RollupBucket(String aliasOrIpKey, String periodKey, long now) {
            this.aliasOrIpKey = aliasOrIpKey;
            this.periodKey = periodKey;
            this.windowStart = now;
            this.windowEnd = now;
        }
    }

    /**
     * Buffers non-billed, best-effort aggregate telemetry rollup
     * contributions and flushes them to the platform in small batches.
     * Mirrors Node's {@code TelemetryRollupBuffer}.
     */
    public static final class RollupBuffer implements AutoCloseable {
        // Bounded per-bucket endpoint tracking — uniqueEndpoints is an approximation
        // (this is non-billing, best-effort aggregate telemetry, not an exact count).
        private static final int MAX_ENDPOINTS_TRACKED_PER_BUCKET = 50;
        // Matches DEFAULT_HEARTBEAT_INTERVAL_MS above — this is aggregate,
        // non-billing telemetry, not real-time-critical, so a wider batching
        // window means fewer platform requests and keeps this interval
        // consistent with this SDK's other daemon background timer.
        private static final long DEFAULT_FLUSH_INTERVAL_MS = 5 * 60 * 1000;
        private static final int DEFAULT_MAX_BUFFERED_KEYS = 500;

        /** Configures a {@link RollupBuffer}. */
        public static final class Builder {
            private final String apiKey;
            private final String endpoint;
            private long flushIntervalMs = DEFAULT_FLUSH_INTERVAL_MS;
            private int maxBufferedKeys = DEFAULT_MAX_BUFFERED_KEYS;
            private boolean debug;
            private Transport transport;
            private Logger logger;

            private Builder(String apiKey, String endpoint) {
                this.apiKey = apiKey;
                this.endpoint = endpoint;
            }

            public Builder flushIntervalMs(long flushIntervalMs) {
                this.flushIntervalMs = flushIntervalMs;
                return this;
            }

            public Builder maxBufferedKeys(int maxBufferedKeys) {
                this.maxBufferedKeys = maxBufferedKeys;
                return this;
            }

            public Builder debug(boolean debug) {
                this.debug = debug;
                return this;
            }

            public Builder transport(Transport transport) {
                this.transport = transport;
                return this;
            }

            public Builder logger(Logger logger) {
                this.logger = logger;
                return this;
            }

            public RollupBuffer build() {
                return new RollupBuffer(this);
            }
        }

        public static Builder builder(String apiKey, String endpoint) {
            return new Builder(apiKey, endpoint);
        }

        private final String endpoint;
        private final long flushIntervalMs;
        private final int maxBufferedKeys;
        private final boolean debug;
        private final Transport transport;
        private final Logger logger;
        private final Signer signer;

        private final Map<BucketKey, RollupBucket> buckets = new ConcurrentHashMap<>();
        private ScheduledExecutorService flushExecutor;
        private ScheduledFuture<?> flushTask;

        private RollupBuffer(Builder b) {
            if (b.apiKey == null || b.apiKey.isEmpty()) {
                throw new IllegalArgumentException("devfortress: an API key is required");
            }
            this.endpoint = b.endpoint;
            this.flushIntervalMs = b.flushIntervalMs;
            this.maxBufferedKeys = b.maxBufferedKeys;
            this.debug = b.debug;
            this.transport = b.transport == null ? new HttpTransport() : b.transport;
            this.logger = b.logger;
            this.signer = new Signer(b.apiKey);
        }

        /** Start the periodic flush timer. Safe to call multiple times (a no-op if already started). */
        public synchronized void start() {
            if (flushExecutor != null) {
                return;
            }
            flushExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "devfortress-rollup-flush");
                t.setDaemon(true); // mirrors Node's timer.unref(): never blocks process exit
                return t;
            });
            flushTask = flushExecutor.scheduleAtFixedRate(
                    this::flushQuietly, flushIntervalMs, flushIntervalMs, TimeUnit.MILLISECONDS);
        }

        private void flushQuietly() {
            try {
                flush();
            } catch (RuntimeException ignored) {
                // Best-effort — see flush()'s own failure handling.
            }
        }

        /**
         * Buffer one clean (non-flagged) request's contribution.
         * Synchronous, no network call — actual delivery happens on the
         * next {@link #flush}.
         */
        public void add(RollupContribution input) {
            String periodKey = hourlyPeriodKey();
            BucketKey bucketKey = new BucketKey(input.aliasOrIpKey(), periodKey);
            long now = System.currentTimeMillis();

            RollupBucket bucket = buckets.get(bucketKey);
            if (bucket == null) {
                // Bound total buffered keys so a burst of unique IPs can't grow memory
                // unbounded — force an early flush and drop this one contribution.
                // Acceptable: this is approximate, non-billing aggregate telemetry.
                if (buckets.size() >= maxBufferedKeys) {
                    flushQuietly();
                    return;
                }
                bucket = buckets.computeIfAbsent(bucketKey, k -> new RollupBucket(input.aliasOrIpKey(), periodKey, now));
            }

            synchronized (bucket) {
                bucket.requestCount++;
                if (bucket.endpoints.size() < MAX_ENDPOINTS_TRACKED_PER_BUCKET) {
                    bucket.endpoints.add(input.endpoint());
                }
                if (input.isError()) {
                    bucket.errorCount++;
                }
                bucket.latencySumMs += input.latencyMs();
                bucket.windowEnd = now;
            }
        }

        /** Flush all buffered buckets to the platform in one batch request. */
        public void flush() {
            if (buckets.isEmpty()) {
                return;
            }
            List<BucketKey> keys = new ArrayList<>(buckets.keySet());
            List<Map<String, Object>> contributions = new ArrayList<>();
            for (BucketKey key : keys) {
                RollupBucket b = buckets.remove(key);
                if (b == null) {
                    continue;
                }
                synchronized (b) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("aliasOrIpKey", b.aliasOrIpKey);
                    entry.put("periodKey", b.periodKey);
                    entry.put("requestCount", b.requestCount);
                    entry.put("uniqueEndpointsInBatch", b.endpoints.size());
                    entry.put("errorCount", b.errorCount);
                    entry.put("latencySumMs", b.latencySumMs);
                    entry.put("windowStart", b.windowStart);
                    entry.put("windowEnd", b.windowEnd);
                    contributions.add(entry);
                }
            }
            if (contributions.isEmpty()) {
                return;
            }

            try {
                String url = endpoint + "/api/events/telemetry-rollup";
                String requestTarget = Signer.requestTargetFromUrl(url);
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("contributions", contributions);
                String body = Json.encode(payload);

                Map<String, String> headers = new LinkedHashMap<>(signer.sign("POST", requestTarget, body, null, null));
                headers.put("Content-Type", "application/json");

                transport.send("POST", url, headers, body.getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(10));
            } catch (Exception e) {
                // Best-effort — aggregate telemetry is not billing-relevant, so
                // dropping a batch on transient failure is acceptable (unlike the
                // full event relay path, which retries).
                log("debug", "telemetry rollup flush failed: " + (e.getMessage() != null ? e.getMessage() : "Unknown"));
            }
        }

        /** Clean up the flush timer and drop any unflushed buckets. */
        public synchronized void destroy() {
            if (flushTask != null) {
                flushTask.cancel(false);
                flushTask = null;
            }
            if (flushExecutor != null) {
                flushExecutor.shutdown();
                flushExecutor = null;
            }
            buckets.clear();
        }

        @Override
        public void close() {
            destroy();
        }

        private void log(String level, String message) {
            if (!debug) {
                return;
            }
            String prefix = "[DevFortress]";
            if (logger != null) {
                try {
                    logger.log(level, prefix + " " + message, Map.of());
                    return;
                } catch (RuntimeException ignored) {
                    // A panicking Logger must not reach the host application either.
                }
            }
            System.out.println(prefix + " " + message);
        }
    }
}
