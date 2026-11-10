package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A DevFortress event client (external mode).
 *
 * <p>Events are queued in memory ({@link #trackEvent}, {@link #trackEvents})
 * and delivered in batches ({@code {"events": [...]}}, server maximum
 * {@link #MAX_SERVER_BATCH}) by {@link #flush}. Every request is signed
 * with the request signature contract (see {@link Signer}): the API key
 * never goes on the wire, only a key ID does.
 *
 * <p>Retry: up to {@code retries} attempts, exponential backoff, only on 5xx
 * responses and network errors. 3xx and 4xx responses are never retried.
 * Every attempt is signed again with a fresh nonce and timestamp.
 *
 * <p>Delivery never throws into the host application: a failed delivery
 * comes back as a {@link DeliveryResult} and is logged. Only a missing API
 * key fails construction. The queue is safe for concurrent use. Mirrors
 * {@code packages/devfortress-go/client.go}.
 */
public final class Client implements AutoCloseable {
    public static final String VERSION = "0.1.0";
    public static final String DEFAULT_ENDPOINT = "https://www.devfortress.net/api/events/ingest";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(15);
    public static final int DEFAULT_RETRIES = 3;
    public static final int DEFAULT_BATCH_SIZE = 25;
    /** Largest number of events the platform accepts in one ingest request; flush splits into chunks this size. */
    public static final int MAX_SERVER_BATCH = 100;

    private final Signer signer;
    private final String endpoint;
    private final String requestTarget;
    private final Duration timeout;
    private final int retries;
    private final int batchSize;
    private final Duration backoffBase;
    private final Map<String, Object> defaults;
    private final String privacy;
    private final Logger logger;
    private final Transport transport;

    private final Object lock = new Object();
    private final List<Map<String, Object>> queue = new ArrayList<>();

    // ── Mode / internal closed-loop engine (TODO 407 port) ──────────────
    // Mirrors Node's DevFortressCore and the Python port's DevFortressClient:
    // internal/hybrid mode gets its own InternalClosedLoopEngine instance;
    // hybrid additionally gets a PlatformCircuitBreaker guarding the
    // external-enrichment leg. External mode (the default) leaves both null
    // — no behavior change for existing callers.
    private final TierGate.CLMode mode;
    private final InternalClosedLoopEngine internalEngine;
    private final PlatformCircuitBreaker circuitBreaker;

    private final ScheduledExecutorService flushExecutor;
    private final ExecutorService observerExecutor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "devfortress-observer");
        t.setDaemon(true);
        return t;
    });
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private ScheduledFuture<?> flushTask;

    private Client(Builder b) {
        this.signer = new Signer(b.apiKey);
        this.endpoint = (b.endpoint == null || b.endpoint.isEmpty()) ? DEFAULT_ENDPOINT : b.endpoint;
        this.requestTarget = Signer.requestTargetFromUrl(this.endpoint);
        this.timeout = b.timeout;
        this.retries = Math.max(1, b.retries);
        this.batchSize = Math.max(1, b.batchSize);
        this.backoffBase = b.backoffBase;
        this.defaults = b.defaults == null ? Map.of() : b.defaults;
        this.privacy = b.privacy;
        this.logger = b.logger;
        this.transport = b.transport == null ? new HttpTransport() : b.transport;

        this.mode = b.mode;
        InternalClosedLoopEngine engine = null;
        PlatformCircuitBreaker breaker = null;
        if (mode == TierGate.CLMode.INTERNAL || mode == TierGate.CLMode.HYBRID) {
            InternalClosedLoopEngine.Config cfg = b.internalClConfig == null
                    ? InternalClosedLoopEngine.Config.builder().build()
                    : b.internalClConfig;
            cfg = cfg.withEnableExternalRelay(mode == TierGate.CLMode.HYBRID);
            if (cfg.onRelay() == null && mode == TierGate.CLMode.HYBRID) {
                cfg = cfg.withOnRelay(this::relayInternalDecisionToPlatform);
            }
            engine = new InternalClosedLoopEngine(cfg);
        }
        if (mode == TierGate.CLMode.HYBRID) {
            breaker = new PlatformCircuitBreaker(b.circuitBreakerFailureThreshold, b.circuitBreakerRecoveryTimeMs, null);
        }
        this.internalEngine = engine;
        this.circuitBreaker = breaker;

        if (b.flushInterval != null && !b.flushInterval.isZero()) {
            this.flushExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "devfortress-flush");
                t.setDaemon(true);
                return t;
            });
            this.flushTask = flushExecutor.scheduleAtFixedRate(
                    this::flush, b.flushInterval.toMillis(), b.flushInterval.toMillis(), TimeUnit.MILLISECONDS);
        } else {
            this.flushExecutor = null;
        }
    }

    public static Builder builder(String apiKey) {
        return new Builder(apiKey);
    }

    /** Configures a {@link Client}. */
    public static final class Builder {
        private final String apiKey;
        private String endpoint;
        private Duration timeout = DEFAULT_TIMEOUT;
        private int retries = DEFAULT_RETRIES;
        private int batchSize = DEFAULT_BATCH_SIZE;
        private Duration backoffBase = Duration.ofSeconds(1);
        private Map<String, Object> defaults;
        private String privacy = "standard";
        private Logger logger;
        private Transport transport;
        private Duration flushInterval;
        private TierGate.CLMode mode = TierGate.CLMode.EXTERNAL;
        private InternalClosedLoopEngine.Config internalClConfig;
        private int circuitBreakerFailureThreshold = 3;
        private long circuitBreakerRecoveryTimeMs = 60_000L;

        private Builder(String apiKey) {
            this.apiKey = apiKey;
        }

        public Builder endpoint(String endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder retries(int retries) {
            this.retries = retries;
            return this;
        }

        public Builder batchSize(int batchSize) {
            this.batchSize = batchSize;
            return this;
        }

        public Builder backoffBase(Duration backoffBase) {
            this.backoffBase = backoffBase;
            return this;
        }

        public Builder defaults(Map<String, Object> defaults) {
            this.defaults = defaults;
            return this;
        }

        /** "standard" (default) or "strict" (no user agents, 16-hex-character hashed IPs). */
        public Builder privacy(String privacy) {
            this.privacy = privacy;
            return this;
        }

        public Builder logger(Logger logger) {
            this.logger = logger;
            return this;
        }

        /** Replaces the HTTP transport, e.g. with a recording transport in tests. */
        public Builder transport(Transport transport) {
            this.transport = transport;
            return this;
        }

        /**
         * Starts a background task that flushes the queue on this interval,
         * stopped by {@link Client#close}. Omitted (the default) disables
         * it; callers then flush explicitly ({@link Client#flush},
         * {@link Client#close}, the batch-size auto-flush, or
         * {@link Observer#observeAndFlush}) — mirrors Go's
         * {@code WithFlushInterval} safety net.
         */
        public Builder flushInterval(Duration flushInterval) {
            this.flushInterval = flushInterval;
            return this;
        }

        /**
         * Closed-loop mode: "external" (default, no behavior change for
         * existing callers), "internal", or "hybrid". Internal/hybrid get
         * their own {@link InternalClosedLoopEngine}; hybrid additionally
         * gets a {@link PlatformCircuitBreaker}. Mirrors Node's and the
         * Python port's {@code mode} constructor kwarg.
         */
        public Builder mode(String mode) {
            this.mode = TierGate.CLMode.fromWire(mode);
            return this;
        }

        public Builder mode(TierGate.CLMode mode) {
            this.mode = mode;
            return this;
        }

        /** Overrides the default {@link InternalClosedLoopEngine.Config} used for internal/hybrid mode. */
        public Builder internalClConfig(InternalClosedLoopEngine.Config config) {
            this.internalClConfig = config;
            return this;
        }

        /** Hybrid mode only: {@link PlatformCircuitBreaker} failure threshold (default 3). */
        public Builder circuitBreakerFailureThreshold(int threshold) {
            this.circuitBreakerFailureThreshold = threshold;
            return this;
        }

        /** Hybrid mode only: {@link PlatformCircuitBreaker} recovery time in milliseconds (default 60000). */
        public Builder circuitBreakerRecoveryTimeMs(long ms) {
            this.circuitBreakerRecoveryTimeMs = ms;
            return this;
        }

        public Client build() {
            return new Client(this);
        }
    }

    /** {@link #observe} result: non-null only when the request should be blocked/rate-limited/challenged/quarantined. */
    public record ObserveResult(
            boolean flagged,
            String eventId,
            double confidence,
            InternalClosedLoopEngine.Decision decision,
            List<String> matchedRules) {
    }

    /** The configured closed-loop mode (default {@link TierGate.CLMode#EXTERNAL}). */
    public TierGate.CLMode getMode() {
        return mode;
    }

    /** Non-null only in internal/hybrid mode. */
    public InternalClosedLoopEngine getInternalEngine() {
        return internalEngine;
    }

    /** Non-null only in hybrid mode. */
    public PlatformCircuitBreaker getCircuitBreaker() {
        return circuitBreaker;
    }

    /**
     * Evaluate a request through internal/hybrid closed-loop mode. Returns
     * a flagged {@link ObserveResult} if the request should be blocked/
     * rate-limited/challenged/quarantined, else {@code null} (allowed).
     * No-op (returns {@code null}) in external mode. Mirrors Node's
     * {@code observeInternal}/{@code observeHybrid} and the Python port's
     * {@code observe()}.
     */
    public ObserveResult observe(InternalClosedLoopEngine.InternalCLRequest req) {
        if (mode == TierGate.CLMode.INTERNAL) {
            return observeInternal(req);
        }
        if (mode == TierGate.CLMode.HYBRID) {
            return observeHybrid(req);
        }
        return null;
    }

    private ObserveResult observeInternal(InternalClosedLoopEngine.InternalCLRequest req) {
        if (internalEngine == null) {
            return null;
        }
        InternalClosedLoopEngine.InternalCLResult result = internalEngine.evaluate(req);
        if (result.decision() != InternalClosedLoopEngine.Decision.ALLOW) {
            return new ObserveResult(true, result.eventId(), result.score() / 100.0, result.decision(), result.matchedRules());
        }
        return null;
    }

    private ObserveResult observeHybrid(InternalClosedLoopEngine.InternalCLRequest req) {
        // Step 1: internal evaluation (immediate, sub-ms, no round-trip).
        ObserveResult internalResult = observeInternal(req);
        if (internalResult != null) {
            // The internal engine's own onRelay callback (see the constructor)
            // already handles the Tier-3 relay for this decision — no second
            // relay call here, matching Node's TODO-210 double-billing fix and
            // the Python port's same no-second-relay behavior.
            return internalResult;
        }

        // Step 2: external enrichment, circuit-breaker gated.
        //
        // KNOWN LIMITATION (flagged explicitly, not silently claimed as full
        // parity): Node's observeHybrid() calls observeExternal() here to
        // fetch a real platform-side enrichment verdict. Like the Python
        // port, this does not yet make that platform call — it only
        // exercises the circuit breaker's success/failure bookkeeping around
        // a no-op enrichment step, so clean traffic is allowed and the
        // circuit stays closed, but a request internal mode misses that only
        // the platform's own cross-customer intelligence would have caught
        // is not enriched here.
        if (circuitBreaker != null && circuitBreaker.shouldCallExternal()) {
            circuitBreaker.recordSuccess();
        }
        return null;
    }

    /**
     * Whether {@code ip} is currently blocked by the internal engine's
     * in-memory cache. Always false in external mode (no internal engine
     * exists). Mirrors Node's {@code isIPBlocked} and the Python port's
     * {@code is_blocked()}.
     */
    public boolean isBlocked(String ip) {
        if (internalEngine == null) {
            return false;
        }
        return internalEngine.isIpBlocked(ip);
    }

    /**
     * Tier-3 relay target for hybrid mode — wired as the internal engine's
     * {@code onRelay} callback in the constructor. Reuses the existing
     * {@link #trackEvent} path, same as every other outbound event in this
     * client, rather than opening a second HTTP path. Mirrors Python's
     * {@code _relay_internal_decision_to_platform}.
     */
    /**
     * Wired as the internal engine's {@code onRelay} callback, invoked
     * synchronously within {@code evaluate} (see {@link
     * InternalClosedLoopEngine}'s own doc comment on why: evaluation
     * itself must stay zero-network and deterministic). {@link
     * #trackEvent} below only enqueues — fast, in-memory, safe to call
     * synchronously here — and {@link #runDetached} pushes the actual
     * delivery onto this client's own detached observer executor,
     * mirroring {@link Observer#observeAndFlush}'s exact pattern. Found
     * live, via this port's own end-to-end demo proof against a real
     * platform (not the dummy unreachable endpoint sdk-validation-v4.sh's
     * own ICL phase deliberately uses): without this, a relayed event
     * could sit queued for up to this client's flush interval, even
     * though the request itself was already blocked and responded to.
     */
    private void relayInternalDecisionToPlatform(InternalClosedLoopEngine.InternalCLResult result, InternalClosedLoopEngine.InternalCLRequest req) {
        String eventType = result.matchedRules().isEmpty()
                ? "icl_" + result.decision().wireValue()
                : result.matchedRules().get(0);
        String severity = result.score() >= 85 ? "CRITICAL" : result.score() >= 60 ? "HIGH" : result.score() >= 35 ? "MEDIUM" : "LOW";
        String actionTaken = switch (result.decision()) {
            case ALLOW -> "allowed";
            case BLOCK -> "blocked";
            case RATE_LIMIT -> "rate_limited";
            case CHALLENGE -> "challenge_required";
            case QUARANTINE -> "flagged";
        };

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("source", "internal-closed-loop-engine");
        metadata.put("tier", result.tier());
        metadata.put("matchedRules", result.matchedRules());
        metadata.put("internalEventId", result.eventId());
        metadata.put("sessionId", req.sessionId());
        metadata.put("agentId", req.agentId());

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventType", eventType);
        event.put("ip", req.ip());
        event.put("severity", severity);
        event.put("method", req.method());
        event.put("path", req.path());
        event.put("userAgent", req.userAgent());
        event.put("authPhase", notEmptyString(req.userId()) ? "post_auth" : "pre_auth");
        event.put("actionTaken", actionTaken);
        event.put("responseLatencyMs", Math.round(result.evaluationTimeUs() / 1000.0));
        event.put("clMode", "hybrid");
        event.put("metadata", metadata);

        try {
            trackEvent(event);
            runDetached(this::flush);
        } catch (RuntimeException e) {
            log("warning", "devfortress: internal-decision relay failed: " + e.getMessage(), Map.of());
        }
    }

    private static boolean notEmptyString(String s) {
        return s != null && !s.isEmpty();
    }

    /**
     * Queues one event. The queue is sent (synchronously, like
     * {@link #flush}) once it reaches the batch size; it is also sent when
     * {@link #flush} is called, or at {@link #close}.
     *
     * <p><b>This only queues.</b> Under sparse traffic (fewer events than
     * the batch size between flushes and no {@code flushInterval}
     * configured), a tracked event can sit undelivered indefinitely. A
     * caller that observes one request at a time (an adapter/filter) should
     * use {@link Observer#observeAndFlush}, not raw {@code trackEvent}
     * followed by nothing — this is the exact gap Go's gin adapter shipped
     * with originally (see the SDK audit notes), fixed by flushing after
     * every observed request.
     */
    public void trackEvent(Map<String, Object> event) {
        trackEvents(List.of(event));
    }

    public void trackEvents(List<Map<String, Object>> events) {
        boolean shouldFlush;
        synchronized (lock) {
            for (Map<String, Object> event : events) {
                queue.add(prepare(event));
            }
            shouldFlush = queue.size() >= batchSize;
        }
        if (shouldFlush) {
            flush();
        }
    }

    /**
     * Sends everything queued, in chunks of at most {@link #MAX_SERVER_BATCH}
     * events, and returns one {@link DeliveryResult} per chunk. Never throws;
     * failures are reported through the returned results.
     */
    public List<DeliveryResult> flush() {
        List<Map<String, Object>> events;
        synchronized (lock) {
            events = new ArrayList<>(queue);
            queue.clear();
        }
        if (events.isEmpty()) {
            return List.of();
        }

        List<DeliveryResult> results = new ArrayList<>();
        for (int i = 0; i < events.size(); i += MAX_SERVER_BATCH) {
            List<Map<String, Object>> chunk = events.subList(i, Math.min(i + MAX_SERVER_BATCH, events.size()));
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("events", chunk);
            results.add(post(payload));
        }
        return results;
    }

    /** The number of events waiting to be flushed. */
    public int pendingEvents() {
        synchronized (lock) {
            return queue.size();
        }
    }

    /**
     * Reports whether the platform accepts a signed test event with this
     * key. Never throws; an unreachable platform or a rejected key both
     * report false.
     */
    public boolean testConnection() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("test", true);
        metadata.put("sdk", "java");
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventType", "custom");
        event.put("ip", "127.0.0.1");
        event.put("method", "GET");
        event.put("path", "/__devfortress/test");
        event.put("severity", "LOW");
        event.put("authPhase", "pre_auth");
        event.put("actionTaken", "monitored");
        event.put("responseLatencyMs", 0);
        event.put("clMode", "external");
        event.put("metadata", metadata);
        return post(prepare(event)).ok;
    }

    /**
     * Stops the background flush task (if any), the observer executor, and
     * flushes whatever is still queued. Safe to call more than once.
     */
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        if (flushTask != null) {
            flushTask.cancel(false);
        }
        if (flushExecutor != null) {
            flushExecutor.shutdown();
        }
        observerExecutor.shutdown();
        try {
            observerExecutor.awaitTermination(timeout.toMillis() + 1000, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        flush();
    }

    /** Submits a task to this client's observer executor — used by {@link Observer}. */
    void runDetached(Runnable task) {
        if (closed.get()) {
            return;
        }
        observerExecutor.submit(task);
    }

    private Map<String, Object> prepare(Map<String, Object> event) {
        Map<String, Object> item = new LinkedHashMap<>(defaults);
        item.putAll(event);
        item.putIfAbsent("timestamp", Instant.now().atZone(java.time.ZoneOffset.UTC)
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")));
        if ("strict".equals(privacy)) {
            item.remove("userAgent");
            Object ip = item.get("ip");
            if (ip instanceof String ipStr) {
                item.put("ip", hashIp(ipStr));
            }
        }
        if (item.containsKey("metadata") && item.get("metadata") == null) {
            item.put("metadata", new LinkedHashMap<>());
        }
        return item;
    }

    private static String hashIp(String ip) {
        try {
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(ip.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : sum) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.substring(0, 16);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private DeliveryResult post(Map<String, Object> payload) {
        byte[] raw;
        try {
            raw = Json.encode(payload).getBytes(StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return fail(DeliveryResult.failed(e, 0));
        }

        DeliveryResult last = DeliveryResult.failed(new RuntimeException("no delivery attempt was made"), 0);
        for (int attempt = 1; attempt <= retries; attempt++) {
            // A fresh nonce and timestamp on every attempt, so a retry is not a replay.
            Map<String, String> headers = new LinkedHashMap<>(signer.sign("POST", requestTarget, new String(raw, StandardCharsets.UTF_8), null, null));
            headers.put("Content-Type", "application/json");
            headers.put("Accept", "application/json");
            headers.put("User-Agent", "devfortress-sdk-java/" + VERSION);

            Transport.TransportResponse response;
            try {
                response = transport.send("POST", endpoint, headers, raw, timeout);
            } catch (Exception sendErr) {
                last = DeliveryResult.failed(new RuntimeException("request failed: " + sendErr.getMessage(), sendErr), attempt);
                response = null;
            }

            if (response != null) {
                Object body = decodeBody(response.body());
                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    return new DeliveryResult(true, response.statusCode(), body, null, attempt);
                }
                last = DeliveryResult.httpFailure(response.statusCode(), body,
                        new RuntimeException("HTTP " + response.statusCode()), attempt);
                if (response.statusCode() < 500) {
                    return fail(last); // 3xx and 4xx: never retried
                }
            }

            if (attempt < retries) {
                sleep(Duration.ofMillis((long) (backoffBase.toMillis() * Math.pow(2, attempt - 1))));
            }
        }

        return fail(last);
    }

    private void sleep(Duration d) {
        if (d.isZero() || d.isNegative()) {
            return;
        }
        try {
            Thread.sleep(d.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private DeliveryResult fail(DeliveryResult result) {
        String message = result.error != null ? result.error.getMessage() : "unknown error";
        log("warning", "devfortress: delivery failed: " + message, Map.of(
                "status", result.statusCode,
                "attempts", result.attempts));
        return result;
    }

    private void log(String level, String message, Map<String, Object> fields) {
        if (logger == null) {
            return;
        }
        try {
            logger.log(level, message, fields);
        } catch (RuntimeException ignored) {
            // A panicking Logger must not reach the host application either.
        }
    }

    private static Object decodeBody(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return Map.of();
        }
        try {
            return Json.decode(new String(raw, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return new String(raw, StandardCharsets.UTF_8);
        }
    }
}
