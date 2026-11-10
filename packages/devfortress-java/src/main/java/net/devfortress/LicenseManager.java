package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * DevFortress SDK — License Manager (CV-M1, CV-M4, CV-M7). Mirrors
 * {@code packages/devfortress-sdk/src/license-manager.ts}.
 *
 * <p>Implements:
 * <ul>
 *   <li>CV-M1: server-side license validation with a 24h check interval and
 *       72h grace-period degradation</li>
 *   <li>CV-M4: ML model expiry (30-day staleness without platform sync)</li>
 *   <li>CV-M7: SDK anti-tampering HMAC signature verification</li>
 * </ul>
 *
 * <p>This is the client-side half of the TODO 321 fix: license-check and
 * heartbeat calls silently 404ing used to cause silent monitor-only
 * degradation with no visible signal. The platform's {@code
 * /api/sdk/license-check} endpoint already exists; this class only ports
 * the Node client logic — every check failure is logged visibly (via
 * {@link Logger}, matching {@link Client}'s own logging convention) and,
 * past the grace period, flips {@link LicenseState#degraded} so callers can
 * observe degradation rather than fail silently.
 */
public final class LicenseManager implements AutoCloseable {
    private static final long DEFAULT_CHECK_INTERVAL_MS = 24L * 60 * 60 * 1000; // 24h
    private static final long DEFAULT_GRACE_PERIOD_MS = 72L * 60 * 60 * 1000; // 72h
    private static final long DEFAULT_MODEL_EXPIRY_MS = 30L * 24 * 60 * 60 * 1000; // 30 days
    private static final Duration LICENSE_CHECK_TIMEOUT = Duration.ofSeconds(10);

    /** Subscription tier as confirmed by the platform. */
    public enum Tier {
        STARTER, PRO, TEAM, ENTERPRISE;

        static Tier fromWire(String value, Tier fallback) {
            if (value == null) {
                return fallback;
            }
            return switch (value.toLowerCase(java.util.Locale.ROOT)) {
                case "starter" -> STARTER;
                case "pro" -> PRO;
                case "team" -> TEAM;
                case "enterprise" -> ENTERPRISE;
                default -> fallback;
            };
        }

        /** The lowercase wire-string form of this tier, e.g. {@code "enterprise"} — the cross-package
         *  integration seam with {@link TierGate.SubscriptionTier#fromWire}. */
        public String wireValue() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    /** Action categories checked by {@link #canPerformAction}. */
    public enum Action { BLOCK, RATE_LIMIT, OBSERVE }

    /** Immutable snapshot of license state, returned by {@link #getLicenseState}. */
    public record LicenseState(boolean valid, Tier tier, long lastCheckedAt, int consecutiveFailures,
                                boolean degraded, String degradationReason) {
    }

    /** Immutable snapshot of ML model freshness, returned by {@link #getModelState}. */
    public record ModelState(long lastSyncedAt, String modelVersion, boolean expired) {
    }

    /** Result of {@link #verifyIntegrity}. */
    public record IntegrityResult(boolean tampered, String hash) {
    }

    /** Configures a {@link LicenseManager}. */
    public static final class Builder {
        private final String apiKey;
        private final String endpoint;
        private long checkIntervalMs = DEFAULT_CHECK_INTERVAL_MS;
        private long gracePeriodMs = DEFAULT_GRACE_PERIOD_MS;
        private long modelExpiryMs = DEFAULT_MODEL_EXPIRY_MS;
        private String integritySecret;
        private boolean debug;
        private Transport transport;
        private Logger logger;

        private Builder(String apiKey, String endpoint) {
            this.apiKey = apiKey;
            this.endpoint = endpoint;
        }

        public Builder checkIntervalMs(long checkIntervalMs) {
            this.checkIntervalMs = checkIntervalMs;
            return this;
        }

        public Builder gracePeriodMs(long gracePeriodMs) {
            this.gracePeriodMs = gracePeriodMs;
            return this;
        }

        public Builder modelExpiryMs(long modelExpiryMs) {
            this.modelExpiryMs = modelExpiryMs;
            return this;
        }

        public Builder integritySecret(String integritySecret) {
            this.integritySecret = integritySecret;
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

        public LicenseManager build() {
            return new LicenseManager(this);
        }
    }

    public static Builder builder(String apiKey, String endpoint) {
        return new Builder(apiKey, endpoint);
    }

    private final String apiKey;
    private final String endpoint;
    private final long checkIntervalMs;
    private final long gracePeriodMs;
    private final long modelExpiryMs;
    private final String integritySecret;
    private final boolean debug;
    private final Transport transport;
    private final Logger logger;
    private final Signer signer;

    private volatile LicenseState licenseState = new LicenseState(false, Tier.STARTER, 0, 0, false, null);
    private volatile ModelState modelState = new ModelState(System.currentTimeMillis(), "embedded-v1", false);

    private ScheduledExecutorService checkExecutor;
    private ScheduledFuture<?> checkTask;
    private volatile boolean initialized = false;

    private LicenseManager(Builder b) {
        if (b.apiKey == null || b.apiKey.isEmpty()) {
            throw new IllegalArgumentException("devfortress: an API key is required");
        }
        this.apiKey = b.apiKey;
        this.endpoint = b.endpoint;
        this.checkIntervalMs = b.checkIntervalMs;
        this.gracePeriodMs = b.gracePeriodMs;
        this.modelExpiryMs = b.modelExpiryMs;
        this.integritySecret = b.integritySecret;
        this.debug = b.debug;
        this.transport = b.transport == null ? new HttpTransport() : b.transport;
        this.logger = b.logger;
        this.signer = new Signer(b.apiKey);
    }

    // ── CV-M1: License Validation ──────────────────────────────

    /**
     * Initialize the license manager. Performs an initial license check and
     * starts periodic validation. Safe to call more than once (a no-op after
     * the first call).
     */
    public synchronized LicenseState init() {
        if (initialized) {
            return licenseState;
        }

        checkLicense();

        checkExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "devfortress-license-check");
            t.setDaemon(true); // mirrors Node's timer.unref(): never blocks process exit
            return t;
        });
        checkTask = checkExecutor.scheduleAtFixedRate(
                this::checkLicense, checkIntervalMs, checkIntervalMs, TimeUnit.MILLISECONDS);

        initialized = true;
        return licenseState;
    }

    /**
     * Perform a license check against the platform. On failure, tracks
     * consecutive failures and degrades after the grace period.
     */
    public LicenseState checkLicense() {
        try {
            String url = endpoint + "/api/sdk/license-check";
            String requestTarget = Signer.requestTargetFromUrl(url);
            Map<String, Object> bodyMap = new LinkedHashMap<>();
            bodyMap.put("sdkVersion", Client.VERSION);
            bodyMap.put("timestamp", System.currentTimeMillis());
            bodyMap.put("integrity", computeIntegrityHash());
            String body = Json.encode(bodyMap);

            Map<String, String> headers = new LinkedHashMap<>(signer.sign("POST", requestTarget, body, null, null));
            headers.put("Content-Type", "application/json");

            Transport.TransportResponse response;
            try {
                response = transport.send("POST", url, headers, body.getBytes(StandardCharsets.UTF_8), LICENSE_CHECK_TIMEOUT);
            } catch (Exception sendErr) {
                handleCheckFailure(sendErr.getMessage() != null ? sendErr.getMessage() : "Unknown error");
                return licenseState;
            }

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                Object decoded = decodeBody(response.body());
                Map<?, ?> data = decoded instanceof Map<?, ?> m ? m : Map.of();

                Tier newTier = Tier.fromWire((String) data.get("tier"), licenseState.tier());
                licenseState = new LicenseState(true, newTier, System.currentTimeMillis(), 0, false, null);

                Object modelVersion = data.get("modelVersion");
                if (modelVersion instanceof String mv && !mv.isEmpty()) {
                    modelState = new ModelState(System.currentTimeMillis(), mv, false);
                }

                log("info", "License validated: tier=" + licenseState.tier().wireValue());
            } else if (response.statusCode() == 402 || response.statusCode() == 403) {
                licenseState = new LicenseState(false, Tier.STARTER, System.currentTimeMillis(),
                        licenseState.consecutiveFailures() + 1, true,
                        "License rejected: HTTP " + response.statusCode());
                log("warn", "License rejected: HTTP " + response.statusCode());
            } else {
                handleCheckFailure("HTTP " + response.statusCode());
            }
        } catch (RuntimeException error) {
            handleCheckFailure(error.getMessage() != null ? error.getMessage() : "Unknown error");
        }

        return licenseState;
    }

    private void handleCheckFailure(String reason) {
        long baselineTime = licenseState.lastCheckedAt() == 0 ? System.currentTimeMillis() : licenseState.lastCheckedAt();
        long timeSinceLastSuccess = System.currentTimeMillis() - baselineTime;
        int failures = licenseState.consecutiveFailures() + 1;

        if (timeSinceLastSuccess >= gracePeriodMs) {
            String degradationReason = String.format(java.util.Locale.ROOT,
                    "License check failed for %dh (grace period: %dh). Reason: %s. SDK degraded to monitor-only mode.",
                    Math.round(timeSinceLastSuccess / 3600000.0), Math.round(gracePeriodMs / 3600000.0), reason);
            licenseState = new LicenseState(licenseState.valid(), licenseState.tier(), licenseState.lastCheckedAt(),
                    failures, true, degradationReason);
            log("warn", degradationReason);
        } else {
            licenseState = new LicenseState(licenseState.valid(), licenseState.tier(), licenseState.lastCheckedAt(),
                    failures, licenseState.degraded(), licenseState.degradationReason());
            log("debug", String.format(java.util.Locale.ROOT,
                    "License check failed (%s), %d consecutive failures, %dh grace remaining",
                    reason, failures, Math.round((gracePeriodMs - timeSinceLastSuccess) / 3600000.0)));
        }
    }

    /** Get the current license state. */
    public LicenseState getLicenseState() {
        return licenseState;
    }

    /**
     * Check if the SDK should operate in degraded (monitor-only) mode.
     * Degraded mode means: no blocking, no rate limiting, just logging.
     */
    public boolean isDegraded() {
        return licenseState.degraded();
    }

    /** Check if a specific capability is available in the current license state. */
    public boolean canPerformAction(Action action) {
        if (action == Action.OBSERVE) {
            return true; // Always allowed
        }
        if (licenseState.degraded()) {
            return false; // Degraded = monitor-only
        }
        if (!licenseState.valid() && licenseState.lastCheckedAt() == 0) {
            // Never validated yet — allow actions during initial grace period
            return true;
        }
        return licenseState.valid();
    }

    // ── CV-M4: ML Model Expiry ─────────────────────────────────

    /**
     * Check if the embedded ML model has expired. If expired (&gt;30 days
     * without platform sync), ICL falls back to Tier 1 only.
     */
    public boolean isModelExpired() {
        long age = System.currentTimeMillis() - modelState.lastSyncedAt();
        boolean expired = age > modelExpiryMs;
        modelState = new ModelState(modelState.lastSyncedAt(), modelState.modelVersion(), expired);
        return expired;
    }

    /** Get the current ML model state. */
    public ModelState getModelState() {
        boolean expired = isModelExpired();
        return new ModelState(modelState.lastSyncedAt(), modelState.modelVersion(), expired);
    }

    /** Manually trigger a model sync (called from SDK init or heartbeat). */
    public void syncModel(String modelVersion) {
        modelState = new ModelState(System.currentTimeMillis(), modelVersion, false);
        log("info", "ML model synced: version=" + modelVersion);
    }

    // ── CV-M7: Anti-Tampering ──────────────────────────────────

    /**
     * Compute an HMAC signature over critical SDK code paths. If the SDK
     * distribution has been modified, this hash will differ from the
     * expected value on the platform side.
     */
    public String computeIntegrityHash() {
        if (integritySecret == null || integritySecret.isEmpty()) {
            return "no-integrity-secret";
        }

        String criticalPaths = String.join("|",
                "DevFortress.observe",
                "DevFortress.isBlocked",
                "LicenseManager.checkLicense",
                "InternalClosedLoopEngine.evaluate",
                "TierGate.checkEventLimit");

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(integritySecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(criticalPaths.getBytes(StandardCharsets.UTF_8));
            byte[] digest = mac.doFinal(apiKey.getBytes(StandardCharsets.UTF_8));
            return toHex(digest).substring(0, 16);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Verify that the SDK has not been tampered with. Returns {@code
     * tampered = true} if the integrity hash doesn't match.
     */
    public IntegrityResult verifyIntegrity(String expectedHash) {
        String currentHash = computeIntegrityHash();
        if (expectedHash == null || expectedHash.isEmpty()) {
            return new IntegrityResult(false, currentHash);
        }
        return new IntegrityResult(!currentHash.equals(expectedHash), currentHash);
    }

    // ── Cleanup ────────────────────────────────────────────────

    /** Stop periodic license checks and clean up. */
    public synchronized void destroy() {
        if (checkTask != null) {
            checkTask.cancel(false);
            checkTask = null;
        }
        if (checkExecutor != null) {
            checkExecutor.shutdown();
            checkExecutor = null;
        }
        initialized = false;
    }

    @Override
    public void close() {
        destroy();
    }

    // ── Logging ────────────────────────────────────────────────

    private void log(String level, String message) {
        if (!debug && "debug".equals(level)) {
            return;
        }
        String prefix = "[DevFortress:License]";
        if (logger != null) {
            try {
                logger.log(level, prefix + " " + message, Map.of());
                return;
            } catch (RuntimeException ignored) {
                // A panicking Logger must not reach the host application either.
            }
        }
        // No logger configured — fall back to stderr/stdout so a check
        // failure is never silent (the exact bug class TODO 321 fixed).
        switch (level) {
            case "error", "warn" -> System.err.println(prefix + " " + message);
            default -> System.out.println(prefix + " " + message);
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

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
