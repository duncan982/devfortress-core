package net.devfortress;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * DevFortress SDK — Internal Closed-Loop Protection Engine (TODO 407 port).
 * Port of the Node SDK's {@code internal-closed-loop-engine.ts}, following
 * the same structure as the already-completed Python port
 * ({@code packages/devfortress-python/src/devfortress/internal_closed_loop_engine.py}).
 *
 * <p>Three tiers:
 * <ul>
 *   <li>Tier 1: deterministic rule engine (&lt;1ms) — regex/signature/
 *       set-membership rules, highest-scoring match wins.</li>
 *   <li>Tier 2: an optional caller-supplied {@link Tier2Scorer}.
 *       <b>Unimplemented/pass-through by default</b> — {@link #evaluate}
 *       skips Tier 2 entirely when none is configured, exactly as Node does
 *       when {@code tier2Scorer} is unset and as the Python port does when
 *       {@code tier2_scorer} is {@code None}. This is deliberately not a
 *       Java port of Node's separate {@code MLClassifier} adapter — that
 *       remains Node-specific and out of scope here.</li>
 *   <li>Tier 3: an optional caller-supplied {@link RelayCallback}, fired
 *       only for non-{@code allow} decisions when
 *       {@link Config#enableExternalRelay()} is true (hybrid mode only).
 *       This engine has no HTTP client or platform credentials of its own
 *       by design — it stays air-gapped otherwise; the caller's relay
 *       callback does the actual platform call, mirroring Node's
 *       {@code onRelay}/{@code relayInternalDecisionToPlatform} and
 *       Python's {@code on_relay}.</li>
 * </ul>
 *
 * <p><b>Concurrency:</b> unlike the Python/Ruby/PHP ports (typically one
 * thread per request), a Spring Boot/Tomcat host calls {@link #evaluate}
 * concurrently from many request threads. All shared mutable state goes
 * through {@link BoundedMap} (already internally synchronized) or an
 * explicit lock: {@link #auditLock} guards the bounded audit log's
 * check-then-trim-then-append sequence, and {@link #rateLimitLock} guards
 * the sliding-window rate limiter's check-then-record sequence so two
 * concurrent requests from the same IP cannot both pass a check that should
 * have tipped the window over the limit. The rule list is a
 * {@link CopyOnWriteArrayList} so concurrent {@link #evaluate} calls can
 * iterate it safely while {@link #addRule}/{@link #removeRule} are rare.
 *
 * <p><b>Fail mode:</b> {@link FailMode#CLOSED} (block, score 100) or
 * {@link FailMode#OPEN} (allow, score 0) on an uncaught exception during
 * evaluation; default closed. Per-rule exceptions are caught individually
 * in {@link #evaluateTier1} (mirroring Node's per-rule try/catch) so one bad
 * rule cannot escalate to the top-level fail-mode handler or crash the
 * engine for every other rule.
 */
public final class InternalClosedLoopEngine {

    // ── Decision / fail-mode enums ──────────────────────────────

    /** Mirrors Node's {@code InternalCLDecision} union. */
    public enum Decision {
        ALLOW, BLOCK, RATE_LIMIT, CHALLENGE, QUARANTINE;

        public String wireValue() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** Mirrors Node's {@code InternalCLConfig.failMode}. */
    public enum FailMode { CLOSED, OPEN }

    // ── Callback interfaces ─────────────────────────────────────

    /** Tier 2 custom scorer. Returns a 0-100 threat score. Unimplemented/pass-through unless configured. */
    @FunctionalInterface
    public interface Tier2Scorer {
        double score(InternalCLRequest req);
    }

    /** Tier 3 relay target — fired for non-'allow' decisions when external relay is enabled (hybrid mode only). */
    @FunctionalInterface
    public interface RelayCallback {
        void relay(InternalCLResult result, InternalCLRequest req);
    }

    /** Fired once per {@link InternalCLAction} executed for a flagged decision. */
    @FunctionalInterface
    public interface ActionCallback {
        void onAction(InternalCLAction action);
    }

    /** The Tier-1 rule match predicate. */
    @FunctionalInterface
    public interface RuleMatcher extends Predicate<InternalCLRequest> {
    }

    // ── Request model ────────────────────────────────────────────

    /**
     * Mirrors Node's {@code InternalCLRequest}. {@code headers} is never
     * null (an absent map becomes empty); every other field may be null.
     * {@code timestamp} (epoch millis) defaults to {@code System.currentTimeMillis()}
     * at evaluation time when null.
     */
    public record InternalCLRequest(
            String ip,
            String method,
            String path,
            String userAgent,
            String userId,
            String sessionId,
            String body,
            String query,
            Map<String, String> headers,
            String agentId,
            String toolName,
            Long timestamp) {

        public InternalCLRequest {
            headers = headers == null ? Map.of() : headers;
        }

        public static Builder builder(String ip, String method, String path) {
            return new Builder(ip, method, path);
        }

        /** Builder for {@link InternalCLRequest} — convenient given its 9 optional fields. */
        public static final class Builder {
            private final String ip;
            private final String method;
            private final String path;
            private String userAgent;
            private String userId;
            private String sessionId;
            private String body;
            private String query;
            private Map<String, String> headers = Map.of();
            private String agentId;
            private String toolName;
            private Long timestamp;

            private Builder(String ip, String method, String path) {
                this.ip = ip;
                this.method = method;
                this.path = path;
            }

            public Builder userAgent(String v) { this.userAgent = v; return this; }
            public Builder userId(String v) { this.userId = v; return this; }
            public Builder sessionId(String v) { this.sessionId = v; return this; }
            public Builder body(String v) { this.body = v; return this; }
            public Builder query(String v) { this.query = v; return this; }
            public Builder headers(Map<String, String> v) { this.headers = v == null ? Map.of() : v; return this; }
            public Builder agentId(String v) { this.agentId = v; return this; }
            public Builder toolName(String v) { this.toolName = v; return this; }
            public Builder timestamp(Long v) { this.timestamp = v; return this; }

            public InternalCLRequest build() {
                return new InternalCLRequest(ip, method, path, userAgent, userId, sessionId, body, query,
                        headers, agentId, toolName, timestamp);
            }
        }
    }

    // ── Result / action / audit / rule models ───────────────────

    public record InternalCLAction(String type, String target, String reason, int ttlSeconds, long timestamp, String eventId) {
    }

    public record InternalCLResult(
            Decision decision,
            double score,
            int tier,
            List<String> matchedRules,
            long evaluationTimeUs,
            List<InternalCLAction> actions,
            String eventId) {
    }

    public record InternalCLAuditEntry(
            String eventId,
            long timestamp,
            String ip,
            Decision decision,
            double score,
            int tier,
            List<String> matchedRules,
            String userId,
            String agentId,
            String path,
            String method) {
    }

    /** A Tier-1 rule. {@code match} must not be assumed exception-free — {@link #evaluateTier1} isolates it per-rule. */
    public record InternalCLRule(
            String name,
            String description,
            String severity,
            double score,
            Decision decision,
            RuleMatcher match,
            boolean enabled) {

        public InternalCLRule(String name, String description, String severity, double score, Decision decision, RuleMatcher match) {
            this(name, description, severity, score, decision, match, true);
        }
    }

    /** {@link #getRules} snapshot — omits the match predicate, mirroring Node's {@code getRules()}. */
    public record RuleInfo(String name, String description, String severity, double score, Decision decision, boolean enabled) {
    }

    /** {@link #getStats} snapshot. */
    public record Stats(
            int blockedIPs, int blockedUsers, int blockedSessions, int quarantinedAgents,
            int rateLimitEntries, int auditLogSize, int rulesCount, String failMode) {
    }

    /** One entry for {@link #importBlockedIPs}. */
    public record ImportEntry(String ip, String reason, Integer ttlSeconds) {
    }

    private record PreCheck(Decision decision, String reason) {
    }

    private record Tier1Outcome(Decision decision, double score, List<String> matchedRules) {
    }

    private record BlockEntry(long expiresAt, String reason) {
    }

    private record QuarantineEntry(String reason, long timestamp) {
    }

    /** Mutable — {@code timestamps}/{@code blocked} are updated under {@link #rateLimitLock}. */
    private static final class RateLimitEntry {
        final List<Long> timestamps = new ArrayList<>();
        boolean blocked = false;
    }

    // ── Configuration ────────────────────────────────────────────

    /** Mirrors Node's {@code InternalCLConfig}. Build via {@link Config#builder()}. */
    public static final class Config {
        private final FailMode failMode;
        private final boolean enableExternalRelay;
        private final int maxBlockedEntries;
        private final int maxRateLimitEntries;
        private final int maxAuditEntries;
        private final int defaultBlockTtlSeconds;
        private final Tier2Scorer tier2Scorer;
        private final double blockThreshold;
        private final double rateLimitThreshold;
        private final int rateLimitMax;
        private final long rateLimitWindowMs;
        private final boolean debug;
        private final ActionCallback onAction;
        private final RelayCallback onRelay;

        private Config(Builder b) {
            this.failMode = b.failMode;
            this.enableExternalRelay = b.enableExternalRelay;
            this.maxBlockedEntries = b.maxBlockedEntries;
            this.maxRateLimitEntries = b.maxRateLimitEntries;
            this.maxAuditEntries = b.maxAuditEntries;
            this.defaultBlockTtlSeconds = b.defaultBlockTtlSeconds;
            this.tier2Scorer = b.tier2Scorer;
            this.blockThreshold = b.blockThreshold;
            this.rateLimitThreshold = b.rateLimitThreshold;
            this.rateLimitMax = b.rateLimitMax;
            this.rateLimitWindowMs = b.rateLimitWindowMs;
            this.debug = b.debug;
            this.onAction = b.onAction;
            this.onRelay = b.onRelay;
        }

        public static Builder builder() {
            return new Builder();
        }

        public FailMode failMode() { return failMode; }
        public boolean enableExternalRelay() { return enableExternalRelay; }
        public int maxBlockedEntries() { return maxBlockedEntries; }
        public int maxRateLimitEntries() { return maxRateLimitEntries; }
        public int maxAuditEntries() { return maxAuditEntries; }
        public int defaultBlockTtlSeconds() { return defaultBlockTtlSeconds; }
        public Tier2Scorer tier2Scorer() { return tier2Scorer; }
        public double blockThreshold() { return blockThreshold; }
        public double rateLimitThreshold() { return rateLimitThreshold; }
        public int rateLimitMax() { return rateLimitMax; }
        public long rateLimitWindowMs() { return rateLimitWindowMs; }
        public boolean debug() { return debug; }
        public ActionCallback onAction() { return onAction; }
        public RelayCallback onRelay() { return onRelay; }

        /** Returns a copy of this config with {@code onRelay} set, for mode wiring (e.g. hybrid's relay-to-platform target). */
        public Config withOnRelay(RelayCallback relay) {
            return builder()
                    .failMode(failMode).enableExternalRelay(enableExternalRelay)
                    .maxBlockedEntries(maxBlockedEntries).maxRateLimitEntries(maxRateLimitEntries)
                    .maxAuditEntries(maxAuditEntries).defaultBlockTtlSeconds(defaultBlockTtlSeconds)
                    .tier2Scorer(tier2Scorer).blockThreshold(blockThreshold).rateLimitThreshold(rateLimitThreshold)
                    .rateLimitMax(rateLimitMax).rateLimitWindowMs(rateLimitWindowMs).debug(debug)
                    .onAction(onAction).onRelay(relay)
                    .build();
        }

        /** Returns a copy of this config with {@code enableExternalRelay} set. */
        public Config withEnableExternalRelay(boolean enabled) {
            return builder()
                    .failMode(failMode).enableExternalRelay(enabled)
                    .maxBlockedEntries(maxBlockedEntries).maxRateLimitEntries(maxRateLimitEntries)
                    .maxAuditEntries(maxAuditEntries).defaultBlockTtlSeconds(defaultBlockTtlSeconds)
                    .tier2Scorer(tier2Scorer).blockThreshold(blockThreshold).rateLimitThreshold(rateLimitThreshold)
                    .rateLimitMax(rateLimitMax).rateLimitWindowMs(rateLimitWindowMs).debug(debug)
                    .onAction(onAction).onRelay(onRelay)
                    .build();
        }

        public static final class Builder {
            private FailMode failMode = FailMode.CLOSED;
            private boolean enableExternalRelay = false;
            private int maxBlockedEntries = 10_000;
            private int maxRateLimitEntries = 50_000;
            private int maxAuditEntries = 100_000;
            private int defaultBlockTtlSeconds = 3600;
            private Tier2Scorer tier2Scorer;
            private double blockThreshold = 85;
            private double rateLimitThreshold = 60;
            private int rateLimitMax = 100;
            private long rateLimitWindowMs = 60_000;
            private boolean debug = false;
            private ActionCallback onAction;
            private RelayCallback onRelay;

            public Builder failMode(FailMode v) { this.failMode = v; return this; }
            public Builder enableExternalRelay(boolean v) { this.enableExternalRelay = v; return this; }
            public Builder maxBlockedEntries(int v) { this.maxBlockedEntries = v; return this; }
            public Builder maxRateLimitEntries(int v) { this.maxRateLimitEntries = v; return this; }
            public Builder maxAuditEntries(int v) { this.maxAuditEntries = v; return this; }
            public Builder defaultBlockTtlSeconds(int v) { this.defaultBlockTtlSeconds = v; return this; }
            public Builder tier2Scorer(Tier2Scorer v) { this.tier2Scorer = v; return this; }
            public Builder blockThreshold(double v) { this.blockThreshold = v; return this; }
            public Builder rateLimitThreshold(double v) { this.rateLimitThreshold = v; return this; }
            public Builder rateLimitMax(int v) { this.rateLimitMax = v; return this; }
            public Builder rateLimitWindowMs(long v) { this.rateLimitWindowMs = v; return this; }
            public Builder debug(boolean v) { this.debug = v; return this; }
            public Builder onAction(ActionCallback v) { this.onAction = v; return this; }
            public Builder onRelay(RelayCallback v) { this.onRelay = v; return this; }

            public Config build() {
                return new Config(this);
            }
        }
    }

    // ── Default Tier-1 attack patterns ──────────────────────────
    //
    // Independently verified against Node's actual regex objects (V8/ECMA
    // engine) via `node -e`, and against java.util.regex via a JEP-330
    // single-file-source probe, for 26 representative inputs covering every
    // pattern below plus the known /.env path_traversal/sensitive_file_access
    // overlap and the "q=UNION SELECT..." non-match edge case the Python
    // port's test-fix history flagged. Zero divergence found between the two
    // engines for any pattern/input pair tested — see the session report for
    // the full probe transcript. Patterns are otherwise a literal transliteration
    // of Node's /pattern/flags into Java string-escaped equivalents (each
    // single backslash becomes "\\\\" in source, matching Java string-literal
    // escaping rules — Node's bare /../ literal syntax needs no such doubling).

    private static final Pattern[] SQL_INJECTION_STRICT = {
            Pattern.compile(
                    "(?:^|\\s)(?:UNION\\s+(?:ALL\\s+)?SELECT|DROP\\s+TABLE|INSERT\\s+INTO|UPDATE\\s+[a-zA-Z0-9_]+\\s+SET|DELETE\\s+FROM)(?:\\s|$)",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile(
                    "(?:'|\")\\s*OR\\s+(?:\\d+\\s*=\\s*\\d+|'[^']*'\\s*=\\s*'[^']*'|\"[^\"]*\"\\s*=\\s*\"[^\"]*\")",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:'|\")\\s*;\\s*(?:--|/\\*)"),
            Pattern.compile("(\\bxp_\\w+)", Pattern.CASE_INSENSITIVE),
    };

    private static final Pattern[] SQL_INJECTION_MODERATE = {
            Pattern.compile("(/\\*.*\\*/)"),
            Pattern.compile("(\\bEXEC\\b|\\bEXECUTE\\b)\\s*\\(", Pattern.CASE_INSENSITIVE),
    };

    private static final Pattern[] XSS_PATTERNS = {
            Pattern.compile("<script[\\s>]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript\\s*:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on(load|error|click|mouseover|submit|focus|blur)\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(<iframe|<object|<embed|<applet)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(document\\.(cookie|write|location))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(window\\.(location|open))", Pattern.CASE_INSENSITIVE),
    };

    private static final Pattern[] PATH_TRAVERSAL_PATTERNS = {
            Pattern.compile("\\.\\./"),
            Pattern.compile("\\.\\.%2[fF]"),
            Pattern.compile("\\.\\.\\\\$"),
            Pattern.compile("%2e%2e[%/\\\\]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/etc/(passwd|shadow|hosts)"),
            Pattern.compile("/proc/self"),
            Pattern.compile("(/\\.env|/\\.git|/\\.ssh)"),
    };

    private static final Pattern[] SCANNER_SIGNATURES = {
            Pattern.compile("sqlmap", Pattern.CASE_INSENSITIVE),
            Pattern.compile("nikto", Pattern.CASE_INSENSITIVE),
            Pattern.compile("nmap", Pattern.CASE_INSENSITIVE),
            Pattern.compile("dirbuster", Pattern.CASE_INSENSITIVE),
            Pattern.compile("gobuster", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wpscan", Pattern.CASE_INSENSITIVE),
            Pattern.compile("burp\\s*suite", Pattern.CASE_INSENSITIVE),
            Pattern.compile("acunetix", Pattern.CASE_INSENSITIVE),
            Pattern.compile("nessus", Pattern.CASE_INSENSITIVE),
            Pattern.compile("masscan", Pattern.CASE_INSENSITIVE),
            Pattern.compile("zgrab", Pattern.CASE_INSENSITIVE),
            Pattern.compile("nuclei", Pattern.CASE_INSENSITIVE),
    };

    private static final Pattern[] SENSITIVE_FILE_PATTERNS = {
            Pattern.compile("/\\.env"),
            Pattern.compile("/\\.git"),
            Pattern.compile("/\\.ssh"),
            Pattern.compile("/wp-admin"),
            Pattern.compile("/wp-login"),
            Pattern.compile("/phpmyadmin", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/admin\\.php"),
            Pattern.compile("/\\.htaccess"),
            Pattern.compile("/\\.htpasswd"),
            Pattern.compile("/server-status"),
            Pattern.compile("/actuator"),
            Pattern.compile("/debug/"),
    };

    private static final String[] AUTH_PATHS = {"/login", "/signin", "/auth", "/api/auth", "/api/login", "/oauth/token"};
    private static final List<String> DANGEROUS_TOOLS = List.of("shell_exec", "eval", "exec", "rm", "sudo", "chmod", "kill");

    /**
     * Lightweight, synchronous, zero-network content check reusing the same
     * Tier-1 patterns as {@link #registerDefaultRules}. Mirrors Node's
     * {@code matchesKnownAttackPattern} and Python's
     * {@code matches_known_attack_pattern} (Option B, 2026-08-27): external
     * mode's own behavioral preflight is purely statistical and cannot flag
     * a single first-ever malicious request from a fresh entity. Not wired
     * into any adapter by this port — kept for parity with the other SDKs
     * and for a future external-mode content check, same as the Python port.
     */
    public static boolean matchesKnownAttackPattern(String path, String userAgent) {
        if (notEmpty(path)) {
            for (Pattern p : SQL_INJECTION_STRICT) if (p.matcher(path).find()) return true;
            for (Pattern p : SQL_INJECTION_MODERATE) if (p.matcher(path).find()) return true;
            for (Pattern p : XSS_PATTERNS) if (p.matcher(path).find()) return true;
            for (Pattern p : PATH_TRAVERSAL_PATTERNS) if (p.matcher(path).find()) return true;
        }
        if (notEmpty(userAgent)) {
            for (Pattern p : SCANNER_SIGNATURES) if (p.matcher(userAgent).find()) return true;
        }
        return false;
    }

    private static boolean notEmpty(String s) {
        return s != null && !s.isEmpty();
    }

    /** Returns the non-null, non-empty strings among {@code values}, in order. Null-safe unlike {@code List.of}. */
    private static List<String> nonEmptyOf(String... values) {
        List<String> out = new ArrayList<>(values.length);
        for (String v : values) {
            if (notEmpty(v)) {
                out.add(v);
            }
        }
        return out;
    }

    // ── Engine state ──────────────────────────────────────────────

    private final Config config;
    private final BoundedMap<String, BlockEntry> blockedIPs;
    private final BoundedMap<String, BlockEntry> blockedUsers;
    private final BoundedMap<String, BlockEntry> blockedSessions;
    private final BoundedMap<String, QuarantineEntry> quarantinedAgents;
    private final BoundedMap<String, RateLimitEntry> rateLimiter;
    private final Object rateLimitLock = new Object();
    private final Object auditLock = new Object();
    private final List<InternalCLAuditEntry> auditLog = new ArrayList<>();
    private final List<InternalCLRule> rules = new CopyOnWriteArrayList<>();
    private final AtomicLong eventCounter = new AtomicLong(0);

    public InternalClosedLoopEngine() {
        this(Config.builder().build());
    }

    public InternalClosedLoopEngine(Config config) {
        this.config = config;
        this.blockedIPs = new BoundedMap<>(config.maxBlockedEntries());
        this.blockedUsers = new BoundedMap<>(config.maxBlockedEntries());
        this.blockedSessions = new BoundedMap<>(config.maxBlockedEntries());
        this.quarantinedAgents = new BoundedMap<>(config.maxBlockedEntries());
        this.rateLimiter = new BoundedMap<>(config.maxRateLimitEntries());
        registerDefaultRules();
        log("info", "Internal Closed-Loop Engine initialized (failMode=" + config.failMode() + ")");
    }

    /** Returns this engine's config (e.g. so a client wrapper can derive a hybrid-mode copy via {@link Config#withOnRelay}). */
    public Config getConfig() {
        return config;
    }

    // ── Public API ────────────────────────────────────────────────

    /**
     * Evaluate a request through the 3-tier engine. Call this for every
     * inbound request, before it reaches the application — the defining
     * behaviour of internal mode is that this never needs a platform
     * round-trip to produce a decision. Safe to call concurrently.
     */
    public InternalCLResult evaluate(InternalCLRequest req) {
        long startNanos = System.nanoTime();
        long now = req.timestamp() != null ? req.timestamp() : System.currentTimeMillis();
        String eventId = generateEventId();

        try {
            PreCheck pre = checkBlocked(req, now);
            if (pre != null) {
                long elapsedUs = (System.nanoTime() - startNanos) / 1000;
                InternalCLResult result = new InternalCLResult(
                        pre.decision(), 100, 1, List.of(pre.reason()), elapsedUs, List.of(), eventId);
                recordAudit(result, req);
                return result;
            }

            Tier1Outcome tier1 = evaluateTier1(req);
            if (tier1.decision() != Decision.ALLOW) {
                long elapsedUs = (System.nanoTime() - startNanos) / 1000;
                List<InternalCLAction> actions = executeActions(tier1.decision(), tier1.matchedRules(), req, eventId, now);
                InternalCLResult result = new InternalCLResult(
                        tier1.decision(), tier1.score(), 1, tier1.matchedRules(), elapsedUs, actions, eventId);
                recordAudit(result, req);
                if (config.enableExternalRelay()) {
                    relayToExternal(result, req);
                }
                return result;
            }

            if (checkAndRecordRateLimit(req.ip(), now)) {
                long elapsedUs = (System.nanoTime() - startNanos) / 1000;
                List<InternalCLAction> actions = executeActions(Decision.RATE_LIMIT, List.of("rate_limit_exceeded"), req, eventId, now);
                InternalCLResult result = new InternalCLResult(
                        Decision.RATE_LIMIT, 65, 1, List.of("rate_limit_exceeded"), elapsedUs, actions, eventId);
                recordAudit(result, req);
                return result;
            }

            // ─── Tier 2: optional custom scorer — unimplemented/pass-through
            // by default. Skipped entirely when no scorer is configured. ───
            if (config.tier2Scorer() != null) {
                double score = config.tier2Scorer().score(req);
                if (score >= config.blockThreshold()) {
                    long elapsedUs = (System.nanoTime() - startNanos) / 1000;
                    List<InternalCLAction> actions = executeActions(Decision.BLOCK, List.of("tier2_ml_score"), req, eventId, now);
                    InternalCLResult result = new InternalCLResult(
                            Decision.BLOCK, score, 2, List.of("tier2_ml_score"), elapsedUs, actions, eventId);
                    recordAudit(result, req);
                    if (config.enableExternalRelay()) {
                        relayToExternal(result, req);
                    }
                    return result;
                } else if (score >= config.rateLimitThreshold()) {
                    long elapsedUs = (System.nanoTime() - startNanos) / 1000;
                    InternalCLResult result = new InternalCLResult(
                            Decision.RATE_LIMIT, score, 2, List.of("tier2_ml_elevated"), elapsedUs, List.of(), eventId);
                    recordAudit(result, req);
                    return result;
                }
            }

            long elapsedUs = (System.nanoTime() - startNanos) / 1000;
            return new InternalCLResult(Decision.ALLOW, 0, 1, List.of(), elapsedUs, List.of(), eventId);
        } catch (RuntimeException error) {
            long elapsedUs = (System.nanoTime() - startNanos) / 1000;
            log("error", "Evaluation error: " + error.getMessage());
            if (config.failMode() == FailMode.CLOSED) {
                return new InternalCLResult(Decision.BLOCK, 100, 1, List.of("fail_closed_error"), elapsedUs, List.of(), eventId);
            }
            return new InternalCLResult(Decision.ALLOW, 0, 1, List.of("fail_open_error"), elapsedUs, List.of(), eventId);
        }
    }

    public void blockIP(String ip, String reason, Integer ttlSeconds) {
        int ttl = ttlSeconds != null ? ttlSeconds : config.defaultBlockTtlSeconds();
        blockedIPs.set(ip, new BlockEntry(System.currentTimeMillis() + ttl * 1000L, reason));
        log("info", "IP blocked: " + ip + " — " + reason + " (TTL: " + ttl + "s)");
    }

    public boolean unblockIP(String ip) {
        boolean existed = blockedIPs.has(ip);
        blockedIPs.delete(ip);
        if (existed) {
            log("info", "IP unblocked: " + ip);
        }
        return existed;
    }

    public void blockUser(String userId, String reason, Integer ttlSeconds) {
        int ttl = ttlSeconds != null ? ttlSeconds : config.defaultBlockTtlSeconds();
        blockedUsers.set(userId, new BlockEntry(System.currentTimeMillis() + ttl * 1000L, reason));
        log("info", "User blocked: " + userId + " — " + reason);
    }

    public void blockSession(String sessionId, String reason, Integer ttlSeconds) {
        int ttl = ttlSeconds != null ? ttlSeconds : config.defaultBlockTtlSeconds();
        blockedSessions.set(sessionId, new BlockEntry(System.currentTimeMillis() + ttl * 1000L, reason));
        log("info", "Session blocked: " + sessionId + " — " + reason);
    }

    public void quarantineAgent(String agentId, String reason) {
        quarantinedAgents.set(agentId, new QuarantineEntry(reason, System.currentTimeMillis()));
        log("info", "Agent quarantined: " + agentId + " — " + reason);
    }

    public boolean unquarantineAgent(String agentId) {
        boolean existed = quarantinedAgents.has(agentId);
        quarantinedAgents.delete(agentId);
        if (existed) {
            log("info", "Agent unquarantined: " + agentId);
        }
        return existed;
    }

    public boolean isIpBlocked(String ip) {
        BlockEntry entry = blockedIPs.get(ip);
        if (entry == null) {
            return false;
        }
        if (System.currentTimeMillis() > entry.expiresAt()) {
            blockedIPs.delete(ip);
            return false;
        }
        return true;
    }

    public boolean isAgentQuarantined(String agentId) {
        return quarantinedAgents.has(agentId);
    }

    public void addRule(InternalCLRule rule) {
        rules.add(rule);
        log("debug", "Rule added: " + rule.name());
    }

    public boolean removeRule(String name) {
        for (InternalCLRule rule : rules) {
            if (rule.name().equals(name)) {
                boolean removed = rules.remove(rule);
                if (removed) {
                    log("debug", "Rule removed: " + name);
                }
                return removed;
            }
        }
        return false;
    }

    public List<RuleInfo> getRules() {
        List<RuleInfo> out = new ArrayList<>();
        for (InternalCLRule r : rules) {
            out.add(new RuleInfo(r.name(), r.description(), r.severity(), r.score(), r.decision(), r.enabled()));
        }
        return out;
    }

    public List<InternalCLAuditEntry> getAuditLog(int limit) {
        synchronized (auditLock) {
            int from = Math.max(0, auditLog.size() - limit);
            return new ArrayList<>(auditLog.subList(from, auditLog.size()));
        }
    }

    public Stats getStats() {
        synchronized (auditLock) {
            return new Stats(blockedIPs.size(), blockedUsers.size(), blockedSessions.size(),
                    quarantinedAgents.size(), rateLimiter.size(), auditLog.size(), rules.size(),
                    config.failMode().name().toLowerCase(Locale.ROOT));
        }
    }

    public int importBlockedIPs(List<ImportEntry> entries) {
        int count = 0;
        for (ImportEntry entry : entries) {
            blockIP(entry.ip(), entry.reason(), entry.ttlSeconds());
            count++;
        }
        return count;
    }

    /** Resets all state. For tests only — mirrors Node's {@code @internal _reset()} and Python's {@code _reset()}. */
    public void resetForTesting() {
        blockedIPs.clear();
        blockedUsers.clear();
        blockedSessions.clear();
        quarantinedAgents.clear();
        rateLimiter.clear();
        synchronized (auditLock) {
            auditLog.clear();
        }
        eventCounter.set(0);
    }

    // ── Private: pre-check / Tier 1 / rate limit / actions ───────

    private PreCheck checkBlocked(InternalCLRequest req, long now) {
        BlockEntry ipBlock = blockedIPs.get(req.ip());
        if (ipBlock != null) {
            if (now > ipBlock.expiresAt()) {
                blockedIPs.delete(req.ip());
            } else {
                return new PreCheck(Decision.BLOCK, "ip_blocked:" + ipBlock.reason());
            }
        }

        if (notEmpty(req.userId())) {
            BlockEntry userBlock = blockedUsers.get(req.userId());
            if (userBlock != null) {
                if (now > userBlock.expiresAt()) {
                    blockedUsers.delete(req.userId());
                } else {
                    return new PreCheck(Decision.BLOCK, "user_blocked:" + userBlock.reason());
                }
            }
        }

        if (notEmpty(req.sessionId())) {
            BlockEntry sessionBlock = blockedSessions.get(req.sessionId());
            if (sessionBlock != null) {
                if (now > sessionBlock.expiresAt()) {
                    blockedSessions.delete(req.sessionId());
                } else {
                    return new PreCheck(Decision.BLOCK, "session_blocked:" + sessionBlock.reason());
                }
            }
        }

        if (notEmpty(req.agentId()) && quarantinedAgents.has(req.agentId())) {
            return new PreCheck(Decision.QUARANTINE, "agent_quarantined:" + req.agentId());
        }

        return null;
    }

    private Tier1Outcome evaluateTier1(InternalCLRequest req) {
        List<String> matchedRules = new ArrayList<>();
        double maxScore = 0;
        Decision decision = Decision.ALLOW;

        for (InternalCLRule rule : rules) {
            if (!rule.enabled()) {
                continue;
            }
            try {
                if (rule.match().test(req)) {
                    matchedRules.add(rule.name());
                    if (rule.score() > maxScore) {
                        maxScore = rule.score();
                        decision = rule.decision();
                    }
                }
            } catch (RuntimeException e) {
                // Individual rule errors must not crash the engine or escalate
                // to the top-level fail-mode handler — mirrors Node's per-rule
                // try/catch around rule.match(req).
                log("error", "Rule " + rule.name() + " threw an error");
            }
        }

        return new Tier1Outcome(decision, maxScore, matchedRules);
    }

    /**
     * Atomically checks the sliding-window rate limit for {@code ip} and, if
     * not exceeded, records this request's timestamp — the two steps Node
     * and Python perform sequentially (safe there; single-threaded per
     * request) but which must be one atomic operation here so two concurrent
     * requests from the same IP cannot both observe "under the limit" and
     * both get recorded past it. Returns true if the request is rate-limited
     * (and was NOT recorded); false if it was allowed through (and WAS recorded).
     */
    private boolean checkAndRecordRateLimit(String ip, long now) {
        synchronized (rateLimitLock) {
            RateLimitEntry entry = rateLimiter.get(ip);
            if (entry != null) {
                long windowStart = now - config.rateLimitWindowMs();
                entry.timestamps.removeIf(t -> t <= windowStart);
                if (entry.timestamps.size() >= config.rateLimitMax()) {
                    entry.blocked = true;
                    return true;
                }
            } else {
                entry = new RateLimitEntry();
            }
            entry.timestamps.add(now);
            rateLimiter.set(ip, entry);
            return false;
        }
    }

    private List<InternalCLAction> executeActions(Decision decision, List<String> matchedRules, InternalCLRequest req, String eventId, long now) {
        List<InternalCLAction> actions = new ArrayList<>();
        int ttl = config.defaultBlockTtlSeconds();
        String reason = String.join(", ", matchedRules);

        if (decision == Decision.BLOCK || decision == Decision.QUARANTINE) {
            blockedIPs.set(req.ip(), new BlockEntry(now + ttl * 1000L, reason));
            actions.add(new InternalCLAction("block_ip", req.ip(), reason, ttl, now, eventId));

            if (notEmpty(req.sessionId())) {
                blockedSessions.set(req.sessionId(), new BlockEntry(now + ttl * 1000L, reason));
                actions.add(new InternalCLAction("block_session", req.sessionId(), reason, ttl, now, eventId));
            }

            if (notEmpty(req.agentId())) {
                quarantinedAgents.set(req.agentId(), new QuarantineEntry(reason, now));
                // Permanent until manual unquarantine — mirrors Node's ttlSeconds: 0 for this action.
                actions.add(new InternalCLAction("quarantine_agent", req.agentId(), reason, 0, now, eventId));
            }
        }

        if (config.onAction() != null) {
            for (InternalCLAction action : actions) {
                try {
                    config.onAction().onAction(action);
                } catch (RuntimeException e) {
                    log("error", "onAction callback error for " + action.type());
                }
            }
        }

        return actions;
    }

    private void recordAudit(InternalCLResult result, InternalCLRequest req) {
        synchronized (auditLock) {
            if (auditLog.size() >= config.maxAuditEntries()) {
                int toRemove = Math.max(1, (int) (config.maxAuditEntries() * 0.1));
                for (int i = 0; i < toRemove && !auditLog.isEmpty(); i++) {
                    auditLog.remove(0);
                }
            }
            auditLog.add(new InternalCLAuditEntry(
                    result.eventId(),
                    req.timestamp() != null ? req.timestamp() : System.currentTimeMillis(),
                    req.ip(), result.decision(), result.score(), result.tier(), result.matchedRules(),
                    req.userId(), req.agentId(), req.path(), req.method()));
        }
    }

    /**
     * Tier 3: relay via the caller-supplied {@link RelayCallback}. Called
     * synchronously within {@link #evaluate} (this SDK's {@code Client} is
     * synchronous throughout — there is no async/event-loop plumbing to fire
     * this detached the way Node's {@code .catch(() => {})} does); a slow or
     * failing relay callback therefore does add to this call's latency, same
     * as the Python port's {@code await}ed relay inside its own
     * {@code evaluate()} coroutine. This engine has no HTTP client or
     * platform credentials of its own by design — the caller does the actual
     * platform call.
     */
    private void relayToExternal(InternalCLResult result, InternalCLRequest req) {
        log("debug", "Tier 3 relay: " + result.eventId() + " -> external platform");
        if (config.onRelay() == null) {
            return;
        }
        try {
            config.onRelay().relay(result, req);
        } catch (RuntimeException e) {
            log("error", "onRelay callback error for " + result.eventId() + ": " + e.getMessage());
        }
    }

    private String generateEventId() {
        long counter = eventCounter.incrementAndGet();
        String ts = Long.toString(System.currentTimeMillis(), 36);
        String counterStr = padLeft(Long.toString(counter, 36), 4);
        String rand = padLeft(Long.toString((long) (Math.random() * 1_679_616), 36), 4);
        return "icl_" + ts + "_" + counterStr + "_" + rand;
    }

    private static String padLeft(String s, int width) {
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < width) {
            sb.insert(0, '0');
        }
        return sb.toString();
    }

    private void registerDefaultRules() {
        rules.add(new InternalCLRule(
                "sql_injection",
                "Detects SQL injection patterns context-aware (strict on path/query, moderate on body)",
                "critical", 95, Decision.BLOCK,
                req -> {
                    List<String> strictTargets = new ArrayList<>();
                    if (notEmpty(req.path())) strictTargets.add(req.path());
                    if (notEmpty(req.query())) strictTargets.add(req.query());
                    for (String t : strictTargets) {
                        for (Pattern p : SQL_INJECTION_STRICT) if (p.matcher(t).find()) return true;
                    }
                    for (String t : strictTargets) {
                        for (Pattern p : SQL_INJECTION_MODERATE) if (p.matcher(t).find()) return true;
                    }

                    List<String> bodyTargets = new ArrayList<>();
                    if (notEmpty(req.body())) bodyTargets.add(req.body());
                    for (String v : req.headers().values()) {
                        if (notEmpty(v)) bodyTargets.add(v);
                    }
                    for (String t : bodyTargets) {
                        for (Pattern p : SQL_INJECTION_STRICT) if (p.matcher(t).find()) return true;
                    }
                    return false;
                }));

        rules.add(new InternalCLRule(
                "xss_attempt", "Detects cross-site scripting patterns",
                "high", 90, Decision.BLOCK,
                req -> {
                    // NOTE: req.path()/query()/body() may each be null — never pass them
                    // through List.of (which throws NullPointerException on a null
                    // element); filter with notEmpty() first, same pattern used by
                    // sql_injection's strictTargets/bodyTargets above.
                    for (String t : nonEmptyOf(req.path(), req.query(), req.body())) {
                        for (Pattern p : XSS_PATTERNS) if (p.matcher(t).find()) return true;
                    }
                    return false;
                }));

        rules.add(new InternalCLRule(
                "path_traversal", "Detects directory traversal attempts",
                "high", 90, Decision.BLOCK,
                req -> {
                    for (String t : nonEmptyOf(req.path(), req.query())) {
                        for (Pattern p : PATH_TRAVERSAL_PATTERNS) if (p.matcher(t).find()) return true;
                    }
                    return false;
                }));

        rules.add(new InternalCLRule(
                "scanner_detected", "Detects known vulnerability scanner user agents",
                "medium", 75, Decision.BLOCK,
                req -> {
                    if (!notEmpty(req.userAgent())) return false;
                    for (Pattern p : SCANNER_SIGNATURES) if (p.matcher(req.userAgent()).find()) return true;
                    return false;
                }));

        rules.add(new InternalCLRule(
                "sensitive_file_access", "Detects access to sensitive files (.env, .git, wp-admin, etc.)",
                "high", 85, Decision.BLOCK,
                req -> {
                    if (!notEmpty(req.path())) return false;
                    for (Pattern p : SENSITIVE_FILE_PATTERNS) if (p.matcher(req.path()).find()) return true;
                    return false;
                }));

        rules.add(new InternalCLRule(
                "credential_stuffing_pattern", "Detects credential stuffing via POST to auth endpoints",
                "high", 80, Decision.RATE_LIMIT,
                req -> {
                    if (!"POST".equals(req.method())) return false;
                    if (!notEmpty(req.path())) return false;
                    String pathLower = req.path().toLowerCase(Locale.ROOT);
                    for (String authPath : AUTH_PATHS) {
                        if (pathLower.contains(authPath)) return true;
                    }
                    return false;
                }));

        rules.add(new InternalCLRule(
                "agent_unsanctioned_tool", "Detects agent attempting to use dangerous tools",
                "critical", 95, Decision.QUARANTINE,
                req -> {
                    if (!notEmpty(req.agentId()) || !notEmpty(req.toolName())) return false;
                    return DANGEROUS_TOOLS.contains(req.toolName().toLowerCase(Locale.ROOT));
                }));
    }

    private void log(String level, String message) {
        if (!config.debug() && "debug".equals(level)) {
            return;
        }
        String prefix = "[DevFortress ICL] ";
        if ("error".equals(level) || "warn".equals(level)) {
            System.err.println(prefix + message);
        } else if (config.debug()) {
            System.out.println(prefix + message);
        }
    }
}
