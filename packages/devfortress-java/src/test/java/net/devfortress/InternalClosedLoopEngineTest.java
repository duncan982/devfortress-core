package net.devfortress;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * InternalClosedLoopEngine (TODO 407 port): internal-mode decision engine,
 * ported from {@code internal-closed-loop-engine.ts}, following the same
 * structure as the already-completed Python port's
 * {@code test_internal_closed_loop_engine.py} (29 tests). Also covers the
 * {@link Client}-level mode/observe/isBlocked wiring and a concurrency
 * check this port adds beyond the Python test suite, since (unlike
 * Python/Ruby/PHP) a Spring Boot host calls {@link InternalClosedLoopEngine#evaluate}
 * from many threads at once.
 */
class InternalClosedLoopEngineTest {

    private static InternalClosedLoopEngine.InternalCLRequest req(String path) {
        return InternalClosedLoopEngine.InternalCLRequest.builder("203.0.113.5", "GET", path).build();
    }

    private static InternalClosedLoopEngine.InternalCLRequest.Builder reqBuilder(String path) {
        return InternalClosedLoopEngine.InternalCLRequest.builder("203.0.113.5", "GET", path);
    }

    // ── Tier 1 rule matching ──────────────────────────────────────────

    static Stream<Arguments> sqlInjectionCases() {
        return Stream.of(
                Arguments.of("/products", "search=' OR 1=1 --"),
                Arguments.of("/products", "id=1; DROP TABLE users"),
                Arguments.of("/search", "UNION SELECT password FROM users"));
    }

    @ParameterizedTest
    @MethodSource("sqlInjectionCases")
    void sqlInjectionBlocks(String path, String query) {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(reqBuilder(path).query(query).build());
        assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
        assertTrue(result.matchedRules().contains("sql_injection"));
        assertEquals(1, result.tier());
    }

    @Test
    void cleanRequestAllowed() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(reqBuilder("/products").query("search=laptop").build());
        assertEquals(InternalClosedLoopEngine.Decision.ALLOW, result.decision());
        assertTrue(result.matchedRules().isEmpty());
        assertEquals(0, result.score());
    }

    @Test
    void literalPercentNotFalsePositived() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(reqBuilder("/products").query("discount=50%").build());
        assertEquals(InternalClosedLoopEngine.Decision.ALLOW, result.decision());
    }

    @Test
    void xssBlocks() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(reqBuilder("/comment").query("text=<script>alert(1)</script>").build());
        assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
        assertTrue(result.matchedRules().contains("xss_attempt"));
    }

    @Test
    void pathTraversalBlocks() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(req("/files/../../etc/passwd"));
        assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
        assertTrue(result.matchedRules().contains("path_traversal"));
    }

    @Test
    void scannerUserAgentBlocks() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(reqBuilder("/").userAgent("sqlmap/1.7").build());
        assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
        assertTrue(result.matchedRules().contains("scanner_detected"));
    }

    @Test
    void sensitiveFileAccessBlocks() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(req("/.env"));
        assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
        assertTrue(result.matchedRules().contains("sensitive_file_access"));
    }

    @Test
    void credentialStuffingRateLimits() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(
                InternalClosedLoopEngine.InternalCLRequest.builder("203.0.113.5", "POST", "/api/login").build());
        assertEquals(InternalClosedLoopEngine.Decision.RATE_LIMIT, result.decision());
        assertTrue(result.matchedRules().contains("credential_stuffing_pattern"));
    }

    @Test
    void agentUnsanctionedToolQuarantines() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(reqBuilder("/").agentId("agent-1").toolName("shell_exec").build());
        assertEquals(InternalClosedLoopEngine.Decision.QUARANTINE, result.decision());
        assertTrue(result.matchedRules().contains("agent_unsanctioned_tool"));
        assertTrue(engine.isAgentQuarantined("agent-1"));
    }

    // ── Pre-check (already-blocked) short-circuit ─────────────────────

    @Test
    void blockedIpShortCircuitsBeforeRules() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        engine.blockIP("203.0.113.5", "manual_block", null);
        var result = engine.evaluate(req("/anything"));
        assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
        assertEquals(List.of("ip_blocked:manual_block"), result.matchedRules());
    }

    @Test
    void unblockIpAllowsAgain() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        engine.blockIP("203.0.113.5", "test", null);
        engine.unblockIP("203.0.113.5");
        var result = engine.evaluate(req("/products"));
        assertEquals(InternalClosedLoopEngine.Decision.ALLOW, result.decision());
    }

    @Test
    void blockActionAlsoBlocksSessionAndAgent() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(reqBuilder("/.env").sessionId("sess-1").agentId("agent-9").build());
        assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
        List<String> actionTypes = result.actions().stream().map(InternalClosedLoopEngine.InternalCLAction::type).toList();
        assertTrue(actionTypes.contains("block_ip"));
        assertTrue(actionTypes.contains("block_session"));
        assertTrue(actionTypes.contains("quarantine_agent"));
    }

    // ── Rate limiting ───────────────────────────────────────────────

    @Test
    void rateLimitTriggersAfterMaxRequests() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine(
                InternalClosedLoopEngine.Config.builder().rateLimitMax(3).rateLimitWindowMs(60_000).build());
        for (int i = 0; i < 3; i++) {
            var result = engine.evaluate(reqBuilder("/products").query("p=1").build());
            assertEquals(InternalClosedLoopEngine.Decision.ALLOW, result.decision());
        }
        var result = engine.evaluate(reqBuilder("/products").query("p=1").build());
        assertEquals(InternalClosedLoopEngine.Decision.RATE_LIMIT, result.decision());
        assertEquals(List.of("rate_limit_exceeded"), result.matchedRules());
    }

    // ── Tier 2: unimplemented/pass-through by default ─────────────────

    @Test
    void tier2ScorerUnsetByDefaultSkipsTier2() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        var result = engine.evaluate(reqBuilder("/products").query("p=1").build());
        assertEquals(InternalClosedLoopEngine.Decision.ALLOW, result.decision());
        assertEquals(1, result.tier()); // never reaches tier 2 scoring at all
    }

    @Test
    void tier2ScorerWhenSuppliedCanBlock() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine(
                InternalClosedLoopEngine.Config.builder().tier2Scorer(r -> 90.0).build());
        var result = engine.evaluate(reqBuilder("/products").query("p=1").build());
        assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
        assertEquals(2, result.tier());
        assertEquals(List.of("tier2_ml_score"), result.matchedRules());
    }

    @Test
    void tier2ScorerElevatedRateLimits() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine(
                InternalClosedLoopEngine.Config.builder().tier2Scorer(r -> 70.0).build());
        var result = engine.evaluate(reqBuilder("/products").query("p=1").build());
        assertEquals(InternalClosedLoopEngine.Decision.RATE_LIMIT, result.decision());
        assertEquals(2, result.tier());
    }

    // ── Tier 3: relay callback (hybrid mode only) ──────────────────────

    @Test
    void relayNotCalledWhenExternalRelayDisabled() {
        List<InternalClosedLoopEngine.InternalCLResult> calls = new CopyOnWriteArrayList<>();
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine(
                InternalClosedLoopEngine.Config.builder().onRelay((result, r) -> calls.add(result)).build());
        engine.evaluate(req("/.env"));
        assertTrue(calls.isEmpty());
    }

    @Test
    void relayCalledForFlaggedDecisionWhenEnabled() {
        List<InternalClosedLoopEngine.InternalCLResult> calls = new CopyOnWriteArrayList<>();
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine(
                InternalClosedLoopEngine.Config.builder()
                        .enableExternalRelay(true)
                        .onRelay((result, r) -> calls.add(result))
                        .build());
        // "/.env" matches both path_traversal (score 90) and
        // sensitive_file_access (score 85) in Node's own pattern set
        // (path_traversal's own "(/\.env|/\.git|/\.ssh)" sub-pattern overlaps
        // sensitive_file_access) — not a porting bug, reproduced here
        // deliberately, same as the Python port's equivalent test.
        engine.evaluate(req("/.env"));
        assertEquals(1, calls.size());
        assertEquals(List.of("path_traversal", "sensitive_file_access"), calls.get(0).matchedRules());
    }

    @Test
    void relayNotCalledForAllowedDecision() {
        List<InternalClosedLoopEngine.InternalCLResult> calls = new CopyOnWriteArrayList<>();
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine(
                InternalClosedLoopEngine.Config.builder()
                        .enableExternalRelay(true)
                        .onRelay((result, r) -> calls.add(result))
                        .build());
        engine.evaluate(req("/products"));
        assertTrue(calls.isEmpty());
    }

    // ── Fail mode ───────────────────────────────────────────────────

    @Test
    void failClosedBlocksOnRuleErrorButDoesNotEscalateThroughEvaluate() {
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine(
                InternalClosedLoopEngine.Config.builder().failMode(InternalClosedLoopEngine.FailMode.CLOSED).build());
        engine.addRule(new InternalClosedLoopEngine.InternalCLRule(
                "broken", "x", "low", 1, InternalClosedLoopEngine.Decision.ALLOW,
                r -> { throw new RuntimeException("boom"); }));
        // Individual rule errors are swallowed per-rule (matching Node), not
        // escalated to the top-level fail-mode handler — evaluate() must not
        // throw, and must not report a false block either.
        var result = engine.evaluate(req("/products"));
        assertEquals(InternalClosedLoopEngine.Decision.ALLOW, result.decision());
    }

    // ── matchesKnownAttackPattern (Option B content check) ────────────

    @Test
    void matchesKnownAttackPatternDetectsSqli() {
        assertFalse(InternalClosedLoopEngine.matchesKnownAttackPattern("/search", null));
        assertTrue(InternalClosedLoopEngine.matchesKnownAttackPattern("/search?q=' OR 1=1 --", null));
    }

    @Test
    void matchesKnownAttackPatternDetectsScanner() {
        assertTrue(InternalClosedLoopEngine.matchesKnownAttackPattern("/", "nikto/2.5"));
    }

    // ── Concurrency: evaluate() must be safe under concurrent threads ──

    @RepeatedTest(3)
    void evaluateIsSafeUnderConcurrentRateLimitChecks() throws InterruptedException {
        // rateLimitMax=50: 100 concurrent requests from the SAME ip must
        // result in exactly 50 ALLOW and 50 RATE_LIMIT decisions — not more,
        // not fewer — proving checkAndRecordRateLimit's lock prevents two
        // threads from both observing "under the limit" for the same slot.
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine(
                InternalClosedLoopEngine.Config.builder().rateLimitMax(50).rateLimitWindowMs(60_000).build());

        int threads = 100;
        // Must be able to run all `threads` tasks concurrently: each one blocks on
        // `go.await()` after counting down `ready`, so a pool smaller than `threads`
        // deadlocks (the queued-but-not-yet-started tasks can never get a free worker
        // once every pool thread is parked in go.await(), so `ready` never reaches 0
        // and `go` never releases).
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger rateLimited = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                var result = engine.evaluate(reqBuilder("/products").query("p=1").build());
                if (result.decision() == InternalClosedLoopEngine.Decision.ALLOW) {
                    allowed.incrementAndGet();
                } else {
                    rateLimited.incrementAndGet();
                }
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "all threads should finish within 30s");

        assertEquals(50, allowed.get(), "exactly rateLimitMax requests should be allowed, no more no less");
        assertEquals(50, rateLimited.get());
        assertEquals(threads, allowed.get() + rateLimited.get());
    }

    @Test
    void evaluateIsSafeUnderConcurrentBlockActions() throws InterruptedException {
        // 50 threads each submit an attack request from a DIFFERENT ip
        // simultaneously; every one must independently end up blocked with
        // no lost updates / no corrupted shared state (BoundedMap size must
        // exactly equal the number of distinct IPs blocked).
        InternalClosedLoopEngine engine = new InternalClosedLoopEngine();
        int n = 50;
        ExecutorService pool = Executors.newFixedThreadPool(20);
        CountDownLatch latch = new CountDownLatch(n);
        AtomicInteger blocked = new AtomicInteger();

        for (int i = 0; i < n; i++) {
            String ip = "198.51.100." + i;
            pool.submit(() -> {
                var result = engine.evaluate(
                        InternalClosedLoopEngine.InternalCLRequest.builder(ip, "GET", "/.env").build());
                if (result.decision() == InternalClosedLoopEngine.Decision.BLOCK) {
                    blocked.incrementAndGet();
                }
                latch.countDown();
            });
        }
        assertTrue(latch.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(n, blocked.get());
        for (int i = 0; i < n; i++) {
            assertTrue(engine.isIpBlocked("198.51.100." + i), "every distinct attacking IP must be blocked");
        }
    }

    // ── Client wiring: mode selection, observe(), isBlocked() ─────────

    @Test
    void clientExternalModeObserveIsNoop() {
        try (Client client = Client.builder("k").mode("external").transport(new RecordingTransport()).build()) {
            assertNull(client.getInternalEngine());
            assertNull(client.observe(req("/.env")));
            assertFalse(client.isBlocked("203.0.113.5"));
        }
    }

    @Test
    void clientInternalModeObserveBlocksAttack() {
        try (Client client = Client.builder("k").mode("internal").transport(new RecordingTransport()).build()) {
            assertNotNull(client.getInternalEngine());
            Client.ObserveResult result = client.observe(req("/.env"));
            assertNotNull(result);
            assertTrue(result.flagged());
            assertEquals(InternalClosedLoopEngine.Decision.BLOCK, result.decision());
            assertTrue(client.isBlocked("203.0.113.5"));
        }
    }

    @Test
    void clientInternalModeObserveAllowsCleanRequest() {
        try (Client client = Client.builder("k").mode("internal").transport(new RecordingTransport()).build()) {
            Client.ObserveResult result = client.observe(reqBuilder("/products").query("q=laptop").build());
            assertNull(result);
        }
    }

    @Test
    void clientHybridModeBlocksViaInternalFirst() {
        try (Client client = Client.builder("k").mode("hybrid").transport(new RecordingTransport()).build()) {
            assertNotNull(client.getCircuitBreaker());
            Client.ObserveResult result = client.observe(req("/.env"));
            assertNotNull(result);
            assertTrue(result.flagged());
        }
    }

    @Test
    void clientHybridModeAllowsCleanRequestAndKeepsCircuitClosed() {
        try (Client client = Client.builder("k").mode("hybrid").transport(new RecordingTransport()).build()) {
            Client.ObserveResult result = client.observe(reqBuilder("/products").query("q=laptop").build());
            assertNull(result);
            assertEquals(PlatformCircuitBreaker.State.CLOSED, client.getCircuitBreaker().getState());
        }
    }

    @Test
    void clientDefaultModeIsExternal() {
        try (Client client = Client.builder("k").transport(new RecordingTransport()).build()) {
            assertEquals(TierGate.CLMode.EXTERNAL, client.getMode());
            assertNull(client.getInternalEngine());
            assertNull(client.getCircuitBreaker());
        }
    }
}
