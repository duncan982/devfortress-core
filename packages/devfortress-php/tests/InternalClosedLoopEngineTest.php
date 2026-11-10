<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\Client;
use DevFortress\Sdk\InternalClosedLoopEngine;
use DevFortress\Sdk\Tests\Support\RecordingTransport;
use DevFortress\Sdk\Transport\TransportResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * InternalClosedLoopEngine (TODO 407 port): internal-mode decision engine,
 * ported from internal-closed-loop-engine.ts, following the same scope as
 * this SDK family's Python port
 * (packages/devfortress-python/tests/test_internal_closed_loop_engine.py).
 */
final class InternalClosedLoopEngineTest extends TestCase
{
    /** @param array<string, mixed> $overrides */
    private static function req(array $overrides = []): array
    {
        return array_merge(['ip' => '203.0.113.5', 'method' => 'GET', 'path' => '/'], $overrides);
    }

    // ── Tier 1 rule matching ─────────────────────────────────────────────

    /** @return array<string, array{string, string}> */
    public static function sqlInjectionCases(): array
    {
        return [
            'or-1-equals-1' => ['/products', "search=' OR 1=1 --"],
            'drop-table' => ['/products', 'id=1; DROP TABLE users'],
            'union-select' => ['/search', 'UNION SELECT password FROM users'],
        ];
    }

    #[DataProvider('sqlInjectionCases')]
    public function testSqlInjectionBlocks(string $path, string $query): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['path' => $path, 'query' => $query]));
        self::assertSame('block', $result['decision']);
        self::assertContains('sql_injection', $result['matchedRules']);
        self::assertSame(1, $result['tier']);
    }

    public function testCleanRequestAllowed(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['path' => '/products', 'query' => 'search=laptop']));
        self::assertSame('allow', $result['decision']);
        self::assertSame([], $result['matchedRules']);
        self::assertSame(0.0, $result['score']);
    }

    public function testLiteralPercentNotFalsePositived(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['path' => '/products', 'query' => 'discount=50%']));
        self::assertSame('allow', $result['decision']);
    }

    public function testXssBlocks(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['path' => '/comment', 'query' => 'text=<script>alert(1)</script>']));
        self::assertSame('block', $result['decision']);
        self::assertContains('xss_attempt', $result['matchedRules']);
    }

    public function testPathTraversalBlocks(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['path' => '/files/../../etc/passwd']));
        self::assertSame('block', $result['decision']);
        self::assertContains('path_traversal', $result['matchedRules']);
    }

    public function testScannerUserAgentBlocks(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['userAgent' => 'sqlmap/1.7']));
        self::assertSame('block', $result['decision']);
        self::assertContains('scanner_detected', $result['matchedRules']);
    }

    public function testSensitiveFileAccessBlocks(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['path' => '/.env']));
        self::assertSame('block', $result['decision']);
        self::assertContains('sensitive_file_access', $result['matchedRules']);
    }

    public function testCredentialStuffingRateLimits(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['method' => 'POST', 'path' => '/api/login']));
        self::assertSame('rate_limit', $result['decision']);
        self::assertContains('credential_stuffing_pattern', $result['matchedRules']);
    }

    public function testAgentUnsanctionedToolQuarantines(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['agentId' => 'agent-1', 'toolName' => 'shell_exec']));
        self::assertSame('quarantine', $result['decision']);
        self::assertContains('agent_unsanctioned_tool', $result['matchedRules']);
        self::assertTrue($engine->isAgentQuarantined('agent-1'));
    }

    // ── Pre-check (already-blocked) short-circuit ───────────────────────

    public function testBlockedIpShortCircuitsBeforeRules(): void
    {
        $engine = new InternalClosedLoopEngine();
        $engine->blockIP('203.0.113.5', 'manual_block');
        $result = $engine->evaluate(self::req(['path' => '/anything']));
        self::assertSame('block', $result['decision']);
        self::assertSame(['ip_blocked:manual_block'], $result['matchedRules']);
    }

    public function testUnblockIpAllowsAgain(): void
    {
        $engine = new InternalClosedLoopEngine();
        $engine->blockIP('203.0.113.5', 'test');
        $engine->unblockIP('203.0.113.5');
        $result = $engine->evaluate(self::req(['path' => '/products']));
        self::assertSame('allow', $result['decision']);
    }

    public function testBlockActionAlsoBlocksSessionAndAgent(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['path' => '/.env', 'sessionId' => 'sess-1', 'agentId' => 'agent-9']));
        self::assertSame('block', $result['decision']);
        $types = array_map(static fn (array $a): string => $a['type'], $result['actions']);
        self::assertContains('block_ip', $types);
        self::assertContains('block_session', $types);
        self::assertContains('quarantine_agent', $types);
    }

    // ── Rate limiting ─────────────────────────────────────────────────────

    public function testRateLimitTriggersAfterMaxRequests(): void
    {
        $engine = new InternalClosedLoopEngine(rateLimitMax: 3, rateLimitWindowSeconds: 60.0);
        for ($i = 0; $i < 3; $i++) {
            $result = $engine->evaluate(self::req(['path' => '/products', 'query' => 'p=1']));
            self::assertSame('allow', $result['decision']);
        }
        $result = $engine->evaluate(self::req(['path' => '/products', 'query' => 'p=1']));
        self::assertSame('rate_limit', $result['decision']);
        self::assertSame(['rate_limit_exceeded'], $result['matchedRules']);
    }

    // ── Tier 2: unimplemented/pass-through by default ─────────────────────

    public function testTier2ScorerUnsetByDefaultSkipsTier2(): void
    {
        $engine = new InternalClosedLoopEngine();
        $result = $engine->evaluate(self::req(['path' => '/products', 'query' => 'p=1']));
        self::assertSame('allow', $result['decision']);
        self::assertSame(1, $result['tier']); // never reaches tier 2 scoring at all
    }

    public function testTier2ScorerWhenSuppliedCanBlock(): void
    {
        $engine = new InternalClosedLoopEngine(tier2Scorer: static fn (array $req): float => 90.0);
        $result = $engine->evaluate(self::req(['path' => '/products', 'query' => 'p=1']));
        self::assertSame('block', $result['decision']);
        self::assertSame(2, $result['tier']);
        self::assertSame(['tier2_ml_score'], $result['matchedRules']);
    }

    public function testTier2ScorerElevatedRateLimits(): void
    {
        $engine = new InternalClosedLoopEngine(tier2Scorer: static fn (array $req): float => 70.0);
        $result = $engine->evaluate(self::req(['path' => '/products', 'query' => 'p=1']));
        self::assertSame('rate_limit', $result['decision']);
        self::assertSame(2, $result['tier']);
    }

    // ── Tier 3: relay callback (hybrid mode only) ─────────────────────────

    public function testRelayNotCalledWhenExternalRelayDisabled(): void
    {
        $calls = [];
        $engine = new InternalClosedLoopEngine(onRelay: function (array $result, array $req) use (&$calls): void {
            $calls[] = $result;
        }); // enableExternalRelay defaults false
        $engine->evaluate(self::req(['path' => '/.env']));
        self::assertSame([], $calls);
    }

    public function testRelayCalledForFlaggedDecisionWhenEnabled(): void
    {
        $calls = [];
        $engine = new InternalClosedLoopEngine(
            enableExternalRelay: true,
            onRelay: function (array $result, array $req) use (&$calls): void {
                $calls[] = $result;
            },
        );
        // "/.env" matches both path_traversal (score 90) and
        // sensitive_file_access (score 85) in Node's own pattern set
        // (path_traversal's own `(/\.env|/\.git|/\.ssh)` sub-pattern
        // overlaps sensitive_file_access) — not a porting bug, reproduced
        // here deliberately, and confirmed to hold identically under
        // PHP's PCRE during independent regex verification.
        $engine->evaluate(self::req(['path' => '/.env']));
        self::assertCount(1, $calls);
        self::assertSame(['path_traversal', 'sensitive_file_access'], $calls[0]['matchedRules']);
    }

    public function testRelayNotCalledForAllowedDecision(): void
    {
        $calls = [];
        $engine = new InternalClosedLoopEngine(
            enableExternalRelay: true,
            onRelay: function (array $result, array $req) use (&$calls): void {
                $calls[] = $result;
            },
        );
        $engine->evaluate(self::req(['path' => '/products']));
        self::assertSame([], $calls);
    }

    // ── Fail mode ──────────────────────────────────────────────────────────

    public function testFailClosedSwallowsPerRuleErrorAndAllows(): void
    {
        // The engine intentionally logs this via error_log() (matching
        // Node/Python's always-on error logging) — tell PHPUnit this is
        // expected, not risky.
        $this->expectErrorLog();
        $engine = new InternalClosedLoopEngine();
        $engine->addRule([
            'name' => 'broken',
            'description' => 'x',
            'severity' => 'low',
            'score' => 1.0,
            'decision' => 'allow',
            'enabled' => true,
            'match' => static function (array $req): bool {
                throw new \RuntimeException('boom');
            },
        ]);
        // Individual rule errors are swallowed per-rule (matching Node),
        // not escalated to the top-level fail-mode handler — evaluate()
        // must not throw.
        $result = $engine->evaluate(self::req(['path' => '/products']));
        self::assertSame('allow', $result['decision']);
    }

    public function testFailClosedBlocksOnUncaughtEvaluationError(): void
    {
        $this->expectErrorLog();
        $engine = new InternalClosedLoopEngine(
            failMode: 'closed',
            tier2Scorer: static function (array $req): float {
                throw new \RuntimeException('tier2 boom');
            },
        );
        $result = $engine->evaluate(self::req(['path' => '/products']));
        self::assertSame('block', $result['decision']);
        self::assertSame(100.0, $result['score']);
        self::assertSame(['fail_closed_error'], $result['matchedRules']);
    }

    public function testFailOpenAllowsOnUncaughtEvaluationError(): void
    {
        $this->expectErrorLog();
        $engine = new InternalClosedLoopEngine(
            failMode: 'open',
            tier2Scorer: static function (array $req): float {
                throw new \RuntimeException('tier2 boom');
            },
        );
        $result = $engine->evaluate(self::req(['path' => '/products']));
        self::assertSame('allow', $result['decision']);
        self::assertSame(0.0, $result['score']);
        self::assertSame(['fail_open_error'], $result['matchedRules']);
    }

    // ── matchesKnownAttackPattern (Option B content check) ─────────────────

    public function testMatchesKnownAttackPatternDetectsSqli(): void
    {
        self::assertFalse(InternalClosedLoopEngine::matchesKnownAttackPattern('/search', null));
        self::assertTrue(InternalClosedLoopEngine::matchesKnownAttackPattern("/search?q=' OR 1=1 --"));
    }

    public function testMatchesKnownAttackPatternDetectsScanner(): void
    {
        self::assertTrue(InternalClosedLoopEngine::matchesKnownAttackPattern('/', 'nikto/2.5'));
    }

    // ── Client wiring: mode selection, observe(), isBlocked() ─────────────

    public function testClientExternalModeObserveIsNoop(): void
    {
        $client = new Client(apiKey: 'k', mode: 'external', transport: RecordingTransport::ok());
        self::assertNull($client->internalEngine);
        self::assertNull($client->observe(self::req(['path' => '/.env'])));
        self::assertFalse($client->isBlocked('203.0.113.5'));
    }

    public function testClientInternalModeObserveBlocksAttack(): void
    {
        $client = new Client(apiKey: 'k', mode: 'internal', transport: RecordingTransport::ok());
        self::assertNotNull($client->internalEngine);
        $result = $client->observe(self::req(['path' => '/.env']));
        self::assertNotNull($result);
        self::assertTrue($result['flagged']);
        self::assertSame('block', $result['decision']);
        self::assertTrue($client->isBlocked('203.0.113.5'));
    }

    public function testClientInternalModeObserveAllowsCleanRequest(): void
    {
        $client = new Client(apiKey: 'k', mode: 'internal', transport: RecordingTransport::ok());
        $result = $client->observe(self::req(['path' => '/products', 'query' => 'q=laptop']));
        self::assertNull($result);
    }

    public function testClientHybridModeBlocksViaInternalFirst(): void
    {
        $transport = RecordingTransport::ok();
        $client = new Client(apiKey: 'k', mode: 'hybrid', transport: $transport);
        self::assertNotNull($client->circuitBreaker);
        $result = $client->observe(self::req(['path' => '/.env']));
        self::assertNotNull($result);
        self::assertTrue($result['flagged']);
        // Sole relay path: the internal engine's own onRelay (wired to
        // Client::relayInternalDecisionToPlatform) is the ONLY relay for
        // this flagged decision — exactly one event queued via
        // trackEvent(), not two (TODO-210 double-billing fix, PHP side).
        // trackEvent() queues rather than sending immediately (this
        // client's normal batching model, unlike Node's); flush()
        // delivers what's queued.
        self::assertSame(1, $client->pendingEvents());
        $client->flush();
        self::assertCount(1, $transport->requests);
    }

    public function testClientHybridModeAllowsCleanRequestAndKeepsCircuitClosed(): void
    {
        $transport = RecordingTransport::ok();
        $client = new Client(apiKey: 'k', mode: 'hybrid', transport: $transport);
        $result = $client->observe(self::req(['path' => '/products', 'query' => 'q=laptop']));
        self::assertNull($result);
        self::assertSame('closed', $client->circuitBreaker->getState());
        self::assertSame(0, $client->pendingEvents()); // no relay for an allowed decision
    }
}
