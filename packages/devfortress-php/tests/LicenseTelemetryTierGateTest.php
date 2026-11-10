<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\AgentOutputExfiltrationDetector;
use DevFortress\Sdk\LicenseManager;
use DevFortress\Sdk\LoggerInterface;
use DevFortress\Sdk\ShadowAgentRegistry;
use DevFortress\Sdk\Tests\Support\RecordingTransport;
use DevFortress\Sdk\TelemetryManager;
use DevFortress\Sdk\TelemetryRollupBuffer;
use DevFortress\Sdk\Transport\TransportResponse;
use DevFortress\Sdk\TierGate;
use PHPUnit\Framework\TestCase;
use Stringable;

/**
 * LicenseManager / TelemetryManager / TelemetryRollupBuffer / TierGate
 * (TODO 369/370, Must-Have) and presence checks for AgentOutputExfiltration
 * Detector (B7) / ShadowAgentRegistry (B10) (TODO 380, Should-Have), newly
 * ported from the Node SDK. Mirrors the mock-transport style already used
 * in Tier2PublicTest.php (RecordingTransport) rather than hitting the live
 * platform.
 */
final class LicenseTelemetryTierGateTest extends TestCase
{
    // ── LicenseManager ────────────────────────────────────────────

    public function testLicenseManagerResolvesTierOnSuccessfulCheck(): void
    {
        $transport = new RecordingTransport([
            new TransportResponse(200, json_encode(['tier' => 'pro', 'modelVersion' => 'model-v3'], JSON_THROW_ON_ERROR)),
        ]);
        $manager = new LicenseManager('vx_live_test_key', 'http://platform.test', transport: $transport);

        $state = $manager->checkLicense();
        self::assertTrue($state['valid']);
        self::assertSame('pro', $state['tier']);
        self::assertFalse($state['degraded']);
        self::assertSame(0, $state['consecutiveFailures']);

        // CV-M4: model freshness synced from the same response.
        $model = $manager->getModelState();
        self::assertSame('model-v3', $model['modelVersion']);
        self::assertFalse($model['expired']);

        // The request was signed (X-DevFortress-Key-Id present, no raw key on the wire).
        $headers = $transport->requests[0]['headers'];
        self::assertArrayHasKey('X-DevFortress-Key-Id', $headers);
        self::assertStringNotContainsString('vx_live_test_key', $transport->requests[0]['body']);
    }

    public function testLicenseManagerDegradesVisiblyNotSilentlyAfterGracePeriodExpires(): void
    {
        $logger = new CapturingLogger();
        $transport = new RecordingTransport([
            new TransportResponse(200, json_encode(['tier' => 'team'], JSON_THROW_ON_ERROR)),
            RecordingTransport::down(),
        ]);
        // gracePeriodMs: 0 — any failure after a successful check is
        // immediately past the grace boundary, so this exercises the same
        // degrade-after-grace-expiry branch a real 72h window eventually
        // reaches, without the test needing to fast-forward wall-clock time.
        $manager = new LicenseManager('vx_live_test_key', 'http://platform.test', gracePeriodMs: 0, logger: $logger, transport: $transport);

        $first = $manager->checkLicense();
        self::assertTrue($first['valid']);

        $second = $manager->checkLicense();
        // Faithfully ported from Node: handleCheckFailure() never touches
        // `valid` itself (only an explicit 402/403 rejection does) — it
        // stays at its last-known value from the prior successful check,
        // while `degraded` is the operative flag that actually gates
        // canPerformAction()'s monitor-only behavior below.
        self::assertTrue($second['valid']);
        self::assertTrue($second['degraded'], 'a license check failure past the grace period must degrade, not fail silently');
        self::assertStringContainsString('degraded to monitor-only mode', $second['degradationReason'] ?? '');
        self::assertSame(1, $second['consecutiveFailures']);

        // TODO 321's fix intent: the degradation is LOGGED VISIBLY (warning),
        // never silent.
        self::assertTrue(
            $logger->hasRecordContaining('warning', 'degraded to monitor-only mode'),
            'license degradation must be logged visibly at warning level, not dropped silently',
        );

        // Degraded mode means monitor-only: blocking actions are disallowed,
        // observing is still always allowed.
        self::assertTrue($manager->isDegraded());
        self::assertFalse($manager->canPerformAction('block'));
        self::assertTrue($manager->canPerformAction('observe'));
    }

    public function testLicenseManagerIntegrityHashIsStableAndDetectsTampering(): void
    {
        $manager = new LicenseManager('vx_live_test_key', 'http://platform.test', integritySecret: 'shh', transport: RecordingTransport::ok());
        $hash = $manager->computeIntegrityHash();
        self::assertNotSame('no-integrity-secret', $hash);
        self::assertSame($hash, $manager->computeIntegrityHash());

        $verify = $manager->verifyIntegrity($hash);
        self::assertFalse($verify['tampered']);

        $tampered = $manager->verifyIntegrity('0000000000000000');
        self::assertTrue($tampered['tampered']);
    }

    // ── TelemetryManager ──────────────────────────────────────────

    public function testTelemetryManagerSendsHeartbeatAndResetsCounters(): void
    {
        $transport = RecordingTransport::ok();
        $telemetry = new TelemetryManager('vx_live_test_key', 'http://platform.test', transport: $transport);

        $telemetry->recordEvent();
        $telemetry->recordEvent();
        $telemetry->recordEvent();
        $telemetry->recordBlock();
        $telemetry->recordRateLimit();
        $telemetry->recordLatency(42.0);

        $delivered = $telemetry->sendHeartbeat();
        self::assertTrue($delivered);

        $body = json_decode($transport->requests[0]['body'], true);
        self::assertSame(3, $body['eventCount']);
        self::assertSame(1, $body['blockCount']);
        self::assertSame(1, $body['rateLimitCount']);
        // json_encode omits the ".0" for a whole-number float (no
        // JSON_PRESERVE_ZERO_FRACTION), so json_decode reads it back as an
        // int — assertEquals rather than assertSame for this one field.
        self::assertEquals(42.0, $body['p99LatencyMs']);

        // Counters reset after a successful send.
        $state = $telemetry->getState();
        self::assertSame(0, $state['eventCount']);
        self::assertSame(0, $state['blockCount']);
        self::assertSame(0, $state['rateLimitCount']);
    }

    public function testTelemetryManagerHeartbeatFailureIsFireAndForget(): void
    {
        $transport = new RecordingTransport([RecordingTransport::down()]);
        $telemetry = new TelemetryManager('vx_live_test_key', 'http://platform.test', transport: $transport);
        $telemetry->recordEvent();

        $delivered = $telemetry->sendHeartbeat();
        self::assertFalse($delivered);
        // Does not throw, and counters are NOT cleared on a failed send.
        self::assertSame(1, $telemetry->getState()['eventCount']);
    }

    // ── TelemetryRollupBuffer ─────────────────────────────────────

    public function testTelemetryRollupBufferAggregatesByCompositeKeyAndFlushes(): void
    {
        $transport = RecordingTransport::ok();
        $buffer = new TelemetryRollupBuffer('vx_live_test_key', 'http://platform.test', transport: $transport);

        $buffer->add('1.2.3.4', '/api/widgets', false, 10.0);
        $buffer->add('1.2.3.4', '/api/widgets', true, 20.0);
        $buffer->add('5.6.7.8', '/api/other', false, 5.0);

        // Two distinct aliasOrIpKey values in the same hour period → two buckets.
        self::assertSame(2, $buffer->bufferedKeyCount());

        $buffer->flush();
        self::assertSame(0, $buffer->bufferedKeyCount());

        $body = json_decode($transport->requests[0]['body'], true);
        $contributions = $body['contributions'];
        self::assertCount(2, $contributions);

        $byKey = [];
        foreach ($contributions as $c) {
            $byKey[$c['aliasOrIpKey']] = $c;
        }
        self::assertSame(2, $byKey['1.2.3.4']['requestCount']);
        self::assertSame(1, $byKey['1.2.3.4']['errorCount']);
        self::assertEquals(30.0, $byKey['1.2.3.4']['latencySumMs']);
        self::assertSame(1, $byKey['5.6.7.8']['requestCount']);
    }

    public function testTelemetryRollupBufferHourlyPeriodKeyMatchesIsoHourFormat(): void
    {
        // 1700000000000 ms == 2023-11-14T22:13:20.000Z; Node's
        // `date.toISOString().slice(0, 13)` yields "2023-11-14T22".
        self::assertSame('2023-11-14T22', TelemetryRollupBuffer::hourlyPeriodKey(1_700_000_000_000));
    }

    public function testTelemetryRollupBufferForcesEarlyFlushWhenMaxBufferedKeysReached(): void
    {
        $transport = RecordingTransport::ok();
        $buffer = new TelemetryRollupBuffer('vx_live_test_key', 'http://platform.test', maxBufferedKeys: 2, transport: $transport);

        $buffer->add('key-a', '/x', false, 1.0);
        $buffer->add('key-b', '/x', false, 1.0);
        self::assertSame(2, $buffer->bufferedKeyCount());

        // A third distinct key exceeds maxBufferedKeys → forces an early flush.
        $buffer->add('key-c', '/x', false, 1.0);
        self::assertSame(0, $buffer->bufferedKeyCount());
        self::assertCount(1, $transport->requests);
    }

    // ── TierGate ──────────────────────────────────────────────────

    public function testTierGateResolvesCapabilitiesPerTier(): void
    {
        $team = new TierGate('team');
        self::assertTrue($team->canBlock());
        self::assertSame(['external', 'internal', 'hybrid'], $team->getCapabilities()['allowedModes']);
        self::assertSame('hybrid', $team->getEffectiveMode());
        self::assertSame(2, $team->getMaxICLTier());
        self::assertTrue($team->hasComplianceEvidence());

        $enterprise = new TierGate('enterprise');
        self::assertSame(3, $enterprise->getMaxICLTier());
        self::assertTrue($enterprise->isAirGapEnabled());
        self::assertTrue($enterprise->canConfigureCustomRules());
    }

    public function testTierGateBlocksTierIneligibleFeature(): void
    {
        $starter = new TierGate('starter');
        self::assertFalse($starter->canBlock());

        $blockError = $starter->validateBlockAction('block_ip');
        self::assertNotNull($blockError);
        self::assertStringContainsString('not available on the starter tier', $blockError);

        $modeError = $starter->validateMode('hybrid');
        self::assertNotNull($modeError);
        self::assertStringContainsString("'hybrid' mode is not available on the starter tier", $modeError);

        // Requesting a disallowed mode falls back to the tier's default, not an exception.
        self::assertSame('external', $starter->getEffectiveMode('hybrid'));

        // Pro: blocking allowed, but hybrid still is not (Package A — external CL only).
        $pro = new TierGate('pro');
        self::assertTrue($pro->canBlock());
        self::assertNull($pro->validateBlockAction('block_ip'));
        self::assertNotNull($pro->validateMode('hybrid'));
        self::assertSame('external', $pro->getEffectiveMode('hybrid'));
    }

    public function testTierGateMonthlyQuotaAndSnapshotRoundTrip(): void
    {
        $gate = new TierGate('starter');
        $quota = $gate->checkMonthlyQuota();
        self::assertTrue($quota['allowed']);
        self::assertSame(50_000, $quota['limit']);

        $gate->recordMonthlyEvent();
        $gate->recordEvent();
        $snapshot = $gate->toSnapshot();
        self::assertSame('starter', $snapshot['tier']);
        self::assertSame(1, $snapshot['monthlyEventCount']);
        self::assertSame(1, $snapshot['dailyEventCount']);

        $restored = TierGate::fromSnapshot($snapshot);
        self::assertSame('starter', $restored->getTier());
        self::assertSame(1, $restored->getMonthlyUsage()['used']);
    }

    public function testTierGateRejectsUnknownTier(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TierGate('ultra-plus');
    }

    // ── AgentOutputExfiltrationDetector (B7) — presence/visibility ──

    public function testAgentOutputExfiltrationDetectorIsPublicAndDetectsCredentialLeak(): void
    {
        $detector = new AgentOutputExfiltrationDetector();

        $safe = $detector->analyze([
            'agentId' => 'agent-1',
            'outputContent' => 'The weather today is sunny.',
            'outputType' => 'text',
            'destinationType' => 'user',
            'timestamp' => 1_700_000_000_000,
        ]);
        self::assertFalse($safe['detected']);
        self::assertSame('allow', $safe['recommendation']);

        $leak = $detector->analyze([
            'agentId' => 'agent-1',
            'outputContent' => "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
            'outputType' => 'text',
            'destinationType' => 'api',
            'timestamp' => 1_700_000_000_000,
        ]);
        self::assertTrue($leak['detected']);
        self::assertSame('credential-leak', $leak['threatType']);
        self::assertSame('block', $leak['recommendation']);
    }

    // ── ShadowAgentRegistry (B10) — presence/visibility ─────────────

    public function testShadowAgentRegistryIsPublicAndDistinguishesRegisteredFromShadow(): void
    {
        $registry = new ShadowAgentRegistry();

        $registered = $registry->register([
            'agentId' => 'agent-known-1',
            'name' => 'Known Agent',
            'owner' => 'team-a',
            'permissions' => ['read'],
        ]);
        self::assertTrue($registered['active']);
        self::assertSame(1, $registry->getStats()['registeredCount']);

        $knownResult = $registry->detect('agent-known-1', []);
        self::assertFalse($knownResult['detected']);

        $shadowResult = $registry->detect('unknown-fingerprint', [
            'automated request pattern seen (>100 req/min)',
            'consistent timing between requests observed',
            'sequential resource enumeration detected',
        ]);
        self::assertTrue($shadowResult['detected']);
        self::assertGreaterThan(0.3, $shadowResult['confidence']);
        self::assertSame(1, $registry->getStats()['shadowDetections']);
    }
}

/** A minimal PSR-3-shaped logger that records every call, for assertions on visible-vs-silent logging. */
final class CapturingLogger implements LoggerInterface
{
    /** @var list<array{level: string, message: string}> */
    public array $records = [];

    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = ['level' => (string) $level, 'message' => (string) $message];
    }

    public function hasRecordContaining(string $level, string $needle): bool
    {
        foreach ($this->records as $record) {
            if ($record['level'] === $level && str_contains($record['message'], $needle)) {
                return true;
            }
        }

        return false;
    }
}
