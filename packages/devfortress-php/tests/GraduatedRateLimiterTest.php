<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\GraduatedRateLimiter;
use PHPUnit\Framework\TestCase;

final class GraduatedRateLimiterTest extends TestCase
{
    public function testObservationStageBelowHalfLimit(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 100);
        $result = $limiter->check('alias-1');
        self::assertSame('observation', $result['stage']);
        self::assertFalse($result['blocked']);
    }

    public function testWarningStageAtHalfLimit(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 10);
        $result = null;
        for ($i = 0; $i < 5; $i++) {
            $result = $limiter->check('alias-1');
        }
        self::assertSame('warning', $result['stage']);
        self::assertFalse($result['blocked']);
    }

    public function testSoftLimitInjectsLatencyWithJitter(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 10, softLimitBaseLatencyMs: 2000);
        $result = null;
        for ($i = 0; $i < 8; $i++) {
            $result = $limiter->check('alias-1');
        }
        self::assertSame('soft_limit', $result['stage']);
        self::assertFalse($result['blocked']);
        self::assertGreaterThan(0, $result['injectedLatencyMs']);
    }

    public function testHardBlockAtLimit(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 5);
        $result = null;
        for ($i = 0; $i < 5; $i++) {
            $result = $limiter->check('alias-1');
        }
        self::assertSame('hard_block', $result['stage']);
        self::assertTrue($result['blocked']);
        self::assertSame(60, $result['cooldownSeconds']);
    }

    public function testEscalatingCooldownDoublesEachConsecutiveBlock(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 1, initialCooldownSeconds: 60);

        $first = $limiter->check('alias-1');
        self::assertSame('hard_block', $first['stage']);
        self::assertSame(60, $first['cooldownSeconds']);

        $this->forceCooldownElapsedAndClearTimestamps($limiter, 'alias-1');

        $second = $limiter->check('alias-1');
        self::assertSame('hard_block', $second['stage']);
        self::assertSame(120, $second['cooldownSeconds']);
    }

    public function testRevokesAfterMaxConsecutiveBlocks(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 1, maxConsecutiveBlocks: 3);

        for ($i = 0; $i < 3; $i++) {
            $limiter->check('alias-1');
            $this->forceCooldownElapsed($limiter, 'alias-1');
        }

        $result = $limiter->check('alias-1');
        self::assertSame('revocation', $result['stage']);
        self::assertTrue($limiter->isRevoked('alias-1'));
    }

    public function testRevokedAliasStaysBlockedWithoutReRevoking(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 100);
        $limiter->revokeAlias('alias-1');
        $result = $limiter->check('alias-1');
        self::assertSame('revocation', $result['stage']);
        self::assertFalse($result['revoke']);
    }

    public function testResetAliasClearsEscalation(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 1);

        $limiter->check('alias-1');
        $this->forceCooldownElapsedAndClearTimestamps($limiter, 'alias-1');
        $escalated = $limiter->check('alias-1');
        self::assertSame(120, $escalated['cooldownSeconds']);

        $limiter->resetAlias('alias-1');

        $result = $limiter->check('alias-1');
        self::assertSame(60, $result['cooldownSeconds']);
    }

    public function testPerEndpointLimitsOverrideDefault(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 100, endpointLimits: ['/api/auth/*' => 2]);
        $limiter->check('alias-1', '/api/auth/login');
        $result = $limiter->check('alias-1', '/api/auth/login');
        self::assertSame(2, $result['limit']);
        self::assertSame('hard_block', $result['stage']);
    }

    public function testBurstDetectionTriggersHardBlock(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 1000, burstLimit: 3);
        $result = null;
        for ($i = 0; $i < 4; $i++) {
            $result = $limiter->check('alias-1');
        }
        self::assertTrue($result['burstDetected']);
        self::assertSame('hard_block', $result['stage']);
    }

    public function testMaxEntriesEvictsOldestAlias(): void
    {
        $limiter = new GraduatedRateLimiter(defaultLimit: 100, maxEntries: 2);
        $limiter->check('alias-1');
        $limiter->check('alias-2');
        $limiter->check('alias-3');

        self::assertSame(2, $limiter->size());
        self::assertArrayNotHasKey('alias-1', $this->readEntries($limiter));
    }

    /** @return array<string, array{timestamps: list<float>, cooldownUntil: float, consecutiveBlocks: int, revoked: bool, burstTimestamps: list<float>}> */
    private function readEntries(GraduatedRateLimiter $limiter): array
    {
        $reflection = new \ReflectionProperty(GraduatedRateLimiter::class, 'entries');

        return $reflection->getValue($limiter);
    }

    private function forceCooldownElapsed(GraduatedRateLimiter $limiter, string $key): void
    {
        $entries = $this->readEntries($limiter);
        $entries[$key]['cooldownUntil'] = microtime(true) - 0.01;
        (new \ReflectionProperty(GraduatedRateLimiter::class, 'entries'))->setValue($limiter, $entries);
    }

    private function forceCooldownElapsedAndClearTimestamps(GraduatedRateLimiter $limiter, string $key): void
    {
        $entries = $this->readEntries($limiter);
        $entries[$key]['cooldownUntil'] = microtime(true) - 0.01;
        $entries[$key]['timestamps'] = [];
        (new \ReflectionProperty(GraduatedRateLimiter::class, 'entries'))->setValue($limiter, $entries);
    }
}
