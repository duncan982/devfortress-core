<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\PlatformCircuitBreaker;
use PHPUnit\Framework\TestCase;

final class PlatformCircuitBreakerTest extends TestCase
{
    public function testStartsClosedAndAllowsExternalCalls(): void
    {
        $breaker = new PlatformCircuitBreaker();
        self::assertSame('closed', $breaker->getState());
        self::assertTrue($breaker->shouldCallExternal());
    }

    public function testOpensAfterConsecutiveFailures(): void
    {
        $transitions = [];
        $breaker = new PlatformCircuitBreaker(
            failureThreshold: 3,
            onStateChange: function (string $from, string $to, string $reason) use (&$transitions): void {
                $transitions[] = "{$from}->{$to}";
            },
        );

        $breaker->recordFailure();
        $breaker->recordFailure();
        self::assertSame('closed', $breaker->getState());

        $breaker->recordFailure();
        self::assertSame('open', $breaker->getState());
        self::assertSame(['closed->open'], $transitions);
        self::assertFalse($breaker->shouldCallExternal());
    }

    public function testHalfOpenAfterRecoveryTimeElapsed(): void
    {
        $breaker = new PlatformCircuitBreaker(failureThreshold: 1, recoveryTimeSeconds: 0.01);
        $breaker->recordFailure();
        usleep(15_000);

        self::assertTrue($breaker->shouldCallExternal());
        self::assertSame('half-open', $breaker->getState());
    }

    public function testHalfOpenSuccessClosesCircuit(): void
    {
        $breaker = new PlatformCircuitBreaker(failureThreshold: 1, recoveryTimeSeconds: 0.01);
        $breaker->recordFailure();
        usleep(15_000);
        $breaker->shouldCallExternal();

        $breaker->recordSuccess();
        self::assertSame('closed', $breaker->getState());
    }

    public function testHalfOpenFailureReopensCircuit(): void
    {
        $breaker = new PlatformCircuitBreaker(failureThreshold: 1, recoveryTimeSeconds: 0.01);
        $breaker->recordFailure();
        usleep(15_000);
        $breaker->shouldCallExternal();

        $breaker->recordFailure();
        self::assertSame('open', $breaker->getState());
    }

    public function testResetForcesClosedAndClearsFailures(): void
    {
        $breaker = new PlatformCircuitBreaker(failureThreshold: 1);
        $breaker->recordFailure();
        self::assertSame('open', $breaker->getState());

        $breaker->reset();
        self::assertSame('closed', $breaker->getState());
        self::assertSame(0, $breaker->getDiagnostics()['failureCount']);
    }

    public function testRulesBecomeStaleAfterThreshold(): void
    {
        $breaker = new PlatformCircuitBreaker(failureThreshold: 1);
        $breaker->recordFailure();

        $property = new \ReflectionProperty(PlatformCircuitBreaker::class, 'staleSince');
        $property->setValue($breaker, microtime(true) - PlatformCircuitBreaker::STALE_THRESHOLD_SECONDS - 1);

        self::assertTrue($breaker->isRulesStale());
        self::assertTrue($breaker->getDiagnostics()['rulesStale']);
    }

    public function testSuccessResetsStaleTracking(): void
    {
        $breaker = new PlatformCircuitBreaker(failureThreshold: 1, recoveryTimeSeconds: 0.01);
        $breaker->recordFailure();
        usleep(15_000);
        $breaker->shouldCallExternal();
        $breaker->recordSuccess();

        self::assertFalse($breaker->isRulesStale());
    }
}
