<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\ClockDriftDetector;
use PHPUnit\Framework\TestCase;

/**
 * ClockDriftDetector (Invention A18, TODO 419/422): server-authoritative
 * clock drift detection, ported from security-extensions.ts.
 */
final class ClockDriftDetectorTest extends TestCase
{
    private function nowMs(): float
    {
        return microtime(true) * 1000;
    }

    public function testWithinAcceptableThresholdIsAllowed(): void
    {
        $detector = new ClockDriftDetector();
        $result = $detector->check($this->nowMs());
        self::assertTrue($result['valid']);
        self::assertSame('LOW', $result['severity']);
        self::assertSame('allow', $result['action']);
    }

    public function testSuspiciousDriftWarnsButStaysValid(): void
    {
        $detector = new ClockDriftDetector();
        $result = $detector->check($this->nowMs() - 60_000);
        self::assertTrue($result['valid']);
        self::assertSame('MEDIUM', $result['severity']);
        self::assertSame('warn', $result['action']);
    }

    public function testHighDriftEnforcesServerTime(): void
    {
        $detector = new ClockDriftDetector();
        $result = $detector->check($this->nowMs() - 200_000);
        self::assertTrue($result['valid']);
        self::assertSame('HIGH', $result['severity']);
        self::assertSame('use_server_time', $result['action']);
    }

    public function testCriticalDriftIsRejected(): void
    {
        $detector = new ClockDriftDetector();
        $result = $detector->check($this->nowMs() - 600_000);
        self::assertFalse($result['valid']);
        self::assertSame('CRITICAL', $result['severity']);
        self::assertSame('reject', $result['action']);
    }

    public function testAheadOfServerTimeIsAlsoDetected(): void
    {
        $detector = new ClockDriftDetector();
        $result = $detector->check($this->nowMs() + 600_000);
        self::assertFalse($result['valid']);
        self::assertStringContainsString('ahead', $result['reason']);
    }

    public function testCustomThresholdsAreRespected(): void
    {
        $detector = new ClockDriftDetector(
            acceptableThresholdMs: 1_000,
            suspiciousThresholdMs: 5_000,
            criticalThresholdMs: 10_000,
        );
        self::assertSame('warn', $detector->check($this->nowMs() - 2_000)['action']);
        self::assertSame('reject', $detector->check($this->nowMs() - 20_000)['action']);
    }

    public function testDriftTrendRequiresAtLeastThreeSamples(): void
    {
        $detector = new ClockDriftDetector();
        $detector->check($this->nowMs() - 1_000, 'c1');
        $detector->check($this->nowMs() - 2_000, 'c1');
        self::assertNull($detector->getDriftTrend('c1'));

        $detector->check($this->nowMs() - 3_000, 'c1');
        $trend = $detector->getDriftTrend('c1');
        self::assertNotNull($trend);
        self::assertGreaterThan(0, $trend['avgDrift']);
    }

    public function testDriftTrendDetectsIncreasingDrift(): void
    {
        $detector = new ClockDriftDetector();
        foreach ([1_000, 1_000, 1_000, 5_000, 5_000, 5_000] as $driftMs) {
            $detector->check($this->nowMs() - $driftMs, 'growing');
        }
        $trend = $detector->getDriftTrend('growing');
        self::assertNotNull($trend);
        self::assertTrue($trend['increasing']);
    }

    public function testGetStatsCountsTrackedClients(): void
    {
        $detector = new ClockDriftDetector();
        $detector->check($this->nowMs(), 'a');
        $detector->check($this->nowMs(), 'b');
        $detector->check($this->nowMs()); // no clientId — not tracked
        self::assertSame(['trackedClients' => 2], $detector->getStats());
    }
}
