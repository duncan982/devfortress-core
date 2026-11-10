package net.devfortress;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ClockDriftDetector (Invention A18, TODO 419/422): server-authoritative
 * clock drift detection, ported from
 * {@code packages/devfortress-sdk/src/security-extensions.ts}.
 */
class ClockDriftDetectorTest {

    private static double nowMs() {
        return System.currentTimeMillis();
    }

    @Test
    void withinAcceptableThresholdIsAllowed() {
        var detector = new ClockDriftDetector();
        var result = detector.check(nowMs(), null);
        assertTrue(result.valid());
        assertEquals(ClockDriftDetector.Severity.LOW, result.severity());
        assertEquals(ClockDriftDetector.Action.ALLOW, result.action());
    }

    @Test
    void suspiciousDriftWarnsButStaysValid() {
        var detector = new ClockDriftDetector();
        var result = detector.check(nowMs() - 60_000, null);
        assertTrue(result.valid());
        assertEquals(ClockDriftDetector.Severity.MEDIUM, result.severity());
        assertEquals(ClockDriftDetector.Action.WARN, result.action());
    }

    @Test
    void highDriftEnforcesServerTime() {
        var detector = new ClockDriftDetector();
        var result = detector.check(nowMs() - 200_000, null);
        assertTrue(result.valid());
        assertEquals(ClockDriftDetector.Severity.HIGH, result.severity());
        assertEquals(ClockDriftDetector.Action.USE_SERVER_TIME, result.action());
    }

    @Test
    void criticalDriftIsRejected() {
        var detector = new ClockDriftDetector();
        var result = detector.check(nowMs() - 600_000, null);
        assertFalse(result.valid());
        assertEquals(ClockDriftDetector.Severity.CRITICAL, result.severity());
        assertEquals(ClockDriftDetector.Action.REJECT, result.action());
    }

    @Test
    void aheadOfServerTimeIsAlsoDetected() {
        var detector = new ClockDriftDetector();
        var result = detector.check(nowMs() + 600_000, null);
        assertFalse(result.valid());
        assertTrue(result.reason().contains("ahead"));
    }

    @Test
    void customThresholdsAreRespected() {
        var detector = new ClockDriftDetector(1_000, 5_000, 10_000);
        assertEquals(ClockDriftDetector.Action.WARN, detector.check(nowMs() - 2_000, null).action());
        assertEquals(ClockDriftDetector.Action.REJECT, detector.check(nowMs() - 20_000, null).action());
    }

    @Test
    void driftTrendRequiresAtLeastThreeSamples() {
        var detector = new ClockDriftDetector();
        detector.check(nowMs() - 1_000, "c1");
        detector.check(nowMs() - 2_000, "c1");
        assertEquals(Optional.empty(), detector.getDriftTrend("c1"));

        detector.check(nowMs() - 3_000, "c1");
        var trend = detector.getDriftTrend("c1");
        assertTrue(trend.isPresent());
        assertTrue(trend.get().avgDrift() > 0);
    }

    @Test
    void driftTrendDetectsIncreasingDrift() {
        var detector = new ClockDriftDetector();
        for (double driftMs : new double[] {1_000, 1_000, 1_000, 5_000, 5_000, 5_000}) {
            detector.check(nowMs() - driftMs, "growing");
        }
        var trend = detector.getDriftTrend("growing");
        assertTrue(trend.isPresent());
        assertTrue(trend.get().increasing());
    }

    @Test
    void getStatsCountsTrackedClients() {
        var detector = new ClockDriftDetector();
        detector.check(nowMs(), "a");
        detector.check(nowMs(), "b");
        detector.check(nowMs(), null); // no clientId — not tracked
        assertEquals(2, detector.getStats());
    }
}
