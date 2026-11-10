package net.devfortress;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PlatformCircuitBreaker (TODO 372), ported from
 * {@code packages/devfortress-sdk/src/circuit-breaker.ts}.
 */
class PlatformCircuitBreakerTest {

    private static void setStaleSince(PlatformCircuitBreaker breaker, long value) {
        try {
            Field f = PlatformCircuitBreaker.class.getDeclaredField("staleSince");
            f.setAccessible(true);
            f.set(breaker, value);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void startsClosedAndAllowsExternalCalls() {
        PlatformCircuitBreaker breaker = new PlatformCircuitBreaker();
        assertEquals(PlatformCircuitBreaker.State.CLOSED, breaker.getState());
        assertTrue(breaker.shouldCallExternal());
    }

    @Test
    void opensAfterConsecutiveFailures() {
        List<String> transitions = new ArrayList<>();
        PlatformCircuitBreaker breaker = new PlatformCircuitBreaker(3, 60_000L,
                (from, to, reason) -> transitions.add(from + "->" + to));

        breaker.recordFailure();
        breaker.recordFailure();
        assertEquals(PlatformCircuitBreaker.State.CLOSED, breaker.getState());

        breaker.recordFailure();
        assertEquals(PlatformCircuitBreaker.State.OPEN, breaker.getState());
        assertEquals(List.of("CLOSED->OPEN"), transitions);
        assertFalse(breaker.shouldCallExternal());
    }

    @Test
    void halfOpenAfterRecoveryTimeElapsed() throws InterruptedException {
        PlatformCircuitBreaker breaker = new PlatformCircuitBreaker(1, 10L, null);
        breaker.recordFailure();
        Thread.sleep(20);

        assertTrue(breaker.shouldCallExternal());
        assertEquals(PlatformCircuitBreaker.State.HALF_OPEN, breaker.getState());
    }

    @Test
    void halfOpenSuccessClosesCircuit() throws InterruptedException {
        PlatformCircuitBreaker breaker = new PlatformCircuitBreaker(1, 10L, null);
        breaker.recordFailure();
        Thread.sleep(20);
        breaker.shouldCallExternal();

        breaker.recordSuccess();
        assertEquals(PlatformCircuitBreaker.State.CLOSED, breaker.getState());
    }

    @Test
    void halfOpenFailureReopensCircuit() throws InterruptedException {
        PlatformCircuitBreaker breaker = new PlatformCircuitBreaker(1, 10L, null);
        breaker.recordFailure();
        Thread.sleep(20);
        breaker.shouldCallExternal();

        breaker.recordFailure();
        assertEquals(PlatformCircuitBreaker.State.OPEN, breaker.getState());
    }

    @Test
    void resetForcesClosedAndClearsFailures() {
        PlatformCircuitBreaker breaker = new PlatformCircuitBreaker(1, 60_000L, null);
        breaker.recordFailure();
        assertEquals(PlatformCircuitBreaker.State.OPEN, breaker.getState());

        breaker.reset();
        assertEquals(PlatformCircuitBreaker.State.CLOSED, breaker.getState());
        assertEquals(0, breaker.getDiagnostics().failureCount());
    }

    @Test
    void rulesBecomeStaleAfterThreshold() {
        PlatformCircuitBreaker breaker = new PlatformCircuitBreaker(1, 60_000L, null);
        breaker.recordFailure();

        setStaleSince(breaker, System.currentTimeMillis() - PlatformCircuitBreaker.STALE_THRESHOLD_MS - 1000);

        assertTrue(breaker.isRulesStale());
        assertTrue(breaker.getDiagnostics().rulesStale());
    }

    @Test
    void successResetsStaleTracking() throws InterruptedException {
        PlatformCircuitBreaker breaker = new PlatformCircuitBreaker(1, 10L, null);
        breaker.recordFailure();
        Thread.sleep(20);
        breaker.shouldCallExternal();
        breaker.recordSuccess();

        assertFalse(breaker.isRulesStale());
    }
}
