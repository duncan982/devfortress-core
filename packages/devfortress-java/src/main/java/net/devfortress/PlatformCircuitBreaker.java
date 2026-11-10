package net.devfortress;

/**
 * DevFortress SDK — Platform Circuit Breaker. Mirrors
 * {@code packages/devfortress-sdk/src/circuit-breaker.ts}.
 *
 * <p>Monitors connectivity to the DevFortress platform and provides
 * automatic failover from external to internal closed-loop mode.
 *
 * <p>Three states:
 * <ul>
 *   <li>{@link State#CLOSED}: Platform is reachable, external CL is active</li>
 *   <li>{@link State#OPEN}: Platform is unreachable, internal CL takes over</li>
 *   <li>{@link State#HALF_OPEN}: Testing if the platform has recovered</li>
 * </ul>
 *
 * <p>Transition rules:
 * <ul>
 *   <li>CLOSED -&gt; OPEN: After failureThreshold consecutive failures</li>
 *   <li>OPEN -&gt; HALF_OPEN: After recoveryTimeMs elapsed</li>
 *   <li>HALF_OPEN -&gt; CLOSED: First successful call</li>
 *   <li>HALF_OPEN -&gt; OPEN: First failed call</li>
 * </ul>
 *
 * <p>Safe for concurrent use.
 */
public final class PlatformCircuitBreaker {

    /** A {@link PlatformCircuitBreaker}'s state. */
    public enum State { CLOSED, OPEN, HALF_OPEN }

    /** Called when the circuit's state changes. */
    public interface StateChangeListener {
        void onStateChange(State from, State to, String reason);
    }

    /** Rules older than 5 minutes without a platform sync are considered stale. */
    public static final long STALE_THRESHOLD_MS = 300_000L;

    /** The result of {@link #getDiagnostics}. */
    public record Diagnostics(
            State state,
            int failureCount,
            long lastFailureTime,
            long msUntilRecoveryAttempt,
            boolean rulesStale,
            long staleDurationMs) {
    }

    private final Object lock = new Object();
    private State state = State.CLOSED;
    private int failureCount = 0;
    private long lastFailureTime = 0L;
    private final int failureThreshold;
    private final long recoveryTimeMs;
    private final StateChangeListener onStateChange;

    /** When internal rules became stale (circuit opened); null if not stale. */
    private Long staleSince = null;

    public PlatformCircuitBreaker(int failureThreshold, long recoveryTimeMs, StateChangeListener onStateChange) {
        this.failureThreshold = failureThreshold;
        this.recoveryTimeMs = recoveryTimeMs;
        this.onStateChange = onStateChange;
    }

    public PlatformCircuitBreaker() {
        this(3, 60_000L, null);
    }

    /**
     * Returns whether external platform calls should be attempted
     * (true if closed or half-open).
     */
    public boolean shouldCallExternal() {
        synchronized (lock) {
            if (state == State.CLOSED) {
                return true;
            }
            if (state == State.OPEN) {
                if (System.currentTimeMillis() - lastFailureTime >= recoveryTimeMs) {
                    transition(State.HALF_OPEN, "recovery_timeout_elapsed");
                    return true; // allow one test call
                }
                return false;
            }
            // HALF_OPEN: allow the test call.
            return true;
        }
    }

    /** Records a successful external call. */
    public void recordSuccess() {
        synchronized (lock) {
            if (state == State.HALF_OPEN) {
                transition(State.CLOSED, "test_call_succeeded");
            }
            failureCount = 0;
            staleSince = null;
        }
    }

    /** Records a failed external call. */
    public void recordFailure() {
        synchronized (lock) {
            failureCount++;
            lastFailureTime = System.currentTimeMillis();

            if (state == State.HALF_OPEN) {
                transition(State.OPEN, "test_call_failed");
                return;
            }
            if (state == State.CLOSED && failureCount >= failureThreshold) {
                transition(State.OPEN, "consecutive_failures");
            }
        }
    }

    /** Returns the current circuit state. */
    public State getState() {
        synchronized (lock) {
            return state;
        }
    }

    /** Returns diagnostics info. */
    public Diagnostics getDiagnostics() {
        synchronized (lock) {
            long msUntilRecovery = 0L;
            if (state == State.OPEN) {
                long elapsed = System.currentTimeMillis() - lastFailureTime;
                msUntilRecovery = elapsed < recoveryTimeMs ? recoveryTimeMs - elapsed : 0L;
            }

            long staleDurationMs = staleSince != null ? System.currentTimeMillis() - staleSince : 0L;

            return new Diagnostics(state, failureCount, lastFailureTime, msUntilRecovery,
                    staleDurationMs > STALE_THRESHOLD_MS, staleDurationMs);
        }
    }

    /** Forces the circuit breaker back to the closed state. */
    public void reset() {
        synchronized (lock) {
            transition(State.CLOSED, "manual_reset");
            failureCount = 0;
            lastFailureTime = 0L;
            staleSince = null;
        }
    }

    /** Returns whether internal rules are stale (no platform sync for longer than {@link #STALE_THRESHOLD_MS}). */
    public boolean isRulesStale() {
        synchronized (lock) {
            return staleSince != null && (System.currentTimeMillis() - staleSince) > STALE_THRESHOLD_MS;
        }
    }

    private void transition(State to, String reason) {
        State from = state;
        if (from == to) {
            return;
        }
        state = to;

        if (to == State.OPEN && staleSince == null) {
            staleSince = System.currentTimeMillis();
        }

        if (onStateChange != null) {
            try {
                onStateChange.onStateChange(from, to, reason);
            } catch (RuntimeException e) {
                // Callback errors should not break the circuit breaker.
            }
        }
    }
}
