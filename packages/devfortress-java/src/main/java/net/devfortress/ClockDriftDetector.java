package net.devfortress;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * DevFortress SDK — Clock Drift Anomaly Detector (Invention A18). Mirrors
 * {@code packages/devfortress-sdk/src/security-extensions.ts}'s
 * {@code ClockDriftDetector}.
 *
 * <p>TODO 419/422 — one of the 20 Node-only claims identified by the
 * 2026-11-02 patent audit; ported to Python and Go in that session, here
 * extended to Java.
 *
 * <p>Compares a client-supplied timestamp against server time and
 * classifies the drift into an escalating action: allow, warn (audit
 * with server time), use_server_time (enforce server-authoritative
 * timestamps), or reject (possible timestamp manipulation).
 *
 * <p>Safe for concurrent use.
 */
public final class ClockDriftDetector {

    private static final int MAX_HISTORY_PER_CLIENT = 100;

    /** Severity band of a {@link Result}. */
    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

    /** Recommended action from a {@link Result}. */
    public enum Action { ALLOW, WARN, USE_SERVER_TIME, REJECT }

    /** The outcome of one {@link #check} call. */
    public record Result(boolean valid, double driftMs, Severity severity, Action action, String reason) {
    }

    /** The drift trend for a client, from {@link #getDriftTrend}. */
    public record Trend(double avgDrift, boolean increasing) {
    }

    private final double acceptableThresholdMs;
    private final double suspiciousThresholdMs;
    private final double criticalThresholdMs;

    private final Object lock = new Object();
    private final Map<String, List<Double>> driftHistory = new HashMap<>();

    public ClockDriftDetector() {
        this(30_000.0, 120_000.0, 300_000.0);
    }

    public ClockDriftDetector(double acceptableThresholdMs, double suspiciousThresholdMs, double criticalThresholdMs) {
        this.acceptableThresholdMs = acceptableThresholdMs;
        this.suspiciousThresholdMs = suspiciousThresholdMs;
        this.criticalThresholdMs = criticalThresholdMs;
    }

    /**
     * Checks a client timestamp (epoch milliseconds) against server time.
     * {@code clientId} may be {@code null} — drift is not tracked for an
     * anonymous caller.
     */
    public Result check(double clientTimestampMs, String clientId) {
        double serverTimeMs = System.currentTimeMillis();
        double driftMs = Math.abs(clientTimestampMs - serverTimeMs);
        String direction = clientTimestampMs > serverTimeMs ? "ahead" : "behind";

        if (clientId != null) {
            synchronized (lock) {
                List<Double> history = driftHistory.computeIfAbsent(clientId, k -> new ArrayList<>());
                history.add(driftMs);
                while (history.size() > MAX_HISTORY_PER_CLIENT) {
                    history.remove(0);
                }
            }
        }

        if (driftMs <= acceptableThresholdMs) {
            return new Result(true, driftMs, Severity.LOW, Action.ALLOW,
                    String.format("Clock drift %.0fms (%s) within acceptable range", driftMs, direction));
        }
        if (driftMs <= suspiciousThresholdMs) {
            return new Result(true, driftMs, Severity.MEDIUM, Action.WARN,
                    String.format("Clock drift %.0fms (%s) — suspicious, using server time for audit", driftMs, direction));
        }
        if (driftMs <= criticalThresholdMs) {
            return new Result(true, driftMs, Severity.HIGH, Action.USE_SERVER_TIME,
                    String.format("Clock drift %.0fms (%s) — enforcing server-authoritative timestamps", driftMs, direction));
        }
        return new Result(false, driftMs, Severity.CRITICAL, Action.REJECT,
                String.format("Clock drift %.0fms (%s) exceeds critical threshold — possible timestamp manipulation", driftMs, direction));
    }

    /** Returns the drift trend for a client, or empty if fewer than 3 samples. */
    public Optional<Trend> getDriftTrend(String clientId) {
        List<Double> history;
        synchronized (lock) {
            history = driftHistory.get(clientId);
            if (history == null) {
                return Optional.empty();
            }
            history = new ArrayList<>(history);
        }
        if (history.size() < 3) {
            return Optional.empty();
        }

        double avgDrift = history.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        List<Double> recent = history.subList(history.size() - 3, history.size());
        double recentAvg = recent.stream().mapToDouble(Double::doubleValue).average().orElse(0);

        return Optional.of(new Trend(avgDrift, recentAvg > avgDrift * 1.2));
    }

    /** Returns the number of clients with tracked drift history. */
    public int getStats() {
        synchronized (lock) {
            return driftHistory.size();
        }
    }
}
