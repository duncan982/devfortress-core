package net.devfortress;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * DevFortress SDK — A10: Agent Loop Detector. Mirrors
 * {@code packages/devfortress-sdk/src/agent-loop-detector.ts}.
 *
 * <p>Tracks agent execution cycles and token consumption. Detects infinite
 * loops via cycle count, time budget, and token budget thresholds.
 * Implements an automatic circuit breaker: pause agent, alert owner.
 * Distinguishes legitimate long operations from runaway loops via
 * progress metrics.
 *
 * <p>Patent: Filing 2 — Zero-Cost Extensions (A10).
 */
public final class AgentLoopDetector {
    public enum Action {
        CONTINUE, WARN, PAUSE_AGENT, TERMINATE
    }

    public record CycleContext(Integer tokensUsed, String toolName, Map<String, Object> toolArgs, Integer progressMetric) {
        public CycleContext(String toolName) {
            this(null, toolName, null, null);
        }
    }

    public record DetectionResult(boolean loop, String reason, Action action, int cycles, long totalTokens,
                                   long elapsedMs, boolean makingProgress, double repetitionScore) {
    }

    public record ProgressThreshold(int uniqueTools, int windowCycles) {
    }

    private static final class LoopSession {
        final String agentId;
        final long startedAt = System.currentTimeMillis();
        int cycles;
        long totalTokens;
        final List<String> toolHistory = new ArrayList<>();
        final List<String> argHashes = new ArrayList<>();
        final List<Integer> progressMetrics = new ArrayList<>();
        volatile boolean paused;

        LoopSession(String agentId) {
            this.agentId = agentId;
        }
    }

    private final int maxCycles;
    private final long maxDurationMs;
    private final long maxTokens;
    private final ProgressThreshold progressThreshold;
    private final int maxSessions;
    private final Map<String, LoopSession> sessions = new LinkedHashMap<>();
    private final Object lock = new Object();

    public AgentLoopDetector() {
        this(20, 120_000, 100_000, new ProgressThreshold(2, 5), 50_000);
    }

    public AgentLoopDetector(int maxCycles, long maxDurationMs, long maxTokens, ProgressThreshold progressThreshold, int maxSessions) {
        this.maxCycles = maxCycles;
        this.maxDurationMs = maxDurationMs;
        this.maxTokens = maxTokens;
        this.progressThreshold = progressThreshold;
        this.maxSessions = maxSessions;
    }

    /**
     * Record a new execution cycle for an agent session. The legacy
     * {@code sessionId} is hardcoded to the literal {@code "agent_session"}
     * (matching Node's own quirk in {@code detectLoop}): two different
     * agents calling this overload share one process-wide loop-detection
     * session. Call {@link #recordCycle(String, String, CycleContext)}
     * directly with a real per-agent session id to avoid that.
     */
    public DetectionResult detectLoop(String agentId, List<String> toolCallHistory) {
        String toolName = toolCallHistory.isEmpty() ? null : toolCallHistory.get(toolCallHistory.size() - 1);
        return recordCycle(agentId, "agent_session", new CycleContext(null, toolName, null, null));
    }

    public DetectionResult recordCycle(String agentId, String sessionId, CycleContext context) {
        synchronized (lock) {
            LoopSession session = getOrCreateSession(agentId, sessionId);
            long now = System.currentTimeMillis();

            if (session.paused) {
                return buildResult(session, now, true, "agent_paused", Action.TERMINATE);
            }

            session.cycles++;
            session.totalTokens += context.tokensUsed() != null ? context.tokensUsed() : 0;

            if (context.toolName() != null) {
                session.toolHistory.add(context.toolName());
            }
            if (context.toolArgs() != null) {
                session.argHashes.add(hashArgs(context.toolArgs()));
            }
            if (context.progressMetric() != null) {
                session.progressMetrics.add(context.progressMetric());
            }

            long elapsedMs = now - session.startedAt;
            boolean makingProgress = checkProgress(session);
            double repetitionScore = computeRepetitionScore(session);

            if (session.cycles >= maxCycles && !makingProgress) {
                session.paused = true;
                return buildResult(session, now, true, "max_cycles", Action.PAUSE_AGENT);
            }
            if (elapsedMs >= maxDurationMs) {
                session.paused = true;
                return buildResult(session, now, true, "max_duration", Action.PAUSE_AGENT);
            }
            if (session.totalTokens >= maxTokens) {
                session.paused = true;
                return buildResult(session, now, true, "max_tokens", Action.PAUSE_AGENT);
            }
            if (repetitionScore > 0.8 && session.cycles > 5 && !makingProgress) {
                session.paused = true;
                return buildResult(session, now, true, "repetitive_pattern", Action.PAUSE_AGENT);
            }
            if (session.cycles >= maxCycles * 0.8 || elapsedMs >= maxDurationMs * 0.8 || session.totalTokens >= maxTokens * 0.8) {
                return buildResult(session, now, false, "approaching_limit", Action.WARN);
            }
            return buildResult(session, now, false, "within_limits", Action.CONTINUE);
        }
    }

    /** Clear a session (keyed by {@code agentId:sessionId}, or by a bare key if {@code sessionId} is null). */
    public void clearSession(String agentIdOrSessionId, String sessionId) {
        synchronized (lock) {
            String key = sessionId != null ? agentIdOrSessionId + ":" + sessionId : agentIdOrSessionId;
            sessions.remove(key);
        }
    }

    public void clearSession(String sessionId) {
        clearSession(sessionId, null);
    }

    /** Release an agent from paused state (after human review). */
    public boolean releaseAgent(String sessionId) {
        synchronized (lock) {
            LoopSession session = sessions.get(sessionId);
            if (session == null) {
                return false;
            }
            session.paused = false;
            session.cycles = 0;
            session.totalTokens = 0;
            session.toolHistory.clear();
            session.argHashes.clear();
            return true;
        }
    }

    public boolean isPaused(String sessionId) {
        synchronized (lock) {
            LoopSession session = sessions.get(sessionId);
            return session != null && session.paused;
        }
    }

    public record Metrics(boolean exists, int cycles, long tokens, long elapsedMs, boolean paused) {
    }

    public Metrics getMetrics(String sessionId) {
        synchronized (lock) {
            LoopSession session = sessions.get(sessionId);
            if (session == null) {
                return new Metrics(false, 0, 0, 0, false);
            }
            return new Metrics(true, session.cycles, session.totalTokens, System.currentTimeMillis() - session.startedAt, session.paused);
        }
    }

    public void destroy() {
        synchronized (lock) {
            sessions.clear();
        }
    }

    private LoopSession getOrCreateSession(String agentId, String sessionId) {
        LoopSession session = sessions.get(sessionId);
        if (session == null) {
            if (sessions.size() >= maxSessions) {
                var it = sessions.keySet().iterator();
                if (it.hasNext()) {
                    it.next();
                    it.remove();
                }
            }
            session = new LoopSession(agentId);
            sessions.put(sessionId, session);
        }
        return session;
    }

    private boolean checkProgress(LoopSession session) {
        int windowCycles = progressThreshold.windowCycles();
        List<String> recentTools = session.toolHistory.subList(
                Math.max(0, session.toolHistory.size() - windowCycles), session.toolHistory.size());
        Set<String> uniqueInWindow = new HashSet<>(recentTools);
        if (uniqueInWindow.size() >= progressThreshold.uniqueTools()) {
            return true;
        }

        if (session.progressMetrics.size() >= 2) {
            List<Integer> recent = session.progressMetrics.subList(
                    Math.max(0, session.progressMetrics.size() - 3), session.progressMetrics.size());
            boolean increasing = true;
            for (int i = 1; i < recent.size(); i++) {
                if (recent.get(i) <= recent.get(i - 1)) {
                    increasing = false;
                    break;
                }
            }
            if (increasing) {
                return true;
            }
        }
        return false;
    }

    private double computeRepetitionScore(LoopSession session) {
        if (session.argHashes.size() < 3) {
            return 0;
        }
        List<String> recent = session.argHashes.subList(Math.max(0, session.argHashes.size() - 10), session.argHashes.size());
        long uniqueHashes = new HashSet<>(recent).size();
        return 1 - (double) uniqueHashes / recent.size();
    }

    /** Simple deterministic hash for arg comparison, mirroring Node's 32-bit rolling hash over sorted-key JSON. */
    private String hashArgs(Map<String, Object> args) {
        String json = Json.encode(new TreeMap<>(args));
        int hash = 0;
        for (int i = 0; i < json.length(); i++) {
            hash = (hash << 5) - hash + json.charAt(i);
        }
        return Integer.toString(hash, 36);
    }

    private DetectionResult buildResult(LoopSession session, long now, boolean loop, String reason, Action action) {
        long elapsedMs = now - session.startedAt;
        boolean makingProgress = checkProgress(session);
        double repetitionScore = computeRepetitionScore(session);
        return new DetectionResult(loop, reason, action, session.cycles, session.totalTokens, elapsedMs, makingProgress, repetitionScore);
    }
}
