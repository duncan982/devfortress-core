package net.devfortress;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DevFortress SDK — A7: Tool-Call Sequence Validator. Mirrors
 * {@code packages/devfortress-sdk/src/tool-call-sequence-validator.ts}.
 *
 * <p>Validates AI agent tool calls against an authorized directed acyclic
 * graph (DAG). Detects out-of-sequence tool calls that indicate prompt
 * injection attacks — e.g., an agent jumping directly to {@code
 * place_order} without first calling {@code add_to_cart}. Graduated
 * response: log → rate-limit → block → revoke session.
 *
 * <p>Patent: Filing 2 — Zero-Cost Extensions (A7).
 */
public final class ToolCallSequenceValidator {
    public enum RiskLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    public record GraphNode(List<String> requires, int maxCalls, RiskLevel riskLevel) {
        public GraphNode(List<String> requires) {
            this(requires, 0, null);
        }

        public GraphNode(List<String> requires, int maxCalls) {
            this(requires, maxCalls, null);
        }
    }

    public enum Action {
        ALLOW, LOG, RATE_LIMIT, BLOCK, REVOKE_SESSION
    }

    public record ValidationResult(boolean allowed, String reason, Action action, boolean promptInjectionLikely,
                                    int violationCount, List<String> callHistory, List<String> missingPrerequisites) {
    }

    private record Violation(long timestamp, String tool, String reason) {
    }

    private static final class SessionState {
        final List<String> callHistory = new ArrayList<>();
        final Map<String, Integer> callCounts = new HashMap<>();
        List<Violation> violations = new ArrayList<>();
    }

    private static final int MAX_SESSIONS = 50_000;

    private final Map<String, GraphNode> graph;
    private final int maxViolations;
    private final long violationWindowMs;
    private final boolean graduatedResponse;
    private final Map<String, SessionState> sessions = new LinkedHashMap<>();
    private final Object lock = new Object();

    public ToolCallSequenceValidator(Map<String, GraphNode> graph) {
        this(graph, 3, 300_000, true);
    }

    public ToolCallSequenceValidator(Map<String, GraphNode> graph, int maxViolations, long violationWindowMs, boolean graduatedResponse) {
        this.graph = graph;
        this.maxViolations = maxViolations;
        this.violationWindowMs = violationWindowMs;
        this.graduatedResponse = graduatedResponse;
    }

    /**
     * Legacy wrapper matching Node's {@code validateToolCall(agentId, toolName, previousTools)}.
     * {@code previousTools} is accepted for call-shape parity but — faithfully, per the audited
     * Node quirk — never read; this delegates to {@link #validate(String, String)} keyed by
     * {@code agentId} exactly as Node's wrapper does, which also means call history is tracked
     * per-agentId here, not per-session, unlike the real {@link #validate} entry point below.
     */
    @SuppressWarnings("unused")
    public ValidationResult validateToolCall(String agentId, String toolName, List<String> previousTools) {
        return validate(agentId, toolName);
    }

    public ValidationResult validateToolCall(String agentId, String toolName) {
        return validateToolCall(agentId, toolName, List.of());
    }

    /** Validate a tool call against the authorized sequence graph. */
    public ValidationResult validate(String sessionId, String toolName) {
        return validate(sessionId, toolName, System.currentTimeMillis());
    }

    public ValidationResult validate(String sessionId, String toolName, long timestamp) {
        synchronized (lock) {
            SessionState session = getOrCreateSession(sessionId);

            session.violations = new ArrayList<>(session.violations.stream()
                    .filter(v -> timestamp - v.timestamp() < violationWindowMs).toList());

            GraphNode node = graph.get(toolName);

            if (node == null) {
                session.violations.add(new Violation(timestamp, toolName, "unknown_tool"));
                return buildResult(session, false, "unknown_tool", toolName, List.of());
            }

            List<String> missingPrereqs = node.requires().stream()
                    .filter(req -> !session.callHistory.contains(req)).toList();

            if (!missingPrereqs.isEmpty()) {
                session.violations.add(new Violation(timestamp, toolName, "missing_prerequisites: " + String.join(", ", missingPrereqs)));
                return buildResult(session, false, "out_of_sequence", toolName, missingPrereqs);
            }

            int currentCalls = session.callCounts.getOrDefault(toolName, 0);
            if (node.maxCalls() > 0 && currentCalls >= node.maxCalls()) {
                session.violations.add(new Violation(timestamp, toolName,
                        "max_calls_exceeded: " + currentCalls + "/" + node.maxCalls()));
                return buildResult(session, false, "max_calls_exceeded", toolName, List.of());
            }

            session.callHistory.add(toolName);
            session.callCounts.put(toolName, currentCalls + 1);

            return new ValidationResult(true, "valid_sequence", Action.ALLOW, false,
                    session.violations.size(), List.copyOf(session.callHistory), null);
        }
    }

    /** Reset a session's state (e.g., after quarantine release). */
    public void resetSession(String sessionId) {
        synchronized (lock) {
            sessions.remove(sessionId);
        }
    }

    public List<String> getHistory(String sessionId) {
        synchronized (lock) {
            SessionState session = sessions.get(sessionId);
            return session != null ? List.copyOf(session.callHistory) : List.of();
        }
    }

    public record SessionStats(boolean exists, int callCount, int violationCount, List<String> history) {
    }

    public SessionStats getSessionStats(String sessionId) {
        synchronized (lock) {
            SessionState session = sessions.get(sessionId);
            if (session == null) {
                return new SessionStats(false, 0, 0, List.of());
            }
            return new SessionStats(true, session.callHistory.size(), session.violations.size(), List.copyOf(session.callHistory));
        }
    }

    /** Destroy all sessions and free memory. */
    public void destroy() {
        synchronized (lock) {
            sessions.clear();
        }
    }

    private SessionState getOrCreateSession(String sessionId) {
        SessionState session = sessions.get(sessionId);
        if (session == null) {
            if (sessions.size() >= MAX_SESSIONS) {
                var it = sessions.keySet().iterator();
                if (it.hasNext()) {
                    it.next();
                    it.remove();
                }
            }
            session = new SessionState();
            sessions.put(sessionId, session);
        }
        return session;
    }

    private ValidationResult buildResult(SessionState session, boolean allowed, String reason, String toolName,
                                          List<String> missingPrerequisites) {
        int violationCount = session.violations.size();

        Action action;
        if (graduatedResponse) {
            if (violationCount >= maxViolations) {
                action = Action.REVOKE_SESSION;
            } else if (violationCount >= 2) {
                action = Action.BLOCK;
            } else if (violationCount >= 1) {
                action = Action.RATE_LIMIT;
            } else {
                action = Action.LOG;
            }
        } else {
            action = Action.BLOCK;
        }

        GraphNode node = graph.get(toolName);
        boolean promptInjectionLikely = "out_of_sequence".equals(reason)
                && node != null && (node.riskLevel() == RiskLevel.HIGH || node.riskLevel() == RiskLevel.CRITICAL);

        return new ValidationResult(allowed, reason, action, promptInjectionLikely, violationCount,
                List.copyOf(session.callHistory), missingPrerequisites.isEmpty() ? null : missingPrerequisites);
    }
}
