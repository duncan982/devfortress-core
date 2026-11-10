package net.devfortress;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Agent Credential Aliasing &amp; Security (IP-C2 through IP-C5). Mirrors
 * {@code packages/devfortress-sdk/src/agent-security.ts}.
 *
 * <p>IP-C2 Agent Credential Aliasing (create/revoke/quarantine agent
 * credentials); IP-C3 Agent Behavioral Baseline (normal tool-call patterns
 * over a 30-day rolling window); IP-C4 Agent Anomaly Detection (sequence
 * entropy, scope deviation, data-volume 3σ deviation, cross-agent
 * credential sharing); IP-C5 Agent Access Scope Enforcement (sanctioned-
 * tool allowlists).
 *
 * <p>Node's underlying stores ({@code agentCredentials}/{@code
 * agentBaselines}/{@code agentSessions}/{@code agentScopes}/{@code
 * agentQuarantines}) are module-level, not per-instance — every {@link
 * AgentCredentialManager}/{@link AgentBaselineEngine}/{@link
 * AgentAnomalyDetector}/{@link AgentScopeEnforcer} constructed in the same
 * process shares the same underlying state. Ported faithfully here as
 * process-wide static stores rather than "fixed" into per-instance state,
 * since changing that would be an observable behavior change, not a port.
 */
public final class AgentSecurity {
    private AgentSecurity() {
    }

    public enum CredentialType {
        AGENT_API_KEY, AGENT_OAUTH_TOKEN, SERVICE_ACCOUNT
    }

    public record ExecutionContext(String containerId, String expectedEgressPath, String expectedProcessSignature) {
    }

    public static final class CredentialAliasData {
        public final String alias;
        public final String agentId;
        public final CredentialType credentialType;
        public final long createdAt;
        public volatile boolean quarantined;
        public volatile String quarantineReason;
        public volatile Long quarantinedAt;
        public final ExecutionContext executionContext;

        CredentialAliasData(String alias, String agentId, CredentialType credentialType, long createdAt, ExecutionContext executionContext) {
            this.alias = alias;
            this.agentId = agentId;
            this.credentialType = credentialType;
            this.createdAt = createdAt;
            this.quarantined = false;
            this.executionContext = executionContext;
        }
    }

    public record BaselineMetrics(
            double avgToolsPerSession,
            double toolDiversityEntropy,
            double avgDataVolumeBytes,
            double avgSessionDurationMs,
            List<String> topTools,
            int totalSessions,
            long createdAt,
            long lastUpdatedAt,
            String taskDefinition) {
    }

    public record ToolCallRecord(String tool, Integer durationMs, Long dataBytes) {
    }

    public static final class SessionRecord {
        public final String sessionId;
        public final String agentId;
        public final List<ToolCallRecord> toolCalls;
        public final long startedAt;
        public final Long endedAt;
        public final long totalDataBytes;

        public SessionRecord(String sessionId, String agentId, List<ToolCallRecord> toolCalls, long startedAt, Long endedAt, long totalDataBytes) {
            this.sessionId = sessionId;
            this.agentId = agentId;
            this.toolCalls = toolCalls;
            this.startedAt = startedAt;
            this.endedAt = endedAt;
            this.totalDataBytes = totalDataBytes;
        }
    }

    public enum AnomalyType {
        SEQUENCE_ENTROPY_ANOMALY, SCOPE_DEVIATION, DATA_VOLUME_ANOMALY, CROSS_AGENT_CREDENTIAL_SHARING, UNSANCTIONED_TOOL
    }

    public enum AnomalySeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    public record AnomalySignal(
            AnomalyType type, String agentId, AnomalySeverity severity, String description, long detectedAt,
            Map<String, Object> details) {
    }

    public static final class ScopeDefinition {
        public final String agentId;
        public volatile List<String> allowedTools;
        public final boolean strictMode;
        public final long createdAt;
        public volatile long updatedAt;

        ScopeDefinition(String agentId, List<String> allowedTools, boolean strictMode, long createdAt, long updatedAt) {
            this.agentId = agentId;
            this.allowedTools = allowedTools;
            this.strictMode = strictMode;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
        }
    }

    /** Process-wide in-memory stores shared by every agent-security class instance — see the class-level doc. */
    private static final class Stores {
        static final Map<String, List<CredentialAliasData>> CREDENTIALS = new HashMap<>();
        static final Map<String, BaselineMetrics> BASELINES = new HashMap<>();
        static final Map<String, List<SessionRecord>> SESSIONS = new HashMap<>();
        static final Map<String, ScopeDefinition> SCOPES = new HashMap<>();
        static final Map<String, Map.Entry<String, Long>> QUARANTINES = new HashMap<>();
        static final Object LOCK = new Object();
    }

    /** Resets all in-memory stores. Used for testing only. */
    public static void resetStores() {
        synchronized (Stores.LOCK) {
            Stores.CREDENTIALS.clear();
            Stores.BASELINES.clear();
            Stores.SESSIONS.clear();
            Stores.SCOPES.clear();
            Stores.QUARANTINES.clear();
        }
    }

    static double shannonEntropy(List<String> items) {
        if (items.isEmpty()) {
            return 0;
        }
        Map<String, Integer> freq = new HashMap<>();
        for (String item : items) {
            freq.merge(item, 1, Integer::sum);
        }
        double entropy = 0;
        int total = items.size();
        for (int count : freq.values()) {
            double p = (double) count / total;
            if (p > 0) {
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    /** Agent Credential Manager (IP-C2). */
    public static final class AgentCredentialManager {
        private final CredentialIsolation.CredentialIsolationManager tokenManager;
        private final CredentialIsolation.CacheAdapter cache;

        public AgentCredentialManager(CredentialIsolation.CredentialIsolationManager tokenManager, CredentialIsolation.CacheAdapter cache) {
            this.tokenManager = tokenManager;
            this.cache = cache;
        }

        /** Create an alias for an agent credential. The real credential never leaves the client application. */
        public String createAgentAlias(String realCredential, String agentId, CredentialType credentialType) {
            return createAgentAlias(realCredential, agentId, credentialType, 7200, null);
        }

        @SuppressWarnings("unchecked")
        public String createAgentAlias(String realCredential, String agentId, CredentialType credentialType,
                                        int ttlSeconds, ExecutionContext executionContext) {
            AgentId.validate(agentId);
            String alias = tokenManager.createAlias(realCredential, agentId, ttlSeconds).join();

            CredentialAliasData data = new CredentialAliasData(alias, agentId, credentialType, System.currentTimeMillis(), executionContext);
            synchronized (Stores.LOCK) {
                Stores.CREDENTIALS.computeIfAbsent(agentId, k -> new ArrayList<>()).add(data);
            }

            if (cache != null) {
                try {
                    String existing = cache.get("agent:creds:" + agentId).join();
                    List<Object> list = existing != null ? (List<Object>) Json.decode(existing) : new ArrayList<>();
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("alias", alias);
                    entry.put("agentId", agentId);
                    entry.put("credentialType", credentialType.name());
                    entry.put("createdAt", data.createdAt);
                    list.add(entry);
                    cache.set("agent:creds:" + agentId, Json.encode(list), ttlSeconds).join();
                } catch (RuntimeException ignored) {
                    // In-memory is already set.
                }
            }

            return alias;
        }

        /** Revoke ALL credentials for an agent. Used when an agent is compromised or decommissioned. */
        public int revokeAgentAccess(String agentId) {
            return revokeAgentAccess(agentId, CredentialIsolation.RevocationReason.ACTIVE_THREAT);
        }

        public int revokeAgentAccess(String agentId, CredentialIsolation.RevocationReason reason) {
            List<CredentialAliasData> creds;
            synchronized (Stores.LOCK) {
                creds = new ArrayList<>(Stores.CREDENTIALS.getOrDefault(agentId, List.of()));
            }

            int revokedCount = 0;
            for (CredentialAliasData cred : creds) {
                try {
                    tokenManager.revokeByAlias(cred.alias, reason, agentId).join();
                    revokedCount++;
                } catch (RuntimeException ignored) {
                    // Continue revoking remaining credentials.
                }
            }

            synchronized (Stores.LOCK) {
                Stores.CREDENTIALS.remove(agentId);
                Stores.QUARANTINES.remove(agentId);
            }

            if (cache != null) {
                try {
                    cache.del("agent:creds:" + agentId).join();
                    cache.del("agent:quarantine:" + agentId).join();
                } catch (RuntimeException ignored) {
                    // Best-effort.
                }
            }

            return revokedCount;
        }

        /** Quarantine an agent — suspend tool access but preserve session for forensics. Reversible, unlike revocation. */
        public void quarantineAgent(String agentId, String reason) {
            long at = System.currentTimeMillis();
            synchronized (Stores.LOCK) {
                Stores.QUARANTINES.put(agentId, Map.entry(reason, at));
                for (CredentialAliasData cred : Stores.CREDENTIALS.getOrDefault(agentId, List.of())) {
                    cred.quarantined = true;
                    cred.quarantineReason = reason;
                    cred.quarantinedAt = at;
                }
            }

            if (cache != null) {
                try {
                    Map<String, Object> payload = new LinkedHashMap<>();
                    payload.put("reason", reason);
                    payload.put("at", at);
                    cache.set("agent:quarantine:" + agentId, Json.encode(payload), 86400).join();
                } catch (RuntimeException ignored) {
                    // In-memory is set.
                }
            }
        }

        /**
         * Lift quarantine for an agent, restoring normal tool access. Throws if the agent isn't
         * currently quarantined — reinstatement is only meaningful as the reverse of an active
         * quarantine, not a silent no-op.
         */
        public void unquarantineAgent(String agentId) {
            synchronized (Stores.LOCK) {
                if (!Stores.QUARANTINES.containsKey(agentId)) {
                    throw new IllegalStateException("Agent \"" + agentId + "\" is not currently quarantined — nothing to reinstate.");
                }
                Stores.QUARANTINES.remove(agentId);
                for (CredentialAliasData cred : Stores.CREDENTIALS.getOrDefault(agentId, List.of())) {
                    cred.quarantined = false;
                    cred.quarantineReason = null;
                    cred.quarantinedAt = null;
                }
            }

            if (cache != null) {
                try {
                    cache.del("agent:quarantine:" + agentId).join();
                } catch (RuntimeException ignored) {
                    // Best-effort.
                }
            }
        }

        public boolean isQuarantined(String agentId) {
            synchronized (Stores.LOCK) {
                return Stores.QUARANTINES.containsKey(agentId);
            }
        }

        public Map.Entry<String, Long> getQuarantineDetails(String agentId) {
            synchronized (Stores.LOCK) {
                return Stores.QUARANTINES.get(agentId);
            }
        }

        public List<CredentialAliasData> getAgentCredentials(String agentId) {
            synchronized (Stores.LOCK) {
                return new ArrayList<>(Stores.CREDENTIALS.getOrDefault(agentId, List.of()));
            }
        }
    }

    /** Agent Behavioral Baseline (IP-C3). */
    public static final class AgentBaselineEngine {
        private static final int BASELINE_WINDOW_DAYS = 30;
        private static final int MIN_SESSIONS_FOR_BASELINE = 5;

        /** Record a completed agent session for baseline building. */
        public void recordSession(SessionRecord record) {
            List<SessionRecord> filtered;
            synchronized (Stores.LOCK) {
                List<SessionRecord> sessions = Stores.SESSIONS.computeIfAbsent(record.agentId, k -> new ArrayList<>());
                long windowStart = System.currentTimeMillis() - BASELINE_WINDOW_DAYS * 24L * 60 * 60 * 1000;
                filtered = new ArrayList<>();
                for (SessionRecord s : sessions) {
                    if (s.startedAt > windowStart) {
                        filtered.add(s);
                    }
                }
                filtered.add(record);
                Stores.SESSIONS.put(record.agentId, filtered);
            }

            if (filtered.size() >= MIN_SESSIONS_FOR_BASELINE) {
                recalculateBaseline(record.agentId, null);
            }
        }

        /** Establish a baseline from a task definition. Call this at the start to register what "normal" looks like. */
        public BaselineMetrics agentBaseline(String agentId, String taskDefinition) {
            synchronized (Stores.LOCK) {
                BaselineMetrics existing = Stores.BASELINES.get(agentId);
                if (existing != null) {
                    BaselineMetrics updated = new BaselineMetrics(
                            existing.avgToolsPerSession(), existing.toolDiversityEntropy(), existing.avgDataVolumeBytes(),
                            existing.avgSessionDurationMs(), existing.topTools(), existing.totalSessions(), existing.createdAt(),
                            System.currentTimeMillis(), taskDefinition);
                    Stores.BASELINES.put(agentId, updated);
                    return updated;
                }

                int sessionCount = Stores.SESSIONS.containsKey(agentId) ? Stores.SESSIONS.get(agentId).size() : 0;
                if (sessionCount < MIN_SESSIONS_FOR_BASELINE) {
                    return null;
                }
            }

            return recalculateBaseline(agentId, taskDefinition);
        }

        public BaselineMetrics getBaseline(String agentId) {
            synchronized (Stores.LOCK) {
                return Stores.BASELINES.get(agentId);
            }
        }

        private BaselineMetrics recalculateBaseline(String agentId, String taskDefinition) {
            synchronized (Stores.LOCK) {
                List<SessionRecord> sessions = Stores.SESSIONS.getOrDefault(agentId, List.of());

                double avgToolsPerSession = sessions.isEmpty() ? 0 :
                        sessions.stream().mapToInt(s -> s.toolCalls.size()).average().orElse(0);

                List<String> allTools = new ArrayList<>();
                for (SessionRecord s : sessions) {
                    for (ToolCallRecord tc : s.toolCalls) {
                        allTools.add(tc.tool());
                    }
                }
                double toolDiversityEntropy = shannonEntropy(allTools);

                double avgDataVolumeBytes = sessions.isEmpty() ? 0 :
                        sessions.stream().mapToLong(s -> s.totalDataBytes).average().orElse(0);

                List<Long> durations = new ArrayList<>();
                for (SessionRecord s : sessions) {
                    if (s.endedAt != null) {
                        durations.add(s.endedAt - s.startedAt);
                    }
                }
                double avgSessionDurationMs = durations.isEmpty() ? 0 :
                        durations.stream().mapToLong(Long::longValue).average().orElse(0);

                Map<String, Integer> toolFreq = new LinkedHashMap<>();
                for (String tool : allTools) {
                    toolFreq.merge(tool, 1, Integer::sum);
                }
                List<String> topTools = new ArrayList<>(toolFreq.keySet());
                topTools.sort((a, b) -> toolFreq.get(b) - toolFreq.get(a));
                if (topTools.size() > 10) {
                    topTools = topTools.subList(0, 10);
                }

                BaselineMetrics existing = Stores.BASELINES.get(agentId);
                long createdAt = existing != null ? existing.createdAt() : System.currentTimeMillis();
                String effectiveTaskDefinition = taskDefinition != null ? taskDefinition : (existing != null ? existing.taskDefinition() : null);

                BaselineMetrics baseline = new BaselineMetrics(
                        avgToolsPerSession, toolDiversityEntropy, avgDataVolumeBytes, avgSessionDurationMs,
                        topTools, sessions.size(), createdAt, System.currentTimeMillis(), effectiveTaskDefinition);
                Stores.BASELINES.put(agentId, baseline);
                return baseline;
            }
        }

        private static double stdDev(List<Double> values) {
            if (values.size() < 2) {
                return 0;
            }
            double mean = values.stream().mapToDouble(Double::doubleValue).average().orElse(0);
            double sumSq = values.stream().mapToDouble(v -> Math.pow(v - mean, 2)).sum();
            return Math.sqrt(sumSq / values.size());
        }

        /** Check if a value is a 3σ deviation from a dataset. */
        public static boolean is3SigmaDeviation(List<Double> values, double newValue) {
            if (values.size() < 2) {
                return false;
            }
            double mean = values.stream().mapToDouble(Double::doubleValue).average().orElse(0);
            double sd = stdDev(values);
            if (sd == 0) {
                return newValue != mean;
            }
            return Math.abs(newValue - mean) > 3 * sd;
        }
    }

    /**
     * Agent Anomaly Detector (IP-C4).
     *
     * <p><b>Baseline-gate ordering quirk, ported faithfully from Node:</b> the IP-C5
     * unsanctioned-tool scope check runs BEFORE the "no baseline yet" early return, so it fires
     * even for an agent with no established baseline. Scope-deviation, data-volume-anomaly, AND
     * cross-agent-credential-sharing detection all run AFTER that early return, so none of them
     * fire until the agent has an established baseline (≥5 recorded sessions) — including
     * cross-agent credential sharing, which arguably shouldn't need a behavioral baseline to
     * detect. Not fixed here; this is Node's real behavior.
     */
    public static final class AgentAnomalyDetector {
        private final AgentBaselineEngine baselineEngine;
        private final List<Consumer<AnomalySignal>> anomalyHandlers = new ArrayList<>();
        private final Map<String, Set<String>> credentialUsage = new HashMap<>();
        private final Object lock = new Object();

        public AgentAnomalyDetector(AgentBaselineEngine baselineEngine) {
            this.baselineEngine = baselineEngine;
        }

        public void onAnomaly(Consumer<AnomalySignal> handler) {
            synchronized (lock) {
                anomalyHandlers.add(handler);
            }
        }

        /** Analyze a tool call for anomalies against the agent's baseline. Returns any anomaly signals detected. */
        public List<AnomalySignal> analyzeToolCall(String agentId, String toolName, long dataBytes, String credentialAlias) {
            List<AnomalySignal> signals = new ArrayList<>();
            BaselineMetrics baseline = baselineEngine.getBaseline(agentId);

            ScopeDefinition scope;
            synchronized (Stores.LOCK) {
                scope = Stores.SCOPES.get(agentId);
            }
            if (scope != null && scope.strictMode && !scope.allowedTools.contains(toolName)) {
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("tool", toolName);
                details.put("allowedTools", scope.allowedTools);
                AnomalySignal signal = new AnomalySignal(AnomalyType.UNSANCTIONED_TOOL, agentId, AnomalySeverity.CRITICAL,
                        "Agent " + agentId + " invoked unsanctioned tool \"" + toolName + "\". Allowed: ["
                                + String.join(", ", scope.allowedTools) + "]",
                        System.currentTimeMillis(), details);
                signals.add(signal);
                emitSignal(signal);
            }

            if (baseline == null) {
                return signals;
            }

            // IP-C4.1: Tool invocation scope deviation.
            if (!baseline.topTools().isEmpty() && !baseline.topTools().contains(toolName)) {
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("tool", toolName);
                details.put("baselineTools", baseline.topTools());
                AnomalySignal signal = new AnomalySignal(AnomalyType.SCOPE_DEVIATION, agentId, AnomalySeverity.MEDIUM,
                        "Agent " + agentId + " invoked tool \"" + toolName + "\" outside its baseline tool set",
                        System.currentTimeMillis(), details);
                signals.add(signal);
                emitSignal(signal);
            }

            // IP-C4.3: Data volume anomaly (3σ deviation).
            if (dataBytes > 0) {
                List<Double> volumes = new ArrayList<>();
                synchronized (Stores.LOCK) {
                    for (SessionRecord s : Stores.SESSIONS.getOrDefault(agentId, List.of())) {
                        volumes.add((double) s.totalDataBytes);
                    }
                }
                if (AgentBaselineEngine.is3SigmaDeviation(volumes, dataBytes)) {
                    Map<String, Object> details = new LinkedHashMap<>();
                    details.put("dataBytes", dataBytes);
                    details.put("baselineAvg", baseline.avgDataVolumeBytes());
                    AnomalySignal signal = new AnomalySignal(AnomalyType.DATA_VOLUME_ANOMALY, agentId, AnomalySeverity.HIGH,
                            "Agent " + agentId + " data volume " + dataBytes + "B is 3σ deviation from baseline avg "
                                    + Math.round(baseline.avgDataVolumeBytes()) + "B",
                            System.currentTimeMillis(), details);
                    signals.add(signal);
                    emitSignal(signal);
                }
            }

            // IP-C4.4: Cross-agent credential sharing detection.
            if (credentialAlias != null) {
                Set<String> agents;
                synchronized (lock) {
                    agents = credentialUsage.computeIfAbsent(credentialAlias, k -> new HashSet<>());
                    agents.add(agentId);
                    agents = new HashSet<>(agents);
                }

                if (agents.size() > 1) {
                    String truncated = credentialAlias.length() > 16 ? credentialAlias.substring(0, 16) : credentialAlias;
                    Map<String, Object> details = new LinkedHashMap<>();
                    details.put("credentialAlias", truncated + "...");
                    details.put("sharingAgents", new ArrayList<>(agents));
                    AnomalySignal signal = new AnomalySignal(AnomalyType.CROSS_AGENT_CREDENTIAL_SHARING, agentId, AnomalySeverity.CRITICAL,
                            "Credential " + truncated + "... shared across " + agents.size() + " agents: [" + String.join(", ", agents) + "]",
                            System.currentTimeMillis(), details);
                    signals.add(signal);
                    emitSignal(signal);
                }
            }

            return signals;
        }

        /** Analyze a completed session for sequence entropy anomaly. */
        public List<AnomalySignal> analyzeSession(SessionRecord record) {
            List<AnomalySignal> signals = new ArrayList<>();
            BaselineMetrics baseline = baselineEngine.getBaseline(record.agentId);
            if (baseline == null || baseline.totalSessions() < 5) {
                return signals;
            }

            List<String> sessionTools = new ArrayList<>();
            for (ToolCallRecord tc : record.toolCalls) {
                sessionTools.add(tc.tool());
            }
            double sessionEntropy = shannonEntropy(sessionTools);
            double entropyDeviation = Math.abs(sessionEntropy - baseline.toolDiversityEntropy());

            if (baseline.toolDiversityEntropy() > 0 && entropyDeviation / baseline.toolDiversityEntropy() > 0.5) {
                double deviationPercent = entropyDeviation / baseline.toolDiversityEntropy() * 100;
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("sessionEntropy", sessionEntropy);
                details.put("baselineEntropy", baseline.toolDiversityEntropy());
                details.put("deviationPercent", deviationPercent);
                AnomalySignal signal = new AnomalySignal(AnomalyType.SEQUENCE_ENTROPY_ANOMALY, record.agentId, AnomalySeverity.HIGH,
                        String.format("Agent %s session entropy %.2f deviates %.0f%% from baseline %.2f",
                                record.agentId, sessionEntropy, deviationPercent, baseline.toolDiversityEntropy()),
                        System.currentTimeMillis(), details);
                signals.add(signal);
                emitSignal(signal);
            }

            return signals;
        }

        private void emitSignal(AnomalySignal signal) {
            List<Consumer<AnomalySignal>> handlers;
            synchronized (lock) {
                handlers = new ArrayList<>(anomalyHandlers);
            }
            for (Consumer<AnomalySignal> handler : handlers) {
                try {
                    handler.accept(signal);
                } catch (RuntimeException ignored) {
                    // Handler errors don't block detection.
                }
            }
        }
    }

    /** Agent Scope Enforcer (IP-C5). */
    public static final class AgentScopeEnforcer {
        /** Define the allowed tool scope for an agent. Any tool invocation outside this scope fires a critical event. */
        public ScopeDefinition defineAgentScope(String agentId, List<String> allowedTools) {
            return defineAgentScope(agentId, allowedTools, true);
        }

        public ScopeDefinition defineAgentScope(String agentId, List<String> allowedTools, boolean strictMode) {
            synchronized (Stores.LOCK) {
                ScopeDefinition existing = Stores.SCOPES.get(agentId);
                long createdAt = existing != null ? existing.createdAt : System.currentTimeMillis();
                ScopeDefinition scope = new ScopeDefinition(agentId, new ArrayList<>(allowedTools), strictMode, createdAt, System.currentTimeMillis());
                Stores.SCOPES.put(agentId, scope);
                return scope;
            }
        }

        /** Check if a tool invocation is within the agent's defined scope. */
        public boolean isToolAllowed(String agentId, String toolName) {
            synchronized (Stores.LOCK) {
                ScopeDefinition scope = Stores.SCOPES.get(agentId);
                if (scope == null) {
                    return true; // No scope defined — allow by default.
                }
                if (!scope.strictMode) {
                    return true; // Non-strict mode — log but allow.
                }
                return scope.allowedTools.contains(toolName);
            }
        }

        public ScopeDefinition getScope(String agentId) {
            synchronized (Stores.LOCK) {
                return Stores.SCOPES.get(agentId);
            }
        }

        public void removeScope(String agentId) {
            synchronized (Stores.LOCK) {
                Stores.SCOPES.remove(agentId);
            }
        }

        public void addAllowedTools(String agentId, List<String> tools) {
            synchronized (Stores.LOCK) {
                ScopeDefinition scope = Stores.SCOPES.get(agentId);
                if (scope == null) {
                    defineAgentScope(agentId, tools, true);
                    return;
                }
                Set<String> merged = new LinkedHashMap<String, Boolean>() {{
                    scope.allowedTools.forEach(t -> put(t, true));
                    tools.forEach(t -> put(t, true));
                }}.keySet();
                scope.allowedTools = new ArrayList<>(merged);
                scope.updatedAt = System.currentTimeMillis();
            }
        }

        public void removeAllowedTools(String agentId, List<String> tools) {
            synchronized (Stores.LOCK) {
                ScopeDefinition scope = Stores.SCOPES.get(agentId);
                if (scope == null) {
                    return;
                }
                Set<String> removeSet = new HashSet<>(tools);
                List<String> filtered = new ArrayList<>();
                for (String t : scope.allowedTools) {
                    if (!removeSet.contains(t)) {
                        filtered.add(t);
                    }
                }
                scope.allowedTools = filtered;
                scope.updatedAt = System.currentTimeMillis();
            }
        }
    }
}
