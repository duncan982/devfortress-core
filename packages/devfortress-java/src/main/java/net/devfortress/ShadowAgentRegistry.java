package net.devfortress;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * DevFortress SDK — Shadow Agent Registry. Mirrors
 * {@code packages/devfortress-sdk/src/shadow-agent-registry.ts}.
 *
 * <p>Detects and tracks unauthorized ("shadow") AI agents that operate
 * without proper registration. Maintains a registry of known agents and
 * flags unregistered agent-like behavior.
 *
 * Patent Pending.
 */
public final class ShadowAgentRegistry {
    private static final List<String> DEFAULT_AGENT_PATTERNS = List.of(
            "automated request pattern (>100 req/min)",
            "consistent timing between requests (<50ms variance)",
            "sequential resource enumeration",
            "user-agent indicates bot/automation",
            "no mouse/keyboard entropy in session",
            "API-only access (no page loads)");

    /** Recommended disposition for a {@link ShadowAgentDetection}. */
    public enum Recommendation { REGISTER, BLOCK, MONITOR }

    /** Input to {@link #register} — mirrors Node's {@code Omit<RegisteredAgent, 'registeredAt' | 'lastHeartbeat' | 'active'>}. */
    public record AgentRegistration(String agentId, String name, String owner, List<String> permissions) {
    }

    /**
     * A known, registered agent. Mutable (like Node's plain object): {@link #lastHeartbeat}
     * and {@link #active} are updated in place by {@link #heartbeat} and {@link #pruneInactive},
     * the same live-reference semantics Node's {@code register()}/{@code registry.get()} have.
     */
    public static final class RegisteredAgent {
        public final String agentId;
        public final String name;
        public final long registeredAt;
        public final String owner;
        public final List<String> permissions;
        public volatile long lastHeartbeat;
        public volatile boolean active;

        RegisteredAgent(String agentId, String name, long registeredAt, String owner, List<String> permissions,
                         long lastHeartbeat, boolean active) {
            this.agentId = agentId;
            this.name = name;
            this.registeredAt = registeredAt;
            this.owner = owner;
            this.permissions = permissions;
            this.lastHeartbeat = lastHeartbeat;
            this.active = active;
        }
    }

    /** Result of {@link #detect}. */
    public record ShadowAgentDetection(boolean detected, String agentFingerprint, List<String> indicators,
                                        double confidence, Recommendation recommendation, List<String> matchedPatterns) {
    }

    /** Point-in-time counters, returned by {@link #getStats}. */
    public record AgentRegistryStats(int registeredCount, int activeCount, int shadowDetections, int blockedShadows) {
    }

    /** Configures a {@link ShadowAgentRegistry}. */
    public static final class Builder {
        private long heartbeatTimeoutMs = 300_000;
        private List<String> agentPatterns = DEFAULT_AGENT_PATTERNS;
        private boolean autoBlock = false;

        public Builder heartbeatTimeoutMs(long heartbeatTimeoutMs) {
            this.heartbeatTimeoutMs = heartbeatTimeoutMs;
            return this;
        }

        public Builder agentPatterns(List<String> agentPatterns) {
            this.agentPatterns = agentPatterns;
            return this;
        }

        public Builder autoBlock(boolean autoBlock) {
            this.autoBlock = autoBlock;
            return this;
        }

        public ShadowAgentRegistry build() {
            return new ShadowAgentRegistry(this);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    private final long heartbeatTimeoutMs;
    private final List<String> agentPatterns;
    private final boolean autoBlock;

    private final Map<String, RegisteredAgent> registry = new ConcurrentHashMap<>();
    private final Map<String, ShadowAgentDetection> shadowDetections = new ConcurrentHashMap<>();

    private final AtomicInteger registeredCount = new AtomicInteger();
    private final AtomicInteger activeCount = new AtomicInteger();
    private final AtomicInteger shadowDetectionCount = new AtomicInteger();
    private final AtomicInteger blockedShadowCount = new AtomicInteger();

    public ShadowAgentRegistry() {
        this(new Builder());
    }

    private ShadowAgentRegistry(Builder b) {
        this.heartbeatTimeoutMs = b.heartbeatTimeoutMs;
        this.agentPatterns = b.agentPatterns;
        this.autoBlock = b.autoBlock;
    }

    /** Register a known agent. */
    public RegisteredAgent register(AgentRegistration agent) {
        if ("false".equals(System.getenv("FEATURE_PLATFORM_INTEL"))) {
            return new RegisteredAgent(agent.agentId(), agent.name(), 0, agent.owner(), agent.permissions(), 0, false);
        }

        long now = System.currentTimeMillis();
        RegisteredAgent registered = new RegisteredAgent(agent.agentId(), agent.name(), now, agent.owner(),
                agent.permissions(), now, true);
        registry.put(agent.agentId(), registered);
        registeredCount.incrementAndGet();
        activeCount.incrementAndGet();
        return registered;
    }

    /** Record a heartbeat from a registered agent. */
    public boolean heartbeat(String agentId) {
        RegisteredAgent agent = registry.get(agentId);
        if (agent == null) {
            return false;
        }
        agent.lastHeartbeat = System.currentTimeMillis();
        agent.active = true;
        return true;
    }

    /** Check if a request source is a registered agent or a shadow. */
    public ShadowAgentDetection detect(String fingerprint, List<String> indicators) {
        if ("false".equals(System.getenv("FEATURE_PLATFORM_INTEL"))) {
            return new ShadowAgentDetection(false, fingerprint, List.of(), 0, Recommendation.MONITOR, List.of());
        }

        // Check if any registered agent matches this fingerprint
        for (RegisteredAgent agent : registry.values()) {
            if (agent.agentId.equals(fingerprint) && agent.active) {
                return new ShadowAgentDetection(false, fingerprint, List.of(), 0, Recommendation.MONITOR, List.of());
            }
        }

        // Check indicators against known agent patterns
        List<String> matchedPatterns = new ArrayList<>();
        for (String pattern : agentPatterns) {
            String patternKey = pattern.split("\\(", 2)[0].trim().toLowerCase(Locale.ROOT);
            boolean matches = indicators.stream().anyMatch(i -> i.toLowerCase(Locale.ROOT).contains(patternKey));
            if (matches) {
                matchedPatterns.add(pattern);
            }
        }

        double confidence = Math.min(1.0, matchedPatterns.size() / 3.0);
        boolean detected = confidence > 0.3;

        if (detected) {
            shadowDetectionCount.incrementAndGet();
            if (autoBlock && confidence > 0.7) {
                blockedShadowCount.incrementAndGet();
            }
        }

        Recommendation recommendation = confidence > 0.7
                ? (autoBlock ? Recommendation.BLOCK : Recommendation.REGISTER)
                : Recommendation.MONITOR;

        ShadowAgentDetection result = new ShadowAgentDetection(detected, fingerprint, indicators, confidence,
                recommendation, matchedPatterns);
        if (detected) {
            shadowDetections.put(fingerprint, result);
        }
        return result;
    }

    /** Prune inactive agents (no heartbeat within the configured timeout). */
    public List<String> pruneInactive() {
        long cutoff = System.currentTimeMillis() - heartbeatTimeoutMs;
        List<String> pruned = new ArrayList<>();
        for (Map.Entry<String, RegisteredAgent> entry : registry.entrySet()) {
            RegisteredAgent agent = entry.getValue();
            if (agent.lastHeartbeat < cutoff) {
                agent.active = false;
                activeCount.decrementAndGet();
                pruned.add(entry.getKey());
            }
        }
        return pruned;
    }

    public AgentRegistryStats getStats() {
        return new AgentRegistryStats(registeredCount.get(), activeCount.get(), shadowDetectionCount.get(),
                blockedShadowCount.get());
    }

    public List<RegisteredAgent> getRegistered() {
        return new ArrayList<>(registry.values());
    }
}
