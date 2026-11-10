namespace DevFortress;

/// <summary>
/// Shadow Agent Registry. Mirrors
/// <c>packages/devfortress-sdk/src/shadow-agent-registry.ts</c>. Detects and tracks unauthorized
/// ("shadow") AI agents that operate without proper registration. Maintains a registry of known
/// agents and flags unregistered agent-like behavior.
/// </summary>
/// <remarks>
/// Node ships this pillar flag-gated only (<c>process.env.FEATURE_PLATFORM_INTEL</c>), in the
/// publicly-shipped part of the npm package. Every prior language port (Go, Ruby, PHP, Java)
/// chose to drop that runtime flag and rely on nothing but public visibility instead — this
/// port does the same, matching Node's public-with-disclosure posture.
/// Patent Pending.
/// </remarks>
public enum ShadowAgentRecommendation { Register, Block, Monitor }

/// <summary>A known, registered agent. Mirrors Node's <c>RegisteredAgent</c>.</summary>
public sealed record RegisteredAgent(string AgentId, string Name, long RegisteredAt, long LastHeartbeat, string Owner,
    IReadOnlyList<string> Permissions, bool Active);

/// <summary>Input to <see cref="ShadowAgentRegistry.Register"/> — everything but the fields the registry itself stamps.</summary>
public sealed record NewAgentRegistration(string AgentId, string Name, string Owner, IReadOnlyList<string> Permissions);

public sealed record ShadowAgentDetection(bool Detected, string AgentFingerprint, IReadOnlyList<string> Indicators,
    double Confidence, ShadowAgentRecommendation Recommendation, IReadOnlyList<string> MatchedPatterns);

public sealed record AgentRegistryStats(int RegisteredCount, int ActiveCount, int ShadowDetections, int BlockedShadows);

public sealed record ShadowAgentConfig(
    long HeartbeatTimeoutMs = 300_000,
    IReadOnlyList<string>? AgentPatterns = null,
    bool AutoBlock = false);

public sealed class ShadowAgentRegistry
{
    public static readonly IReadOnlyList<string> DefaultAgentPatterns =
    [
        "automated request pattern (>100 req/min)",
        "consistent timing between requests (<50ms variance)",
        "sequential resource enumeration",
        "user-agent indicates bot/automation",
        "no mouse/keyboard entropy in session",
        "API-only access (no page loads)",
    ];

    private readonly ShadowAgentConfig _config;
    private readonly IReadOnlyList<string> _agentPatterns;
    private readonly Dictionary<string, RegisteredAgent> _registry = [];
    private readonly Dictionary<string, ShadowAgentDetection> _shadowDetections = [];

    private int _registeredCount;
    private int _activeCount;
    private int _shadowDetectionCount;
    private int _blockedShadows;

    public ShadowAgentRegistry(ShadowAgentConfig? config = null)
    {
        _config = config ?? new ShadowAgentConfig();
        _agentPatterns = _config.AgentPatterns ?? DefaultAgentPatterns;
    }

    /// <summary>Registers a known agent.</summary>
    public RegisteredAgent Register(NewAgentRegistration agent)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var registered = new RegisteredAgent(agent.AgentId, agent.Name, now, now, agent.Owner, agent.Permissions, true);
        _registry[agent.AgentId] = registered;
        _registeredCount++;
        _activeCount++;
        return registered;
    }

    /// <summary>Records a heartbeat from a registered agent.</summary>
    public bool Heartbeat(string agentId)
    {
        if (!_registry.TryGetValue(agentId, out var agent)) return false;
        _registry[agentId] = agent with { LastHeartbeat = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), Active = true };
        return true;
    }

    /// <summary>Checks whether a request source is a registered agent or a shadow.</summary>
    public ShadowAgentDetection Detect(string fingerprint, IReadOnlyList<string> indicators)
    {
        // Check if any registered agent matches this fingerprint.
        foreach (var agent in _registry.Values)
        {
            if (agent.AgentId == fingerprint && agent.Active)
            {
                return new ShadowAgentDetection(false, fingerprint, [], 0, ShadowAgentRecommendation.Monitor, []);
            }
        }

        // Check indicators against known agent patterns.
        var matchedPatterns = _agentPatterns.Where(pattern =>
        {
            string patternKey = pattern.Split('(')[0].Trim().ToLowerInvariant();
            return indicators.Any(i => i.ToLowerInvariant().Contains(patternKey));
        }).ToList();

        double confidence = Math.Min(1, matchedPatterns.Count / 3.0);
        bool detected = confidence > 0.3;

        if (detected)
        {
            _shadowDetectionCount++;
            if (_config.AutoBlock && confidence > 0.7)
            {
                _blockedShadows++;
            }
        }

        var result = new ShadowAgentDetection(
            detected,
            fingerprint,
            indicators,
            confidence,
            confidence > 0.7
                ? (_config.AutoBlock ? ShadowAgentRecommendation.Block : ShadowAgentRecommendation.Register)
                : ShadowAgentRecommendation.Monitor,
            matchedPatterns);

        if (detected)
        {
            _shadowDetections[fingerprint] = result;
        }
        return result;
    }

    /// <summary>Prunes inactive agents (no heartbeat within the configured timeout).</summary>
    public IReadOnlyList<string> PruneInactive()
    {
        long cutoff = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - _config.HeartbeatTimeoutMs;
        var pruned = new List<string>();
        foreach (var (id, agent) in _registry.ToList())
        {
            if (agent.LastHeartbeat < cutoff)
            {
                _registry[id] = agent with { Active = false };
                _activeCount--;
                pruned.Add(id);
            }
        }
        return pruned;
    }

    public AgentRegistryStats GetStats() => new(_registeredCount, _activeCount, _shadowDetectionCount, _blockedShadows);

    public IReadOnlyList<RegisteredAgent> GetRegistered() => [.. _registry.Values];
}
