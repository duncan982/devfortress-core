namespace DevFortress;

/// <summary>
/// Agent Credential Aliasing &amp; Security (IP-C2 through IP-C5). Mirrors
/// <c>packages/devfortress-sdk/src/agent-security.ts</c>.
/// </summary>
/// <remarks>
/// IP-C2 Agent Credential Aliasing (create/revoke/quarantine agent credentials); IP-C3 Agent
/// Behavioral Baseline (normal tool-call patterns over a 30-day rolling window); IP-C4 Agent
/// Anomaly Detection (sequence entropy, scope deviation, data-volume 3σ deviation, cross-agent
/// credential sharing); IP-C5 Agent Access Scope Enforcement (sanctioned-tool allowlists).
///
/// Node's underlying stores (<c>agentCredentials</c>/<c>agentBaselines</c>/<c>agentSessions</c>/
/// <c>agentScopes</c>/<c>agentQuarantines</c>) are module-level, not per-instance — every
/// <c>AgentCredentialManager</c>/<c>AgentBaselineEngine</c>/<c>AgentAnomalyDetector</c>/
/// <c>AgentScopeEnforcer</c> constructed in the same process shares the same underlying state.
/// Ported faithfully here as process-wide static stores rather than "fixed" into per-instance
/// state, since changing that would be an observable behavior change, not a port.
/// </remarks>
public enum AgentCredentialType
{
    AgentApiKey,
    AgentOAuthToken,
    ServiceAccount,
}

public sealed record AgentExecutionContext(string? ContainerId = null, string? ExpectedEgressPath = null, string? ExpectedProcessSignature = null);

public sealed class AgentCredentialAliasData
{
    public required string Alias { get; init; }
    public required string AgentId { get; init; }
    public required AgentCredentialType CredentialType { get; init; }
    public required long CreatedAt { get; init; }
    public bool Quarantined { get; set; }
    public string? QuarantineReason { get; set; }
    public long? QuarantinedAt { get; set; }
    public AgentExecutionContext? ExecutionContext { get; init; }
}

public sealed record AgentBaselineMetrics(
    double AvgToolsPerSession,
    double ToolDiversityEntropy,
    double AvgDataVolumeBytes,
    double AvgSessionDurationMs,
    IReadOnlyList<string> TopTools,
    int TotalSessions,
    long CreatedAt,
    long LastUpdatedAt,
    string? TaskDefinition);

public sealed class AgentToolCallRecord
{
    public required string Tool { get; init; }
    public int? DurationMs { get; init; }
    public long? DataBytes { get; init; }
}

public sealed class AgentSessionRecord
{
    public required string SessionId { get; init; }
    public required string AgentId { get; init; }
    public required List<AgentToolCallRecord> ToolCalls { get; init; }
    public required long StartedAt { get; init; }
    public long? EndedAt { get; set; }
    public required long TotalDataBytes { get; init; }
}

public enum AgentAnomalyType
{
    SequenceEntropyAnomaly,
    ScopeDeviation,
    DataVolumeAnomaly,
    CrossAgentCredentialSharing,
    UnsanctionedTool,
}

public enum AgentAnomalySeverity { Low, Medium, High, Critical }

public sealed record AgentAnomalySignal(
    AgentAnomalyType Type,
    string AgentId,
    AgentAnomalySeverity Severity,
    string Description,
    long DetectedAt,
    IReadOnlyDictionary<string, object?> Details);

public sealed class AgentScopeDefinition
{
    public required string AgentId { get; init; }
    public required List<string> AllowedTools { get; set; }
    public bool StrictMode { get; init; }
    public required long CreatedAt { get; init; }
    public long UpdatedAt { get; set; }
}

/// <summary>Process-wide in-memory stores shared by every agent-security class instance — see the type's remarks.</summary>
internal static class AgentSecurityStores
{
    public static readonly Dictionary<string, List<AgentCredentialAliasData>> Credentials = [];
    public static readonly Dictionary<string, AgentBaselineMetrics> Baselines = [];
    public static readonly Dictionary<string, List<AgentSessionRecord>> Sessions = [];
    public static readonly Dictionary<string, AgentScopeDefinition> Scopes = [];
    public static readonly Dictionary<string, (string Reason, long At)> Quarantines = [];
    public static readonly object Lock = new();

    /// <summary>Resets all in-memory stores. Used for testing only.</summary>
    public static void Reset()
    {
        lock (Lock)
        {
            Credentials.Clear();
            Baselines.Clear();
            Sessions.Clear();
            Scopes.Clear();
            Quarantines.Clear();
        }
    }
}

internal static class ShannonEntropy
{
    public static double Compute(IReadOnlyList<string> items)
    {
        if (items.Count == 0)
        {
            return 0;
        }
        var freq = new Dictionary<string, int>();
        foreach (var item in items)
        {
            freq[item] = freq.GetValueOrDefault(item) + 1;
        }
        double entropy = 0;
        int total = items.Count;
        foreach (int count in freq.Values)
        {
            double p = (double)count / total;
            if (p > 0)
            {
                entropy -= p * Math.Log2(p);
            }
        }
        return entropy;
    }
}

/// <summary>Agent Credential Manager (IP-C2).</summary>
public sealed class AgentCredentialManager(CredentialIsolationManager tokenManager, ICacheAdapter? cache = null)
{
    /// <summary>Create an alias for an agent credential. The real credential never leaves the client application.</summary>
    public async Task<string> CreateAgentAliasAsync(string realCredential, string agentId, AgentCredentialType credentialType,
        int ttlSeconds = 7200, AgentExecutionContext? executionContext = null)
    {
        AgentId.Validate(agentId);
        string alias = await tokenManager.CreateAliasAsync(realCredential, agentId, ttlSeconds).ConfigureAwait(false);

        var data = new AgentCredentialAliasData
        {
            Alias = alias,
            AgentId = agentId,
            CredentialType = credentialType,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Quarantined = false,
            ExecutionContext = executionContext,
        };

        lock (AgentSecurityStores.Lock)
        {
            if (!AgentSecurityStores.Credentials.TryGetValue(agentId, out var list))
            {
                list = [];
                AgentSecurityStores.Credentials[agentId] = list;
            }
            list.Add(data);
        }

        // Persist to cache if available (best-effort — the in-memory store above already holds it).
        if (cache is not null)
        {
            try
            {
                string? existing = await cache.GetAsync($"agent:creds:{agentId}").ConfigureAwait(false);
                var cachedList = existing is not null
                    ? System.Text.Json.JsonSerializer.Deserialize<List<AgentCredentialAliasData>>(existing) ?? []
                    : [];
                cachedList.Add(data);
                await cache.SetAsync($"agent:creds:{agentId}", System.Text.Json.JsonSerializer.Serialize(cachedList), ttlSeconds).ConfigureAwait(false);
            }
            catch
            {
                // In-memory is already set.
            }
        }

        return alias;
    }

    /// <summary>Revoke ALL credentials for an agent. Used when an agent is compromised or decommissioned.</summary>
    public async Task<int> RevokeAgentAccessAsync(string agentId, RevocationReason reason = RevocationReason.ActiveThreat)
    {
        List<AgentCredentialAliasData> creds;
        lock (AgentSecurityStores.Lock)
        {
            creds = AgentSecurityStores.Credentials.TryGetValue(agentId, out var list) ? [.. list] : [];
        }

        int revokedCount = 0;
        foreach (var cred in creds)
        {
            try
            {
                await tokenManager.RevokeByAliasAsync(cred.Alias, reason, agentId).ConfigureAwait(false);
                revokedCount++;
            }
            catch
            {
                // Continue revoking remaining credentials.
            }
        }

        lock (AgentSecurityStores.Lock)
        {
            AgentSecurityStores.Credentials.Remove(agentId);
            AgentSecurityStores.Quarantines.Remove(agentId);
        }

        if (cache is not null)
        {
            try
            {
                await cache.DeleteAsync($"agent:creds:{agentId}").ConfigureAwait(false);
                await cache.DeleteAsync($"agent:quarantine:{agentId}").ConfigureAwait(false);
            }
            catch
            {
                // Best-effort.
            }
        }

        return revokedCount;
    }

    /// <summary>Quarantine an agent — suspend tool access but preserve session for forensics. Reversible, unlike revocation.</summary>
    public async Task QuarantineAgentAsync(string agentId, string reason)
    {
        long at = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        lock (AgentSecurityStores.Lock)
        {
            AgentSecurityStores.Quarantines[agentId] = (reason, at);
            if (AgentSecurityStores.Credentials.TryGetValue(agentId, out var creds))
            {
                foreach (var cred in creds)
                {
                    cred.Quarantined = true;
                    cred.QuarantineReason = reason;
                    cred.QuarantinedAt = at;
                }
            }
        }

        if (cache is not null)
        {
            try
            {
                await cache.SetAsync($"agent:quarantine:{agentId}",
                    System.Text.Json.JsonSerializer.Serialize(new { reason, at }), 86400).ConfigureAwait(false);
            }
            catch
            {
                // In-memory is set.
            }
        }
    }

    /// <summary>
    /// Lift quarantine for an agent, restoring normal tool access. Throws if the agent isn't
    /// currently quarantined — reinstatement is only meaningful as the reverse of an active
    /// quarantine, not a silent no-op.
    /// </summary>
    public async Task UnquarantineAgentAsync(string agentId)
    {
        lock (AgentSecurityStores.Lock)
        {
            if (!AgentSecurityStores.Quarantines.ContainsKey(agentId))
            {
                throw new InvalidOperationException($"Agent \"{agentId}\" is not currently quarantined — nothing to reinstate.");
            }
            AgentSecurityStores.Quarantines.Remove(agentId);
            if (AgentSecurityStores.Credentials.TryGetValue(agentId, out var creds))
            {
                foreach (var cred in creds)
                {
                    cred.Quarantined = false;
                    cred.QuarantineReason = null;
                    cred.QuarantinedAt = null;
                }
            }
        }

        if (cache is not null)
        {
            try
            {
                await cache.DeleteAsync($"agent:quarantine:{agentId}").ConfigureAwait(false);
            }
            catch
            {
                // Best-effort.
            }
        }
    }

    public bool IsQuarantined(string agentId)
    {
        lock (AgentSecurityStores.Lock)
        {
            return AgentSecurityStores.Quarantines.ContainsKey(agentId);
        }
    }

    public (string Reason, long At)? GetQuarantineDetails(string agentId)
    {
        lock (AgentSecurityStores.Lock)
        {
            return AgentSecurityStores.Quarantines.TryGetValue(agentId, out var v) ? v : null;
        }
    }

    public IReadOnlyList<AgentCredentialAliasData> GetAgentCredentials(string agentId)
    {
        lock (AgentSecurityStores.Lock)
        {
            return AgentSecurityStores.Credentials.TryGetValue(agentId, out var list) ? [.. list] : [];
        }
    }
}

/// <summary>Agent Behavioral Baseline (IP-C3).</summary>
public sealed class AgentBaselineEngine
{
    private const int BaselineWindowDays = 30;
    private const int MinSessionsForBaseline = 5;

    /// <summary>Record a completed agent session for baseline building.</summary>
    public void RecordSession(AgentSessionRecord record)
    {
        List<AgentSessionRecord> filtered;
        lock (AgentSecurityStores.Lock)
        {
            if (!AgentSecurityStores.Sessions.TryGetValue(record.AgentId, out var sessions))
            {
                sessions = [];
                AgentSecurityStores.Sessions[record.AgentId] = sessions;
            }

            long windowStart = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - BaselineWindowDays * 24L * 60 * 60 * 1000;
            filtered = sessions.Where(s => s.StartedAt > windowStart).ToList();
            filtered.Add(record);
            AgentSecurityStores.Sessions[record.AgentId] = filtered;
        }

        if (filtered.Count >= MinSessionsForBaseline)
        {
            RecalculateBaseline(record.AgentId);
        }
    }

    /// <summary>Establish a baseline from a task definition. Call this at the start to register what "normal" looks like.</summary>
    public AgentBaselineMetrics? EstablishBaseline(string agentId, string taskDefinition)
    {
        lock (AgentSecurityStores.Lock)
        {
            if (AgentSecurityStores.Baselines.TryGetValue(agentId, out var existing))
            {
                var updated = existing with { TaskDefinition = taskDefinition, LastUpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() };
                AgentSecurityStores.Baselines[agentId] = updated;
                return updated;
            }

            int sessionCount = AgentSecurityStores.Sessions.TryGetValue(agentId, out var s) ? s.Count : 0;
            if (sessionCount < MinSessionsForBaseline)
            {
                return null;
            }
        }

        return RecalculateBaseline(agentId, taskDefinition);
    }

    public AgentBaselineMetrics? GetBaseline(string agentId)
    {
        lock (AgentSecurityStores.Lock)
        {
            return AgentSecurityStores.Baselines.TryGetValue(agentId, out var b) ? b : null;
        }
    }

    private AgentBaselineMetrics RecalculateBaseline(string agentId, string? taskDefinition = null)
    {
        lock (AgentSecurityStores.Lock)
        {
            var sessions = AgentSecurityStores.Sessions.TryGetValue(agentId, out var s) ? s : [];

            double avgToolsPerSession = sessions.Count > 0 ? sessions.Average(x => x.ToolCalls.Count) : 0;
            var allTools = sessions.SelectMany(x => x.ToolCalls.Select(tc => tc.Tool)).ToList();
            double toolDiversityEntropy = ShannonEntropy.Compute(allTools);
            double avgDataVolumeBytes = sessions.Count > 0 ? sessions.Average(x => x.TotalDataBytes) : 0;

            var durations = sessions.Where(x => x.EndedAt.HasValue).Select(x => x.EndedAt!.Value - x.StartedAt).ToList();
            double avgSessionDurationMs = durations.Count > 0 ? durations.Average() : 0;

            var topTools = allTools
                .GroupBy(t => t)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g => g.Key)
                .ToList();

            long createdAt = AgentSecurityStores.Baselines.TryGetValue(agentId, out var existing)
                ? existing.CreatedAt
                : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var baseline = new AgentBaselineMetrics(
                avgToolsPerSession, toolDiversityEntropy, avgDataVolumeBytes, avgSessionDurationMs,
                topTools, sessions.Count, createdAt, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                taskDefinition ?? (AgentSecurityStores.Baselines.TryGetValue(agentId, out var e2) ? e2.TaskDefinition : null));

            AgentSecurityStores.Baselines[agentId] = baseline;
            return baseline;
        }
    }

    private static double StdDev(IReadOnlyList<double> values)
    {
        if (values.Count < 2)
        {
            return 0;
        }
        double mean = values.Average();
        double sumSq = values.Sum(v => Math.Pow(v - mean, 2));
        return Math.Sqrt(sumSq / values.Count);
    }

    /// <summary>Check if a value is a 3σ deviation from a dataset.</summary>
    public static bool Is3SigmaDeviation(IReadOnlyList<double> values, double newValue)
    {
        if (values.Count < 2)
        {
            return false;
        }
        double mean = values.Average();
        double sd = StdDev(values);
        if (sd == 0)
        {
            return newValue != mean;
        }
        return Math.Abs(newValue - mean) > 3 * sd;
    }
}

/// <summary>Agent Anomaly Detector (IP-C4).</summary>
/// <remarks>
/// Baseline-gate ordering quirk, ported faithfully from Node: the IP-C5 unsanctioned-tool scope
/// check runs BEFORE the "no baseline yet" early return, so it fires even for an agent with no
/// established baseline. Scope-deviation, data-volume-anomaly, AND cross-agent-credential-
/// sharing detection all run AFTER that early return, so none of them fire until the agent has
/// an established baseline (≥5 recorded sessions) — including cross-agent credential sharing,
/// which arguably shouldn't need a behavioral baseline to detect. Not fixed here; this is
/// Node's real behavior.
/// </remarks>
public sealed class AgentAnomalyDetector(AgentBaselineEngine baselineEngine)
{
    private readonly List<Action<AgentAnomalySignal>> _anomalyHandlers = [];
    private readonly Dictionary<string, HashSet<string>> _credentialUsage = [];
    private readonly object _lock = new();

    public void OnAnomaly(Action<AgentAnomalySignal> handler)
    {
        lock (_lock)
        {
            _anomalyHandlers.Add(handler);
        }
    }

    /// <summary>Analyze a tool call for anomalies against the agent's baseline. Returns any anomaly signals detected.</summary>
    public List<AgentAnomalySignal> AnalyzeToolCall(string agentId, string toolName, long dataBytes = 0, string? credentialAlias = null)
    {
        var signals = new List<AgentAnomalySignal>();
        var baseline = baselineEngine.GetBaseline(agentId);

        AgentScopeDefinition? scope;
        lock (AgentSecurityStores.Lock)
        {
            AgentSecurityStores.Scopes.TryGetValue(agentId, out scope);
        }
        if (scope is { StrictMode: true } && !scope.AllowedTools.Contains(toolName))
        {
            var signal = new AgentAnomalySignal(
                AgentAnomalyType.UnsanctionedTool, agentId, AgentAnomalySeverity.Critical,
                $"Agent {agentId} invoked unsanctioned tool \"{toolName}\". Allowed: [{string.Join(", ", scope.AllowedTools)}]",
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                new Dictionary<string, object?> { ["tool"] = toolName, ["allowedTools"] = scope.AllowedTools });
            signals.Add(signal);
            EmitSignal(signal);
        }

        if (baseline is null)
        {
            return signals;
        }

        // IP-C4.1: Tool invocation scope deviation.
        if (baseline.TopTools.Count > 0 && !baseline.TopTools.Contains(toolName))
        {
            var signal = new AgentAnomalySignal(
                AgentAnomalyType.ScopeDeviation, agentId, AgentAnomalySeverity.Medium,
                $"Agent {agentId} invoked tool \"{toolName}\" outside its baseline tool set",
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                new Dictionary<string, object?> { ["tool"] = toolName, ["baselineTools"] = baseline.TopTools });
            signals.Add(signal);
            EmitSignal(signal);
        }

        // IP-C4.3: Data volume anomaly (3σ deviation).
        if (dataBytes > 0)
        {
            List<double> volumes;
            lock (AgentSecurityStores.Lock)
            {
                volumes = AgentSecurityStores.Sessions.TryGetValue(agentId, out var s)
                    ? s.Select(x => (double)x.TotalDataBytes).ToList() : [];
            }
            if (AgentBaselineEngine.Is3SigmaDeviation(volumes, dataBytes))
            {
                var signal = new AgentAnomalySignal(
                    AgentAnomalyType.DataVolumeAnomaly, agentId, AgentAnomalySeverity.High,
                    $"Agent {agentId} data volume {dataBytes}B is 3σ deviation from baseline avg {Math.Round(baseline.AvgDataVolumeBytes)}B",
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    new Dictionary<string, object?> { ["dataBytes"] = dataBytes, ["baselineAvg"] = baseline.AvgDataVolumeBytes });
                signals.Add(signal);
                EmitSignal(signal);
            }
        }

        // IP-C4.4: Cross-agent credential sharing detection.
        if (credentialAlias is not null)
        {
            HashSet<string> agents;
            lock (_lock)
            {
                if (!_credentialUsage.TryGetValue(credentialAlias, out agents!))
                {
                    agents = [];
                    _credentialUsage[credentialAlias] = agents;
                }
                agents.Add(agentId);
            }

            if (agents.Count > 1)
            {
                string truncated = credentialAlias.Length > 16 ? credentialAlias[..16] : credentialAlias;
                var signal = new AgentAnomalySignal(
                    AgentAnomalyType.CrossAgentCredentialSharing, agentId, AgentAnomalySeverity.Critical,
                    $"Credential {truncated}... shared across {agents.Count} agents: [{string.Join(", ", agents)}]",
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    new Dictionary<string, object?> { ["credentialAlias"] = truncated + "...", ["sharingAgents"] = agents.ToList() });
                signals.Add(signal);
                EmitSignal(signal);
            }
        }

        return signals;
    }

    /// <summary>Analyze a completed session for sequence entropy anomaly.</summary>
    public List<AgentAnomalySignal> AnalyzeSession(AgentSessionRecord record)
    {
        var signals = new List<AgentAnomalySignal>();
        var baseline = baselineEngine.GetBaseline(record.AgentId);
        if (baseline is null || baseline.TotalSessions < 5)
        {
            return signals;
        }

        var sessionTools = record.ToolCalls.Select(tc => tc.Tool).ToList();
        double sessionEntropy = ShannonEntropy.Compute(sessionTools);
        double entropyDeviation = Math.Abs(sessionEntropy - baseline.ToolDiversityEntropy);

        if (baseline.ToolDiversityEntropy > 0 && entropyDeviation / baseline.ToolDiversityEntropy > 0.5)
        {
            double deviationPercent = entropyDeviation / baseline.ToolDiversityEntropy * 100;
            var signal = new AgentAnomalySignal(
                AgentAnomalyType.SequenceEntropyAnomaly, record.AgentId, AgentAnomalySeverity.High,
                $"Agent {record.AgentId} session entropy {sessionEntropy:F2} deviates {deviationPercent:F0}% from baseline {baseline.ToolDiversityEntropy:F2}",
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                new Dictionary<string, object?>
                {
                    ["sessionEntropy"] = sessionEntropy,
                    ["baselineEntropy"] = baseline.ToolDiversityEntropy,
                    ["deviationPercent"] = deviationPercent,
                });
            signals.Add(signal);
            EmitSignal(signal);
        }

        return signals;
    }

    private void EmitSignal(AgentAnomalySignal signal)
    {
        List<Action<AgentAnomalySignal>> handlers;
        lock (_lock)
        {
            handlers = [.. _anomalyHandlers];
        }
        foreach (var handler in handlers)
        {
            try
            {
                handler(signal);
            }
            catch
            {
                // Handler errors don't block detection.
            }
        }
    }
}

/// <summary>Agent Scope Enforcer (IP-C5).</summary>
public sealed class AgentScopeEnforcer
{
    /// <summary>Define the allowed tool scope for an agent. Any tool invocation outside this scope fires a critical event.</summary>
    public AgentScopeDefinition DefineAgentScope(string agentId, List<string> allowedTools, bool strictMode = true)
    {
        lock (AgentSecurityStores.Lock)
        {
            long createdAt = AgentSecurityStores.Scopes.TryGetValue(agentId, out var existing)
                ? existing.CreatedAt : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var scope = new AgentScopeDefinition
            {
                AgentId = agentId,
                AllowedTools = allowedTools,
                StrictMode = strictMode,
                CreatedAt = createdAt,
                UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };
            AgentSecurityStores.Scopes[agentId] = scope;
            return scope;
        }
    }

    /// <summary>Check if a tool invocation is within the agent's defined scope.</summary>
    public bool IsToolAllowed(string agentId, string toolName)
    {
        lock (AgentSecurityStores.Lock)
        {
            if (!AgentSecurityStores.Scopes.TryGetValue(agentId, out var scope))
            {
                return true; // No scope defined — allow by default.
            }
            if (!scope.StrictMode)
            {
                return true; // Non-strict mode — log but allow.
            }
            return scope.AllowedTools.Contains(toolName);
        }
    }

    public AgentScopeDefinition? GetScope(string agentId)
    {
        lock (AgentSecurityStores.Lock)
        {
            return AgentSecurityStores.Scopes.TryGetValue(agentId, out var s) ? s : null;
        }
    }

    public void RemoveScope(string agentId)
    {
        lock (AgentSecurityStores.Lock)
        {
            AgentSecurityStores.Scopes.Remove(agentId);
        }
    }

    public void AddAllowedTools(string agentId, IReadOnlyList<string> tools)
    {
        lock (AgentSecurityStores.Lock)
        {
            if (!AgentSecurityStores.Scopes.TryGetValue(agentId, out var scope))
            {
                DefineAgentScope(agentId, [.. tools], true);
                return;
            }
            var merged = new HashSet<string>(scope.AllowedTools);
            foreach (var t in tools)
            {
                merged.Add(t);
            }
            scope.AllowedTools = [.. merged];
            scope.UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }
    }

    public void RemoveAllowedTools(string agentId, IReadOnlyList<string> tools)
    {
        lock (AgentSecurityStores.Lock)
        {
            if (!AgentSecurityStores.Scopes.TryGetValue(agentId, out var scope))
            {
                return;
            }
            var removeSet = new HashSet<string>(tools);
            scope.AllowedTools = scope.AllowedTools.Where(t => !removeSet.Contains(t)).ToList();
            scope.UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }
    }
}
