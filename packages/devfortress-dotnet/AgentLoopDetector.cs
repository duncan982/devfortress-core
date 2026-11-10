using System.Text.Json;

namespace DevFortress;

/// <summary>
/// A10: Agent Loop Detector. Mirrors <c>packages/devfortress-sdk/src/agent-loop-detector.ts</c>.
/// </summary>
/// <remarks>
/// Tracks agent execution cycles and token consumption. Detects infinite loops via cycle count,
/// time budget, and token budget thresholds, with an automatic circuit breaker (pause agent,
/// alert owner) that distinguishes legitimate long operations from runaway loops via progress
/// metrics. Patent: Filing 2 — Zero-Cost Extensions (A10).
/// </remarks>
public enum LoopAction { Continue, Warn, PauseAgent, Terminate }

public sealed record LoopCycleContext(long? TokensUsed = null, string? ToolName = null,
    IReadOnlyDictionary<string, object?>? ToolArgs = null, double? ProgressMetric = null);

public sealed record LoopDetectionResult(bool Loop, string Reason, LoopAction Action, int Cycles,
    long TotalTokens, long ElapsedMs, bool MakingProgress, double RepetitionScore);

internal sealed class LoopSession
{
    public required string AgentId { get; init; }
    public long StartedAt { get; init; }
    public int Cycles { get; set; }
    public long TotalTokens { get; set; }
    public List<string> ToolHistory { get; set; } = [];
    public List<string> ArgHashes { get; set; } = [];
    public List<double> ProgressMetrics { get; } = [];
    public bool Paused { get; set; }
}

public sealed class AgentLoopDetector(int maxCycles = 20, long maxDurationMs = 120_000, long maxTokens = 100_000,
    int progressUniqueTools = 2, int progressWindowCycles = 5, int maxSessions = 50_000)
{
    private readonly Dictionary<string, LoopSession> _sessions = [];
    private readonly List<string> _sessionOrder = [];
    private readonly object _lock = new();

    /// <summary>
    /// Legacy-compatible wrapper. Ported faithfully from Node's identical quirk: the session key
    /// is the constant literal "agent_session" regardless of <paramref name="agentId"/> — so two
    /// different agents calling this wrapper (rather than <see cref="RecordCycle"/> directly)
    /// share the SAME loop-detection session state process-wide. <paramref name="agentId"/> only
    /// ends up as metadata on whichever session currently holds that key.
    /// </summary>
    public LoopDetectionResult DetectLoop(string agentId, IReadOnlyList<string>? toolCallHistory = null)
    {
        string? toolName = toolCallHistory is { Count: > 0 } h ? h[^1] : null;
        return RecordCycle(agentId, "agent_session", new LoopCycleContext(ToolName: toolName));
    }

    public LoopDetectionResult RecordCycle(string agentId, string sessionId, LoopCycleContext? context = null)
    {
        context ??= new LoopCycleContext();
        lock (_lock)
        {
            var session = GetOrCreateSession(agentId, sessionId);
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            if (session.Paused)
            {
                return BuildResult(session, now, true, "agent_paused", LoopAction.Terminate);
            }

            session.Cycles++;
            session.TotalTokens += context.TokensUsed ?? 0;

            if (context.ToolName is not null)
            {
                session.ToolHistory.Add(context.ToolName);
            }
            if (context.ToolArgs is not null)
            {
                session.ArgHashes.Add(HashArgs(context.ToolArgs));
            }
            if (context.ProgressMetric is not null)
            {
                session.ProgressMetrics.Add(context.ProgressMetric.Value);
            }

            long elapsedMs = now - session.StartedAt;
            bool makingProgress = CheckProgress(session);
            double repetitionScore = ComputeRepetitionScore(session);

            if (session.Cycles >= maxCycles && !makingProgress)
            {
                session.Paused = true;
                return BuildResult(session, now, true, "max_cycles", LoopAction.PauseAgent);
            }
            if (elapsedMs >= maxDurationMs)
            {
                session.Paused = true;
                return BuildResult(session, now, true, "max_duration", LoopAction.PauseAgent);
            }
            if (session.TotalTokens >= maxTokens)
            {
                session.Paused = true;
                return BuildResult(session, now, true, "max_tokens", LoopAction.PauseAgent);
            }
            if (repetitionScore > 0.8 && session.Cycles > 5 && !makingProgress)
            {
                session.Paused = true;
                return BuildResult(session, now, true, "repetitive_pattern", LoopAction.PauseAgent);
            }
            if (session.Cycles >= maxCycles * 0.8 || elapsedMs >= maxDurationMs * 0.8 || session.TotalTokens >= maxTokens * 0.8)
            {
                return BuildResult(session, now, false, "approaching_limit", LoopAction.Warn);
            }

            return BuildResult(session, now, false, "within_limits", LoopAction.Continue);
        }
    }

    /// <summary>Clear a session. Accepts (agentId, sessionId) or just (sessionId) as key, matching Node's overload.</summary>
    public void ClearSession(string agentIdOrSessionId, string? sessionId = null)
    {
        string key = sessionId is not null ? $"{agentIdOrSessionId}:{sessionId}" : agentIdOrSessionId;
        lock (_lock)
        {
            _sessions.Remove(key);
            _sessionOrder.Remove(key);
        }
    }

    /// <summary>Release an agent from paused state (after human review).</summary>
    public bool ReleaseAgent(string sessionId)
    {
        lock (_lock)
        {
            if (!_sessions.TryGetValue(sessionId, out var session))
            {
                return false;
            }
            session.Paused = false;
            session.Cycles = 0;
            session.TotalTokens = 0;
            session.ToolHistory = [];
            session.ArgHashes = [];
            return true;
        }
    }

    public bool IsPaused(string sessionId)
    {
        lock (_lock)
        {
            return _sessions.TryGetValue(sessionId, out var s) && s.Paused;
        }
    }

    public (bool Exists, int Cycles, long Tokens, long ElapsedMs, bool Paused) GetMetrics(string sessionId)
    {
        lock (_lock)
        {
            if (!_sessions.TryGetValue(sessionId, out var s))
            {
                return (false, 0, 0, 0, false);
            }
            return (true, s.Cycles, s.TotalTokens, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - s.StartedAt, s.Paused);
        }
    }

    public void Destroy()
    {
        lock (_lock)
        {
            _sessions.Clear();
            _sessionOrder.Clear();
        }
    }

    private LoopSession GetOrCreateSession(string agentId, string sessionId)
    {
        if (!_sessions.TryGetValue(sessionId, out var session))
        {
            if (_sessions.Count >= maxSessions && _sessionOrder.Count > 0)
            {
                string first = _sessionOrder[0];
                _sessionOrder.RemoveAt(0);
                _sessions.Remove(first);
            }
            session = new LoopSession { AgentId = agentId, StartedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() };
            _sessions[sessionId] = session;
            _sessionOrder.Add(sessionId);
        }
        return session;
    }

    private bool CheckProgress(LoopSession session)
    {
        var recentTools = session.ToolHistory.Skip(Math.Max(0, session.ToolHistory.Count - progressWindowCycles));
        int uniqueInWindow = recentTools.Distinct().Count();
        if (uniqueInWindow >= progressUniqueTools)
        {
            return true;
        }
        if (session.ProgressMetrics.Count >= 2)
        {
            var recent = session.ProgressMetrics.Skip(Math.Max(0, session.ProgressMetrics.Count - 3)).ToList();
            bool increasing = true;
            for (int i = 1; i < recent.Count; i++)
            {
                if (recent[i] <= recent[i - 1])
                {
                    increasing = false;
                    break;
                }
            }
            if (increasing)
            {
                return true;
            }
        }
        return false;
    }

    private static double ComputeRepetitionScore(LoopSession session)
    {
        if (session.ArgHashes.Count < 3)
        {
            return 0;
        }
        var recent = session.ArgHashes.Skip(Math.Max(0, session.ArgHashes.Count - 10)).ToList();
        int uniqueHashes = recent.Distinct().Count();
        return 1 - (double)uniqueHashes / recent.Count;
    }

    private static string HashArgs(IReadOnlyDictionary<string, object?> args)
    {
        string str = JsonSerializer.Serialize(args.OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .ToDictionary(kv => kv.Key, kv => kv.Value));
        int hash = 0;
        foreach (char c in str)
        {
            hash = unchecked((hash << 5) - hash + c);
        }
        return ToBase36(hash);
    }

    private static string ToBase36(int value)
    {
        const string digits = "0123456789abcdefghijklmnopqrstuvwxyz";
        bool negative = value < 0;
        long v = Math.Abs((long)value);
        if (v == 0)
        {
            return "0";
        }
        var sb = new System.Text.StringBuilder();
        while (v > 0)
        {
            sb.Insert(0, digits[(int)(v % 36)]);
            v /= 36;
        }
        return negative ? "-" + sb : sb.ToString();
    }

    private LoopDetectionResult BuildResult(LoopSession session, long now, bool loop, string reason, LoopAction action)
    {
        long elapsedMs = now - session.StartedAt;
        bool makingProgress = CheckProgress(session);
        double repetitionScore = ComputeRepetitionScore(session);

        return new LoopDetectionResult(loop, reason, action, session.Cycles, session.TotalTokens,
            elapsedMs, makingProgress, repetitionScore);
    }
}
