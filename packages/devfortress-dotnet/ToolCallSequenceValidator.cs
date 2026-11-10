namespace DevFortress;

/// <summary>
/// A7: Tool-Call Sequence Validator. Mirrors
/// <c>packages/devfortress-sdk/src/tool-call-sequence-validator.ts</c>.
/// </summary>
/// <remarks>
/// Validates AI agent tool calls against an authorized directed acyclic graph (DAG). Detects
/// out-of-sequence tool calls that indicate prompt injection attacks — e.g. an agent jumping
/// directly to <c>place_order</c> without first calling <c>add_to_cart</c>. Graduated response:
/// log → rate-limit → block → revoke session. Patent: Filing 2 — Zero-Cost Extensions (A7).
/// </remarks>
public sealed class ToolCallGraphNode
{
    /// <summary>Tools that must have been called before this one is allowed.</summary>
    public IReadOnlyList<string> Requires { get; init; } = [];
    /// <summary>Maximum times this tool can be called per session. 0 = unlimited.</summary>
    public int MaxCalls { get; init; }
    public string? RiskLevel { get; init; } // "low" | "medium" | "high" | "critical"
}

public enum ToolCallAction { Allow, Log, RateLimit, Block, RevokeSession }

public sealed record ToolCallValidationResult(
    bool Allowed, string Reason, ToolCallAction Action, bool PromptInjectionLikely,
    int ViolationCount, IReadOnlyList<string> CallHistory, IReadOnlyList<string>? MissingPrerequisites = null);

internal sealed class ToolCallSessionState
{
    public List<string> CallHistory { get; } = [];
    public Dictionary<string, int> CallCounts { get; } = [];
    public List<(long Timestamp, string Tool, string Reason)> Violations { get; set; } = [];
    public long CreatedAt { get; init; }
}

public sealed class ToolCallSequenceValidator
{
    private const int MaxSessions = 50_000;

    private readonly IReadOnlyDictionary<string, ToolCallGraphNode> _graph;
    private readonly int _maxViolations;
    private readonly long _violationWindowMs;
    private readonly bool _graduatedResponse;
    private readonly Dictionary<string, ToolCallSessionState> _sessions = [];
    private readonly List<string> _sessionOrder = [];
    private readonly object _lock = new();

    public ToolCallSequenceValidator(IReadOnlyDictionary<string, ToolCallGraphNode> graph, int maxViolations = 3,
        long violationWindowMs = 300_000, bool graduatedResponse = true)
    {
        _graph = graph;
        _maxViolations = maxViolations;
        _violationWindowMs = violationWindowMs;
        _graduatedResponse = graduatedResponse;
    }

    /// <summary>
    /// Legacy-compatible wrapper: <paramref name="agentId"/> is used directly as the session id,
    /// and <paramref name="previousTools"/> is accepted but silently discarded — ported
    /// faithfully from Node, which has the identical quirk (the parameter has no effect on
    /// validation; only the validator's own recorded per-session call history matters).
    /// </summary>
    public ToolCallValidationResult ValidateToolCall(string agentId, string toolName, IReadOnlyList<string>? previousTools = null) =>
        Validate(agentId, toolName);

    public ToolCallValidationResult Validate(string sessionId, string toolName, long? timestamp = null)
    {
        lock (_lock)
        {
            var session = GetOrCreateSession(sessionId);
            long now = timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            session.Violations = session.Violations.Where(v => now - v.Timestamp < _violationWindowMs).ToList();

            if (!_graph.TryGetValue(toolName, out var graphNode))
            {
                session.Violations.Add((now, toolName, "unknown_tool"));
                return BuildResult(session, false, "unknown_tool", toolName, []);
            }

            var missingPrereqs = graphNode.Requires.Where(req => !session.CallHistory.Contains(req)).ToList();
            if (missingPrereqs.Count > 0)
            {
                session.Violations.Add((now, toolName, $"missing_prerequisites: {string.Join(", ", missingPrereqs)}"));
                return BuildResult(session, false, "out_of_sequence", toolName, missingPrereqs);
            }

            int currentCalls = session.CallCounts.GetValueOrDefault(toolName);
            if (graphNode.MaxCalls > 0 && currentCalls >= graphNode.MaxCalls)
            {
                session.Violations.Add((now, toolName, $"max_calls_exceeded: {currentCalls}/{graphNode.MaxCalls}"));
                return BuildResult(session, false, "max_calls_exceeded", toolName, []);
            }

            session.CallHistory.Add(toolName);
            session.CallCounts[toolName] = currentCalls + 1;

            return new ToolCallValidationResult(true, "valid_sequence", ToolCallAction.Allow, false,
                session.Violations.Count, [.. session.CallHistory]);
        }
    }

    /// <summary>Reset a session's state (e.g. after quarantine release).</summary>
    public void ResetSession(string sessionId)
    {
        lock (_lock)
        {
            _sessions.Remove(sessionId);
            _sessionOrder.Remove(sessionId);
        }
    }

    /// <summary>Clear a session's state (validation-script compatible alias for <see cref="ResetSession"/>).</summary>
    public void ClearSession(string sessionId) => ResetSession(sessionId);

    public IReadOnlyList<string> GetHistory(string sessionId)
    {
        lock (_lock)
        {
            return _sessions.TryGetValue(sessionId, out var s) ? [.. s.CallHistory] : [];
        }
    }

    public (bool Exists, int CallCount, int ViolationCount, IReadOnlyList<string> History) GetSessionStats(string sessionId)
    {
        lock (_lock)
        {
            if (!_sessions.TryGetValue(sessionId, out var s))
            {
                return (false, 0, 0, []);
            }
            return (true, s.CallHistory.Count, s.Violations.Count, [.. s.CallHistory]);
        }
    }

    /// <summary>Destroy all sessions and free memory.</summary>
    public void Destroy()
    {
        lock (_lock)
        {
            _sessions.Clear();
            _sessionOrder.Clear();
        }
    }

    private ToolCallSessionState GetOrCreateSession(string sessionId)
    {
        if (!_sessions.TryGetValue(sessionId, out var session))
        {
            if (_sessions.Count >= MaxSessions && _sessionOrder.Count > 0)
            {
                string first = _sessionOrder[0];
                _sessionOrder.RemoveAt(0);
                _sessions.Remove(first);
            }
            session = new ToolCallSessionState { CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() };
            _sessions[sessionId] = session;
            _sessionOrder.Add(sessionId);
        }
        return session;
    }

    private ToolCallValidationResult BuildResult(ToolCallSessionState session, bool allowed, string reason,
        string toolName, IReadOnlyList<string> missingPrerequisites)
    {
        int violationCount = session.Violations.Count;

        ToolCallAction action;
        if (_graduatedResponse)
        {
            action = violationCount >= _maxViolations ? ToolCallAction.RevokeSession
                : violationCount >= 2 ? ToolCallAction.Block
                : violationCount >= 1 ? ToolCallAction.RateLimit
                : ToolCallAction.Log;
        }
        else
        {
            action = ToolCallAction.Block;
        }

        bool promptInjectionLikely = reason == "out_of_sequence" && _graph.TryGetValue(toolName, out var node) &&
            (node.RiskLevel == "high" || node.RiskLevel == "critical");

        return new ToolCallValidationResult(allowed, reason, action, promptInjectionLikely, violationCount,
            [.. session.CallHistory], missingPrerequisites.Count > 0 ? missingPrerequisites : null);
    }
}
