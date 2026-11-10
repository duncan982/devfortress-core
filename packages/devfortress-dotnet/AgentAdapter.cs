using System.Text.Json;

namespace DevFortress;

/// <summary>
/// DevFortress Agent Security Adapter (IP-C1). Mirrors
/// <c>packages/devfortress-sdk/src/agent.ts</c>'s <c>AgentAdapter</c>.
/// </summary>
/// <remarks>
/// Unlike the Node SDK's synchronous <c>df.observe()</c> (which can return a server-decided
/// flagged verdict on the same call), this external-mode <see cref="Client"/> queues events
/// asynchronously (<see cref="Client.TrackEvent"/>/<see cref="Client.FlushAsync"/>) — there is
/// no per-call server round trip here to carry a flagged verdict back, so this adapter has no
/// <c>onFlagged</c> callback, matching the Go/Ruby/PHP SDKs' same adaptation for the same
/// reason. The event shape (agent_id, tool_name, input_summary, framework, session tracking)
/// matches the Node SDK field-for-field.
/// </remarks>
public sealed class AgentAdapter
{
    private const int MaxTrackedSessions = 10_000;

    private readonly Client _client;
    private readonly string _agentId;
    private readonly string _agentName;
    private readonly string _agentIp;
    private readonly int _maxInputSummaryLength;
    private readonly bool _sanitizeInputs;
    private readonly Dictionary<string, int> _sessionToolCounts = [];
    private readonly List<string> _sessionOrder = [];
    private readonly object _lock = new();

    public AgentAdapter(Client client, string agentId, string? agentName = null, string agentIp = "127.0.0.1",
        int maxInputSummaryLength = 256, bool sanitizeInputs = true)
    {
        AgentId.Validate(agentId);
        _client = client;
        _agentId = agentId;
        _agentName = agentName ?? agentId;
        _agentIp = agentIp;
        _maxInputSummaryLength = maxInputSummaryLength;
        _sanitizeInputs = sanitizeInputs;
    }

    /// <summary>Queue an observation of an AI agent tool invocation. The real tool inputs stay local — only the summary is transmitted.</summary>
    public void ObserveToolCall(string tool, Dictionary<string, object?>? input = null, int? durationMs = null,
        string? model = null, string framework = "custom", Dictionary<string, object?>? meta = null, string? sessionId = null)
    {
        string summary = SummarizeInput(input);

        string sid = sessionId ?? "default";
        int count;
        lock (_lock)
        {
            count = (_sessionToolCounts.TryGetValue(sid, out int c) ? c : 0) + 1;
            _sessionToolCounts[sid] = count;
            if (!_sessionOrder.Contains(sid))
            {
                _sessionOrder.Add(sid);
            }
        }

        var metadata = new Dictionary<string, object?>
        {
            ["agent_id"] = _agentId,
            ["agent_name"] = _agentName,
            ["tool_name"] = tool,
            ["input_summary"] = summary,
            ["duration_ms"] = durationMs,
            ["model"] = model,
            ["framework"] = framework,
            ["session_tool_count"] = count,
            ["session_id"] = sessionId,
            ["event_category"] = "agent_tool_call",
        };
        if (meta is not null)
        {
            foreach (var (k, v) in meta)
            {
                metadata[k] = v;
            }
        }

        _client.TrackEvent(new Dictionary<string, object?>
        {
            ["eventType"] = "custom",
            ["method"] = "TOOL_CALL",
            ["path"] = $"/agent/{_agentId}/tool/{tool}",
            ["ip"] = _agentIp,
            ["userAgent"] = $"DevFortress-Agent/{_agentName}",
            ["severity"] = "LOW",
            ["metadata"] = metadata,
        });
    }

    /// <summary>Convenience wrapper for a LangChain/LangGraph tool call.</summary>
    public void ObserveLangChainTool(string toolName, Dictionary<string, object?> toolInput, string? sessionId = null,
        string? model = null, int? durationMs = null) =>
        ObserveToolCall(toolName, toolInput, durationMs, model, "langchain", sessionId: sessionId);

    /// <summary>Convenience wrapper extracting from an OpenAI tool_calls entry.</summary>
    public void ObserveOpenAiToolCall(string functionName, string argumentsJson, string? sessionId = null,
        string? model = null, int? durationMs = null)
    {
        Dictionary<string, object?> parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<Dictionary<string, object?>>(argumentsJson) ?? [];
        }
        catch (JsonException)
        {
            parsed = new Dictionary<string, object?> { ["raw"] = argumentsJson };
        }
        ObserveToolCall(functionName, parsed, durationMs, model, "openai", sessionId: sessionId);
    }

    /// <summary>Observe a raw HTTP tool call (e.g. an agent calling an external API).</summary>
    public void ObserveHttpToolCall(string url, string method, int? statusCode = null, int? durationMs = null,
        string? sessionId = null, Dictionary<string, object?>? meta = null) =>
        ObserveToolCall($"http:{method.ToUpperInvariant()}",
            new Dictionary<string, object?> { ["url"] = url, ["status_code"] = statusCode },
            durationMs, framework: "raw_http", meta: meta, sessionId: sessionId);

    /// <summary>Track the start of an agent session (task/conversation).</summary>
    public void TrackSessionStart(string sessionId, string? taskDescription = null)
    {
        lock (_lock)
        {
            if (_sessionToolCounts.Count >= MaxTrackedSessions && _sessionOrder.Count > 0)
            {
                string oldest = _sessionOrder[0];
                _sessionOrder.RemoveAt(0);
                _sessionToolCounts.Remove(oldest);
            }
            _sessionToolCounts[sessionId] = 0;
            _sessionOrder.Add(sessionId);
        }

        _client.TrackEvent(new Dictionary<string, object?>
        {
            ["eventType"] = "custom",
            ["method"] = "SESSION_START",
            ["path"] = $"/agent/{_agentId}/session/{sessionId}",
            ["ip"] = _agentIp,
            ["userAgent"] = $"DevFortress-Agent/{_agentName}",
            ["severity"] = "LOW",
            ["metadata"] = new Dictionary<string, object?>
            {
                ["agent_id"] = _agentId,
                ["session_id"] = sessionId,
                ["task_description"] = taskDescription,
                ["event_category"] = "agent_session_start",
            },
        });
    }

    /// <summary>Track the end of an agent session with summary metrics.</summary>
    public void TrackSessionEnd(string sessionId, int? totalTools = null, int? durationMs = null, bool? success = null)
    {
        int toolCount;
        lock (_lock)
        {
            toolCount = _sessionToolCounts.TryGetValue(sessionId, out int c) ? c : 0;
            _sessionToolCounts.Remove(sessionId);
            _sessionOrder.Remove(sessionId);
        }

        _client.TrackEvent(new Dictionary<string, object?>
        {
            ["eventType"] = "custom",
            ["method"] = "SESSION_END",
            ["path"] = $"/agent/{_agentId}/session/{sessionId}",
            ["ip"] = _agentIp,
            ["userAgent"] = $"DevFortress-Agent/{_agentName}",
            ["severity"] = "LOW",
            ["metadata"] = new Dictionary<string, object?>
            {
                ["agent_id"] = _agentId,
                ["session_id"] = sessionId,
                ["total_tools"] = totalTools ?? toolCount,
                ["total_duration_ms"] = durationMs,
                ["success"] = success,
                ["event_category"] = "agent_session_end",
            },
        });
    }

    /// <summary>Get the current session tool count for monitoring.</summary>
    public int GetSessionToolCount(string sessionId)
    {
        lock (_lock)
        {
            return _sessionToolCounts.TryGetValue(sessionId, out int c) ? c : 0;
        }
    }

    private string SummarizeInput(Dictionary<string, object?>? input)
    {
        if (input is null)
        {
            return "{}";
        }
        var summary = new Dictionary<string, string>();
        foreach (var (key, val) in input)
        {
            summary[key] = val switch
            {
                null => "null",
                string s when _sanitizeInputs && IsSensitiveKey(key) => "[REDACTED]",
                string s => s.Length > 64 ? s[..61] + "..." : s,
                bool b => b ? "true" : "false",
                int or long or double or float or decimal => val.ToString() ?? "",
                System.Collections.ICollection c => $"Array({c.Count})",
                _ => "{...}",
            };
        }
        string str = JsonSerializer.Serialize(summary);
        return str.Length > _maxInputSummaryLength ? str[..(_maxInputSummaryLength - 3)] + "..." : str;
    }

    private static bool IsSensitiveKey(string key)
    {
        string lower = key.ToLowerInvariant();
        return lower.Contains("key") || lower.Contains("token") || lower.Contains("secret") || lower.Contains("password");
    }
}
