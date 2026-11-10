using System.Diagnostics;
using System.Text.RegularExpressions;

namespace DevFortress;

/// <summary>
/// DevFortress SDK — Internal Closed-Loop Protection Engine (TODO 407 port). Ported from
/// <c>packages/devfortress-sdk/src/internal-closed-loop-engine.ts</c>'s <c>InternalClosedLoopEngine</c>
/// (ground truth), structurally mirroring the already-completed Python port
/// (<c>packages/devfortress-python/src/devfortress/internal_closed_loop_engine.py</c>).
///
/// <para>Three tiers:</para>
/// <list type="bullet">
/// <item>Tier 1: deterministic rule engine (regex/signature/heuristic rules, &lt;1ms target).
/// Highest-scoring matched rule wins the decision.</item>
/// <item>Tier 2: an optional custom scorer. <b>Unimplemented/pass-through by default</b> —
/// <see cref="EvaluateAsync"/> skips Tier 2 entirely when <see cref="InternalCLConfig.Tier2Scorer"/>
/// is <c>null</c>, exactly as Node skips it when <c>tier2Scorer</c> is unset. This port does not
/// build a .NET equivalent of Node's MLClassifier adapter — that remains Node-specific and is
/// explicitly out of scope here.</item>
/// <item>Tier 3: an async relay callback (<see cref="InternalCLConfig.OnRelay"/>), fired only for
/// non-'allow' decisions when <see cref="InternalCLConfig.EnableExternalRelay"/> is true (hybrid
/// mode only). This engine has no HTTP client or platform credentials of its own by design — the
/// caller's relay callback does the actual platform call (see <c>Client.cs</c>'s
/// <c>RelayInternalDecisionToPlatform</c>), the sole relay path for a hybrid-mode flagged decision
/// (no duplicate relay call).</item>
/// </list>
///
/// <para>State (blocked IPs/users/sessions, quarantined agents, rate-limiter entries, audit log) is
/// bounded in-memory, lives for the engine instance's lifetime, and is never persisted — reusing
/// this package's own <see cref="DevFortress.BoundedMap{TKey,TValue}"/> (already thread-safe).</para>
///
/// <para><b>Concurrency:</b> unlike Node (single-threaded) and the Python/PHP/Ruby ports (typically
/// single-threaded-per-request), ASP.NET Core calls this engine concurrently across request
/// threads. <see cref="BoundedMap{TKey,TValue}"/>'s own internal lock protects each individual
/// map operation, but the rate limiter's check-then-record sequence touches a mutable
/// <c>List&lt;long&gt;</c> inside one entry across two separate map operations, which needs its own
/// lock to avoid corrupting that list under concurrent requests from the same IP — see
/// <see cref="_rateLimitLock"/>. The audit log (a plain <c>List&lt;T&gt;</c>, trimmed like Node's
/// and Python's) and the event counter are likewise guarded explicitly.</para>
///
/// <para>Fail mode: <c>"closed"</c> (block, score 100) or <c>"open"</c> (allow, score 0) on an
/// uncaught exception during evaluation; default closed. Each Tier 1 rule's <c>Match</c> call is
/// wrapped in its own try/catch so a single bad rule cannot crash the whole engine or escalate to
/// the top-level fail-mode handler — matching Node's and Python's per-rule error isolation.</para>
/// </summary>
public sealed class InternalCLConfig
{
    /// <summary>"closed" (block on error) or "open" (allow on error). Default "closed".</summary>
    public string FailMode { get; set; } = "closed";

    /// <summary>Enable Tier 3 async relay to an external platform. Default false (air-gap).</summary>
    public bool EnableExternalRelay { get; set; } = false;

    public int MaxBlockedEntries { get; set; } = 10_000;
    public int MaxRateLimitEntries { get; set; } = 50_000;
    public int MaxAuditEntries { get; set; } = 100_000;
    public int DefaultBlockTtlSeconds { get; set; } = 3600;

    /// <summary>
    /// Optional Tier 2 custom scorer, returning a 0-100 threat score. Unimplemented/pass-through
    /// by default (<c>null</c>): <see cref="InternalClosedLoopEngine.EvaluateAsync"/> skips Tier 2
    /// entirely in that case. A synchronous scorer can be wrapped with
    /// <c>req =&gt; Task.FromResult(score)</c>.
    /// </summary>
    public Func<InternalCLRequest, Task<double>>? Tier2Scorer { get; set; }

    public double BlockThreshold { get; set; } = 85;
    public double RateLimitThreshold { get; set; } = 60;
    public int RateLimitMax { get; set; } = 100;
    public int RateLimitWindowMs { get; set; } = 60_000;
    public bool Debug { get; set; } = false;

    /// <summary>Callback fired for every action taken (block/rate-limit/quarantine/etc).</summary>
    public Action<InternalCLAction>? OnAction { get; set; }

    /// <summary>
    /// Tier 3 relay callback — fired for every non-'allow' decision when
    /// <see cref="EnableExternalRelay"/> is true (hybrid mode only). Receives the full
    /// <see cref="InternalCLResult"/> and <see cref="InternalCLRequest"/> so the caller can
    /// forward to the platform via its own client without this engine needing any HTTP client
    /// or platform credentials of its own.
    /// </summary>
    public Func<InternalCLResult, InternalCLRequest, Task>? OnRelay { get; set; }
}

/// <summary>A request passed through <see cref="InternalClosedLoopEngine.EvaluateAsync"/>.</summary>
public sealed class InternalCLRequest
{
    public required string Ip { get; init; }
    public required string Method { get; init; }
    public required string Path { get; init; }
    public string? UserAgent { get; init; }
    public string? UserId { get; init; }
    public string? SessionId { get; init; }
    public string? Body { get; init; }
    public string? Query { get; init; }
    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>();
    public string? AgentId { get; init; }
    public string? ToolName { get; init; }

    /// <summary>Milliseconds since epoch; defaults to <c>DateTimeOffset.UtcNow</c> when omitted.</summary>
    public long? Timestamp { get; init; }
}

/// <summary>One action taken as a side effect of a Tier 1/2 decision.</summary>
public sealed class InternalCLAction
{
    /// <summary>"block_ip" | "rate_limit" | "block_session" | "block_user" | "quarantine_agent" | "log"</summary>
    public required string Type { get; init; }
    public required string Target { get; init; }
    public required string Reason { get; init; }
    public required int TtlSeconds { get; init; }
    public required long Timestamp { get; init; }
    public required string EventId { get; init; }
}

/// <summary>The outcome of <see cref="InternalClosedLoopEngine.EvaluateAsync"/>.</summary>
public sealed class InternalCLResult
{
    /// <summary>"allow" | "block" | "rate_limit" | "challenge" | "quarantine"</summary>
    public required string Decision { get; init; }
    public required double Score { get; init; }
    public required int Tier { get; init; }
    public required List<string> MatchedRules { get; init; }
    public required double EvaluationTimeUs { get; init; }
    public required List<InternalCLAction> Actions { get; init; }
    public required string EventId { get; init; }
}

/// <summary>One bounded audit-log entry.</summary>
public sealed class InternalCLAuditEntry
{
    public required string EventId { get; init; }
    public required long Timestamp { get; init; }
    public required string Ip { get; init; }
    public required string Decision { get; init; }
    public required double Score { get; init; }
    public required int Tier { get; init; }
    public required List<string> MatchedRules { get; init; }
    public string? UserId { get; init; }
    public string? AgentId { get; init; }
    public required string Path { get; init; }
    public required string Method { get; init; }
}

/// <summary>A Tier 1 rule: a name, a match predicate, a score/decision pair if it matches.</summary>
public sealed class InternalCLRule
{
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required string Severity { get; init; }
    public required double Score { get; init; }
    public required string Decision { get; init; }
    public required Func<InternalCLRequest, bool> Match { get; init; }
    public bool Enabled { get; init; } = true;
}

/// <summary>Summary statistics, mirroring Node's/Python's <c>getStats()</c>/<c>get_stats()</c>.</summary>
public sealed record InternalCLStats(
    int BlockedIPs,
    int BlockedUsers,
    int BlockedSessions,
    int QuarantinedAgents,
    int RateLimitEntries,
    int AuditLogSize,
    int RulesCount,
    string FailMode);

public sealed class InternalClosedLoopEngine
{
    // ── Tier 1 default pattern sets — read directly from Node's registerDefaultRules() in
    // internal-closed-loop-engine.ts and independently verified against .NET's
    // System.Text.RegularExpressions engine (see the session report for the full methodology
    // and the one real divergence found: RegexOptions.ECMAScript must NOT be used here — it
    // narrows \s to ASCII-only whitespace, excluding U+00A0 (non-breaking space), which both
    // Node's \s and .NET's *default* (non-ECMAScript) \s match identically. Plain
    // RegexOptions.IgnoreCase (no ECMAScript) was confirmed byte-for-byte equivalent to Node's
    // bare /pattern/i literals for every Tier 1 pattern, including the deliberate
    // path_traversal/sensitive_file_access "/.env" overlap, which also reproduces in .NET.
    private static readonly Regex[] SqlInjectionStrict =
    [
        new(@"(?:^|\s)(?:UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+[a-zA-Z0-9_]+\s+SET|DELETE\s+FROM)(?:\s|$)", RegexOptions.IgnoreCase),
        new(@"(?:'|"")\s*OR\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|""[^""]*""\s*=\s*""[^""]*"")", RegexOptions.IgnoreCase),
        new(@"(?:'|"")\s*;\s*(?:--|/\*)"),
        new(@"(\bxp_\w+)", RegexOptions.IgnoreCase),
    ];

    private static readonly Regex[] SqlInjectionModerate =
    [
        new(@"(/\*.*\*/)"),
        new(@"(\bEXEC\b|\bEXECUTE\b)\s*\(", RegexOptions.IgnoreCase),
    ];

    private static readonly Regex[] XssPatterns =
    [
        new(@"<script[\s>]", RegexOptions.IgnoreCase),
        new(@"javascript\s*:", RegexOptions.IgnoreCase),
        new(@"on(load|error|click|mouseover|submit|focus|blur)\s*=", RegexOptions.IgnoreCase),
        new(@"(<iframe|<object|<embed|<applet)", RegexOptions.IgnoreCase),
        new(@"(document\.(cookie|write|location))", RegexOptions.IgnoreCase),
        new(@"(window\.(location|open))", RegexOptions.IgnoreCase),
    ];

    private static readonly Regex[] PathTraversalPatterns =
    [
        new(@"\.\./"),
        new(@"\.\.%2[fF]"),
        new(@"\.\.\\$"),
        new(@"%2e%2e[%/\\]", RegexOptions.IgnoreCase),
        new(@"/etc/(passwd|shadow|hosts)"),
        new(@"/proc/self"),
        new(@"(/\.env|/\.git|/\.ssh)"),
    ];

    private static readonly Regex[] ScannerSignatures =
    [
        new(@"sqlmap", RegexOptions.IgnoreCase),
        new(@"nikto", RegexOptions.IgnoreCase),
        new(@"nmap", RegexOptions.IgnoreCase),
        new(@"dirbuster", RegexOptions.IgnoreCase),
        new(@"gobuster", RegexOptions.IgnoreCase),
        new(@"wpscan", RegexOptions.IgnoreCase),
        new(@"burp\s*suite", RegexOptions.IgnoreCase),
        new(@"acunetix", RegexOptions.IgnoreCase),
        new(@"nessus", RegexOptions.IgnoreCase),
        new(@"masscan", RegexOptions.IgnoreCase),
        new(@"zgrab", RegexOptions.IgnoreCase),
        new(@"nuclei", RegexOptions.IgnoreCase),
    ];

    private static readonly Regex[] SensitiveFilePatterns =
    [
        new(@"/\.env"),
        new(@"/\.git"),
        new(@"/\.ssh"),
        new(@"/wp-admin"),
        new(@"/wp-login"),
        new(@"/phpmyadmin", RegexOptions.IgnoreCase),
        new(@"/admin\.php"),
        new(@"/\.htaccess"),
        new(@"/\.htpasswd"),
        new(@"/server-status"),
        new(@"/actuator"),
        new(@"/debug/"),
    ];

    private static readonly string[] AuthPaths = ["/login", "/signin", "/auth", "/api/auth", "/api/login", "/oauth/token"];
    private static readonly HashSet<string> DangerousTools = new(StringComparer.Ordinal)
    {
        "shell_exec", "eval", "exec", "rm", "sudo", "chmod", "kill",
    };

    /// <summary>
    /// Lightweight, synchronous, zero-network content check reusing the same Tier 1 patterns as
    /// <see cref="RegisterDefaultRules"/>. Mirrors Node's <c>matchesKnownAttackPattern</c>
    /// (Option B, 2026-08-27) and Python's <c>matches_known_attack_pattern</c>.
    /// </summary>
    public static bool MatchesKnownAttackPattern(string? path, string? userAgent = null)
    {
        if (!string.IsNullOrEmpty(path))
        {
            if (Array.Exists(SqlInjectionStrict, p => p.IsMatch(path))) return true;
            if (Array.Exists(SqlInjectionModerate, p => p.IsMatch(path))) return true;
            if (Array.Exists(XssPatterns, p => p.IsMatch(path))) return true;
            if (Array.Exists(PathTraversalPatterns, p => p.IsMatch(path))) return true;
        }
        if (!string.IsNullOrEmpty(userAgent) && Array.Exists(ScannerSignatures, p => p.IsMatch(userAgent)))
        {
            return true;
        }
        return false;
    }

    private readonly InternalCLConfig _config;

    private readonly BoundedMap<string, BlockEntry> _blockedIPs;
    private readonly BoundedMap<string, BlockEntry> _blockedUsers;
    private readonly BoundedMap<string, BlockEntry> _blockedSessions;
    private readonly BoundedMap<string, QuarantineEntry> _quarantinedAgents;
    private readonly BoundedMap<string, RateLimitEntry> _rateLimiter;

    private readonly object _rateLimitLock = new();
    private readonly object _auditLock = new();
    private readonly object _rulesLock = new();

    private readonly List<InternalCLAuditEntry> _auditLog = [];
    private readonly List<InternalCLRule> _rules = [];
    private int _eventCounter;

    private sealed class BlockEntry
    {
        public required long ExpiresAt { get; set; }
        public required string Reason { get; set; }
    }

    private sealed class QuarantineEntry
    {
        public required string Reason { get; set; }
        public required long Timestamp { get; set; }
    }

    private sealed class RateLimitEntry
    {
        public List<long> Timestamps { get; set; } = [];
        public bool Blocked { get; set; }
    }

    public InternalClosedLoopEngine(InternalCLConfig? config = null)
    {
        _config = config ?? new InternalCLConfig();

        _blockedIPs = new BoundedMap<string, BlockEntry>(_config.MaxBlockedEntries);
        _blockedUsers = new BoundedMap<string, BlockEntry>(_config.MaxBlockedEntries);
        _blockedSessions = new BoundedMap<string, BlockEntry>(_config.MaxBlockedEntries);
        _quarantinedAgents = new BoundedMap<string, QuarantineEntry>(_config.MaxBlockedEntries);
        _rateLimiter = new BoundedMap<string, RateLimitEntry>(_config.MaxRateLimitEntries);

        RegisterDefaultRules();
        Log("info", $"Internal Closed-Loop Engine initialized (failMode={_config.FailMode})");
    }

    // ── Public API ───────────────────────────────────────────────────────

    /// <summary>
    /// Evaluate a request through the 3-tier engine. Call this for every inbound request, before
    /// it reaches the application — the defining behaviour of internal mode is that this never
    /// needs a platform round-trip to produce a decision.
    /// </summary>
    public async Task<InternalCLResult> EvaluateAsync(InternalCLRequest req)
    {
        long startTicks = Stopwatch.GetTimestamp();
        long now = req.Timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        string eventId = GenerateEventId();

        try
        {
            var preCheck = CheckBlocked(req, now);
            if (preCheck is { } pc)
            {
                double elapsedUs = Stopwatch.GetElapsedTime(startTicks).TotalMicroseconds;
                var result = new InternalCLResult
                {
                    Decision = pc.Decision,
                    Score = 100,
                    Tier = 1,
                    MatchedRules = [pc.Reason],
                    EvaluationTimeUs = elapsedUs,
                    Actions = [],
                    EventId = eventId,
                };
                RecordAudit(result, req);
                return result;
            }

            var (tier1Decision, tier1Score, tier1Rules) = EvaluateTier1(req);
            if (tier1Decision != "allow")
            {
                double elapsedUs = Stopwatch.GetElapsedTime(startTicks).TotalMicroseconds;
                var actions = ExecuteActions(tier1Decision, tier1Rules, req, eventId, now);
                var result = new InternalCLResult
                {
                    Decision = tier1Decision,
                    Score = tier1Score,
                    Tier = 1,
                    MatchedRules = tier1Rules,
                    EvaluationTimeUs = elapsedUs,
                    Actions = actions,
                    EventId = eventId,
                };
                RecordAudit(result, req);
                if (_config.EnableExternalRelay)
                {
                    await RelayToExternalAsync(result, req).ConfigureAwait(false);
                }
                return result;
            }

            if (CheckAndRecordRateLimit(req.Ip, now))
            {
                double elapsedUs = Stopwatch.GetElapsedTime(startTicks).TotalMicroseconds;
                var actions = ExecuteActions("rate_limit", ["rate_limit_exceeded"], req, eventId, now);
                var result = new InternalCLResult
                {
                    Decision = "rate_limit",
                    Score = 65,
                    Tier = 1,
                    MatchedRules = ["rate_limit_exceeded"],
                    EvaluationTimeUs = elapsedUs,
                    Actions = actions,
                    EventId = eventId,
                };
                RecordAudit(result, req);
                return result;
            }

            // ─── Tier 2: optional custom scorer — unimplemented/pass-through by default.
            // Skipped entirely when no scorer is configured. ───
            if (_config.Tier2Scorer is { } scorer)
            {
                double score = await scorer(req).ConfigureAwait(false);

                if (score >= _config.BlockThreshold)
                {
                    double elapsedUs = Stopwatch.GetElapsedTime(startTicks).TotalMicroseconds;
                    var actions = ExecuteActions("block", ["tier2_ml_score"], req, eventId, now);
                    var result = new InternalCLResult
                    {
                        Decision = "block",
                        Score = score,
                        Tier = 2,
                        MatchedRules = ["tier2_ml_score"],
                        EvaluationTimeUs = elapsedUs,
                        Actions = actions,
                        EventId = eventId,
                    };
                    RecordAudit(result, req);
                    if (_config.EnableExternalRelay)
                    {
                        await RelayToExternalAsync(result, req).ConfigureAwait(false);
                    }
                    return result;
                }

                if (score >= _config.RateLimitThreshold)
                {
                    double elapsedUs = Stopwatch.GetElapsedTime(startTicks).TotalMicroseconds;
                    var result = new InternalCLResult
                    {
                        Decision = "rate_limit",
                        Score = score,
                        Tier = 2,
                        MatchedRules = ["tier2_ml_elevated"],
                        EvaluationTimeUs = elapsedUs,
                        Actions = [],
                        EventId = eventId,
                    };
                    RecordAudit(result, req);
                    return result;
                }
            }

            double allowedElapsedUs = Stopwatch.GetElapsedTime(startTicks).TotalMicroseconds;
            return new InternalCLResult
            {
                Decision = "allow",
                Score = 0,
                Tier = 1,
                MatchedRules = [],
                EvaluationTimeUs = allowedElapsedUs,
                Actions = [],
                EventId = eventId,
            };
        }
        catch (Exception ex)
        {
            double elapsedUs = Stopwatch.GetElapsedTime(startTicks).TotalMicroseconds;
            Log("error", $"Evaluation error: {ex.Message}");

            if (_config.FailMode == "closed")
            {
                return new InternalCLResult
                {
                    Decision = "block",
                    Score = 100,
                    Tier = 1,
                    MatchedRules = ["fail_closed_error"],
                    EvaluationTimeUs = elapsedUs,
                    Actions = [],
                    EventId = eventId,
                };
            }

            return new InternalCLResult
            {
                Decision = "allow",
                Score = 0,
                Tier = 1,
                MatchedRules = ["fail_open_error"],
                EvaluationTimeUs = elapsedUs,
                Actions = [],
                EventId = eventId,
            };
        }
    }

    public void BlockIP(string ip, string reason, int? ttlSeconds = null)
    {
        int ttl = ttlSeconds ?? _config.DefaultBlockTtlSeconds;
        _blockedIPs.Set(ip, new BlockEntry { ExpiresAt = NowMs() + ttl * 1000L, Reason = reason });
        Log("info", $"IP blocked: {ip} — {reason} (TTL: {ttl}s)");
    }

    public bool UnblockIP(string ip)
    {
        bool existed = _blockedIPs.Has(ip);
        _blockedIPs.Delete(ip);
        if (existed)
        {
            Log("info", $"IP unblocked: {ip}");
        }
        return existed;
    }

    public void BlockUser(string userId, string reason, int? ttlSeconds = null)
    {
        int ttl = ttlSeconds ?? _config.DefaultBlockTtlSeconds;
        _blockedUsers.Set(userId, new BlockEntry { ExpiresAt = NowMs() + ttl * 1000L, Reason = reason });
        Log("info", $"User blocked: {userId} — {reason}");
    }

    public void BlockSession(string sessionId, string reason, int? ttlSeconds = null)
    {
        int ttl = ttlSeconds ?? _config.DefaultBlockTtlSeconds;
        _blockedSessions.Set(sessionId, new BlockEntry { ExpiresAt = NowMs() + ttl * 1000L, Reason = reason });
        Log("info", $"Session blocked: {sessionId} — {reason}");
    }

    public void QuarantineAgent(string agentId, string reason)
    {
        _quarantinedAgents.Set(agentId, new QuarantineEntry { Reason = reason, Timestamp = NowMs() });
        Log("info", $"Agent quarantined: {agentId} — {reason}");
    }

    public bool UnquarantineAgent(string agentId)
    {
        bool existed = _quarantinedAgents.Has(agentId);
        _quarantinedAgents.Delete(agentId);
        if (existed)
        {
            Log("info", $"Agent unquarantined: {agentId}");
        }
        return existed;
    }

    public bool IsIpBlocked(string ip)
    {
        var entry = _blockedIPs.Get(ip);
        if (entry is null)
        {
            return false;
        }
        if (NowMs() > entry.ExpiresAt)
        {
            _blockedIPs.Delete(ip);
            return false;
        }
        return true;
    }

    public bool IsAgentQuarantined(string agentId) => _quarantinedAgents.Has(agentId);

    public void AddRule(InternalCLRule rule)
    {
        lock (_rulesLock)
        {
            _rules.Add(rule);
        }
        Log("debug", $"Rule added: {rule.Name}");
    }

    public bool RemoveRule(string name)
    {
        lock (_rulesLock)
        {
            int idx = _rules.FindIndex(r => r.Name == name);
            if (idx >= 0)
            {
                _rules.RemoveAt(idx);
                Log("debug", $"Rule removed: {name}");
                return true;
            }
        }
        return false;
    }

    public List<InternalCLRule> GetRules()
    {
        lock (_rulesLock)
        {
            return [.. _rules];
        }
    }

    public List<InternalCLAuditEntry> GetAuditLog(int limit = 100)
    {
        lock (_auditLock)
        {
            int start = Math.Max(0, _auditLog.Count - limit);
            return _auditLog.GetRange(start, _auditLog.Count - start);
        }
    }

    public InternalCLStats GetStats()
    {
        int rulesCount;
        lock (_rulesLock)
        {
            rulesCount = _rules.Count;
        }
        int auditSize;
        lock (_auditLock)
        {
            auditSize = _auditLog.Count;
        }
        return new InternalCLStats(
            _blockedIPs.Size,
            _blockedUsers.Size,
            _blockedSessions.Size,
            _quarantinedAgents.Size,
            _rateLimiter.Size,
            auditSize,
            rulesCount,
            _config.FailMode);
    }

    public int ImportBlockedIPs(IEnumerable<(string Ip, string Reason, int? TtlSeconds)> entries)
    {
        int count = 0;
        foreach (var entry in entries)
        {
            BlockIP(entry.Ip, entry.Reason, entry.TtlSeconds);
            count++;
        }
        return count;
    }

    /// <summary>Reset all state. For testing.</summary>
    internal void Reset()
    {
        _blockedIPs.Clear();
        _blockedUsers.Clear();
        _blockedSessions.Clear();
        _quarantinedAgents.Clear();
        _rateLimiter.Clear();
        lock (_auditLock)
        {
            _auditLog.Clear();
        }
        Volatile.Write(ref _eventCounter, 0);
    }

    // ── Private: pre-check / Tier 1 / rate limit ────────────────────────

    private (string Decision, string Reason)? CheckBlocked(InternalCLRequest req, long now)
    {
        var ipBlock = _blockedIPs.Get(req.Ip);
        if (ipBlock is not null)
        {
            if (now > ipBlock.ExpiresAt)
            {
                _blockedIPs.Delete(req.Ip);
            }
            else
            {
                return ("block", $"ip_blocked:{ipBlock.Reason}");
            }
        }

        if (!string.IsNullOrEmpty(req.UserId))
        {
            var userBlock = _blockedUsers.Get(req.UserId);
            if (userBlock is not null)
            {
                if (now > userBlock.ExpiresAt)
                {
                    _blockedUsers.Delete(req.UserId);
                }
                else
                {
                    return ("block", $"user_blocked:{userBlock.Reason}");
                }
            }
        }

        if (!string.IsNullOrEmpty(req.SessionId))
        {
            var sessionBlock = _blockedSessions.Get(req.SessionId);
            if (sessionBlock is not null)
            {
                if (now > sessionBlock.ExpiresAt)
                {
                    _blockedSessions.Delete(req.SessionId);
                }
                else
                {
                    return ("block", $"session_blocked:{sessionBlock.Reason}");
                }
            }
        }

        if (!string.IsNullOrEmpty(req.AgentId) && _quarantinedAgents.Has(req.AgentId))
        {
            return ("quarantine", $"agent_quarantined:{req.AgentId}");
        }

        return null;
    }

    private (string Decision, double Score, List<string> MatchedRules) EvaluateTier1(InternalCLRequest req)
    {
        var matchedRules = new List<string>();
        double maxScore = 0;
        string decision = "allow";

        List<InternalCLRule> rulesSnapshot;
        lock (_rulesLock)
        {
            rulesSnapshot = [.. _rules];
        }

        foreach (var rule in rulesSnapshot)
        {
            if (!rule.Enabled)
            {
                continue;
            }
            try
            {
                if (rule.Match(req))
                {
                    matchedRules.Add(rule.Name);
                    if (rule.Score > maxScore)
                    {
                        maxScore = rule.Score;
                        decision = rule.Decision;
                    }
                }
            }
            catch
            {
                // Individual rule errors should not crash the engine (matches Node/Python).
                Log("error", $"Rule {rule.Name} threw an error");
            }
        }

        return (decision, maxScore, matchedRules);
    }

    /// <summary>
    /// Atomically checks and records the sliding-window rate limit for <paramref name="ip"/>.
    /// Combined into one locked operation (unlike Node's/Python's separate
    /// checkRateLimit/recordRequest calls) because, under concurrent requests from the same IP,
    /// two threads interleaving those steps could both read "not yet over the limit" and both
    /// record, letting the count run over the limit — and because
    /// <see cref="RateLimitEntry.Timestamps"/> is a plain mutable list that is not itself
    /// thread-safe once retrieved from the BoundedMap.
    /// </summary>
    private bool CheckAndRecordRateLimit(string ip, long now)
    {
        lock (_rateLimitLock)
        {
            var entry = _rateLimiter.Get(ip);
            if (entry is null)
            {
                entry = new RateLimitEntry();
                _rateLimiter.Set(ip, entry);
            }

            long windowStart = now - _config.RateLimitWindowMs;
            entry.Timestamps = entry.Timestamps.FindAll(t => t > windowStart);

            if (entry.Timestamps.Count >= _config.RateLimitMax)
            {
                entry.Blocked = true;
                return true;
            }

            entry.Timestamps.Add(now);
            return false;
        }
    }

    private List<InternalCLAction> ExecuteActions(string decision, List<string> matchedRules, InternalCLRequest req, string eventId, long now)
    {
        var actions = new List<InternalCLAction>();
        int ttl = _config.DefaultBlockTtlSeconds;
        string reason = string.Join(", ", matchedRules);

        if (decision is "block" or "quarantine")
        {
            _blockedIPs.Set(req.Ip, new BlockEntry { ExpiresAt = now + ttl * 1000L, Reason = reason });
            actions.Add(new InternalCLAction
            {
                Type = "block_ip",
                Target = req.Ip,
                Reason = reason,
                TtlSeconds = ttl,
                Timestamp = now,
                EventId = eventId,
            });

            if (!string.IsNullOrEmpty(req.SessionId))
            {
                _blockedSessions.Set(req.SessionId, new BlockEntry { ExpiresAt = now + ttl * 1000L, Reason = reason });
                actions.Add(new InternalCLAction
                {
                    Type = "block_session",
                    Target = req.SessionId,
                    Reason = reason,
                    TtlSeconds = ttl,
                    Timestamp = now,
                    EventId = eventId,
                });
            }

            if (!string.IsNullOrEmpty(req.AgentId))
            {
                _quarantinedAgents.Set(req.AgentId, new QuarantineEntry { Reason = reason, Timestamp = now });
                actions.Add(new InternalCLAction
                {
                    Type = "quarantine_agent",
                    Target = req.AgentId,
                    Reason = reason,
                    TtlSeconds = 0, // Permanent until manual unquarantine
                    Timestamp = now,
                    EventId = eventId,
                });
            }
        }

        if (_config.OnAction is { } onAction)
        {
            foreach (var action in actions)
            {
                try
                {
                    onAction(action);
                }
                catch
                {
                    Log("error", $"OnAction callback error for {action.Type}");
                }
            }
        }

        return actions;
    }

    private void RecordAudit(InternalCLResult result, InternalCLRequest req)
    {
        lock (_auditLock)
        {
            if (_auditLog.Count >= _config.MaxAuditEntries)
            {
                int trim = Math.Max(1, (int)(_config.MaxAuditEntries * 0.1));
                _auditLog.RemoveRange(0, Math.Min(trim, _auditLog.Count));
            }

            _auditLog.Add(new InternalCLAuditEntry
            {
                EventId = result.EventId,
                Timestamp = req.Timestamp ?? NowMs(),
                Ip = req.Ip,
                Decision = result.Decision,
                Score = result.Score,
                Tier = result.Tier,
                MatchedRules = result.MatchedRules,
                UserId = req.UserId,
                AgentId = req.AgentId,
                Path = req.Path,
                Method = req.Method,
            });
        }
    }

    private async Task RelayToExternalAsync(InternalCLResult result, InternalCLRequest req)
    {
        // Tier 3: relay via the caller-supplied OnRelay callback. This engine has no HTTP client
        // or platform credentials of its own by design — the caller does the actual platform
        // call. The sole relay path for a hybrid-mode flagged decision (see Client.cs) — no
        // duplicate relay call.
        Log("debug", $"Tier 3 relay: {result.EventId} -> external platform");
        if (_config.OnRelay is not { } onRelay)
        {
            return;
        }
        try
        {
            await onRelay(result, req).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            Log("error", $"OnRelay callback error for {result.EventId}: {e.Message}");
        }
    }

    private string GenerateEventId()
    {
        int counter = Interlocked.Increment(ref _eventCounter);
        string ts = NowMs().ToString("x");
        string counterHex = counter.ToString("x").PadLeft(4, '0');
        string rand = Random.Shared.Next(0, 0xFFFF).ToString("x").PadLeft(4, '0');
        return $"icl_{ts}_{counterHex}_{rand}";
    }

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    private void RegisterDefaultRules()
    {
        // ─── SQL Injection ───
        _rules.Add(new InternalCLRule
        {
            Name = "sql_injection",
            Description = "Detects SQL injection patterns context-aware (strict on path/query, moderate on body)",
            Severity = "critical",
            Score = 95,
            Decision = "block",
            Match = req =>
            {
                var strictTargets = new List<string>();
                if (!string.IsNullOrEmpty(req.Path)) strictTargets.Add(req.Path);
                if (!string.IsNullOrEmpty(req.Query)) strictTargets.Add(req.Query);

                if (strictTargets.Exists(t => Array.Exists(SqlInjectionStrict, p => p.IsMatch(t))))
                {
                    return true;
                }
                if (strictTargets.Exists(t => Array.Exists(SqlInjectionModerate, p => p.IsMatch(t))))
                {
                    return true;
                }

                // Body and headers are only checked against strict patterns to reduce false positives.
                var bodyTargets = new List<string>();
                if (!string.IsNullOrEmpty(req.Body)) bodyTargets.Add(req.Body);
                bodyTargets.AddRange(req.Headers.Values.Where(v => !string.IsNullOrEmpty(v)));

                return bodyTargets.Exists(t => Array.Exists(SqlInjectionStrict, p => p.IsMatch(t)));
            },
        });

        // ─── XSS ───
        _rules.Add(new InternalCLRule
        {
            Name = "xss_attempt",
            Description = "Detects cross-site scripting patterns",
            Severity = "high",
            Score = 90,
            Decision = "block",
            Match = req =>
            {
                var targets = new List<string>();
                if (!string.IsNullOrEmpty(req.Path)) targets.Add(req.Path);
                if (!string.IsNullOrEmpty(req.Query)) targets.Add(req.Query);
                if (!string.IsNullOrEmpty(req.Body)) targets.Add(req.Body);
                return targets.Exists(t => Array.Exists(XssPatterns, p => p.IsMatch(t)));
            },
        });

        // ─── Path Traversal ───
        _rules.Add(new InternalCLRule
        {
            Name = "path_traversal",
            Description = "Detects directory traversal attempts",
            Severity = "high",
            Score = 90,
            Decision = "block",
            Match = req =>
            {
                var targets = new List<string>();
                if (!string.IsNullOrEmpty(req.Path)) targets.Add(req.Path);
                if (!string.IsNullOrEmpty(req.Query)) targets.Add(req.Query);
                return targets.Exists(t => Array.Exists(PathTraversalPatterns, p => p.IsMatch(t)));
            },
        });

        // ─── Scanner Detection ───
        _rules.Add(new InternalCLRule
        {
            Name = "scanner_detected",
            Description = "Detects known vulnerability scanner user agents",
            Severity = "medium",
            Score = 75,
            Decision = "block",
            Match = req =>
            {
                if (string.IsNullOrEmpty(req.UserAgent))
                {
                    return false;
                }
                return Array.Exists(ScannerSignatures, p => p.IsMatch(req.UserAgent));
            },
        });

        // ─── Sensitive File Access ───
        _rules.Add(new InternalCLRule
        {
            Name = "sensitive_file_access",
            Description = "Detects access to sensitive files (.env, .git, wp-admin, etc.)",
            Severity = "high",
            Score = 85,
            Decision = "block",
            Match = req => Array.Exists(SensitiveFilePatterns, p => p.IsMatch(req.Path)),
        });

        // ─── Credential Stuffing Heuristic ───
        _rules.Add(new InternalCLRule
        {
            Name = "credential_stuffing_pattern",
            Description = "Detects credential stuffing via POST to auth endpoints",
            Severity = "high",
            Score = 80,
            Decision = "rate_limit",
            Match = req =>
            {
                if (!string.Equals(req.Method, "POST", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
                string pathLower = req.Path.ToLowerInvariant();
                return Array.Exists(AuthPaths, p => pathLower.Contains(p, StringComparison.Ordinal));
            },
        });

        // ─── Agent Unsanctioned Tool ───
        _rules.Add(new InternalCLRule
        {
            Name = "agent_unsanctioned_tool",
            Description = "Detects agent attempting to use dangerous tools",
            Severity = "critical",
            Score = 95,
            Decision = "quarantine",
            Match = req =>
            {
                if (string.IsNullOrEmpty(req.AgentId) || string.IsNullOrEmpty(req.ToolName))
                {
                    return false;
                }
                return DangerousTools.Contains(req.ToolName.ToLowerInvariant());
            },
        });
    }

    private void Log(string level, string message)
    {
        if (!_config.Debug && level == "debug")
        {
            return;
        }
        const string prefix = "[DevFortress ICL]";
        switch (level)
        {
            case "error":
                Console.Error.WriteLine($"{prefix} {message}");
                break;
            case "warn":
                Console.Error.WriteLine($"{prefix} {message}");
                break;
            default:
                if (_config.Debug)
                {
                    Console.WriteLine($"{prefix} {message}");
                }
                break;
        }
    }
}
