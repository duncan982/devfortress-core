using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// InternalClosedLoopEngine (TODO 407 port), ported from
/// <c>packages/devfortress-sdk/src/internal-closed-loop-engine.ts</c>, structurally mirroring
/// Python's <c>test_internal_closed_loop_engine.py</c> (29 tests).
/// </summary>
public class InternalClosedLoopEngineTests
{
    private static InternalCLRequest Req(
        string ip = "203.0.113.5",
        string method = "GET",
        string path = "/",
        string? userAgent = null,
        string? userId = null,
        string? sessionId = null,
        string? body = null,
        string? query = null,
        Dictionary<string, string>? headers = null,
        string? agentId = null,
        string? toolName = null,
        long? timestamp = null) => new()
        {
            Ip = ip,
            Method = method,
            Path = path,
            UserAgent = userAgent,
            UserId = userId,
            SessionId = sessionId,
            Body = body,
            Query = query,
            Headers = headers ?? new Dictionary<string, string>(),
            AgentId = agentId,
            ToolName = toolName,
            Timestamp = timestamp,
        };

    // ── Tier 1 rule matching ─────────────────────────────────────────────

    [Theory]
    [InlineData("/products", "search=' OR 1=1 --")]
    [InlineData("/products", "id=1; DROP TABLE users")]
    [InlineData("/search", "UNION SELECT password FROM users")]
    public async Task SqlInjection_Blocks(string path, string query)
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: path, query: query));
        Assert.Equal("block", result.Decision);
        Assert.Contains("sql_injection", result.MatchedRules);
        Assert.Equal(1, result.Tier);
    }

    [Fact]
    public async Task CleanRequest_IsAllowed()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: "/products", query: "search=laptop"));
        Assert.Equal("allow", result.Decision);
        Assert.Empty(result.MatchedRules);
        Assert.Equal(0, result.Score);
    }

    [Fact]
    public async Task LiteralPercent_IsNotFalsePositived()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: "/products", query: "discount=50%"));
        Assert.Equal("allow", result.Decision);
    }

    [Fact]
    public async Task Xss_Blocks()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: "/comment", query: "text=<script>alert(1)</script>"));
        Assert.Equal("block", result.Decision);
        Assert.Contains("xss_attempt", result.MatchedRules);
    }

    [Fact]
    public async Task PathTraversal_Blocks()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: "/files/../../etc/passwd"));
        Assert.Equal("block", result.Decision);
        Assert.Contains("path_traversal", result.MatchedRules);
    }

    [Fact]
    public async Task ScannerUserAgent_Blocks()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: "/", userAgent: "sqlmap/1.7"));
        Assert.Equal("block", result.Decision);
        Assert.Contains("scanner_detected", result.MatchedRules);
    }

    [Fact]
    public async Task SensitiveFileAccess_Blocks()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: "/.env"));
        Assert.Equal("block", result.Decision);
        Assert.Contains("sensitive_file_access", result.MatchedRules);
    }

    [Fact]
    public async Task CredentialStuffing_RateLimits()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(method: "POST", path: "/api/login"));
        Assert.Equal("rate_limit", result.Decision);
        Assert.Contains("credential_stuffing_pattern", result.MatchedRules);
    }

    [Fact]
    public async Task AgentUnsanctionedTool_Quarantines()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(agentId: "agent-1", toolName: "shell_exec"));
        Assert.Equal("quarantine", result.Decision);
        Assert.Contains("agent_unsanctioned_tool", result.MatchedRules);
        Assert.True(engine.IsAgentQuarantined("agent-1"));
    }

    // ── Pre-check (already-blocked) short-circuit ───────────────────────

    [Fact]
    public async Task BlockedIp_ShortCircuitsBeforeRules()
    {
        var engine = new InternalClosedLoopEngine();
        engine.BlockIP("203.0.113.5", "manual_block");
        var result = await engine.EvaluateAsync(Req(path: "/anything"));
        Assert.Equal("block", result.Decision);
        Assert.Equal(["ip_blocked:manual_block"], result.MatchedRules);
    }

    [Fact]
    public async Task UnblockIp_AllowsAgain()
    {
        var engine = new InternalClosedLoopEngine();
        engine.BlockIP("203.0.113.5", "test");
        engine.UnblockIP("203.0.113.5");
        var result = await engine.EvaluateAsync(Req(path: "/products"));
        Assert.Equal("allow", result.Decision);
    }

    [Fact]
    public async Task BlockAction_AlsoBlocksSessionAndAgent()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: "/.env", sessionId: "sess-1", agentId: "agent-9"));
        Assert.Equal("block", result.Decision);
        var actionTypes = result.Actions.Select(a => a.Type).ToHashSet();
        Assert.Contains("block_ip", actionTypes);
        Assert.Contains("block_session", actionTypes);
        Assert.Contains("quarantine_agent", actionTypes);
    }

    // ── Rate limiting ─────────────────────────────────────────────────────

    [Fact]
    public async Task RateLimit_TriggersAfterMaxRequests()
    {
        var config = new InternalCLConfig { RateLimitMax = 3, RateLimitWindowMs = 60_000 };
        var engine = new InternalClosedLoopEngine(config);
        for (int i = 0; i < 3; i++)
        {
            var result = await engine.EvaluateAsync(Req(path: "/products", query: "p=1"));
            Assert.Equal("allow", result.Decision);
        }
        var limited = await engine.EvaluateAsync(Req(path: "/products", query: "p=1"));
        Assert.Equal("rate_limit", limited.Decision);
        Assert.Equal(["rate_limit_exceeded"], limited.MatchedRules);
    }

    // ── Tier 2: unimplemented/pass-through by default ───────────────────

    [Fact]
    public async Task Tier2Scorer_UnsetByDefault_SkipsTier2()
    {
        var engine = new InternalClosedLoopEngine();
        var result = await engine.EvaluateAsync(Req(path: "/products", query: "p=1"));
        Assert.Equal("allow", result.Decision);
        Assert.Equal(1, result.Tier); // never reaches tier 2 scoring at all
    }

    [Fact]
    public async Task Tier2Scorer_WhenSupplied_CanBlock()
    {
        var config = new InternalCLConfig { Tier2Scorer = _ => Task.FromResult(90.0) };
        var engine = new InternalClosedLoopEngine(config);
        var result = await engine.EvaluateAsync(Req(path: "/products", query: "p=1"));
        Assert.Equal("block", result.Decision);
        Assert.Equal(2, result.Tier);
        Assert.Equal(["tier2_ml_score"], result.MatchedRules);
    }

    [Fact]
    public async Task Tier2Scorer_CanElevateToRateLimit()
    {
        var config = new InternalCLConfig { Tier2Scorer = async _ => { await Task.Delay(1); return 70.0; } };
        var engine = new InternalClosedLoopEngine(config);
        var result = await engine.EvaluateAsync(Req(path: "/products", query: "p=1"));
        Assert.Equal("rate_limit", result.Decision);
        Assert.Equal(2, result.Tier);
    }

    // ── Tier 3: relay callback (hybrid mode only) ───────────────────────

    [Fact]
    public async Task Relay_NotCalledWhenExternalRelayDisabled()
    {
        var calls = new List<InternalCLResult>();
        var config = new InternalCLConfig { OnRelay = (result, _) => { calls.Add(result); return Task.CompletedTask; } };
        var engine = new InternalClosedLoopEngine(config); // EnableExternalRelay defaults false
        await engine.EvaluateAsync(Req(path: "/.env"));
        Assert.Empty(calls);
    }

    [Fact]
    public async Task Relay_CalledForFlaggedDecisionWhenEnabled()
    {
        var calls = new List<InternalCLResult>();
        var config = new InternalCLConfig
        {
            EnableExternalRelay = true,
            OnRelay = (result, _) => { calls.Add(result); return Task.CompletedTask; },
        };
        var engine = new InternalClosedLoopEngine(config);
        // "/.env" matches both path_traversal (score 90) and sensitive_file_access (score 85) —
        // path_traversal's own (/\.env|/\.git|/\.ssh) sub-pattern overlaps sensitive_file_access.
        // Not a porting bug: reproduced here deliberately, matching Node's own rule set and the
        // Python port's equivalent test.
        await engine.EvaluateAsync(Req(path: "/.env"));
        Assert.Single(calls);
        Assert.Equal(["path_traversal", "sensitive_file_access"], calls[0].MatchedRules);
    }

    [Fact]
    public async Task Relay_NotCalledForAllowedDecision()
    {
        var calls = new List<InternalCLResult>();
        var config = new InternalCLConfig
        {
            EnableExternalRelay = true,
            OnRelay = (result, _) => { calls.Add(result); return Task.CompletedTask; },
        };
        var engine = new InternalClosedLoopEngine(config);
        await engine.EvaluateAsync(Req(path: "/products"));
        Assert.Empty(calls);
    }

    // ── Fail mode ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FailClosed_DoesNotBlockOnPerRuleError()
    {
        var engine = new InternalClosedLoopEngine(new InternalCLConfig { FailMode = "closed" });
        engine.AddRule(new InternalCLRule
        {
            Name = "broken",
            Description = "x",
            Severity = "low",
            Score = 1,
            Decision = "allow",
            Match = _ => throw new InvalidOperationException("boom"),
        });
        // Individual rule errors are swallowed per-rule (matching Node/Python), not escalated
        // to the top-level fail-mode handler — EvaluateAsync must not throw or block.
        var result = await engine.EvaluateAsync(Req(path: "/products"));
        Assert.Equal("allow", result.Decision);
    }

    [Fact]
    public async Task FailClosed_BlocksOnTier2ScorerError()
    {
        var config = new InternalCLConfig
        {
            FailMode = "closed",
            Tier2Scorer = _ => throw new InvalidOperationException("tier2 boom"),
        };
        var engine = new InternalClosedLoopEngine(config);
        var result = await engine.EvaluateAsync(Req(path: "/products", query: "p=1"));
        Assert.Equal("block", result.Decision);
        Assert.Equal(100, result.Score);
        Assert.Equal(["fail_closed_error"], result.MatchedRules);
    }

    [Fact]
    public async Task FailOpen_AllowsOnTier2ScorerError()
    {
        var config = new InternalCLConfig
        {
            FailMode = "open",
            Tier2Scorer = _ => throw new InvalidOperationException("tier2 boom"),
        };
        var engine = new InternalClosedLoopEngine(config);
        var result = await engine.EvaluateAsync(Req(path: "/products", query: "p=1"));
        Assert.Equal("allow", result.Decision);
        Assert.Equal(["fail_open_error"], result.MatchedRules);
    }

    // ── matches_known_attack_pattern (Option B content check) ───────────

    [Fact]
    public void MatchesKnownAttackPattern_DetectsSqli()
    {
        Assert.False(InternalClosedLoopEngine.MatchesKnownAttackPattern("/search", null));
        Assert.True(InternalClosedLoopEngine.MatchesKnownAttackPattern("/search?q=' OR 1=1 --"));
    }

    [Fact]
    public void MatchesKnownAttackPattern_DetectsScanner()
    {
        Assert.True(InternalClosedLoopEngine.MatchesKnownAttackPattern("/", "nikto/2.5"));
    }

    // ── Concurrency ───────────────────────────────────────────────────────

    [Fact]
    public async Task ConcurrentEvaluations_FromDistinctIPs_EachBlockOnlyThatIp()
    {
        var engine = new InternalClosedLoopEngine();
        const int n = 50;

        var tasks = Enumerable.Range(0, n).Select(i => engine.EvaluateAsync(Req(ip: $"10.0.0.{i}", path: "/.env"))).ToArray();
        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.Equal("block", r.Decision));
        for (int i = 0; i < n; i++)
        {
            Assert.True(engine.IsIpBlocked($"10.0.0.{i}"));
        }
        Assert.Equal(n, engine.GetStats().BlockedIPs);
    }

    [Fact]
    public async Task ConcurrentEvaluations_FromSameIp_RateLimiterStateStaysConsistent()
    {
        var config = new InternalCLConfig { RateLimitMax = 20, RateLimitWindowMs = 60_000 };
        var engine = new InternalClosedLoopEngine(config);
        const int n = 100;

        // All 100 concurrent requests share one IP and hit no Tier 1 rule, so every one of them
        // reaches the rate limiter; the point of this test is that the sliding-window counter
        // (a List<long> inside one BoundedMap entry) never corrupts or throws under concurrent
        // mutation, and that at most RateLimitMax requests are ever let through as "allow".
        var tasks = Enumerable.Range(0, n).Select(_ => engine.EvaluateAsync(Req(ip: "198.51.100.9", path: "/products", query: "q=laptop"))).ToArray();
        var results = await Task.WhenAll(tasks);

        int allowed = results.Count(r => r.Decision == "allow");
        int rateLimited = results.Count(r => r.Decision == "rate_limit");
        Assert.Equal(n, allowed + rateLimited);
        Assert.True(allowed <= config.RateLimitMax, $"expected at most {config.RateLimitMax} allowed, got {allowed}");
        Assert.True(rateLimited > 0, "expected at least one request to be rate-limited once the max was exceeded");
    }

    // ── Client wiring: mode selection, ObserveAsync(), IsBlocked() ──────

    [Fact]
    public async Task Client_ExternalMode_ObserveIsNoop()
    {
        using var client = DevFortress.Client.Create("k").Build();
        Assert.Equal("external", client.Mode);
        Assert.Null(client.InternalEngine);
        Assert.Null(await client.ObserveAsync(Req(path: "/.env")));
        Assert.False(client.IsBlocked("203.0.113.5"));
    }

    [Fact]
    public async Task Client_InternalMode_ObserveBlocksAttack()
    {
        using var client = DevFortress.Client.Create("k").Mode("internal").Build();
        Assert.NotNull(client.InternalEngine);
        var result = await client.ObserveAsync(Req(path: "/.env"));
        Assert.NotNull(result);
        Assert.True(result!.Flagged);
        Assert.Equal("block", result.Decision);
        Assert.True(client.IsBlocked("203.0.113.5"));
    }

    [Fact]
    public async Task Client_InternalMode_ObserveAllowsCleanRequest()
    {
        using var client = DevFortress.Client.Create("k").Mode("internal").Build();
        var result = await client.ObserveAsync(Req(path: "/products", query: "q=laptop"));
        Assert.Null(result);
    }

    [Fact]
    public async Task Client_HybridMode_BlocksViaInternalFirst()
    {
        using var client = DevFortress.Client.Create("k").Mode("hybrid").Build();
        Assert.NotNull(client.CircuitBreaker);
        var result = await client.ObserveAsync(Req(path: "/.env"));
        Assert.NotNull(result);
        Assert.True(result!.Flagged);
    }

    [Fact]
    public async Task Client_HybridMode_AllowsCleanRequestAndKeepsCircuitClosed()
    {
        using var client = DevFortress.Client.Create("k").Mode("hybrid").Build();
        var result = await client.ObserveAsync(Req(path: "/products", query: "q=laptop"));
        Assert.Null(result);
        Assert.Equal(CircuitState.Closed, client.CircuitBreaker!.State);
    }
}
