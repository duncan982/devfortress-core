using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// GraduatedRateLimiter (Invention A3, TODO 373), ported from
/// <c>packages/devfortress-sdk/src/graduated-rate-limiter.ts</c>.
/// </summary>
public class GraduatedRateLimiterTests
{
    // Uses the non-generic System.Collections.IDictionary interface rather
    // than `dynamic`: the element type (the private nested Entry class) is
    // not accessible from this test's call site, and the C# dynamic
    // binder enforces accessibility even for reflection-obtained values,
    // so `dynamic` indexing on it fails at runtime ("Cannot apply
    // indexing with [] to an expression of type 'object'"). IDictionary's
    // non-generic, object-typed members sidestep that entirely.
    private static System.Reflection.FieldInfo EntriesField() =>
        typeof(GraduatedRateLimiter).GetField("_entries", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;

    private static System.Collections.IDictionary GetEntries(GraduatedRateLimiter limiter) =>
        (System.Collections.IDictionary)EntriesField().GetValue(limiter)!;

    private static void ForceCooldownElapsed(GraduatedRateLimiter limiter, string key)
    {
        var entry = GetEntries(limiter)[key]!;
        var cooldownField = entry.GetType().GetField("CooldownUntil")!;
        cooldownField.SetValue(entry, DateTime.UtcNow.AddMilliseconds(-10));
    }

    private static void ClearTimestamps(GraduatedRateLimiter limiter, string key)
    {
        var entry = GetEntries(limiter)[key]!;
        var timestampsField = entry.GetType().GetField("Timestamps")!;
        ((List<DateTime>)timestampsField.GetValue(entry)!).Clear();
    }

    [Fact]
    public void Check_BelowHalfLimit_ReturnsObservation()
    {
        using var limiter = new GraduatedRateLimiter();
        var result = limiter.Check("alias-1");
        Assert.Equal(RateLimitStage.Observation, result.Stage);
        Assert.False(result.Blocked);
    }

    [Fact]
    public void Check_AtHalfLimit_ReturnsWarning()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig { DefaultLimit = 10 });
        RateLimitResult? result = null;
        for (var i = 0; i < 5; i++)
        {
            result = limiter.Check("alias-1");
        }
        Assert.Equal(RateLimitStage.Warning, result!.Stage);
        Assert.False(result.Blocked);
    }

    [Fact]
    public void Check_AtSoftLimit_InjectsLatencyWithJitter()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig
        {
            DefaultLimit = 10,
            SoftLimitBaseLatency = TimeSpan.FromSeconds(2),
        });
        RateLimitResult? result = null;
        for (var i = 0; i < 8; i++)
        {
            result = limiter.Check("alias-1");
        }
        Assert.Equal(RateLimitStage.SoftLimit, result!.Stage);
        Assert.False(result.Blocked);
        Assert.True(result.InjectedLatencyMs > 0);
    }

    [Fact]
    public void Check_AtLimit_ReturnsHardBlock()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig { DefaultLimit = 5 });
        RateLimitResult? result = null;
        for (var i = 0; i < 5; i++)
        {
            result = limiter.Check("alias-1");
        }
        Assert.Equal(RateLimitStage.HardBlock, result!.Stage);
        Assert.True(result.Blocked);
        Assert.Equal(60, result.CooldownSeconds);
    }

    [Fact]
    public void Check_ConsecutiveBlocks_DoublesCooldownEachTime()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig
        {
            DefaultLimit = 1,
            InitialCooldownSeconds = 60,
        });

        var first = limiter.Check("alias-1");
        Assert.Equal(RateLimitStage.HardBlock, first.Stage);
        Assert.Equal(60, first.CooldownSeconds);

        ForceCooldownElapsed(limiter, "alias-1");
        ClearTimestamps(limiter, "alias-1");

        var second = limiter.Check("alias-1");
        Assert.Equal(RateLimitStage.HardBlock, second.Stage);
        Assert.Equal(120, second.CooldownSeconds);
    }

    [Fact]
    public void Check_MaxConsecutiveBlocksReached_Revokes()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig
        {
            DefaultLimit = 1,
            MaxConsecutiveBlocks = 3,
        });

        for (var i = 0; i < 3; i++)
        {
            limiter.Check("alias-1");
            ForceCooldownElapsed(limiter, "alias-1");
        }

        var result = limiter.Check("alias-1");
        Assert.Equal(RateLimitStage.Revocation, result.Stage);
        Assert.True(limiter.IsRevoked("alias-1"));
    }

    [Fact]
    public void Check_RevokedAlias_StaysBlockedWithoutReRevoking()
    {
        using var limiter = new GraduatedRateLimiter();
        limiter.RevokeAlias("alias-1");
        var result = limiter.Check("alias-1");
        Assert.Equal(RateLimitStage.Revocation, result.Stage);
        Assert.False(result.Revoke);
    }

    [Fact]
    public void ResetAlias_ClearsEscalation()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig { DefaultLimit = 1 });

        limiter.Check("alias-1");
        ForceCooldownElapsed(limiter, "alias-1");
        ClearTimestamps(limiter, "alias-1");
        var escalated = limiter.Check("alias-1");
        Assert.Equal(120, escalated.CooldownSeconds);

        limiter.ResetAlias("alias-1");

        var result = limiter.Check("alias-1");
        Assert.Equal(60, result.CooldownSeconds);
    }

    [Fact]
    public void Check_PerEndpointLimit_OverridesDefault()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig
        {
            DefaultLimit = 100,
            EndpointLimits = new Dictionary<string, int> { ["/api/auth/*"] = 2 },
        });
        limiter.Check("alias-1", "/api/auth/login");
        var result = limiter.Check("alias-1", "/api/auth/login");
        Assert.Equal(2, result.Limit);
        Assert.Equal(RateLimitStage.HardBlock, result.Stage);
    }

    [Fact]
    public void Check_BurstWithinMicroWindow_TriggersHardBlock()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig
        {
            DefaultLimit = 1000,
            BurstLimit = 3,
        });
        RateLimitResult? result = null;
        for (var i = 0; i < 4; i++)
        {
            result = limiter.Check("alias-1");
        }
        Assert.True(result!.BurstDetected);
        Assert.Equal(RateLimitStage.HardBlock, result.Stage);
    }

    [Fact]
    public void Check_MaxEntriesReached_EvictsOldestAlias()
    {
        using var limiter = new GraduatedRateLimiter(new GraduatedRateLimiterConfig
        {
            DefaultLimit = 100,
            MaxEntries = 2,
        });
        limiter.Check("alias-1");
        limiter.Check("alias-2");
        limiter.Check("alias-3");

        Assert.Equal(2, limiter.Size);
        Assert.False(GetEntries(limiter).Contains("alias-1"));
    }
}
