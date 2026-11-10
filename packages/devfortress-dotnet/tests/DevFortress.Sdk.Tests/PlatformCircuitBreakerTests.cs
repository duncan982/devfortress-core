using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// PlatformCircuitBreaker (TODO 372), ported from
/// <c>packages/devfortress-sdk/src/circuit-breaker.ts</c>.
/// </summary>
public class PlatformCircuitBreakerTests
{
    private static void SetStaleSince(PlatformCircuitBreaker breaker, DateTime value)
    {
        var field = typeof(PlatformCircuitBreaker).GetField("_staleSince",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        field.SetValue(breaker, value);
    }

    [Fact]
    public void InitialState_IsClosedAndAllowsExternalCalls()
    {
        var breaker = new PlatformCircuitBreaker();
        Assert.Equal(CircuitState.Closed, breaker.State);
        Assert.True(breaker.ShouldCallExternal());
    }

    [Fact]
    public void RecordFailure_AtThreshold_OpensCircuit()
    {
        var transitions = new List<string>();
        var breaker = new PlatformCircuitBreaker(failureThreshold: 3,
            onStateChange: (from, to, _) => transitions.Add($"{from}->{to}"));

        breaker.RecordFailure();
        breaker.RecordFailure();
        Assert.Equal(CircuitState.Closed, breaker.State);

        breaker.RecordFailure();
        Assert.Equal(CircuitState.Open, breaker.State);
        Assert.Equal(new[] { "Closed->Open" }, transitions);
        Assert.False(breaker.ShouldCallExternal());
    }

    [Fact]
    public async Task ShouldCallExternal_AfterRecoveryTime_TransitionsToHalfOpen()
    {
        var breaker = new PlatformCircuitBreaker(failureThreshold: 1, recoveryTime: TimeSpan.FromMilliseconds(10));
        breaker.RecordFailure();
        await Task.Delay(20);

        Assert.True(breaker.ShouldCallExternal());
        Assert.Equal(CircuitState.HalfOpen, breaker.State);
    }

    [Fact]
    public async Task RecordSuccess_WhileHalfOpen_ClosesCircuit()
    {
        var breaker = new PlatformCircuitBreaker(failureThreshold: 1, recoveryTime: TimeSpan.FromMilliseconds(10));
        breaker.RecordFailure();
        await Task.Delay(20);
        breaker.ShouldCallExternal();

        breaker.RecordSuccess();
        Assert.Equal(CircuitState.Closed, breaker.State);
    }

    [Fact]
    public async Task RecordFailure_WhileHalfOpen_ReopensCircuit()
    {
        var breaker = new PlatformCircuitBreaker(failureThreshold: 1, recoveryTime: TimeSpan.FromMilliseconds(10));
        breaker.RecordFailure();
        await Task.Delay(20);
        breaker.ShouldCallExternal();

        breaker.RecordFailure();
        Assert.Equal(CircuitState.Open, breaker.State);
    }

    [Fact]
    public void Reset_ForcesClosedAndClearsFailures()
    {
        var breaker = new PlatformCircuitBreaker(failureThreshold: 1);
        breaker.RecordFailure();
        Assert.Equal(CircuitState.Open, breaker.State);

        breaker.Reset();
        Assert.Equal(CircuitState.Closed, breaker.State);
        Assert.Equal(0, breaker.GetDiagnostics().FailureCount);
    }

    [Fact]
    public void IsRulesStale_PastThreshold_ReturnsTrue()
    {
        var breaker = new PlatformCircuitBreaker(failureThreshold: 1);
        breaker.RecordFailure();

        SetStaleSince(breaker, DateTime.UtcNow - PlatformCircuitBreaker.StaleThreshold - TimeSpan.FromSeconds(1));

        Assert.True(breaker.IsRulesStale());
        Assert.True(breaker.GetDiagnostics().RulesStale);
    }

    [Fact]
    public async Task RecordSuccess_ResetsStaleTracking()
    {
        var breaker = new PlatformCircuitBreaker(failureThreshold: 1, recoveryTime: TimeSpan.FromMilliseconds(10));
        breaker.RecordFailure();
        await Task.Delay(20);
        breaker.ShouldCallExternal();
        breaker.RecordSuccess();

        Assert.False(breaker.IsRulesStale());
    }
}
