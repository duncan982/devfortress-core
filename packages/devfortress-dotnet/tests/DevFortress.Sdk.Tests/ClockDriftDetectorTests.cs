using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// ClockDriftDetector (Invention A18, TODO 419/422): server-authoritative
/// clock drift detection, ported from
/// <c>packages/devfortress-sdk/src/security-extensions.ts</c>.
/// </summary>
public class ClockDriftDetectorTests
{
    private static double NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    [Fact]
    public void WithinAcceptableThresholdIsAllowed()
    {
        var detector = new ClockDriftDetector();
        var result = detector.Check(NowMs());
        Assert.True(result.Valid);
        Assert.Equal(ClockDriftSeverity.Low, result.Severity);
        Assert.Equal(ClockDriftAction.Allow, result.Action);
    }

    [Fact]
    public void SuspiciousDriftWarnsButStaysValid()
    {
        var detector = new ClockDriftDetector();
        var result = detector.Check(NowMs() - 60_000);
        Assert.True(result.Valid);
        Assert.Equal(ClockDriftSeverity.Medium, result.Severity);
        Assert.Equal(ClockDriftAction.Warn, result.Action);
    }

    [Fact]
    public void HighDriftEnforcesServerTime()
    {
        var detector = new ClockDriftDetector();
        var result = detector.Check(NowMs() - 200_000);
        Assert.True(result.Valid);
        Assert.Equal(ClockDriftSeverity.High, result.Severity);
        Assert.Equal(ClockDriftAction.UseServerTime, result.Action);
    }

    [Fact]
    public void CriticalDriftIsRejected()
    {
        var detector = new ClockDriftDetector();
        var result = detector.Check(NowMs() - 600_000);
        Assert.False(result.Valid);
        Assert.Equal(ClockDriftSeverity.Critical, result.Severity);
        Assert.Equal(ClockDriftAction.Reject, result.Action);
    }

    [Fact]
    public void AheadOfServerTimeIsAlsoDetected()
    {
        var detector = new ClockDriftDetector();
        var result = detector.Check(NowMs() + 600_000);
        Assert.False(result.Valid);
        Assert.Contains("ahead", result.Reason);
    }

    [Fact]
    public void CustomThresholdsAreRespected()
    {
        var detector = new ClockDriftDetector(1_000, 5_000, 10_000);
        Assert.Equal(ClockDriftAction.Warn, detector.Check(NowMs() - 2_000).Action);
        Assert.Equal(ClockDriftAction.Reject, detector.Check(NowMs() - 20_000).Action);
    }

    [Fact]
    public void DriftTrendRequiresAtLeastThreeSamples()
    {
        var detector = new ClockDriftDetector();
        detector.Check(NowMs() - 1_000, "c1");
        detector.Check(NowMs() - 2_000, "c1");
        Assert.Null(detector.GetDriftTrend("c1"));

        detector.Check(NowMs() - 3_000, "c1");
        var trend = detector.GetDriftTrend("c1");
        Assert.NotNull(trend);
        Assert.True(trend!.AvgDrift > 0);
    }

    [Fact]
    public void DriftTrendDetectsIncreasingDrift()
    {
        var detector = new ClockDriftDetector();
        foreach (double driftMs in new double[] { 1_000, 1_000, 1_000, 5_000, 5_000, 5_000 })
        {
            detector.Check(NowMs() - driftMs, "growing");
        }
        var trend = detector.GetDriftTrend("growing");
        Assert.NotNull(trend);
        Assert.True(trend!.Increasing);
    }

    [Fact]
    public void GetStatsCountsTrackedClients()
    {
        var detector = new ClockDriftDetector();
        detector.Check(NowMs(), "a");
        detector.Check(NowMs(), "b");
        detector.Check(NowMs()); // no clientId — not tracked
        Assert.Equal(2, detector.GetStats());
    }
}
