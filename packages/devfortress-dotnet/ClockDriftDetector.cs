namespace DevFortress;

/// <summary>Severity band of a <see cref="ClockDriftResult"/>.</summary>
public enum ClockDriftSeverity { Low, Medium, High, Critical }

/// <summary>Recommended action from a <see cref="ClockDriftResult"/>.</summary>
public enum ClockDriftAction { Allow, Warn, UseServerTime, Reject }

/// <summary>The outcome of one <see cref="ClockDriftDetector.Check"/> call.</summary>
public sealed record ClockDriftResult(
    bool Valid,
    double DriftMs,
    ClockDriftSeverity Severity,
    ClockDriftAction Action,
    string Reason);

/// <summary>The drift trend for a client, from <see cref="ClockDriftDetector.GetDriftTrend"/>.</summary>
public sealed record ClockDriftTrend(double AvgDrift, bool Increasing);

/// <summary>
/// DevFortress SDK — Clock Drift Anomaly Detector (Invention A18). Mirrors
/// the Node SDK's <c>security-extensions.ts</c> <c>ClockDriftDetector</c>.
///
/// TODO 419/422 — one of the 20 Node-only claims identified by the
/// 2026-11-02 patent audit; ported to Python and Go in that session, here
/// extended to .NET.
///
/// Compares a client-supplied timestamp against server time and
/// classifies the drift into an escalating action: allow, warn (audit
/// with server time), use-server-time (enforce server-authoritative
/// timestamps), or reject (possible timestamp manipulation).
///
/// Thread-safe.
/// </summary>
public sealed class ClockDriftDetector
{
    private const int MaxHistoryPerClient = 100;

    private readonly double _acceptableThresholdMs;
    private readonly double _suspiciousThresholdMs;
    private readonly double _criticalThresholdMs;

    private readonly object _lock = new();
    private readonly Dictionary<string, List<double>> _driftHistory = new();

    public ClockDriftDetector(
        double acceptableThresholdMs = 30_000,
        double suspiciousThresholdMs = 120_000,
        double criticalThresholdMs = 300_000)
    {
        _acceptableThresholdMs = acceptableThresholdMs;
        _suspiciousThresholdMs = suspiciousThresholdMs;
        _criticalThresholdMs = criticalThresholdMs;
    }

    /// <summary>
    /// Checks a client timestamp (epoch milliseconds) against server
    /// time. <paramref name="clientId"/> may be null — drift is not
    /// tracked for an anonymous caller.
    /// </summary>
    public ClockDriftResult Check(double clientTimestampMs, string? clientId = null)
    {
        double serverTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        double driftMs = Math.Abs(clientTimestampMs - serverTimeMs);
        string direction = clientTimestampMs > serverTimeMs ? "ahead" : "behind";

        if (clientId is not null)
        {
            lock (_lock)
            {
                if (!_driftHistory.TryGetValue(clientId, out var history))
                {
                    history = new List<double>();
                    _driftHistory[clientId] = history;
                }
                history.Add(driftMs);
                while (history.Count > MaxHistoryPerClient)
                {
                    history.RemoveAt(0);
                }
            }
        }

        if (driftMs <= _acceptableThresholdMs)
        {
            return new ClockDriftResult(true, driftMs, ClockDriftSeverity.Low, ClockDriftAction.Allow,
                $"Clock drift {driftMs:F0}ms ({direction}) within acceptable range");
        }
        if (driftMs <= _suspiciousThresholdMs)
        {
            return new ClockDriftResult(true, driftMs, ClockDriftSeverity.Medium, ClockDriftAction.Warn,
                $"Clock drift {driftMs:F0}ms ({direction}) — suspicious, using server time for audit");
        }
        if (driftMs <= _criticalThresholdMs)
        {
            return new ClockDriftResult(true, driftMs, ClockDriftSeverity.High, ClockDriftAction.UseServerTime,
                $"Clock drift {driftMs:F0}ms ({direction}) — enforcing server-authoritative timestamps");
        }
        return new ClockDriftResult(false, driftMs, ClockDriftSeverity.Critical, ClockDriftAction.Reject,
            $"Clock drift {driftMs:F0}ms ({direction}) exceeds critical threshold — possible timestamp manipulation");
    }

    /// <summary>Returns the drift trend for a client, or null if fewer than 3 samples.</summary>
    public ClockDriftTrend? GetDriftTrend(string clientId)
    {
        List<double> history;
        lock (_lock)
        {
            if (!_driftHistory.TryGetValue(clientId, out var tracked))
            {
                return null;
            }
            history = new List<double>(tracked);
        }
        if (history.Count < 3)
        {
            return null;
        }

        double avgDrift = history.Average();
        var recent = history.GetRange(history.Count - 3, 3);
        double recentAvg = recent.Average();

        return new ClockDriftTrend(avgDrift, recentAvg > avgDrift * 1.2);
    }

    /// <summary>Returns the number of clients with tracked drift history.</summary>
    public int GetStats()
    {
        lock (_lock)
        {
            return _driftHistory.Count;
        }
    }
}
