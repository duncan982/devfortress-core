namespace DevFortress;

/// <summary>
/// Which graduated response stage a <see cref="GraduatedRateLimiter.Check"/> call triggered.
/// </summary>
public enum RateLimitStage { Observation, Warning, SoftLimit, HardBlock, Revocation }

/// <summary>The outcome of one <see cref="GraduatedRateLimiter.Check"/> call.</summary>
public sealed record RateLimitResult(
    RateLimitStage Stage,
    int CurrentRate,
    int Limit,
    double Ratio,
    long InjectedLatencyMs,
    bool Blocked,
    bool Revoke,
    long CooldownSeconds,
    int Remaining,
    bool BurstDetected);

/// <summary>Configuration for a <see cref="GraduatedRateLimiter"/>.</summary>
public sealed class GraduatedRateLimiterConfig
{
    /// <summary>Default rate limit (requests per window). Default: 100.</summary>
    public int DefaultLimit { get; init; } = 100;
    /// <summary>Sliding window size. Default: 1 minute.</summary>
    public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(1);
    /// <summary>Base latency for soft-limit injection. Default: 2s.</summary>
    public TimeSpan SoftLimitBaseLatency { get; init; } = TimeSpan.FromSeconds(2);
    /// <summary>Maximum number of tracked aliases. Default: 50,000.</summary>
    public int MaxEntries { get; init; } = 50_000;
    /// <summary>Per-endpoint rate limits: endpoint path pattern -> max requests/window.</summary>
    public Dictionary<string, int> EndpointLimits { get; init; } = new();
    /// <summary>Max requests per 1-second micro-window. Default: 20.</summary>
    public int BurstLimit { get; init; } = 20;
    /// <summary>Initial cooldown duration. Default: 60s.</summary>
    public long InitialCooldownSeconds { get; init; } = 60;
    /// <summary>Max consecutive hard-blocks before revocation. Default: 3.</summary>
    public int MaxConsecutiveBlocks { get; init; } = 3;
}

/// <summary>
/// DevFortress SDK — Graduated Rate Limiter (Invention A3). Mirrors
/// <c>packages/devfortress-sdk/src/graduated-rate-limiter.ts</c>.
///
/// <para>Implements alias-scoped graduated rate limiting with multi-stage
/// response escalation. Addresses GAP-A3-1 through GAP-A3-4:</para>
/// <list type="bullet">
///   <item>GAP-A3-1: Latency jitter (+/-20%) in soft-limit injection</item>
///   <item>GAP-A3-2: Per-endpoint hierarchical rate limits (configurable)</item>
///   <item>GAP-A3-3: Burst detection (1-second micro-window)</item>
///   <item>GAP-A3-4: Escalating cooldowns (60s-&gt;120s-&gt;240s, revoke after 3)</item>
/// </list>
///
/// <para>Four-stage graduated response: Observation (&lt;50%), Warning
/// (50-75%), SoftLimit (75-100%, latency injection), HardBlock (&gt;=100%,
/// escalating cooldown), Revocation (&gt;=120% or 3 consecutive blocks).</para>
///
/// <para>Thread-safe.</para>
/// </summary>
public sealed class GraduatedRateLimiter : IDisposable
{
    private sealed class Entry
    {
        public List<DateTime> Timestamps = new();
        public DateTime CooldownUntil = DateTime.MinValue;
        public int ConsecutiveBlocks;
        public bool Revoked;
        public List<DateTime> BurstTimestamps = new();
    }

    private readonly object _lock = new();
    private readonly Dictionary<string, Entry> _entries = new();
    // Insertion order, for oldest-first eviction mirroring Node's Map iteration order.
    private readonly List<string> _order = new();

    private readonly int _defaultLimit;
    private readonly TimeSpan _window;
    private readonly TimeSpan _softLimitBaseLatency;
    private readonly int _maxEntries;
    private readonly Dictionary<string, int> _endpointLimits;
    private readonly int _burstLimit;
    private readonly long _initialCooldownSeconds;
    private readonly int _maxConsecutiveBlocks;
    private readonly Random _random = new();
    private readonly Timer _cleanupTimer;

    public GraduatedRateLimiter(GraduatedRateLimiterConfig? config = null)
    {
        config ??= new GraduatedRateLimiterConfig();
        _defaultLimit = config.DefaultLimit;
        _window = config.Window;
        _softLimitBaseLatency = config.SoftLimitBaseLatency;
        _maxEntries = config.MaxEntries;
        _endpointLimits = new Dictionary<string, int>(config.EndpointLimits);
        _burstLimit = config.BurstLimit;
        _initialCooldownSeconds = config.InitialCooldownSeconds;
        _maxConsecutiveBlocks = config.MaxConsecutiveBlocks;

        _cleanupTimer = new Timer(_ => Cleanup(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// Checks the rate limit for an alias (identified by <paramref name="key"/>,
    /// typically an IP or session ID). Records the request and returns the
    /// graduated response. <paramref name="endpoint"/> is optional and enables
    /// per-endpoint limits (GAP-A3-2).
    /// </summary>
    public RateLimitResult Check(string key, string? endpoint = null)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var existed = _entries.TryGetValue(key, out var entry);
            entry ??= new Entry();

            if (entry.Revoked)
            {
                return new RateLimitResult(RateLimitStage.Revocation, 0, 0, double.PositiveInfinity,
                    0, true, false, 0, 0, false);
            }

            if (entry.CooldownUntil > now)
            {
                var cooldownRemaining = (long)Math.Ceiling((entry.CooldownUntil - now).TotalSeconds);
                return new RateLimitResult(RateLimitStage.HardBlock, entry.Timestamps.Count,
                    EffectiveLimit(endpoint), 1.0, 0, true, false, cooldownRemaining, 0, false);
            }

            var windowStart = now - _window;
            entry.Timestamps.RemoveAll(t => t <= windowStart);

            // GAP-A3-3: clean burst micro-window (1 second).
            var burstWindowStart = now - TimeSpan.FromSeconds(1);
            entry.BurstTimestamps.RemoveAll(t => t <= burstWindowStart);

            entry.Timestamps.Add(now);
            entry.BurstTimestamps.Add(now);

            if (!existed && _entries.Count >= _maxEntries)
            {
                EvictOldest();
            }
            if (!existed)
            {
                _order.Add(key);
            }
            _entries[key] = entry;

            var limit = EffectiveLimit(endpoint);
            var currentRate = entry.Timestamps.Count;
            var ratio = (double)currentRate / limit;

            // GAP-A3-3: burst detection.
            var burstDetected = entry.BurstTimestamps.Count > _burstLimit;

            if (ratio >= 1.2 || entry.ConsecutiveBlocks >= _maxConsecutiveBlocks)
            {
                entry.Revoked = true;
                return new RateLimitResult(RateLimitStage.Revocation, currentRate, limit, ratio, 0,
                    true, true, 0, 0, burstDetected);
            }

            if (ratio >= 1.0 || burstDetected)
            {
                entry.ConsecutiveBlocks++;
                var cooldownMultiplier = 1L << (entry.ConsecutiveBlocks - 1);
                var cooldownSeconds = _initialCooldownSeconds * cooldownMultiplier;
                entry.CooldownUntil = now + TimeSpan.FromSeconds(cooldownSeconds);

                return new RateLimitResult(RateLimitStage.HardBlock, currentRate, limit, ratio, 0,
                    true, false, cooldownSeconds, 0, burstDetected);
            }

            if (ratio >= 0.75)
            {
                entry.ConsecutiveBlocks = 0;

                var progress = (ratio - 0.75) / 0.25;
                var baseLatency = _softLimitBaseLatency.TotalMilliseconds * Math.Pow(progress, 2);
                // GAP-A3-1: add +/-20% random jitter.
                var jitter = 0.8 + 0.4 * _random.NextDouble();
                var injectedLatencyMs = (long)Math.Round(baseLatency * jitter);

                return new RateLimitResult(RateLimitStage.SoftLimit, currentRate, limit, ratio,
                    injectedLatencyMs, false, false, 0, Math.Max(0, limit - currentRate), burstDetected);
            }

            if (ratio >= 0.5)
            {
                entry.ConsecutiveBlocks = 0;
                return new RateLimitResult(RateLimitStage.Warning, currentRate, limit, ratio, 0,
                    false, false, 0, Math.Max(0, limit - currentRate), false);
            }

            entry.ConsecutiveBlocks = 0;
            return new RateLimitResult(RateLimitStage.Observation, currentRate, limit, ratio, 0,
                false, false, 0, Math.Max(0, limit - currentRate), false);
        }
    }

    /// <summary>Manually revokes an alias (e.g. from an external security decision).</summary>
    public void RevokeAlias(string key)
    {
        lock (_lock)
        {
            if (!_entries.TryGetValue(key, out var entry))
            {
                entry = new Entry { Revoked = true };
                _order.Add(key);
            }
            else
            {
                entry.Revoked = true;
            }
            _entries[key] = entry;
        }
    }

    /// <summary>Resets an alias's rate limit state (e.g. after an admin override).</summary>
    public void ResetAlias(string key)
    {
        lock (_lock)
        {
            _entries.Remove(key);
        }
    }

    /// <summary>Returns whether an alias has been revoked.</summary>
    public bool IsRevoked(string key)
    {
        lock (_lock)
        {
            return _entries.TryGetValue(key, out var entry) && entry.Revoked;
        }
    }

    /// <summary>Sets per-endpoint rate limits (merged into any existing endpoint limits). GAP-A3-2.</summary>
    public void SetEndpointLimits(Dictionary<string, int> limits)
    {
        lock (_lock)
        {
            foreach (var (pattern, limit) in limits)
            {
                _endpointLimits[pattern] = limit;
            }
        }
    }

    /// <summary>The current number of tracked aliases.</summary>
    public int Size
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }

    private int EffectiveLimit(string? endpoint)
    {
        if (endpoint is null || _endpointLimits.Count == 0)
        {
            return _defaultLimit;
        }

        if (_endpointLimits.TryGetValue(endpoint, out var exact))
        {
            return exact;
        }

        foreach (var (pattern, limit) in _endpointLimits)
        {
            if (pattern.EndsWith('*') && endpoint.StartsWith(pattern[..^1]))
            {
                return limit;
            }
        }

        return _defaultLimit;
    }

    private void EvictOldest()
    {
        while (_order.Count > 0)
        {
            var oldest = _order[0];
            _order.RemoveAt(0);
            if (_entries.Remove(oldest))
            {
                return;
            }
        }
    }

    private void Cleanup()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var windowStart = now - _window;

            foreach (var key in _entries.Keys.ToList())
            {
                var entry = _entries[key];
                var hasRecentActivity = entry.Timestamps.Any(t => t > windowStart);
                var inCooldown = entry.CooldownUntil > now;

                if (!hasRecentActivity && !inCooldown && !entry.Revoked)
                {
                    _entries.Remove(key);
                }
            }
        }
    }

    /// <summary>Stops the limiter's cleanup timer and clears its state.</summary>
    public void Dispose()
    {
        _cleanupTimer.Dispose();
        lock (_lock)
        {
            _entries.Clear();
            _order.Clear();
        }
    }
}
