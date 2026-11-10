using System.Globalization;
using System.Text;
using System.Text.Json;

namespace DevFortress;

/// <summary>
/// Telemetry Heartbeat (CV-M2). Mirrors <c>packages/devfortress-sdk/src/telemetry.ts</c>. Sends
/// anonymised usage telemetry to the platform every 5 minutes by default. No PII is
/// transmitted — only aggregate counts and operational metadata. If the heartbeat stops, the
/// platform dashboard shows "SDK offline — upgrade to Hybrid for guaranteed visibility."
/// </summary>
public sealed record TelemetrySnapshot(
    long EventCount,
    long BlockCount,
    long RateLimitCount,
    string ClMode,
    string Tier,
    string SdkVersion,
    bool ModelExpired,
    bool LicenseDegraded,
    string IntegrityHash,
    long UptimeSeconds,
    double P99LatencyMs);

/// <summary>
/// Caller-supplied enrichment for the next heartbeat snapshot — mirrors Node's
/// <c>Partial&lt;TelemetrySnapshot&gt;</c> provider callback. Any field left <c>null</c> falls
/// back to the default ("external"/"starter"/<see cref="TelemetryManager"/>'s own SDK version).
/// </summary>
public sealed record TelemetrySnapshotOverrides(
    string? ClMode = null,
    string? Tier = null,
    string? SdkVersion = null,
    bool? ModelExpired = null,
    bool? LicenseDegraded = null,
    string? IntegrityHash = null);

/// <summary>Lightweight diagnostics view returned by <see cref="TelemetryManager.GetState"/>.</summary>
public readonly record struct TelemetryCounters(long EventCount, long BlockCount, long RateLimitCount, long UptimeSeconds);

public sealed class TelemetryManager : IDisposable
{
    public const long DefaultHeartbeatIntervalMs = 5 * 60 * 1000; // 5 minutes
    private static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan InitialHeartbeatDelay = TimeSpan.FromSeconds(5);
    private const int MaxLatencySamples = 100;

    private readonly string _apiKey;
    private readonly string _endpoint;
    private readonly long _heartbeatIntervalMs;
    private readonly bool _debug;
    private readonly Signer _signer;
    private readonly ITransport _transport;
    private readonly bool _ownsTransport;
    private readonly IDevFortressLogger? _logger;

    private readonly object _lock = new();
    private long _eventCount;
    private long _blockCount;
    private long _rateLimitCount;
    private readonly List<double> _latencies = [];

    private long _startedAtMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    private Timer? _heartbeatTimer;
    private Func<TelemetrySnapshotOverrides>? _snapshotProvider;
    private int _disposed;

    public TelemetryManager(string apiKey, string endpoint, long? heartbeatIntervalMs = null, bool debug = false,
        ITransport? transport = null, IDevFortressLogger? logger = null)
    {
        if (string.IsNullOrEmpty(apiKey))
        {
            throw new ArgumentException("devfortress: an API key is required", nameof(apiKey));
        }
        _apiKey = apiKey;
        _endpoint = endpoint;
        _heartbeatIntervalMs = heartbeatIntervalMs ?? DefaultHeartbeatIntervalMs;
        _debug = debug;
        _signer = new Signer(apiKey);
        _transport = transport ?? new HttpTransport();
        _ownsTransport = transport is null;
        _logger = logger;
    }

    /// <summary>
    /// Starts sending periodic heartbeats. Safe to call more than once (a second call is a
    /// no-op). <paramref name="snapshotProvider"/> optionally enriches each heartbeat with live
    /// state (closed-loop mode, tier, etc).
    /// </summary>
    public void Start(Func<TelemetrySnapshotOverrides>? snapshotProvider = null)
    {
        if (_heartbeatTimer is not null) return; // Already started

        _snapshotProvider = snapshotProvider;
        _startedAtMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Send the first heartbeat after a short delay (don't block init), then on the
        // configured interval.
        _heartbeatTimer = new Timer(_ => FireAndForgetHeartbeat(), null, InitialHeartbeatDelay,
            TimeSpan.FromMilliseconds(_heartbeatIntervalMs));

        Log("info", $"Telemetry heartbeat started (interval: {_heartbeatIntervalMs / 1000}s)");
    }

    private void FireAndForgetHeartbeat()
    {
        _ = Task.Run(() => SendHeartbeatAsync());
    }

    /// <summary>Records an observed event.</summary>
    public void RecordEvent()
    {
        lock (_lock) { _eventCount++; }
    }

    /// <summary>Records a blocked event.</summary>
    public void RecordBlock()
    {
        lock (_lock) { _blockCount++; }
    }

    /// <summary>Records a rate-limited event.</summary>
    public void RecordRateLimit()
    {
        lock (_lock) { _rateLimitCount++; }
    }

    /// <summary>Records observe latency for p99 calculation (reservoir-sampled).</summary>
    public void RecordLatency(double ms)
    {
        lock (_lock)
        {
            if (_latencies.Count >= MaxLatencySamples)
            {
                // Reservoir sampling: replace a random element.
                int idx = Random.Shared.Next(_latencies.Count);
                _latencies[idx] = ms;
            }
            else
            {
                _latencies.Add(ms);
            }
        }
    }

    /// <summary>Sends one heartbeat to the platform. Fire-and-forget — failures are silently logged.</summary>
    public async Task SendHeartbeatAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var overrides = _snapshotProvider?.Invoke() ?? new TelemetrySnapshotOverrides();

            TelemetrySnapshot snapshot;
            lock (_lock)
            {
                snapshot = new TelemetrySnapshot(
                    EventCount: _eventCount,
                    BlockCount: _blockCount,
                    RateLimitCount: _rateLimitCount,
                    ClMode: overrides.ClMode ?? "external",
                    Tier: overrides.Tier ?? "starter",
                    SdkVersion: overrides.SdkVersion ?? Client.Version,
                    ModelExpired: overrides.ModelExpired ?? false,
                    LicenseDegraded: overrides.LicenseDegraded ?? false,
                    IntegrityHash: overrides.IntegrityHash ?? "",
                    UptimeSeconds: (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - _startedAtMs) / 1000,
                    P99LatencyMs: ComputeP99());
            }

            string url = $"{_endpoint}/api/sdk/heartbeat";
            string requestTarget = Signer.RequestTargetFromUrl(url);
            var bodyObj = new Dictionary<string, object?>
            {
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["eventCount"] = snapshot.EventCount,
                ["blockCount"] = snapshot.BlockCount,
                ["rateLimitCount"] = snapshot.RateLimitCount,
                ["clMode"] = snapshot.ClMode,
                ["tier"] = snapshot.Tier,
                ["sdkVersion"] = snapshot.SdkVersion,
                ["modelExpired"] = snapshot.ModelExpired,
                ["licenseDegraded"] = snapshot.LicenseDegraded,
                ["integrityHash"] = snapshot.IntegrityHash,
                ["uptimeSeconds"] = snapshot.UptimeSeconds,
                ["p99LatencyMs"] = snapshot.P99LatencyMs,
            };
            byte[] raw = JsonSerializer.SerializeToUtf8Bytes(bodyObj);
            // Signed with a key ID and a fresh nonce per beat: the key is never sent.
            var headers = new Dictionary<string, string>(_signer.Sign("POST", requestTarget, Encoding.UTF8.GetString(raw)))
            {
                ["Content-Type"] = "application/json",
            };

            await _transport.SendAsync("POST", url, headers, raw, HeartbeatTimeout, cancellationToken).ConfigureAwait(false);

            Log("debug", $"Heartbeat sent: events={snapshot.EventCount}, blocks={snapshot.BlockCount}, uptime={snapshot.UptimeSeconds}s");

            // Reset counters after a send attempt (Node resets unconditionally inside the try
            // block on any non-throwing path, i.e. regardless of the response status — ported
            // faithfully, since the heartbeat is best-effort telemetry, not billing-critical).
            lock (_lock)
            {
                _eventCount = 0;
                _blockCount = 0;
                _rateLimitCount = 0;
                _latencies.Clear();
            }
        }
        catch (Exception error)
        {
            // Fire-and-forget: don't throw, just log.
            Log("debug", $"Heartbeat failed: {error.Message}");
        }
    }

    /// <summary>Computes p99 latency from sampled observations.</summary>
    private double ComputeP99()
    {
        lock (_lock)
        {
            if (_latencies.Count == 0) return 0;
            var sorted = _latencies.OrderBy(x => x).ToList();
            int idx = (int)Math.Floor(sorted.Count * 0.99);
            return sorted[Math.Min(idx, sorted.Count - 1)];
        }
    }

    /// <summary>Returns the current telemetry counters (for diagnostics).</summary>
    public TelemetryCounters GetState()
    {
        lock (_lock)
        {
            return new TelemetryCounters(_eventCount, _blockCount, _rateLimitCount,
                (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - _startedAtMs) / 1000);
        }
    }

    /// <summary>Stops sending heartbeats and cleans up. Safe to call more than once.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _heartbeatTimer?.Dispose();
        _heartbeatTimer = null;
        if (_ownsTransport && _transport is IDisposable disposableTransport)
        {
            disposableTransport.Dispose();
        }
    }

    private void Log(string level, string message)
    {
        if (!_debug && level == "debug") return;
        if (_logger is null) return;
        try
        {
            _logger.Log(level, $"[DevFortress:Telemetry] {message}", new Dictionary<string, object?>());
        }
        catch
        {
            // A throwing logger must not reach the host application either.
        }
    }
}

// ── Anomaly-Gated Metering: Aggregate Telemetry Rollup Buffer ──────────────

/// <summary>
/// One clean (non-flagged) request's contribution to the rollup buffer. Mirrors Node's
/// <c>RollupContributionInput</c>.
/// </summary>
public sealed record RollupContributionInput(string AliasOrIpKey, string Endpoint, bool IsError, double LatencyMs);

/// <summary>
/// Aggregate Telemetry Rollup Buffer. Mirrors
/// <c>packages/devfortress-sdk/src/telemetry-rollup-buffer.ts</c>.
/// </summary>
/// <remarks>
/// Option B (2026-08-27): clean/unflagged traffic no longer gets a full, billed
/// <c>LiveThreatEvent</c> row per request. Instead this buffer accumulates lightweight
/// per-alias/IP-per-hour counters in memory (request count, unique endpoints seen, error count,
/// latency sum) and flushes them as a small number of upsert-increment rows to
/// <c>/api/events/telemetry-rollup</c> on a short interval — not per request. This is what feeds
/// B1/B10's population-level baseline needs without counting toward the customer's billed event
/// quota (see <c>AliasTelemetryRollup</c> in <c>prisma/schema.prisma</c>).
///
/// Node's bucket key is a NUL-byte-separated string concatenation
/// (<c>`${aliasOrIpKey}\x00${periodKey}`</c>) used purely as a collision-free composite map key.
/// This port uses C#'s native idiom instead — a <c>(string AliasOrIpKey, string PeriodKey)</c>
/// value-tuple as the <see cref="Dictionary{TKey,TValue}"/> key — which gives the same
/// collision-free bucketing semantics without the NUL-byte trick.
///
/// Node's own config doc comment claims a 30s default flush interval, but the constant it
/// actually initializes from (<c>DEFAULT_FLUSH_INTERVAL_MS</c>) is 5 minutes, matching
/// <see cref="TelemetryManager.DefaultHeartbeatIntervalMs"/> — the doc comment is stale relative
/// to the real default. Ported faithfully (the real 5-minute default), not the stale comment.
/// </remarks>
public sealed class TelemetryRollupBuffer : IDisposable
{
    public const long DefaultFlushIntervalMs = 5 * 60 * 1000; // 5 minutes (see remarks above)
    public const int DefaultMaxBufferedKeys = 500;
    // Bounded per-bucket endpoint tracking — uniqueEndpoints is an approximation (this is
    // non-billing, best-effort aggregate telemetry, not an exact count).
    private const int MaxEndpointsTrackedPerBucket = 50;

    private sealed class RollupBucket
    {
        public required string AliasOrIpKey;
        public required string PeriodKey;
        public long RequestCount;
        public readonly HashSet<string> Endpoints = [];
        public long ErrorCount;
        public double LatencySumMs;
        public long WindowStart;
        public long WindowEnd;
    }

    private readonly string _apiKey;
    private readonly string _endpoint;
    private readonly long _flushIntervalMs;
    private readonly int _maxBufferedKeys;
    private readonly bool _debug;
    private readonly Signer _signer;
    private readonly ITransport _transport;
    private readonly bool _ownsTransport;
    private readonly IDevFortressLogger? _logger;

    private readonly object _lock = new();
    private readonly Dictionary<(string AliasOrIpKey, string PeriodKey), RollupBucket> _buckets = [];
    private Timer? _flushTimer;
    private int _disposed;

    public TelemetryRollupBuffer(string apiKey, string endpoint, long? flushIntervalMs = null, int? maxBufferedKeys = null,
        bool debug = false, ITransport? transport = null, IDevFortressLogger? logger = null)
    {
        if (string.IsNullOrEmpty(apiKey))
        {
            throw new ArgumentException("devfortress: an API key is required", nameof(apiKey));
        }
        _apiKey = apiKey;
        _endpoint = endpoint;
        _flushIntervalMs = flushIntervalMs ?? DefaultFlushIntervalMs;
        _maxBufferedKeys = maxBufferedKeys ?? DefaultMaxBufferedKeys;
        _debug = debug;
        _signer = new Signer(apiKey);
        _transport = transport ?? new HttpTransport();
        _ownsTransport = transport is null;
        _logger = logger;
    }

    /// <summary>Hour-bucket period key, e.g. "2026-08-27T14" — matches AliasTelemetryRollup.periodKey.</summary>
    public static string HourlyPeriodKey(DateTimeOffset? instant = null)
    {
        DateTime utc = (instant ?? DateTimeOffset.UtcNow).UtcDateTime;
        return utc.ToString("yyyy-MM-ddTHH", CultureInfo.InvariantCulture);
    }

    /// <summary>Starts the periodic flush timer. Safe to call multiple times (no-op if already started).</summary>
    public void Start()
    {
        if (_flushTimer is not null) return;
        _flushTimer = new Timer(_ => FireAndForgetFlush(), null, TimeSpan.FromMilliseconds(_flushIntervalMs),
            TimeSpan.FromMilliseconds(_flushIntervalMs));
    }

    private void FireAndForgetFlush()
    {
        _ = Task.Run(() => FlushAsync());
    }

    /// <summary>
    /// Buffers one clean (non-flagged) request's contribution. Synchronous, no network call —
    /// actual delivery happens on the next <see cref="FlushAsync"/>.
    /// </summary>
    public void Add(RollupContributionInput input)
    {
        string periodKey = HourlyPeriodKey();
        var bucketKey = (input.AliasOrIpKey, periodKey);
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        bool forceFlush = false;

        lock (_lock)
        {
            if (!_buckets.TryGetValue(bucketKey, out var bucket))
            {
                // Bound total buffered keys so a burst of unique IPs can't grow memory
                // unbounded — force an early flush and drop this one contribution.
                // Acceptable: this is approximate, non-billing aggregate telemetry.
                if (_buckets.Count >= _maxBufferedKeys)
                {
                    forceFlush = true;
                }
                else
                {
                    bucket = new RollupBucket
                    {
                        AliasOrIpKey = input.AliasOrIpKey,
                        PeriodKey = periodKey,
                        WindowStart = now,
                        WindowEnd = now,
                    };
                    _buckets[bucketKey] = bucket;
                }
            }

            if (bucket is not null)
            {
                bucket.RequestCount++;
                if (bucket.Endpoints.Count < MaxEndpointsTrackedPerBucket)
                {
                    bucket.Endpoints.Add(input.Endpoint);
                }
                if (input.IsError) bucket.ErrorCount++;
                bucket.LatencySumMs += input.LatencyMs;
                bucket.WindowEnd = now;
            }
        }

        if (forceFlush)
        {
            _ = Task.Run(() => FlushAsync());
        }
    }

    /// <summary>Flushes all buffered buckets to the platform in one batch request.</summary>
    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        List<Dictionary<string, object?>> contributions;
        lock (_lock)
        {
            if (_buckets.Count == 0) return;
            contributions = _buckets.Values.Select(b => new Dictionary<string, object?>
            {
                ["aliasOrIpKey"] = b.AliasOrIpKey,
                ["periodKey"] = b.PeriodKey,
                ["requestCount"] = b.RequestCount,
                ["uniqueEndpointsInBatch"] = b.Endpoints.Count,
                ["errorCount"] = b.ErrorCount,
                ["latencySumMs"] = b.LatencySumMs,
                ["windowStart"] = b.WindowStart,
                ["windowEnd"] = b.WindowEnd,
            }).ToList();
            _buckets.Clear();
        }

        try
        {
            string url = $"{_endpoint}/telemetry-rollup";
            string requestTarget = Signer.RequestTargetFromUrl(url);
            var payload = new Dictionary<string, object?> { ["contributions"] = contributions };
            byte[] raw = JsonSerializer.SerializeToUtf8Bytes(payload);
            var headers = new Dictionary<string, string>(_signer.Sign("POST", requestTarget, Encoding.UTF8.GetString(raw)))
            {
                ["Content-Type"] = "application/json",
            };
            await _transport.SendAsync("POST", url, headers, raw, TimeSpan.FromSeconds(10), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // Best-effort — aggregate telemetry is not billing-relevant, so dropping a batch on
            // transient failure is acceptable (unlike the full LiveThreatEvent relay path, which
            // retries).
            Log("debug", $"telemetry rollup flush failed: {e.Message}");
        }
    }

    /// <summary>Cleans up the flush timer and drops any unflushed buckets.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _flushTimer?.Dispose();
        _flushTimer = null;
        lock (_lock) { _buckets.Clear(); }
        if (_ownsTransport && _transport is IDisposable disposableTransport)
        {
            disposableTransport.Dispose();
        }
    }

    private void Log(string level, string message)
    {
        if (!_debug) return;
        if (_logger is null) return;
        try
        {
            _logger.Log(level, $"[DevFortress] {message}", new Dictionary<string, object?>());
        }
        catch
        {
            // A throwing logger must not reach the host application either.
        }
    }
}
