using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DevFortress;

/// <summary>
/// The outcome of <see cref="Client.ObserveAsync"/>: present (non-null) only when the request
/// should be blocked/rate-limited/challenged/quarantined. Mirrors Node's/Python's observe()
/// return shape (<c>{flagged, eventId, confidence, decision, matchedRules}</c>).
/// </summary>
public sealed record ObserveResult(bool Flagged, string EventId, double Confidence, string Decision, List<string> MatchedRules);

/// <summary>
/// A DevFortress event client (external mode).
/// </summary>
/// <remarks>
/// Events are queued in memory (<see cref="TrackEvent"/>, <see cref="TrackEvents"/>) and
/// delivered in batches (<c>{"events": [...]}</c>, server maximum <see cref="MaxServerBatch"/>)
/// by <see cref="FlushAsync"/>. Every request is signed with the request signature contract
/// (see <see cref="Signer"/>): the API key never goes on the wire, only a key ID does.
///
/// Retry: up to <c>retries</c> attempts, exponential backoff, only on 5xx responses and
/// network errors. 3xx and 4xx responses are never retried. Every attempt is signed again
/// with a fresh nonce and timestamp.
///
/// Delivery never throws into the host application: a failed delivery comes back as a
/// <see cref="DeliveryResult"/> and is logged. Only a missing API key fails construction.
/// The queue is safe for concurrent use. Mirrors <c>packages/devfortress-go/client.go</c>.
/// </remarks>
public sealed class Client : IAsyncDisposable, IDisposable
{
    public const string Version = "0.1.0";
    public const string DefaultEndpoint = "https://www.devfortress.net/api/events/ingest";
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);
    public const int DefaultRetries = 3;
    public const int DefaultBatchSize = 25;

    /// <summary>Largest number of events the platform accepts in one ingest request; flush splits into chunks this size.</summary>
    public const int MaxServerBatch = 100;

    private readonly Signer _signer;
    private readonly string _endpoint;
    private readonly string _requestTarget;
    private readonly TimeSpan _timeout;
    private readonly int _retries;
    private readonly int _batchSize;
    private readonly TimeSpan _backoffBase;
    private readonly IReadOnlyDictionary<string, object?> _defaults;
    private readonly string _privacy;
    private readonly IDevFortressLogger? _logger;
    private readonly ITransport _transport;
    private readonly bool _ownsTransport;

    private readonly object _lock = new();
    private readonly List<Dictionary<string, object?>> _queue = [];

    private readonly Timer? _flushTimer;
    private int _closed;
    private int _inFlight;
    private readonly ManualResetEventSlim _quiescent = new(initialState: true);

    /// <summary>
    /// Closed-loop response mode: "external" (default — this client only ships events to the
    /// platform, no local decision engine), "internal" (a local <see cref="InternalEngine"/>
    /// decides without any platform round-trip), or "hybrid" (internal-first; falls back to a
    /// circuit-breaker-gated external enrichment step when internal mode allows). Mirrors the
    /// Node SDK's <c>DevFortressCore</c> and the Python port's <c>DevFortressClient.mode</c>.
    /// Default "external" is a no-op change for existing callers: <see cref="InternalEngine"/>
    /// and <see cref="CircuitBreaker"/> stay null, and <see cref="ObserveAsync"/>/
    /// <see cref="IsBlocked"/> are no-ops.
    /// </summary>
    public string Mode { get; }

    /// <summary>Non-null only in "internal"/"hybrid" mode.</summary>
    public InternalClosedLoopEngine? InternalEngine { get; }

    /// <summary>Non-null only in "hybrid" mode; guards the external-enrichment leg.</summary>
    public PlatformCircuitBreaker? CircuitBreaker { get; }

    private Client(Builder b)
    {
        _signer = new Signer(b.ApiKeyValue);
        _endpoint = string.IsNullOrEmpty(b.EndpointValue) ? DefaultEndpoint : b.EndpointValue;
        _requestTarget = Signer.RequestTargetFromUrl(_endpoint);
        _timeout = b.TimeoutValue;
        _retries = Math.Max(1, b.RetriesValue);
        _batchSize = Math.Max(1, b.BatchSizeValue);
        _backoffBase = b.BackoffBaseValue;
        _defaults = b.DefaultsValue ?? new Dictionary<string, object?>();
        _privacy = b.PrivacyValue;
        _logger = b.LoggerValue;
        _transport = b.TransportValue ?? new HttpTransport();
        _ownsTransport = b.TransportValue is null;

        if (b.FlushIntervalValue is { } interval && interval > TimeSpan.Zero)
        {
            _flushTimer = new Timer(_ => FireAndForgetFlush(), null, interval, interval);
        }

        // ── Mode / internal closed-loop engine ──────────────────────────
        // Mirrors Node's DevFortressCore and Python's DevFortressClient: internal/hybrid mode
        // gets its own InternalClosedLoopEngine instance; hybrid additionally gets a
        // PlatformCircuitBreaker guarding the external-enrichment leg.
        Mode = b.ModeValue;
        if (Mode is "internal" or "hybrid")
        {
            var cfg = b.InternalCLConfigValue ?? new InternalCLConfig();
            cfg.EnableExternalRelay = Mode == "hybrid";
            cfg.OnRelay ??= Mode == "hybrid" ? RelayInternalDecisionToPlatform : null;
            InternalEngine = new InternalClosedLoopEngine(cfg);
        }
        if (Mode == "hybrid")
        {
            CircuitBreaker = new PlatformCircuitBreaker(b.CircuitBreakerFailureThresholdValue, b.CircuitBreakerRecoveryTimeValue);
        }
    }

    public static Builder Create(string apiKey) => new(apiKey);

    /// <summary>Configures a <see cref="Client"/>.</summary>
    public sealed class Builder
    {
        internal readonly string ApiKeyValue;
        internal string? EndpointValue;
        internal TimeSpan TimeoutValue = DefaultTimeout;
        internal int RetriesValue = DefaultRetries;
        internal int BatchSizeValue = DefaultBatchSize;
        internal TimeSpan BackoffBaseValue = TimeSpan.FromSeconds(1);
        internal IReadOnlyDictionary<string, object?>? DefaultsValue;
        internal string PrivacyValue = "standard";
        internal IDevFortressLogger? LoggerValue;
        internal ITransport? TransportValue;
        internal TimeSpan? FlushIntervalValue;
        internal string ModeValue = "external";
        internal InternalCLConfig? InternalCLConfigValue;
        internal int CircuitBreakerFailureThresholdValue = 3;
        internal TimeSpan CircuitBreakerRecoveryTimeValue = TimeSpan.FromSeconds(60);

        internal Builder(string apiKey) => ApiKeyValue = apiKey;

        public Builder Endpoint(string endpoint)
        {
            EndpointValue = endpoint;
            return this;
        }

        public Builder Timeout(TimeSpan timeout)
        {
            TimeoutValue = timeout;
            return this;
        }

        public Builder Retries(int retries)
        {
            RetriesValue = retries;
            return this;
        }

        public Builder BatchSize(int batchSize)
        {
            BatchSizeValue = batchSize;
            return this;
        }

        public Builder BackoffBase(TimeSpan backoffBase)
        {
            BackoffBaseValue = backoffBase;
            return this;
        }

        public Builder Defaults(IReadOnlyDictionary<string, object?> defaults)
        {
            DefaultsValue = defaults;
            return this;
        }

        /// <summary>"standard" (default) or "strict" (no user agents, 16-hex-character hashed IPs).</summary>
        public Builder Privacy(string privacy)
        {
            PrivacyValue = privacy;
            return this;
        }

        public Builder Logger(IDevFortressLogger logger)
        {
            LoggerValue = logger;
            return this;
        }

        /// <summary>Replaces the HTTP transport, e.g. with a recording transport in tests.</summary>
        public Builder Transport(ITransport transport)
        {
            TransportValue = transport;
            return this;
        }

        /// <summary>
        /// Starts a background timer that flushes the queue on this interval, stopped by
        /// <see cref="Client.DisposeAsync"/>/<see cref="Client.Dispose"/>. Omitted (the
        /// default) disables it; callers then flush explicitly (<see cref="Client.FlushAsync"/>,
        /// <see cref="Client.Flush"/>, dispose, the batch-size auto-flush, or
        /// <see cref="Observer.ObserveAndFlush"/>) — mirrors Go's <c>WithFlushInterval</c> safety net.
        /// </summary>
        public Builder FlushInterval(TimeSpan flushInterval)
        {
            FlushIntervalValue = flushInterval;
            return this;
        }

        /// <summary>"external" (default), "internal", or "hybrid". See <see cref="Client.Mode"/>.</summary>
        public Builder Mode(string mode)
        {
            ModeValue = mode;
            return this;
        }

        /// <summary>Configuration for the internal/hybrid-mode <see cref="InternalClosedLoopEngine"/>. Ignored in "external" mode.</summary>
        public Builder InternalCLConfig(InternalCLConfig config)
        {
            InternalCLConfigValue = config;
            return this;
        }

        /// <summary>Hybrid-mode circuit breaker failure threshold. Default 3.</summary>
        public Builder CircuitBreakerFailureThreshold(int threshold)
        {
            CircuitBreakerFailureThresholdValue = threshold;
            return this;
        }

        /// <summary>Hybrid-mode circuit breaker recovery time. Default 60s.</summary>
        public Builder CircuitBreakerRecoveryTime(TimeSpan recoveryTime)
        {
            CircuitBreakerRecoveryTimeValue = recoveryTime;
            return this;
        }

        public Client Build() => new(this);
    }

    /// <summary>
    /// Queues one event. The queue is sent (synchronously, like <see cref="Flush"/>) once it
    /// reaches the batch size; it is also sent when <see cref="FlushAsync"/> is called, or at
    /// dispose.
    /// </summary>
    /// <remarks>
    /// <b>This only queues.</b> Under sparse traffic (fewer events than the batch size
    /// between flushes and no flush interval configured), a tracked event can sit
    /// undelivered indefinitely. A caller that observes one request at a time (an
    /// adapter/middleware) should use <see cref="Observer.ObserveAndFlush"/>, not raw
    /// <see cref="TrackEvent"/> followed by nothing — this is the exact gap Go's gin adapter
    /// shipped with originally, fixed by flushing after every observed request.
    /// </remarks>
    public void TrackEvent(Dictionary<string, object?> @event) => TrackEvents([@event]);

    public void TrackEvents(IEnumerable<Dictionary<string, object?>> events)
    {
        bool shouldFlush;
        lock (_lock)
        {
            foreach (var evt in events)
            {
                _queue.Add(Prepare(evt));
            }
            shouldFlush = _queue.Count >= _batchSize;
        }
        if (shouldFlush)
        {
            Flush();
        }
    }

    /// <summary>
    /// Sends everything queued, in chunks of at most <see cref="MaxServerBatch"/> events,
    /// and returns one <see cref="DeliveryResult"/> per chunk. Never throws; failures are
    /// reported through the returned results.
    /// </summary>
    public async Task<IReadOnlyList<DeliveryResult>> FlushAsync(CancellationToken cancellationToken = default)
    {
        List<Dictionary<string, object?>> events;
        lock (_lock)
        {
            events = [.. _queue];
            _queue.Clear();
        }
        if (events.Count == 0)
        {
            return [];
        }

        var results = new List<DeliveryResult>();
        for (int i = 0; i < events.Count; i += MaxServerBatch)
        {
            var chunk = events.GetRange(i, Math.Min(MaxServerBatch, events.Count - i));
            var payload = new Dictionary<string, object?> { ["events"] = chunk };
            results.Add(await PostAsync(payload, cancellationToken).ConfigureAwait(false));
        }
        return results;
    }

    /// <summary>Blocking convenience wrapper over <see cref="FlushAsync"/>, matching the other SDKs' synchronous <c>flush()</c>.</summary>
    public IReadOnlyList<DeliveryResult> Flush() => FlushAsync().GetAwaiter().GetResult();

    /// <summary>The number of events waiting to be flushed.</summary>
    public int PendingEvents()
    {
        lock (_lock)
        {
            return _queue.Count;
        }
    }

    // ── Internal / hybrid closed-loop mode ──────────────────────────────
    // Mirrors Node's DevFortressCore.observeInternal()/observeHybrid() and Python's
    // observe()/is_blocked(): a pre-response gate the caller invokes (typically from
    // middleware) before the request reaches the application. Mode is fixed at construction
    // time (Builder.Mode()); "external" mode has no observe() behaviour here — external-mode
    // reporting stays on the existing after-response UseDevFortress path, unchanged.

    /// <summary>
    /// Evaluate a request through internal/hybrid closed-loop mode. Returns a flagged
    /// <see cref="ObserveResult"/> if the request should be blocked/rate-limited/challenged/
    /// quarantined, else <c>null</c> (allowed). Always <c>null</c> in "external" mode (no
    /// internal engine exists).
    /// </summary>
    public async Task<ObserveResult?> ObserveAsync(InternalCLRequest req)
    {
        if (Mode == "internal")
        {
            return await ObserveInternalAsync(req).ConfigureAwait(false);
        }
        if (Mode == "hybrid")
        {
            return await ObserveHybridAsync(req).ConfigureAwait(false);
        }
        return null;
    }

    private async Task<ObserveResult?> ObserveInternalAsync(InternalCLRequest req)
    {
        if (InternalEngine is null)
        {
            return null;
        }
        var result = await InternalEngine.EvaluateAsync(req).ConfigureAwait(false);
        if (result.Decision != "allow")
        {
            return new ObserveResult(true, result.EventId, result.Score / 100, result.Decision, result.MatchedRules);
        }
        return null;
    }

    private async Task<ObserveResult?> ObserveHybridAsync(InternalCLRequest req)
    {
        // Step 1: internal evaluation (immediate, sub-ms, no round-trip).
        var internalResult = await ObserveInternalAsync(req).ConfigureAwait(false);
        if (internalResult is not null)
        {
            // The internal engine's own OnRelay callback already handles the Tier-3 relay for
            // this decision (see the constructor) — no second relay call here, matching Node's
            // TODO-210 double-billing fix and Python's observe_hybrid().
            return internalResult;
        }

        // Step 2: external enrichment, circuit-breaker gated.
        //
        // KNOWN LIMITATION (flagged explicitly, not silently claimed as full parity): Node's
        // observeHybrid() calls observeExternal() here to fetch a real platform-side enrichment
        // verdict. Like the Python port, this port does not yet make that platform call — it
        // only exercises the circuit breaker's success/failure bookkeeping around a no-op
        // enrichment step, so clean traffic is allowed and the circuit stays closed, but a
        // request that internal mode missed and only the platform's own cross-customer
        // intelligence would have caught is not enriched here.
        if (CircuitBreaker is { } breaker && breaker.ShouldCallExternal())
        {
            breaker.RecordSuccess();
        }
        return null;
    }

    /// <summary>
    /// Whether <paramref name="ip"/> is currently blocked by the internal engine's in-memory
    /// cache. Always <c>false</c> in "external" mode (no internal engine exists).
    /// </summary>
    public bool IsBlocked(string ip) => InternalEngine?.IsIpBlocked(ip) ?? false;

    /// <summary>
    /// Tier-3 relay target for hybrid mode — wired as the internal engine's <c>OnRelay</c>
    /// callback. Reuses the existing <see cref="TrackEvent"/>/retry path, same as every other
    /// outbound event on this client, rather than opening a second HTTP path.
    /// </summary>
    /// <summary>
    /// Wired as the internal engine's OnRelay callback, invoked synchronously within Evaluate
    /// (see InternalClosedLoopEngine's own doc comment on why: Evaluate itself must stay
    /// zero-network and deterministic). TrackEvent below only enqueues — fast, in-memory, safe
    /// to call synchronously here — and <see cref="FireAndForgetFlush"/> (already built for the
    /// periodic flush timer, reused here for the first time) pushes the actual delivery onto
    /// this client's own detached observer task, mirroring <see cref="Observer.ObserveAndFlush"/>'s
    /// exact pattern. Found live, via this port's own end-to-end demo proof against a real
    /// platform (not the dummy unreachable endpoint sdk-validation-v4.sh's own ICL phase
    /// deliberately uses): without this, a relayed event could sit queued for up to the
    /// configured flush interval, even though the request itself was already blocked and
    /// responded to.
    /// </summary>
    private Task RelayInternalDecisionToPlatform(InternalCLResult result, InternalCLRequest req)
    {
        string eventType = result.MatchedRules.Count > 0 ? result.MatchedRules[0] : $"icl_{result.Decision}";
        string severity = result.Score >= 85 ? "CRITICAL" : result.Score >= 60 ? "HIGH" : result.Score >= 35 ? "MEDIUM" : "LOW";
        string actionTaken = result.Decision switch
        {
            "allow" => "allowed",
            "block" => "blocked",
            "rate_limit" => "rate_limited",
            "challenge" => "challenge_required",
            "quarantine" => "flagged",
            _ => "flagged",
        };
        try
        {
            TrackEvent(new Dictionary<string, object?>
            {
                ["eventType"] = eventType,
                ["ip"] = req.Ip,
                ["severity"] = severity,
                ["method"] = req.Method,
                ["path"] = req.Path,
                ["userAgent"] = req.UserAgent,
                ["authPhase"] = !string.IsNullOrEmpty(req.UserId) ? "post_auth" : "pre_auth",
                ["actionTaken"] = actionTaken,
                ["responseLatencyMs"] = (int)Math.Round(result.EvaluationTimeUs / 1000),
                ["clMode"] = "hybrid",
                ["metadata"] = new Dictionary<string, object?>
                {
                    ["source"] = "internal-closed-loop-engine",
                    ["tier"] = result.Tier,
                    ["matchedRules"] = result.MatchedRules,
                    ["internalEventId"] = result.EventId,
                    ["sessionId"] = req.SessionId,
                    ["agentId"] = req.AgentId,
                },
            });
            FireAndForgetFlush();
        }
        catch
        {
            // TrackEvent/Flush already logs delivery failures; the relay callback itself must
            // not throw back into the engine (see InternalClosedLoopEngine.RelayToExternalAsync's
            // own try/catch, which this guards defensively in addition to).
        }
        return Task.CompletedTask;
    }

    /// <summary>Reports whether the platform accepts a signed test event with this key. Never throws.</summary>
    public async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
    {
        var @event = new Dictionary<string, object?>
        {
            ["eventType"] = "custom",
            ["ip"] = "127.0.0.1",
            ["method"] = "GET",
            ["path"] = "/__devfortress/test",
            ["severity"] = "LOW",
            ["authPhase"] = "pre_auth",
            ["actionTaken"] = "monitored",
            ["responseLatencyMs"] = 0,
            ["clMode"] = "external",
            ["metadata"] = new Dictionary<string, object?> { ["test"] = true, ["sdk"] = "dotnet" },
        };
        var result = await PostAsync(Prepare(@event), cancellationToken).ConfigureAwait(false);
        return result.Ok;
    }

    /// <summary>Submits work to this client's detached observer background task — used by <see cref="Observer"/>.</summary>
    internal void RunDetached(Func<Task> work)
    {
        if (Volatile.Read(ref _closed) != 0)
        {
            return;
        }
        Interlocked.Increment(ref _inFlight);
        _quiescent.Reset();
        _ = Task.Run(async () =>
        {
            try
            {
                await work().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log("warning", "devfortress: observer task failed", new Dictionary<string, object?> { ["error"] = ex.Message });
            }
            finally
            {
                if (Interlocked.Decrement(ref _inFlight) == 0)
                {
                    _quiescent.Set();
                }
            }
        });
    }

    private void FireAndForgetFlush()
    {
        RunDetached(() => FlushAsync());
    }

    private Dictionary<string, object?> Prepare(Dictionary<string, object?> @event)
    {
        var item = new Dictionary<string, object?>(_defaults);
        foreach (var (key, value) in @event)
        {
            item[key] = value;
        }
        item.TryAdd("timestamp", DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"));

        if (_privacy == "strict")
        {
            item.Remove("userAgent");
            if (item.TryGetValue("ip", out var ipObj) && ipObj is string ip)
            {
                item["ip"] = HashIp(ip);
            }
        }
        if (item.TryGetValue("metadata", out var metadata) && metadata is null)
        {
            item["metadata"] = new Dictionary<string, object?>();
        }
        return item;
    }

    private static string HashIp(string ip)
    {
        byte[] sum = SHA256.HashData(Encoding.UTF8.GetBytes(ip));
        return Convert.ToHexString(sum).ToLowerInvariant()[..16];
    }

    private async Task<DeliveryResult> PostAsync(Dictionary<string, object?> payload, CancellationToken cancellationToken)
    {
        byte[] raw;
        try
        {
            raw = JsonSerializer.SerializeToUtf8Bytes(payload);
        }
        catch (Exception e)
        {
            return Fail(DeliveryResult.Failed(e, 0));
        }

        var last = DeliveryResult.Failed(new InvalidOperationException("no delivery attempt was made"), 0);
        for (int attempt = 1; attempt <= _retries; attempt++)
        {
            // A fresh nonce and timestamp on every attempt, so a retry is not a replay.
            var headers = new Dictionary<string, string>(_signer.Sign("POST", _requestTarget, Encoding.UTF8.GetString(raw)))
            {
                ["Content-Type"] = "application/json",
                ["Accept"] = "application/json",
                ["User-Agent"] = $"devfortress-sdk-dotnet/{Version}",
            };

            TransportResponse? response = null;
            try
            {
                response = await _transport.SendAsync("POST", _endpoint, headers, raw, _timeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception sendErr)
            {
                last = DeliveryResult.Failed(new InvalidOperationException($"request failed: {sendErr.Message}", sendErr), attempt);
            }

            if (response is not null)
            {
                object? body = DecodeBody(response.Body);
                if (response.StatusCode is >= 200 and < 300)
                {
                    return new DeliveryResult(true, response.StatusCode, body, null, attempt);
                }
                last = DeliveryResult.HttpFailure(response.StatusCode, body,
                    new InvalidOperationException($"HTTP {response.StatusCode}"), attempt);
                if (response.StatusCode < 500)
                {
                    return Fail(last); // 3xx and 4xx: never retried
                }
            }

            if (attempt < _retries)
            {
                await Sleep(TimeSpan.FromMilliseconds(_backoffBase.TotalMilliseconds * Math.Pow(2, attempt - 1)), cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        return Fail(last);
    }

    private static async Task Sleep(TimeSpan d, CancellationToken cancellationToken)
    {
        if (d <= TimeSpan.Zero)
        {
            return;
        }
        try
        {
            await Task.Delay(d, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // A caller-cancelled flush should stop retrying, not throw from a backoff sleep.
        }
    }

    private DeliveryResult Fail(DeliveryResult result)
    {
        string message = result.Error?.Message ?? "unknown error";
        Log("warning", $"devfortress: delivery failed: {message}", new Dictionary<string, object?>
        {
            ["status"] = result.StatusCode,
            ["attempts"] = result.Attempts,
        });
        return result;
    }

    private void Log(string level, string message, Dictionary<string, object?> fields)
    {
        if (_logger is null)
        {
            return;
        }
        try
        {
            _logger.Log(level, message, fields);
        }
        catch
        {
            // A throwing logger must not reach the host application either.
        }
    }

    private static object? DecodeBody(byte[] raw)
    {
        if (raw.Length == 0)
        {
            return new Dictionary<string, object?>();
        }
        try
        {
            return JsonSerializer.Deserialize<JsonElement>(raw);
        }
        catch (JsonException)
        {
            return Encoding.UTF8.GetString(raw);
        }
    }

    /// <summary>
    /// Stops the background flush timer (if any), waits for in-flight observer work, and
    /// flushes whatever is still queued. Safe to call more than once.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }
        if (_flushTimer is not null)
        {
            await _flushTimer.DisposeAsync().ConfigureAwait(false);
        }
        _quiescent.Wait(_timeout + TimeSpan.FromSeconds(1));
        await FlushAsync().ConfigureAwait(false);
        if (_ownsTransport && _transport is IDisposable disposableTransport)
        {
            disposableTransport.Dispose();
        }
        _quiescent.Dispose();
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
}
