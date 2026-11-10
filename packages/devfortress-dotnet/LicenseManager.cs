using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DevFortress;

/// <summary>
/// License Manager (CV-M1, CV-M4, CV-M7). Mirrors
/// <c>packages/devfortress-sdk/src/license-manager.ts</c>. Implements:
/// <list type="bullet">
/// <item>CV-M1: server-side license validation with a 24h check interval and a 72h grace
/// period before degrading to monitor-only mode.</item>
/// <item>CV-M4: ML model expiry (30-day staleness without a platform sync).</item>
/// <item>CV-M7: SDK anti-tampering HMAC signature verification.</item>
/// </list>
/// </summary>
/// <remarks>
/// This is the client-side half of the exact bug class already fixed on the platform and the
/// Node SDK (TODO 321): a license-check or heartbeat call that silently 404s must never leave
/// the SDK stuck in monitor-only mode without a trace. Every check failure is logged through
/// <see cref="IDevFortressLogger"/> (when configured), and <see cref="GetLicenseState"/> always
/// reports whether — and why — the SDK is degraded, rather than failing silently. Requests are
/// signed with <see cref="Signer"/> exactly like every other SDK-to-platform call: the API key
/// never goes on the wire, only a key ID does. Mirrors
/// <c>packages/devfortress-go/license_manager.go</c>-equivalent intent.
///
/// <see cref="LicenseState.Tier"/> is a plain wire string ("starter"/"pro"/"team"/"enterprise"),
/// not <see cref="SubscriptionTier"/> — matching Node, where license-manager.ts declares its own
/// inline tier union and does not import tier-gate.ts's type (confirmed: no cross-file import
/// between the two modules). A caller wiring this into <see cref="TierGate"/> bridges the two
/// with <see cref="SubscriptionTierExtensions.ParseSubscriptionTier"/>.
/// </remarks>
public sealed record LicenseState(
    bool Valid,
    string Tier,
    long LastCheckedAt,
    int ConsecutiveFailures,
    bool Degraded,
    string? DegradationReason = null);

/// <summary>CV-M4: ML model freshness state.</summary>
public sealed record ModelState(long LastSyncedAt, string ModelVersion, bool Expired);

/// <summary>CV-M7: result of <see cref="LicenseManager.VerifyIntegrity"/>.</summary>
public readonly record struct IntegrityVerification(bool Tampered, string Hash);

/// <summary>Action categories gated by <see cref="LicenseManager.CanPerformAction"/>.</summary>
public enum LicenseAction { Observe, Block, RateLimit }

public sealed class LicenseManager : IDisposable
{
    public const long DefaultCheckIntervalMs = 24L * 60 * 60 * 1000; // 24 hours
    public const long DefaultGracePeriodMs = 72L * 60 * 60 * 1000; // 72 hours
    public const long DefaultModelExpiryMs = 30L * 24 * 60 * 60 * 1000; // 30 days
    private static readonly TimeSpan LicenseCheckTimeout = TimeSpan.FromSeconds(10);

    private readonly string _apiKey;
    private readonly string _endpoint;
    private readonly long _checkIntervalMs;
    private readonly long _gracePeriodMs;
    private readonly long _modelExpiryMs;
    private readonly string? _integritySecret;
    private readonly bool _debug;
    private readonly Signer _signer;
    private readonly ITransport _transport;
    private readonly bool _ownsTransport;
    private readonly IDevFortressLogger? _logger;

    private readonly object _stateLock = new();
    private bool _valid;
    private string _tier = "starter";
    private long _lastCheckedAt;
    private int _consecutiveFailures;
    private bool _degraded;
    private string? _degradationReason;

    private long _modelLastSyncedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); // Assume fresh on init
    private string _modelVersion = "embedded-v1";

    private Timer? _checkTimer;
    private bool _initialized;
    private int _disposed;

    public LicenseManager(string apiKey, string endpoint, long? checkIntervalMs = null, long? gracePeriodMs = null,
        long? modelExpiryMs = null, string? integritySecret = null, bool debug = false,
        ITransport? transport = null, IDevFortressLogger? logger = null)
    {
        if (string.IsNullOrEmpty(apiKey))
        {
            throw new ArgumentException("devfortress: an API key is required", nameof(apiKey));
        }
        _apiKey = apiKey;
        _endpoint = endpoint;
        _checkIntervalMs = checkIntervalMs ?? DefaultCheckIntervalMs;
        _gracePeriodMs = gracePeriodMs ?? DefaultGracePeriodMs;
        _modelExpiryMs = modelExpiryMs ?? DefaultModelExpiryMs;
        _integritySecret = integritySecret;
        _debug = debug;
        _signer = new Signer(apiKey);
        _transport = transport ?? new HttpTransport();
        _ownsTransport = transport is null;
        _logger = logger;
    }

    // ── CV-M1: License Validation ──────────────────────────────

    /// <summary>
    /// Initializes the license manager: performs an initial license check and starts periodic
    /// validation on <c>checkIntervalMs</c>. Idempotent — a second call is a no-op that returns
    /// the current state.
    /// </summary>
    public async Task<LicenseState> InitAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized)
        {
            return GetLicenseState();
        }

        var state = await CheckLicenseAsync(cancellationToken).ConfigureAwait(false);

        _checkTimer = new Timer(_ => FireAndForgetCheck(), null, TimeSpan.FromMilliseconds(_checkIntervalMs),
            TimeSpan.FromMilliseconds(_checkIntervalMs));
        _initialized = true;
        return state;
    }

    private void FireAndForgetCheck()
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await CheckLicenseAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log("warn", $"License check timer failed: {ex.Message}");
            }
        });
    }

    /// <summary>
    /// Performs one license check against the platform. On failure, tracks consecutive
    /// failures and degrades to monitor-only mode once the grace period has elapsed.
    /// </summary>
    public async Task<LicenseState> CheckLicenseAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            string url = $"{_endpoint}/api/sdk/license-check";
            string requestTarget = Signer.RequestTargetFromUrl(url);

            // Signed with a key ID and a fresh nonce per attempt: the key is never sent.
            var bodyObj = new Dictionary<string, object?>
            {
                ["sdkVersion"] = Client.Version,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["integrity"] = ComputeIntegrityHash(),
            };
            byte[] raw = JsonSerializer.SerializeToUtf8Bytes(bodyObj);
            string rawBodyStr = Encoding.UTF8.GetString(raw);
            var headers = new Dictionary<string, string>(_signer.Sign("POST", requestTarget, rawBodyStr))
            {
                ["Content-Type"] = "application/json",
            };

            TransportResponse response;
            try
            {
                response = await _transport.SendAsync("POST", url, headers, raw, LicenseCheckTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception sendErr)
            {
                HandleCheckFailure(sendErr.Message);
                return GetLicenseState();
            }

            if (response.StatusCode is >= 200 and < 300)
            {
                JsonElement data = default;
                bool parsed = false;
                try
                {
                    data = JsonSerializer.Deserialize<JsonElement>(response.Body);
                    parsed = true;
                }
                catch (JsonException)
                {
                    // Fall through: treat an unparsable 2xx body as "no fields provided".
                }

                string tierReported;
                lock (_stateLock)
                {
                    string? tierFromBody = parsed && data.ValueKind == JsonValueKind.Object &&
                        data.TryGetProperty("tier", out var tierEl) && tierEl.ValueKind == JsonValueKind.String
                        ? tierEl.GetString()
                        : null;

                    _valid = true;
                    _tier = tierFromBody ?? _tier;
                    _lastCheckedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    _consecutiveFailures = 0;
                    _degraded = false;
                    _degradationReason = null;
                    tierReported = _tier;

                    // CV-M4: sync ML model freshness on successful license check
                    if (parsed && data.ValueKind == JsonValueKind.Object &&
                        data.TryGetProperty("modelVersion", out var mv) && mv.ValueKind == JsonValueKind.String)
                    {
                        _modelLastSyncedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        _modelVersion = mv.GetString()!;
                    }
                }

                Log("info", $"License validated: tier={tierReported}");
            }
            else if (response.StatusCode is 402 or 403)
            {
                // Explicitly unauthorized/payment required.
                lock (_stateLock)
                {
                    _valid = false;
                    _tier = "starter";
                    _lastCheckedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    _consecutiveFailures += 1;
                    _degraded = true;
                    _degradationReason = $"License rejected: HTTP {response.StatusCode}";
                }
                Log("warn", $"License rejected: HTTP {response.StatusCode}");
            }
            else
            {
                // Server error — treat as transient failure.
                HandleCheckFailure($"HTTP {response.StatusCode}");
            }
        }
        catch (Exception error)
        {
            HandleCheckFailure(error.Message);
        }

        return GetLicenseState();
    }

    private void HandleCheckFailure(string reason)
    {
        string? degradedMessage = null;
        string? debugMessage = null;

        lock (_stateLock)
        {
            _consecutiveFailures += 1;
            // If never successfully checked, start the grace period from initialization.
            long baselineTime = _lastCheckedAt == 0 ? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() : _lastCheckedAt;
            long timeSinceLastSuccess = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - baselineTime;

            if (timeSinceLastSuccess >= _gracePeriodMs)
            {
                // Grace period expired — degrade to monitor-only.
                _degraded = true;
                _degradationReason =
                    $"License check failed for {Math.Round(timeSinceLastSuccess / 3600000.0)}h " +
                    $"(grace period: {Math.Round(_gracePeriodMs / 3600000.0)}h). " +
                    $"Reason: {reason}. SDK degraded to monitor-only mode.";
                degradedMessage = _degradationReason;
            }
            else
            {
                debugMessage =
                    $"License check failed ({reason}), {_consecutiveFailures} consecutive failures, " +
                    $"{Math.Round((_gracePeriodMs - timeSinceLastSuccess) / 3600000.0)}h grace remaining";
            }
        }

        if (degradedMessage is not null)
        {
            Log("warn", degradedMessage);
        }
        else if (debugMessage is not null)
        {
            Log("debug", debugMessage);
        }
    }

    /// <summary>Returns a snapshot of the current license state.</summary>
    public LicenseState GetLicenseState()
    {
        lock (_stateLock)
        {
            return new LicenseState(_valid, _tier, _lastCheckedAt, _consecutiveFailures, _degraded, _degradationReason);
        }
    }

    /// <summary>
    /// Whether the SDK should operate in degraded (monitor-only) mode. Degraded mode means:
    /// no blocking, no rate limiting, just logging.
    /// </summary>
    public bool IsDegraded()
    {
        lock (_stateLock)
        {
            return _degraded;
        }
    }

    /// <summary>Whether a specific capability is available in the current license state.</summary>
    public bool CanPerformAction(LicenseAction action)
    {
        lock (_stateLock)
        {
            if (action == LicenseAction.Observe) return true; // Always allowed
            if (_degraded) return false; // Degraded = monitor-only
            if (!_valid && _lastCheckedAt == 0) return true; // Never validated yet — allow during initial grace period
            return _valid;
        }
    }

    // ── CV-M4: ML Model Expiry ─────────────────────────────────

    /// <summary>
    /// Whether the embedded ML model has expired (&gt;30 days without a platform sync). If
    /// expired, ICL falls back to Tier 1 only.
    /// </summary>
    public bool IsModelExpired()
    {
        lock (_stateLock)
        {
            long age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - _modelLastSyncedAt;
            return age > _modelExpiryMs;
        }
    }

    /// <summary>Returns the current ML model state.</summary>
    public ModelState GetModelState()
    {
        lock (_stateLock)
        {
            long age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - _modelLastSyncedAt;
            return new ModelState(_modelLastSyncedAt, _modelVersion, age > _modelExpiryMs);
        }
    }

    /// <summary>Manually triggers a model sync (called from init or a heartbeat response).</summary>
    public void SyncModel(string modelVersion)
    {
        lock (_stateLock)
        {
            _modelLastSyncedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            _modelVersion = modelVersion;
        }
        Log("info", $"ML model synced: version={modelVersion}");
    }

    // ── CV-M7: Anti-Tampering ──────────────────────────────────

    /// <summary>
    /// Computes an HMAC signature over critical SDK code paths. If the SDK distribution has
    /// been modified, this hash differs from the platform's expected value.
    /// </summary>
    public string ComputeIntegrityHash()
    {
        if (string.IsNullOrEmpty(_integritySecret))
        {
            return "no-integrity-secret";
        }

        // Hash critical module references (class names, method signatures) — mirrors Node's
        // fixed critical-paths list exactly (order matters: it's part of the signed data).
        string criticalPaths = string.Join('|',
        [
            "DevFortress.observe",
            "DevFortress.isBlocked",
            "LicenseManager.checkLicense",
            "InternalClosedLoopEngine.evaluate",
            "TierGate.checkEventLimit",
        ]);

        byte[] data = Encoding.UTF8.GetBytes(criticalPaths + _apiKey);
        byte[] hmac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(_integritySecret), data);
        return Convert.ToHexString(hmac).ToLowerInvariant()[..16];
    }

    /// <summary>Verifies that the SDK has not been tampered with.</summary>
    public IntegrityVerification VerifyIntegrity(string? expectedHash = null)
    {
        string currentHash = ComputeIntegrityHash();
        if (string.IsNullOrEmpty(expectedHash))
        {
            return new IntegrityVerification(false, currentHash);
        }
        return new IntegrityVerification(currentHash != expectedHash, currentHash);
    }

    // ── Cleanup ────────────────────────────────────────────────

    /// <summary>Stops periodic license checks and cleans up. Safe to call more than once.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _checkTimer?.Dispose();
        _checkTimer = null;
        _initialized = false;
        if (_ownsTransport && _transport is IDisposable disposableTransport)
        {
            disposableTransport.Dispose();
        }
    }

    // ── Logging ────────────────────────────────────────────────

    private void Log(string level, string message)
    {
        if (!_debug && level == "debug") return;
        if (_logger is null) return;
        try
        {
            _logger.Log(level, $"[DevFortress:License] {message}", new Dictionary<string, object?>());
        }
        catch
        {
            // A throwing logger must not reach the host application either.
        }
    }
}
