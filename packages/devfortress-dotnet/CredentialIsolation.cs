using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DevFortress;

/// <summary>
/// Credential Isolation Security — Session Indirection (Hardened). Mirrors
/// <c>packages/devfortress-sdk/src/credential-isolation.ts</c>.
/// </summary>
/// <remarks>
/// Replaces real session tokens with opaque, random aliases before they leave the client app's
/// trust boundary. DevFortress only ever sees the alias — never the real token. Hardening:
/// AES-256-GCM encryption of forward-mapping values, SHA-256 hashed reverse-mapping keys,
/// subjectId-level fallback revocation on cache failure, alias rotation grace period, and an
/// in-memory LRU fallback cache that survives cache-adapter outages.
/// </remarks>
public interface ICacheAdapter
{
    Task<string?> GetAsync(string key);
    Task SetAsync(string key, string value, int ttlSeconds);
    Task DeleteAsync(string key);
}

/// <summary>In-process, non-persistent <see cref="ICacheAdapter"/> — the development/test fallback.</summary>
public sealed class InMemoryCacheAdapter : ICacheAdapter
{
    private sealed record Entry(string Value, long ExpiresAtMs);
    private readonly Dictionary<string, Entry> _store = [];
    private readonly object _lock = new();

    public Task<string?> GetAsync(string key)
    {
        lock (_lock)
        {
            if (!_store.TryGetValue(key, out var entry))
            {
                return Task.FromResult<string?>(null);
            }
            if (NowMs() > entry.ExpiresAtMs)
            {
                _store.Remove(key);
                return Task.FromResult<string?>(null);
            }
            return Task.FromResult<string?>(entry.Value);
        }
    }

    public Task SetAsync(string key, string value, int ttlSeconds)
    {
        lock (_lock)
        {
            _store[key] = new Entry(value, NowMs() + ttlSeconds * 1000L);
        }
        return Task.CompletedTask;
    }

    public Task DeleteAsync(string key)
    {
        lock (_lock)
        {
            _store.Remove(key);
        }
        return Task.CompletedTask;
    }

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

/// <summary>Bounded, TTL'd in-memory LRU cache — the fallback path when <see cref="ICacheAdapter"/> fails.</summary>
internal sealed class LruCache(int maxEntries = 1000, int defaultTtlSeconds = 60)
{
    private sealed record Entry(string Value, long ExpiresAtMs);
    private readonly Dictionary<string, Entry> _cache = [];
    private readonly List<string> _order = [];
    private readonly object _lock = new();

    public string? Get(string key)
    {
        lock (_lock)
        {
            if (!_cache.TryGetValue(key, out var entry))
            {
                return null;
            }
            if (NowMs() > entry.ExpiresAtMs)
            {
                _cache.Remove(key);
                _order.Remove(key);
                return null;
            }
            // Move to end (most recently used)
            _order.Remove(key);
            _order.Add(key);
            return entry.Value;
        }
    }

    public void Set(string key, string value, int? ttlSeconds = null)
    {
        lock (_lock)
        {
            if (!_cache.ContainsKey(key) && _cache.Count >= maxEntries && _order.Count > 0)
            {
                string oldest = _order[0];
                _order.RemoveAt(0);
                _cache.Remove(oldest);
            }
            if (_cache.ContainsKey(key))
            {
                _order.Remove(key);
            }
            _order.Add(key);
            _cache[key] = new Entry(value, NowMs() + (ttlSeconds ?? defaultTtlSeconds) * 1000L);
        }
    }

    public void Delete(string key)
    {
        lock (_lock)
        {
            _cache.Remove(key);
            _order.Remove(key);
        }
    }

    public bool Has(string key) => Get(key) is not null;

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

/// <summary>
/// Local emergency blocklist — synchronous, pre-webhook IP blocking. When a critical event
/// fires, the IP is written here BEFORE the webhook is sent, ensuring the IP is blocked even if
/// the webhook receiver is down.
/// </summary>
public sealed class ThreatInterceptor(ICacheAdapter? cache = null, int ttlSeconds = 900)
{
    private readonly ICacheAdapter _cache = cache ?? new InMemoryCacheAdapter();
    private readonly LruCache _lru = new(5000, ttlSeconds);
    private readonly int _defaultTtlSeconds = ttlSeconds;

    /// <summary>Block an IP immediately on critical event classification.</summary>
    public async Task BlockIpAsync(string ip, string reason = "critical_event")
    {
        string value = JsonSerializer.Serialize(new { reason, blockedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() });
        _lru.Set($"emergency:block:{ip}", value, _defaultTtlSeconds);
        try
        {
            await _cache.SetAsync($"emergency:block:{ip}", value, _defaultTtlSeconds).ConfigureAwait(false);
        }
        catch
        {
            // LRU cache is already set — cache-adapter failure doesn't prevent blocking.
        }
    }

    /// <summary>Check if an IP is emergency-blocked. O(1) — safe for every request.</summary>
    public async Task<bool> IsBlockedAsync(string ip)
    {
        if (_lru.Has($"emergency:block:{ip}"))
        {
            return true;
        }
        try
        {
            string? val = await _cache.GetAsync($"emergency:block:{ip}").ConfigureAwait(false);
            return val is not null;
        }
        catch
        {
            return false; // On cache-adapter failure, LRU was already checked.
        }
    }

    /// <summary>Unblock an IP (manual override).</summary>
    public async Task UnblockIpAsync(string ip)
    {
        _lru.Delete($"emergency:block:{ip}");
        try
        {
            await _cache.DeleteAsync($"emergency:block:{ip}").ConfigureAwait(false);
        }
        catch
        {
            // Best-effort.
        }
    }
}

public enum RevocationReason
{
    ActiveThreat,
    RotationExpired,
    Logout,
}

internal static class RevocationReasonExtensions
{
    public static string ToWireString(this RevocationReason reason) => reason switch
    {
        RevocationReason.ActiveThreat => "active_threat",
        RevocationReason.RotationExpired => "rotation_expired",
        RevocationReason.Logout => "logout",
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };
}

public sealed record IsolatedCredentialData(string RealToken, string UserId, long CreatedAt);

public sealed record RevocationDetails(RevocationReason Reason, long RevokedAt, string RevocationScope);

public sealed class CredentialIsolationManagerConfig
{
    /// <summary>AES-256-GCM encryption key for forward-mapping values (32-byte hex string, 64 hex characters).</summary>
    public string? EncryptionKey { get; set; }
    public int LruMaxEntries { get; set; } = 1000;
    public int LruTtlSeconds { get; set; } = 60;
    public int RotationGracePeriodSeconds { get; set; } = 1200;
    /// <summary>Invoked on fallback revocation (cache failure) so the app can do broad session deletion.</summary>
    public Func<string, string, Task>? OnFallbackRevocation { get; set; }
}

/// <summary>Credential Isolation Manager (hardened). See the file-level remarks for the hardening measures.</summary>
public sealed class CredentialIsolationManager
{
    private readonly ICacheAdapter _cache;
    private readonly string _encryptionKey;
    private readonly LruCache _lru;
    private readonly int _rotationGracePeriod;
    private readonly Func<string, string, Task>? _onFallbackRevocation;

    /// <summary>
    /// Encryption is mandatory: credentials must never be cached in plaintext. Throws at
    /// construction time (rather than silently no-op'ing later) if no key is supplied.
    /// </summary>
    public CredentialIsolationManager(ICacheAdapter? cacheAdapter = null, CredentialIsolationManagerConfig? config = null)
    {
        _cache = cacheAdapter ?? new InMemoryCacheAdapter();
        _lru = new LruCache(config?.LruMaxEntries ?? 1000, config?.LruTtlSeconds ?? 60);
        _rotationGracePeriod = config?.RotationGracePeriodSeconds ?? 1200;
        _onFallbackRevocation = config?.OnFallbackRevocation;

        string? key = config?.EncryptionKey;
        if (string.IsNullOrEmpty(key))
        {
            throw new InvalidOperationException(
                "An encryption key is required — CredentialIsolationManager refuses to store credentials " +
                "without encryption. Pass config.EncryptionKey as a 32-byte hex string (64 hex characters), " +
                "e.g. from `openssl rand -hex 32`.");
        }
        if (key.Length != 64)
        {
            throw new InvalidOperationException("EncryptionKey must be a 32-byte hex string (64 hex characters)");
        }
        _encryptionKey = key;
    }

    private string EncryptValue(string plaintext) => Encrypt(plaintext, _encryptionKey);
    private string DecryptValue(string ciphertext) => Decrypt(ciphertext, _encryptionKey);

    private const string EncryptedPrefix = "enc:v1:";

    private static string Encrypt(string plaintext, string keyHex)
    {
        byte[] key = Convert.FromHexString(keyHex);
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] authTag = new byte[16];
        using var aes = new AesGcm(key, authTag.Length);
        aes.Encrypt(iv, plaintextBytes, ciphertext, authTag);
        return EncryptedPrefix + Convert.ToHexString(iv).ToLowerInvariant() + ":" +
            Convert.ToHexString(ciphertext).ToLowerInvariant() + ":" + Convert.ToHexString(authTag).ToLowerInvariant();
    }

    private static string Decrypt(string ciphertext, string keyHex)
    {
        if (!ciphertext.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
        {
            // Legacy unencrypted format — return as-is (rolling migration).
            return ciphertext;
        }
        string[] parts = ciphertext[EncryptedPrefix.Length..].Split(':');
        if (parts.Length != 3)
        {
            throw new InvalidOperationException("Invalid encrypted format");
        }
        byte[] iv = Convert.FromHexString(parts[0]);
        byte[] encrypted = Convert.FromHexString(parts[1]);
        byte[] authTag = Convert.FromHexString(parts[2]);
        byte[] key = Convert.FromHexString(keyHex);
        byte[] plaintext = new byte[encrypted.Length];
        using var aes = new AesGcm(key, authTag.Length);
        aes.Decrypt(iv, encrypted, authTag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }

    private async Task<string?> CacheGetAsync(string key)
    {
        try
        {
            string? value = await _cache.GetAsync(key).ConfigureAwait(false);
            if (value is not null)
            {
                _lru.Set(key, value); // Backfill LRU on successful cache-adapter read.
                return value;
            }
        }
        catch
        {
            // Cache-adapter failure — fall back to LRU.
        }
        return _lru.Get(key);
    }

    private async Task CacheSetAsync(string key, string value, int ttlSeconds)
    {
        _lru.Set(key, value, ttlSeconds); // Always write to LRU first (synchronous, can't fail).
        try
        {
            await _cache.SetAsync(key, value, ttlSeconds).ConfigureAwait(false);
        }
        catch
        {
            // LRU is set — cache-adapter failure is survivable.
        }
    }

    private async Task CacheDelAsync(string key)
    {
        _lru.Delete(key);
        try
        {
            await _cache.DeleteAsync(key).ConfigureAwait(false);
        }
        catch
        {
            // Best-effort.
        }
    }

    private static string HashToken(string realToken) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(realToken))).ToLowerInvariant();

    /// <summary>
    /// Generate a cryptographically random alias for a real session token. The alias has NO
    /// mathematical relationship to the real token.
    /// </summary>
    public async Task<string> CreateAliasAsync(string realToken, string userId, int ttlSeconds = 3600)
    {
        string tokenHash = HashToken(realToken);

        string? existingAlias = await CacheGetAsync($"cred:alias:{tokenHash}").ConfigureAwait(false);
        if (existingAlias is not null)
        {
            return existingAlias;
        }

        string alias = "df_sid_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        var data = new IsolatedCredentialData(realToken, userId, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        string encryptedData = EncryptValue(JsonSerializer.Serialize(data));

        await CacheSetAsync($"alias:{alias}", encryptedData, ttlSeconds).ConfigureAwait(false);
        await CacheSetAsync($"cred:alias:{tokenHash}", alias, ttlSeconds).ConfigureAwait(false);

        return alias;
    }

    /// <summary>
    /// Resolve an alias back to the real token and user. Called ONLY when a revocation webhook
    /// arrives from DevFortress. Valid for revocation even if the alias is in a "rotating"
    /// state.
    /// </summary>
    public async Task<IsolatedCredentialData?> ResolveAliasAsync(string alias)
    {
        string? raw = await CacheGetAsync($"alias:{alias}").ConfigureAwait(false);
        if (raw is null)
        {
            return null;
        }
        try
        {
            string decrypted = DecryptValue(raw);
            using var doc = JsonDocument.Parse(decrypted);
            var root = doc.RootElement;
            return new IsolatedCredentialData(
                root.GetProperty("realToken").GetString()!,
                root.GetProperty("userId").GetString()!,
                root.GetProperty("createdAt").GetInt64());
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Revoke a session by alias. The real token is resolved within the client app — DevFortress
    /// never touches the real token. On cache failure, falls back to subjectId-level revocation.
    /// Returns the resolved token data so the caller can perform the actual session revocation.
    /// </summary>
    public async Task<IsolatedCredentialData?> RevokeByAliasAsync(string alias, RevocationReason reason = RevocationReason.ActiveThreat, string? subjectId = null)
    {
        try
        {
            var resolved = await ResolveAliasAsync(alias).ConfigureAwait(false);
            if (resolved is null)
            {
                if (subjectId is not null && _onFallbackRevocation is not null)
                {
                    await _onFallbackRevocation(subjectId,
                        $"[DF] alias resolution failed for {alias} — falling back to subjectId revocation").ConfigureAwait(false);
                }
                return null;
            }

            string tokenHash = HashToken(resolved.RealToken);
            await CacheDelAsync($"alias:{alias}").ConfigureAwait(false);
            await CacheDelAsync($"cred:alias:{tokenHash}").ConfigureAwait(false);

            string revocationMarker = JsonSerializer.Serialize(new
            {
                revoked = true,
                reason = reason.ToWireString(),
                revokedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                revocation_scope = "precise",
            });
            await CacheSetAsync($"revoked:alias:{alias}", revocationMarker, 86400).ConfigureAwait(false);

            return resolved;
        }
        catch (Exception error)
        {
            string fallbackSubject = subjectId ?? "unknown";
            if (_onFallbackRevocation is not null)
            {
                await _onFallbackRevocation(fallbackSubject,
                    $"[DF] cache error during RevokeByAliasAsync({alias}) — falling back to subjectId revocation. Error: {error.Message}").ConfigureAwait(false);
            }
            try
            {
                string revocationMarker = JsonSerializer.Serialize(new
                {
                    revoked = true,
                    reason = reason.ToWireString(),
                    revokedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    revocation_scope = "broad",
                });
                await CacheSetAsync($"revoked:alias:{alias}", revocationMarker, 86400).ConfigureAwait(false);
            }
            catch
            {
                // Best-effort.
            }
            return null;
        }
    }

    /// <summary>
    /// Rotate alias — replaces the alias for a live session. The old alias is NOT deleted
    /// immediately; it gets a grace-period TTL and remains resolvable for revocation purposes.
    /// </summary>
    public async Task<string?> RotateAliasAsync(string oldAlias, int ttlSeconds = 3600)
    {
        var resolved = await ResolveAliasAsync(oldAlias).ConfigureAwait(false);
        if (resolved is null)
        {
            return null;
        }

        string encryptedRotating = EncryptValue(JsonSerializer.Serialize(new
        {
            realToken = resolved.RealToken,
            userId = resolved.UserId,
            createdAt = resolved.CreatedAt,
            status = "rotating",
            canCreateNewEvents = false,
        }));
        await CacheSetAsync($"alias:{oldAlias}", encryptedRotating, _rotationGracePeriod).ConfigureAwait(false);

        string tokenHash = HashToken(resolved.RealToken);
        await CacheDelAsync($"cred:alias:{tokenHash}").ConfigureAwait(false);

        return await CreateAliasAsync(resolved.RealToken, resolved.UserId, ttlSeconds).ConfigureAwait(false);
    }

    /// <summary>Clean up alias when user logs out normally. Always call this on logout — don't wait for TTL expiry.</summary>
    public async Task RevokeOnLogoutAsync(string realToken)
    {
        string tokenHash = HashToken(realToken);
        string? alias = await CacheGetAsync($"cred:alias:{tokenHash}").ConfigureAwait(false);
        if (alias is null)
        {
            return;
        }

        string revocationMarker = JsonSerializer.Serialize(new
        {
            revoked = true,
            reason = RevocationReason.Logout.ToWireString(),
            revokedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            revocation_scope = "precise",
        });
        await CacheSetAsync($"revoked:alias:{alias}", revocationMarker, 86400).ConfigureAwait(false);

        await CacheDelAsync($"alias:{alias}").ConfigureAwait(false);
        await CacheDelAsync($"cred:alias:{tokenHash}").ConfigureAwait(false);
    }

    /// <summary>Check if an alias was already revoked (idempotency for webhook retries).</summary>
    public async Task<bool> IsRevokedAsync(string alias) => await CacheGetAsync($"revoked:alias:{alias}").ConfigureAwait(false) is not null;

    /// <summary>Get revocation details for an alias.</summary>
    public async Task<RevocationDetails?> GetRevocationDetailsAsync(string alias)
    {
        string? raw = await CacheGetAsync($"revoked:alias:{alias}").ConfigureAwait(false);
        if (raw is null)
        {
            return null;
        }
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            string reasonStr = root.GetProperty("reason").GetString()!;
            RevocationReason reason = reasonStr switch
            {
                "active_threat" => RevocationReason.ActiveThreat,
                "rotation_expired" => RevocationReason.RotationExpired,
                "logout" => RevocationReason.Logout,
                _ => RevocationReason.ActiveThreat,
            };
            return new RevocationDetails(reason, root.GetProperty("revokedAt").GetInt64(), root.GetProperty("revocation_scope").GetString()!);
        }
        catch
        {
            // Legacy format (just '1').
            return new RevocationDetails(RevocationReason.ActiveThreat, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), "precise");
        }
    }
}
