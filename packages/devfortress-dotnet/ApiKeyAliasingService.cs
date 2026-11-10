using System.Security.Cryptography;
using System.Text.Json;

namespace DevFortress;

/// <summary>
/// API Key Aliasing Service (A19). Mirrors <c>packages/devfortress-sdk/src/api-key-aliasing.ts</c>.
/// Provides alias lifecycle management for API keys: create, rotate, revoke, inspect, and audit.
/// Each alias is scoped to a workload (CI, agent, browser, server) with fingerprint and scope
/// binding. Forward-map storage uses <see cref="CredentialVault"/> (real AES-256-GCM).
/// </summary>
public enum AliasWorkload { Ci, Agent, Plugin, Browser, Server, Custom }
public enum AliasState { Active, Rotating, Revoked, Expired }

public sealed class AliasConfig
{
    public int MaxAliasesPerKey { get; set; } = 50;
    public long RotationOverlapMs { get; set; } = 300_000;
    public int MaxPrimaryKeys { get; set; } = 10_000;
    public bool AnomalyDetection { get; set; } = true;
    public int CreationBurstThreshold { get; set; } = 10;
    /// <summary>
    /// Application secret used to derive the forward-map's AES-256-GCM vault key. If omitted, a
    /// random per-instance key is generated at construction time — alias keys remain resolvable
    /// for the lifetime of this service instance, but not across process restarts.
    /// </summary>
    public string? VaultSecret { get; set; }
}

public sealed class AliasRecord
{
    public required string AliasId { get; init; }
    public required string AliasKeyEncrypted { get; set; } // encrypted in storage
    public required string PrimaryKeyHash { get; init; }
    public required AliasWorkload Workload { get; init; }
    public required string Label { get; init; }
    public AliasState State { get; set; }
    public string? Fingerprint { get; init; }
    public IReadOnlyList<string>? Scope { get; init; }
    public required long CreatedAt { get; init; }
    public long? ExpiresAt { get; set; }
    public long LastUsedAt { get; set; }
    public string? RotatedFromId { get; set; }
    public string? RotatedToId { get; set; }
    public int UsageCount { get; set; }
}

public enum AliasAuditEventType { AliasCreated, AliasRotated, AliasRevoked, AliasMisuseDetected, AliasExpired, AliasUsed }

public sealed record AliasAuditEvent(
    AliasAuditEventType Type, string AliasId, string PrimaryKeyHash, AliasWorkload Workload,
    long Timestamp, IReadOnlyDictionary<string, object?>? Metadata = null);

public sealed record AliasCreationResult(bool Success, AliasRecord? Alias = null, string? AliasKey = null, string? Error = null);
public sealed record AliasRotationResult(bool Success, string? OldAliasId = null, AliasRecord? NewAlias = null,
    string? NewAliasKey = null, long? OverlapExpiresAt = null, string? Error = null);
public sealed record AliasValidationResult(bool Valid, string? AliasId, AliasWorkload? Workload,
    string? PrimaryKeyHash, string Reason, bool AnomalyDetected = false);
public sealed record AliasStats(int TotalAliases, int ActiveAliases, int RotatingAliases, int RevokedAliases,
    IReadOnlyDictionary<AliasWorkload, int> ByWorkload, int RecentAnomalies);

/// <summary>API Key Aliasing Service (Invention A19). Patent Pending — KIPI KE/P/2026/005972.</summary>
public sealed class ApiKeyAliasingService(AliasConfig? config = null)
{
    private readonly AliasConfig _config = config ?? new AliasConfig();
    private readonly Dictionary<string, AliasRecord> _aliases = [];
    private readonly Dictionary<string, string> _aliasKeyIndex = []; // aliasKeyHash -> aliasId
    private readonly Dictionary<string, HashSet<string>> _primaryKeyAliases = [];
    private readonly List<AliasAuditEvent> _auditLog = [];
    private readonly List<long> _creationTimestamps = [];
    private readonly byte[] _vaultKey = string.IsNullOrEmpty(config?.VaultSecret)
        ? RandomNumberGenerator.GetBytes(32)
        : CredentialVault.DeriveVaultKey(config.VaultSecret, "api-key-aliasing");
    private readonly object _lock = new();

    /// <summary>Create a new alias for a primary API key.</summary>
    public AliasCreationResult CreateAlias(string primaryKeyHash, AliasWorkload workload, string label,
        string? fingerprint = null, IReadOnlyList<string>? scope = null, long? expiresInMs = null)
    {
        lock (_lock)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            if (_primaryKeyAliases.TryGetValue(primaryKeyHash, out var existing) && existing.Count >= _config.MaxAliasesPerKey)
            {
                return new AliasCreationResult(false, Error: $"Maximum aliases ({_config.MaxAliasesPerKey}) reached for this key");
            }

            if (_config.AnomalyDetection)
            {
                _creationTimestamps.Add(now);
                int recentCreations = _creationTimestamps.Count(t => now - t <= 3_600_000);
                if (recentCreations > _config.CreationBurstThreshold)
                {
                    EmitAudit(new AliasAuditEvent(AliasAuditEventType.AliasMisuseDetected, "N/A", primaryKeyHash, workload, now,
                        new Dictionary<string, object?> { ["reason"] = "creation_burst", ["count"] = recentCreations }));
                    return new AliasCreationResult(false, Error: $"Alias creation burst detected: {recentCreations} in 1 hour");
                }
            }

            string aliasId = "alias_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            string aliasKey = "vx_alias_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
            string aliasKeyHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(aliasKey))).ToLowerInvariant();

            var record = new AliasRecord
            {
                AliasId = aliasId,
                AliasKeyEncrypted = EncryptAliasKey(aliasKey, primaryKeyHash),
                PrimaryKeyHash = primaryKeyHash,
                Workload = workload,
                Label = label,
                State = AliasState.Active,
                Fingerprint = fingerprint,
                Scope = scope,
                CreatedAt = now,
                ExpiresAt = expiresInMs.HasValue ? now + expiresInMs.Value : null,
                LastUsedAt = now,
                UsageCount = 0,
            };

            _aliases[aliasId] = record;
            _aliasKeyIndex[aliasKeyHash] = aliasId;
            if (!_primaryKeyAliases.TryGetValue(primaryKeyHash, out var set))
            {
                set = [];
                _primaryKeyAliases[primaryKeyHash] = set;
            }
            set.Add(aliasId);

            EmitAudit(new AliasAuditEvent(AliasAuditEventType.AliasCreated, aliasId, primaryKeyHash, workload, now,
                new Dictionary<string, object?> { ["label"] = label, ["hasFingerprint"] = fingerprint is not null, ["scope"] = scope }));

            return new AliasCreationResult(true, record, aliasKey);
        }
    }

    /// <summary>Rotate an alias with zero-downtime overlap window.</summary>
    public AliasRotationResult RotateAlias(string aliasId)
    {
        lock (_lock)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (!_aliases.TryGetValue(aliasId, out var oldAlias) || oldAlias.State != AliasState.Active)
            {
                return new AliasRotationResult(false, Error: $"Alias {aliasId} not found or not active");
            }

            oldAlias.State = AliasState.Rotating;
            oldAlias.ExpiresAt = now + _config.RotationOverlapMs;

            var result = CreateAlias(oldAlias.PrimaryKeyHash, oldAlias.Workload, $"{oldAlias.Label} (rotated)",
                oldAlias.Fingerprint, oldAlias.Scope);

            if (!result.Success || result.Alias is null)
            {
                oldAlias.State = AliasState.Active; // Rollback.
                return new AliasRotationResult(false, Error: result.Error);
            }

            oldAlias.RotatedToId = result.Alias.AliasId;
            result.Alias.RotatedFromId = aliasId;

            EmitAudit(new AliasAuditEvent(AliasAuditEventType.AliasRotated, aliasId, oldAlias.PrimaryKeyHash, oldAlias.Workload, now,
                new Dictionary<string, object?> { ["newAliasId"] = result.Alias.AliasId, ["overlapMs"] = _config.RotationOverlapMs }));

            return new AliasRotationResult(true, aliasId, result.Alias, result.AliasKey, oldAlias.ExpiresAt);
        }
    }

    /// <summary>Revoke a specific alias without affecting other aliases.</summary>
    public bool RevokeAlias(string aliasId, string? reason = null)
    {
        lock (_lock)
        {
            if (!_aliases.TryGetValue(aliasId, out var alias))
            {
                return false;
            }
            alias.State = AliasState.Revoked;
            EmitAudit(new AliasAuditEvent(AliasAuditEventType.AliasRevoked, aliasId, alias.PrimaryKeyHash, alias.Workload,
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                new Dictionary<string, object?> { ["reason"] = reason ?? "manual_revocation" }));
            return true;
        }
    }

    /// <summary>Validate an alias key for incoming requests.</summary>
    public AliasValidationResult ValidateAliasKey(string aliasKey, string? fingerprint = null)
    {
        lock (_lock)
        {
            string aliasKeyHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(aliasKey))).ToLowerInvariant();
            if (!_aliasKeyIndex.TryGetValue(aliasKeyHash, out var aliasId))
            {
                return new AliasValidationResult(false, null, null, null, "Unknown alias key");
            }
            if (!_aliases.TryGetValue(aliasId, out var alias))
            {
                return new AliasValidationResult(false, null, null, null, "Alias record not found");
            }

            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            if (alias.State == AliasState.Revoked)
            {
                return new AliasValidationResult(false, aliasId, alias.Workload, null, "Alias has been revoked");
            }

            if (alias.ExpiresAt.HasValue && now > alias.ExpiresAt.Value)
            {
                alias.State = AliasState.Expired;
                EmitAudit(new AliasAuditEvent(AliasAuditEventType.AliasExpired, aliasId, alias.PrimaryKeyHash, alias.Workload, now));
                return new AliasValidationResult(false, aliasId, alias.Workload, null, "Alias has expired");
            }

            bool anomalyDetected = false;
            if (alias.Fingerprint is not null && fingerprint is not null && alias.Fingerprint != fingerprint)
            {
                anomalyDetected = true;
                EmitAudit(new AliasAuditEvent(AliasAuditEventType.AliasMisuseDetected, aliasId, alias.PrimaryKeyHash, alias.Workload, now,
                    new Dictionary<string, object?> { ["reason"] = "fingerprint_mismatch", ["expectedFingerprint"] = alias.Fingerprint[..Math.Min(8, alias.Fingerprint.Length)] }));
            }

            alias.LastUsedAt = now;
            alias.UsageCount++;

            EmitAudit(new AliasAuditEvent(AliasAuditEventType.AliasUsed, aliasId, alias.PrimaryKeyHash, alias.Workload, now));

            return new AliasValidationResult(!anomalyDetected, aliasId, alias.Workload, alias.PrimaryKeyHash,
                anomalyDetected ? "Fingerprint mismatch detected" : "Valid alias", anomalyDetected);
        }
    }

    /// <summary>List all aliases for a primary key.</summary>
    public IReadOnlyList<AliasRecord> ListAliases(string primaryKeyHash)
    {
        lock (_lock)
        {
            if (!_primaryKeyAliases.TryGetValue(primaryKeyHash, out var ids))
            {
                return [];
            }
            return ids.Select(id => _aliases.GetValueOrDefault(id)).Where(a => a is not null)
                .Select(a => new AliasRecord
                {
                    AliasId = a!.AliasId, AliasKeyEncrypted = "[REDACTED]", PrimaryKeyHash = a.PrimaryKeyHash,
                    Workload = a.Workload, Label = a.Label, State = a.State, Fingerprint = a.Fingerprint,
                    Scope = a.Scope, CreatedAt = a.CreatedAt, ExpiresAt = a.ExpiresAt, LastUsedAt = a.LastUsedAt,
                    RotatedFromId = a.RotatedFromId, RotatedToId = a.RotatedToId, UsageCount = a.UsageCount,
                }).ToList();
        }
    }

    /// <summary>Get alias statistics.</summary>
    public AliasStats GetStats()
    {
        lock (_lock)
        {
            int active = 0, rotating = 0, revoked = 0;
            var byWorkload = Enum.GetValues<AliasWorkload>().ToDictionary(w => w, _ => 0);
            foreach (var alias in _aliases.Values)
            {
                if (alias.State == AliasState.Active) active++;
                else if (alias.State == AliasState.Rotating) rotating++;
                else if (alias.State == AliasState.Revoked) revoked++;
                byWorkload[alias.Workload]++;
            }
            long oneHourAgo = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 3_600_000;
            int recentAnomalies = _auditLog.Count(e => e.Type == AliasAuditEventType.AliasMisuseDetected && e.Timestamp > oneHourAgo);
            return new AliasStats(_aliases.Count, active, rotating, revoked, byWorkload, recentAnomalies);
        }
    }

    /// <summary>Get audit log entries.</summary>
    public IReadOnlyList<AliasAuditEvent> GetAuditLog(int limit = 100)
    {
        lock (_lock)
        {
            return _auditLog.Skip(Math.Max(0, _auditLog.Count - limit)).ToList();
        }
    }

    /// <summary>
    /// AES-256-GCM encrypt the alias key for forward-map storage. Genuinely reversible via
    /// <see cref="Resolve"/>, unlike an HMAC-SHA256 digest (one-way, never decryptable).
    /// </summary>
    private string EncryptAliasKey(string aliasKey, string primaryKeyHash)
    {
        var record = CredentialVault.Encrypt($"{primaryKeyHash}:{aliasKey}", _vaultKey);
        return JsonSerializer.Serialize(record);
    }

    /// <summary>
    /// Resolve a stored alias back to its real alias key. Returns null for an unknown/revoked/
    /// expired alias, or if the stored ciphertext fails auth-tag verification (tampered/corrupted).
    /// </summary>
    public string? Resolve(string aliasId)
    {
        lock (_lock)
        {
            if (!_aliases.TryGetValue(aliasId, out var alias) || alias.State is AliasState.Revoked or AliasState.Expired)
            {
                return null;
            }

            CredentialVault.VaultEncryptedRecord record;
            try
            {
                var parsed = JsonSerializer.Deserialize<JsonElement>(alias.AliasKeyEncrypted);
                record = new CredentialVault.VaultEncryptedRecord(
                    parsed.GetProperty("Ciphertext").GetString()!,
                    parsed.GetProperty("Iv").GetString()!,
                    parsed.GetProperty("AuthTag").GetString()!);
            }
            catch
            {
                return null;
            }

            try
            {
                string decrypted = CredentialVault.Decrypt(record, _vaultKey);
                int separatorIndex = decrypted.IndexOf(':');
                return separatorIndex == -1 ? decrypted : decrypted[(separatorIndex + 1)..];
            }
            catch
            {
                // Auth-tag verification failed — do not return garbage plaintext.
                return null;
            }
        }
    }

    private void EmitAudit(AliasAuditEvent @event)
    {
        _auditLog.Add(@event);
        if (_auditLog.Count > 10_000)
        {
            _auditLog.RemoveRange(0, _auditLog.Count - 10_000);
        }
    }
}
