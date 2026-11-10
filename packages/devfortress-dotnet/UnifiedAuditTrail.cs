using System.Text;
using System.Text.Json;

namespace DevFortress;

/// <summary>Source of an audit decision.</summary>
public enum AuditSource { Internal, External, Hybrid }

/// <summary>One audit record, from any source.</summary>
public sealed record UnifiedAuditEntry(
    string EventId,
    long Timestamp,
    AuditSource Source,
    int Tier,
    string Decision,
    double Score,
    string Severity,
    double LatencyMs,
    string Ip,
    string Path,
    string Method,
    IReadOnlyList<string>? MatchedRules = null,
    string? UserId = null,
    string? AgentId = null,
    string? SessionId = null,
    bool FallbackMode = false,
    IReadOnlyDictionary<string, object?>? Meta = null);

/// <summary>Filters for <see cref="UnifiedAuditTrail.Query"/>; a null field is not applied.</summary>
public sealed record UnifiedAuditQuery(
    AuditSource? Source = null,
    string? Decision = null,
    string? Ip = null,
    string? UserId = null,
    string? AgentId = null,
    double? MinScore = null,
    long? Since = null,
    int Limit = 100);

/// <summary>The result of <see cref="UnifiedAuditTrail.GetStats"/>.</summary>
public sealed record UnifiedAuditStats(
    int Total,
    int InternalDecisions,
    int ExternalDecisions,
    int HybridDecisions,
    int FallbackEvents,
    int TotalBlocks,
    int TotalAllows,
    int TotalRateLimits,
    long AvgInternalLatencyMs,
    long AvgExternalLatencyMs);

/// <summary>The result of <see cref="UnifiedAuditTrail.GetLatencyHistogram"/>.</summary>
public sealed record LatencyHistogram(
    int Under1ms, int Under5ms, int Under50ms, int Under200ms, int Under1s, int Over1s);

/// <summary>
/// DevFortress SDK — Unified Audit Trail (CL-M3). Mirrors
/// <c>packages/devfortress-sdk/src/unified-audit.ts</c>.
/// </summary>
/// <remarks>
/// Merges internal and external closed-loop audit events into a single
/// in-memory timeline with consistent fields regardless of source.
///
/// <para><b>NOTE on tamper-evidence:</b> this is an in-memory log only — it
/// is not cryptographically signed or hash-chained, and neither is Node's
/// own <c>UnifiedAuditTrail</c>. The HMAC-signed, hash-chained
/// tamper-evident audit trail (TODO 265/266/272) is a separate,
/// server-side Next.js module (<c>lib/audit-trail-signer.ts</c>) operating
/// directly on the <c>LiveThreatEvent</c> Postgres table. It has no
/// SDK-side analog in any language, including Node, so this port does not
/// and cannot provide tamper-evidence either.</para>
///
/// <para>Thread-safe.</para>
/// </remarks>
public sealed class UnifiedAuditTrail
{
    private const long DedupWindowMs = 5_000;
    private const int DedupMapCap = 10_000;
    private const int DefaultMaxEntries = 100_000;

    private readonly object _lock = new();
    private readonly List<UnifiedAuditEntry> _entries = new();
    private readonly Dictionary<string, long> _recentEventIds = new();

    private readonly int _maxEntries;
    private readonly Action<UnifiedAuditEntry>? _onEntry;
    private readonly bool _debug;

    private int _internalDecisions, _externalDecisions, _hybridDecisions;
    private int _fallbackEvents, _totalBlocks, _totalAllows, _totalRateLimits;
    private double _internalLatencySum, _externalLatencySum;

    public UnifiedAuditTrail(int maxEntries = DefaultMaxEntries, Action<UnifiedAuditEntry>? onEntry = null, bool debug = false)
    {
        _maxEntries = maxEntries > 0 ? maxEntries : DefaultMaxEntries;
        _onEntry = onEntry;
        _debug = debug;
    }

    /// <summary>
    /// Records an audit entry from any source. S27: the same EventId
    /// within the 5s dedup window is merged (external overrides
    /// internal), not duplicated.
    /// </summary>
    public void Record(UnifiedAuditEntry entry)
    {
        UnifiedAuditEntry? fired = null;

        lock (_lock)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (_recentEventIds.TryGetValue(entry.EventId, out long existing) && (now - existing) < DedupWindowMs)
            {
                if (entry.Source == AuditSource.External)
                {
                    for (int i = 0; i < _entries.Count; i++)
                    {
                        UnifiedAuditEntry e = _entries[i];
                        if (e.EventId == entry.EventId && e.Source == AuditSource.Internal)
                        {
                            _entries[i] = entry with { Source = AuditSource.Hybrid };
                            if (_debug)
                            {
                                Console.Error.WriteLine($"[DF Audit] DEDUP: merged {entry.EventId} (external overrides internal)");
                            }
                            break;
                        }
                    }
                }
                return;
            }

            _recentEventIds[entry.EventId] = now;
            if (_recentEventIds.Count > DedupMapCap)
            {
                long cutoff = now - DedupWindowMs;
                foreach (string id in _recentEventIds.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                {
                    _recentEventIds.Remove(id);
                }
            }

            if (_entries.Count >= _maxEntries)
            {
                int evict = (int)(_maxEntries * 0.1);
                _entries.RemoveRange(0, Math.Min(evict, _entries.Count));
            }
            _entries.Add(entry);
            UpdateStats(entry);
            fired = entry;
        }

        if (fired != null && _onEntry != null)
        {
            try
            {
                _onEntry(fired);
            }
            catch
            {
                // Callback errors must not break the audit trail.
            }
        }

        if (_debug && fired != null)
        {
            Console.Error.WriteLine(
                $"[DF Audit] {entry.Source}:tier{entry.Tier} {entry.Decision} score={entry.Score} " +
                $"{entry.Ip} {entry.Method} {entry.Path} ({entry.LatencyMs}ms)");
        }
    }

    /// <summary>Queries audit entries matching <paramref name="query"/>, most recent last, capped at its Limit (default 100).</summary>
    public IReadOnlyList<UnifiedAuditEntry> Query(UnifiedAuditQuery? query = null)
    {
        query ??= new UnifiedAuditQuery();

        List<UnifiedAuditEntry> result;
        lock (_lock)
        {
            result = new List<UnifiedAuditEntry>(_entries);
        }

        if (query.Source is { } source)
        {
            result = result.Where(e => e.Source == source).ToList();
        }
        if (query.Decision is { } decision)
        {
            result = result.Where(e => e.Decision == decision).ToList();
        }
        if (query.Ip is { } ip)
        {
            result = result.Where(e => e.Ip == ip).ToList();
        }
        if (query.UserId is { } userId)
        {
            result = result.Where(e => e.UserId == userId).ToList();
        }
        if (query.AgentId is { } agentId)
        {
            result = result.Where(e => e.AgentId == agentId).ToList();
        }
        if (query.MinScore is { } minScore)
        {
            result = result.Where(e => e.Score >= minScore).ToList();
        }
        if (query.Since is { } since)
        {
            result = result.Where(e => e.Timestamp >= since).ToList();
        }

        int limit = query.Limit > 0 ? query.Limit : 100;
        return result.Count > limit ? result.Skip(result.Count - limit).ToList() : result;
    }

    /// <summary>Returns aggregated statistics.</summary>
    public UnifiedAuditStats GetStats()
    {
        lock (_lock)
        {
            long avgInternal = _internalDecisions > 0 ? (long)Math.Round(_internalLatencySum / _internalDecisions) : 0;
            long avgExternal = _externalDecisions > 0 ? (long)Math.Round(_externalLatencySum / _externalDecisions) : 0;
            return new UnifiedAuditStats(_entries.Count, _internalDecisions, _externalDecisions, _hybridDecisions,
                _fallbackEvents, _totalBlocks, _totalAllows, _totalRateLimits, avgInternal, avgExternal);
        }
    }

    /// <summary>Returns source:decision counts, for dashboard visualization.</summary>
    public IReadOnlyDictionary<string, int> GetDecisionDistribution()
    {
        List<UnifiedAuditEntry> snapshot;
        lock (_lock)
        {
            snapshot = new List<UnifiedAuditEntry>(_entries);
        }

        var dist = new Dictionary<string, int>();
        foreach (UnifiedAuditEntry e in snapshot)
        {
            string key = $"{e.Source}:{e.Decision}";
            dist[key] = dist.GetValueOrDefault(key) + 1;
        }
        return dist;
    }

    /// <summary>Returns latency histogram buckets.</summary>
    public LatencyHistogram GetLatencyHistogram()
    {
        List<UnifiedAuditEntry> snapshot;
        lock (_lock)
        {
            snapshot = new List<UnifiedAuditEntry>(_entries);
        }

        int under1Ms = 0, under5Ms = 0, under50Ms = 0, under200Ms = 0, under1S = 0, over1S = 0;
        foreach (UnifiedAuditEntry e in snapshot)
        {
            if (e.LatencyMs < 1) under1Ms++;
            else if (e.LatencyMs < 5) under5Ms++;
            else if (e.LatencyMs < 50) under50Ms++;
            else if (e.LatencyMs < 200) under200Ms++;
            else if (e.LatencyMs < 1000) under1S++;
            else over1S++;
        }
        return new LatencyHistogram(under1Ms, under5Ms, under50Ms, under200Ms, under1S, over1S);
    }

    /// <summary>Exports entries as JSON (for compliance/archival).</summary>
    public string ExportJson(long? since = null)
    {
        List<UnifiedAuditEntry> snapshot;
        lock (_lock)
        {
            snapshot = new List<UnifiedAuditEntry>(_entries);
        }
        if (since is { } s)
        {
            snapshot = snapshot.Where(e => e.Timestamp >= s).ToList();
        }

        return JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Resets the audit trail (for testing).</summary>
    public void Reset()
    {
        lock (_lock)
        {
            _entries.Clear();
            _recentEventIds.Clear();
            _internalDecisions = _externalDecisions = _hybridDecisions = 0;
            _fallbackEvents = _totalBlocks = _totalAllows = _totalRateLimits = 0;
            _internalLatencySum = _externalLatencySum = 0;
        }
    }

    /// <summary>Must be called with <see cref="_lock"/> held.</summary>
    private void UpdateStats(UnifiedAuditEntry entry)
    {
        switch (entry.Source)
        {
            case AuditSource.Internal:
                _internalDecisions++;
                _internalLatencySum += entry.LatencyMs;
                break;
            case AuditSource.External:
                _externalDecisions++;
                _externalLatencySum += entry.LatencyMs;
                break;
            default:
                _hybridDecisions++;
                if (entry.Tier > 0)
                {
                    _internalLatencySum += entry.LatencyMs;
                }
                else
                {
                    _externalLatencySum += entry.LatencyMs;
                }
                break;
        }

        if (entry.FallbackMode)
        {
            _fallbackEvents++;
        }

        switch (entry.Decision)
        {
            case "block": _totalBlocks++; break;
            case "allow": _totalAllows++; break;
            case "rate_limit": _totalRateLimits++; break;
        }
    }
}
