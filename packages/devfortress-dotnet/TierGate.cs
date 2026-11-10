using System.Reflection;

namespace DevFortress;

/// <summary>
/// Closed-loop mode. Mirrors the <c>CLMode</c> type in
/// <c>packages/devfortress-sdk/src/types.ts</c> (<c>'external' | 'internal' | 'hybrid'</c>).
/// </summary>
public enum CLMode { External, Internal, Hybrid }

public static class CLModeExtensions
{
    public static string ToWireString(this CLMode mode) => mode switch
    {
        CLMode.External => "external",
        CLMode.Internal => "internal",
        CLMode.Hybrid => "hybrid",
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, null),
    };
}

/// <summary>
/// Subscription tier. Mirrors tier-gate.ts's <c>SubscriptionTier</c> union
/// (<c>'starter' | 'pro' | 'team' | 'enterprise'</c>). Declared independently of
/// <see cref="LicenseState.Tier"/> (a plain wire string), matching Node, where
/// license-manager.ts and tier-gate.ts do not import each other's tier type.
/// </summary>
public enum SubscriptionTier { Starter, Pro, Team, Enterprise }

public static class SubscriptionTierExtensions
{
    public static string ToWireString(this SubscriptionTier tier) => tier switch
    {
        SubscriptionTier.Starter => "starter",
        SubscriptionTier.Pro => "pro",
        SubscriptionTier.Team => "team",
        SubscriptionTier.Enterprise => "enterprise",
        _ => throw new ArgumentOutOfRangeException(nameof(tier), tier, null),
    };

    /// <summary>Parses a platform wire tier string (e.g. from <see cref="LicenseState.Tier"/>) into a <see cref="SubscriptionTier"/>.</summary>
    public static SubscriptionTier ParseSubscriptionTier(string wire) => wire switch
    {
        "starter" => SubscriptionTier.Starter,
        "pro" => SubscriptionTier.Pro,
        "team" => SubscriptionTier.Team,
        "enterprise" => SubscriptionTier.Enterprise,
        _ => throw new ArgumentException($"devfortress: unknown subscription tier '{wire}'", nameof(wire)),
    };
}

/// <summary>Per-tier feature/limit matrix. Mirrors tier-gate.ts's <c>TierCapabilities</c> interface.</summary>
public sealed record TierCapabilities(
    /// <summary>Can observe/collect events.</summary>
    bool CanObserve,
    /// <summary>Can execute blocking actions.</summary>
    bool CanBlock,
    /// <summary>Allowed closed-loop modes.</summary>
    IReadOnlyList<CLMode> AllowedModes,
    /// <summary>Default mode for this tier.</summary>
    CLMode DefaultMode,
    /// <summary>Whether hybrid is an add-on (requires extra payment).</summary>
    bool HybridIsAddon,
    /// <summary>Internal CL acts as backup only (historical Pro behavior).</summary>
    bool InternalAsBackupOnly,
    /// <summary>Can configure custom rules.</summary>
    bool CanConfigureRules,
    /// <summary>Can access the audit trail.</summary>
    bool CanAccessAudit,
    /// <summary>Can manage webhook secrets.</summary>
    bool CanManageWebhooks,
    /// <summary>Maximum events per day (0 = unlimited).</summary>
    int MaxEventsPerDay,
    /// <summary>Maximum blocked IPs (0 = unlimited).</summary>
    int MaxBlockedIPs,
    /// <summary>CV-S2: ICL tiers available: 0=none, 1=deterministic, 2=ML, 3=full.</summary>
    int IclMaxTier,
    /// <summary>CV-S2: whether air-gap (offline) mode is available.</summary>
    bool AirGapEnabled,
    /// <summary>CV-S2: whether custom ICL rules are available.</summary>
    bool CustomRulesEnabled,
    /// <summary>CV-S3: maximum events per month (0 = unlimited).</summary>
    int MaxEventsPerMonth,
    /// <summary>CV-S4: platform alert channels (email/Slack/PagerDuty) available.</summary>
    bool PlatformAlerts,
    /// <summary>CV-S5: cross-instance shared state (IP blocklists, baselines) via platform.</summary>
    bool SharedState,
    /// <summary>CV-S6: compliance evidence generation (PDF reports, audit exports).</summary>
    bool ComplianceEvidence);

/// <summary>S15: serializable snapshot of <see cref="TierGate"/>'s mutable state.</summary>
public sealed record TierGateSnapshot(
    SubscriptionTier Tier,
    bool HybridAddonEnabled,
    long DailyEventCount,
    long DailyResetTime,
    long MonthlyEventCount,
    long MonthlyResetTime,
    long SnapshotTimestamp);

/// <summary>Result of <see cref="TierGate.CheckEventLimit"/>. <see cref="Remaining"/> is <see cref="double.PositiveInfinity"/> when unlimited.</summary>
public readonly record struct EventLimitResult(bool Allowed, double Remaining);

/// <summary>Result of <see cref="TierGate.CheckMonthlyQuota"/>. <see cref="Remaining"/> is <see cref="double.PositiveInfinity"/> when unlimited.</summary>
public readonly record struct MonthlyQuotaResult(bool Allowed, double Remaining, int Limit);

/// <summary>Result of <see cref="TierGate.GetMonthlyUsage"/>.</summary>
public readonly record struct MonthlyUsage(long Used, int Limit, int PercentUsed);

/// <summary>
/// Tier Gating &amp; Feature Access Control. Mirrors
/// <c>packages/devfortress-sdk/src/tier-gate.ts</c>. Enforces feature access based on
/// subscription tier:
/// <list type="bullet">
/// <item>Starter: observe events; response is webhook-dispatched and self-executed by the
/// customer (no platform-side blocking).</item>
/// <item>Pro: view + block via external CL only — no internal/hybrid, not even as an add-on
/// (Package A, 2026-08-28).</item>
/// <item>Team: external, internal, and hybrid all available as first-class capabilities
/// (default: hybrid) — the entry point for internal/hybrid CL under Package A.</item>
/// <item>Enterprise: can select internal, external, or hybrid (default: hybrid with internal
/// backup, external primary).</item>
/// </list>
/// </summary>
/// <remarks>
/// Depends on a tier resolved elsewhere (typically <see cref="LicenseManager"/>'s platform
/// check, bridged via <see cref="SubscriptionTierExtensions.ParseSubscriptionTier"/>) — this
/// class only enforces the capability matrix for whatever tier it is constructed with.
/// </remarks>
public sealed class TierGate
{
    private static readonly IReadOnlyDictionary<SubscriptionTier, TierCapabilities> Matrix = new Dictionary<SubscriptionTier, TierCapabilities>
    {
        [SubscriptionTier.Starter] = new TierCapabilities(
            CanObserve: true, CanBlock: false, AllowedModes: [CLMode.External], DefaultMode: CLMode.External,
            HybridIsAddon: false, InternalAsBackupOnly: false, CanConfigureRules: false, CanAccessAudit: false,
            CanManageWebhooks: false, MaxEventsPerDay: 10_000, MaxBlockedIPs: 0,
            // CV-S2: Starter gets Tier 1 deterministic rules only
            IclMaxTier: 1, AirGapEnabled: false, CustomRulesEnabled: false,
            // CV-S3: 50K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
            MaxEventsPerMonth: 50_000,
            // CV-S4: no platform alerts; CV-S5: no shared state; CV-S6: no compliance evidence
            PlatformAlerts: false, SharedState: false, ComplianceEvidence: false),

        [SubscriptionTier.Pro] = new TierCapabilities(
            CanObserve: true, CanBlock: true,
            // Package A (2026-08-28): Pro gets External CL only, at no point in time does it
            // get ICL/hybrid — differentiation comes from platform-executed response,
            // post-auth detection, alias isolation, and AI insights, never from CL mode depth.
            // Internal/Hybrid access starts at Team.
            AllowedModes: [CLMode.External], DefaultMode: CLMode.External,
            HybridIsAddon: false, InternalAsBackupOnly: false, CanConfigureRules: false, CanAccessAudit: true,
            CanManageWebhooks: true, MaxEventsPerDay: 100_000, MaxBlockedIPs: 1_000,
            // CV-S2: Pro has no ICL access — External CL only (Package A)
            IclMaxTier: 0, AirGapEnabled: false, CustomRulesEnabled: false,
            // CV-S3: 75K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
            MaxEventsPerMonth: 75_000,
            // CV-S4: platform alerts enabled; CV-S5: shared state enabled;
            // CV-S6: no compliance evidence (Enterprise only)
            PlatformAlerts: true, SharedState: true, ComplianceEvidence: false),

        [SubscriptionTier.Team] = new TierCapabilities(
            CanObserve: true, CanBlock: true,
            // Package A (2026-08-28): Team is the new entry point for Internal/Hybrid CL —
            // takes on the internal/hybrid capability profile Pro used to have, but as a
            // first-class capability (no add-on gate, no backup-only limit).
            AllowedModes: [CLMode.External, CLMode.Internal, CLMode.Hybrid], DefaultMode: CLMode.Hybrid,
            HybridIsAddon: false, InternalAsBackupOnly: false, CanConfigureRules: false, CanAccessAudit: true,
            CanManageWebhooks: true,
            MaxEventsPerDay: 0, // Unlimited (ingestion rate; monthly billing quota below still caps flagged events)
            MaxBlockedIPs: 5_000,
            // CV-S2: Team gets Tier 1 + Tier 2 ML (same ceiling Pro used to have)
            IclMaxTier: 2, AirGapEnabled: false, CustomRulesEnabled: false,
            // CV-S3: 100K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
            MaxEventsPerMonth: 100_000,
            // CV-S4: platform alerts enabled; CV-S5: shared state enabled;
            // CV-S6: compliance evidence generation (matches Team's advertised compliance PDF reports)
            PlatformAlerts: true, SharedState: true, ComplianceEvidence: true),

        [SubscriptionTier.Enterprise] = new TierCapabilities(
            CanObserve: true, CanBlock: true,
            AllowedModes: [CLMode.External, CLMode.Internal, CLMode.Hybrid], DefaultMode: CLMode.Hybrid,
            HybridIsAddon: false, InternalAsBackupOnly: false, CanConfigureRules: true, CanAccessAudit: true,
            CanManageWebhooks: true,
            MaxEventsPerDay: 0, // Unlimited
            MaxBlockedIPs: 0, // Unlimited
            // CV-S2: Enterprise gets all tiers + air-gap + custom rules
            IclMaxTier: 3, AirGapEnabled: true, CustomRulesEnabled: true,
            // CV-S3: unlimited events/month
            MaxEventsPerMonth: 0,
            // CV-S4/S5/S6: full alert channels, full shared state, compliance evidence generation
            PlatformAlerts: true, SharedState: true, ComplianceEvidence: true),
    };

    private readonly SubscriptionTier _tier;
    private readonly TierCapabilities _capabilities;
    private readonly bool _hybridAddonEnabled;
    private long _dailyEventCount;
    private long _dailyResetTime;
    private long _monthlyEventCount;
    private long _monthlyResetTime;

    public TierGate(SubscriptionTier tier, bool hybridAddonEnabled = false)
    {
        _tier = tier;
        _capabilities = Matrix[tier];
        _hybridAddonEnabled = hybridAddonEnabled;
        _dailyResetTime = TodayStartMs();
        _monthlyResetTime = MonthStartMs();
    }

    // Both reset boundaries are computed in the local system timezone, matching Node's
    // `new Date().setHours(0,0,0,0)` / `new Date(y, m, 1)`, which are local-time APIs — ported
    // faithfully rather than switched to UTC, which would change reset-boundary behavior.
    private static long TodayStartMs() => new DateTimeOffset(DateTime.Today).ToUnixTimeMilliseconds();

    private static long MonthStartMs()
    {
        var now = DateTime.Now;
        var monthStart = new DateTime(now.Year, now.Month, 1, 0, 0, 0, DateTimeKind.Local);
        return new DateTimeOffset(monthStart).ToUnixTimeMilliseconds();
    }

    /// <summary>Gets the effective closed-loop mode for this tier, validating the requested mode against tier permissions.</summary>
    public CLMode GetEffectiveMode(CLMode? requestedMode = null)
    {
        if (requestedMode is not { } mode)
        {
            return _capabilities.DefaultMode;
        }

        if (!_capabilities.AllowedModes.Contains(mode))
        {
            return _capabilities.DefaultMode;
        }

        // Pro tier: hybrid requires an add-on. HybridIsAddon is false for every tier in the
        // current matrix, so this branch is presently unreachable — ported faithfully from
        // Node rather than dropped, since a future pricing change could re-enable it.
        if (_tier == SubscriptionTier.Pro && mode == CLMode.Hybrid && _capabilities.HybridIsAddon && !_hybridAddonEnabled)
        {
            return CLMode.External;
        }

        return mode;
    }

    /// <summary>Whether blocking is allowed for this tier.</summary>
    public bool CanBlock() => _capabilities.CanBlock;

    /// <summary>Checks whether the daily event limit has been reached.</summary>
    public EventLimitResult CheckEventLimit()
    {
        long dayStart = TodayStartMs();
        if (_dailyResetTime < dayStart)
        {
            _dailyEventCount = 0;
            _dailyResetTime = dayStart;
        }

        if (_capabilities.MaxEventsPerDay == 0)
        {
            return new EventLimitResult(true, double.PositiveInfinity);
        }

        long remaining = _capabilities.MaxEventsPerDay - _dailyEventCount;
        return new EventLimitResult(remaining > 0, Math.Max(0, remaining));
    }

    /// <summary>Records an event (for daily limit tracking).</summary>
    public void RecordEvent() => _dailyEventCount++;

    /// <summary>
    /// Checks whether a specific feature is available for this tier, looked up by
    /// <see cref="TierCapabilities"/> property name (mirrors Node's
    /// <c>hasFeature(feature: keyof TierCapabilities)</c>).
    /// </summary>
    public bool HasFeature(string feature)
    {
        var prop = typeof(TierCapabilities).GetProperty(feature, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
        if (prop is null) return false;
        object? value = prop.GetValue(_capabilities);
        return value switch
        {
            bool b => b,
            // Node: `typeof value === 'number' ? value > 0 || value === 0 : ...` — true for
            // every non-negative number, which is every number this matrix ever stores. Ported
            // faithfully, including the quirk that a hypothetical negative value would read false.
            int i => i >= 0,
            IReadOnlyList<CLMode> list => list.Count > 0,
            _ => false,
        };
    }

    /// <summary>Gets the full capability matrix entry for this tier.</summary>
    public TierCapabilities GetCapabilities() => _capabilities;

    /// <summary>Gets the current tier.</summary>
    public SubscriptionTier GetTier() => _tier;

    /// <summary>Validates a blocking action against tier permissions. Returns an error message if not allowed, null if allowed.</summary>
    public string? ValidateBlockAction(string action)
    {
        if (!_capabilities.CanBlock)
        {
            return $"Blocking is not available on the {_tier.ToWireString()} tier. Upgrade to Pro or Enterprise to enable blocking.";
        }

        if (_capabilities.MaxBlockedIPs > 0 && action == "block_ip")
        {
            // Caller should check the actual blocked count against this limit.
            return null;
        }

        return null;
    }

    /// <summary>Validates a mode selection against tier permissions. Returns an error message if not allowed, null if allowed.</summary>
    public string? ValidateMode(CLMode mode)
    {
        if (!_capabilities.AllowedModes.Contains(mode))
        {
            string allowed = string.Join(", ", _capabilities.AllowedModes.Select(m => m.ToWireString()));
            return $"The '{mode.ToWireString()}' mode is not available on the {_tier.ToWireString()} tier. Allowed modes: {allowed}.";
        }

        if (_tier == SubscriptionTier.Pro && mode == CLMode.Hybrid && _capabilities.HybridIsAddon && !_hybridAddonEnabled)
        {
            return "Hybrid mode requires the hybrid add-on on the Pro tier. Enable it in your subscription settings.";
        }

        return null;
    }

    /// <summary>Resets daily and monthly counters. Test-only (mirrors Node's <c>@internal _reset()</c>).</summary>
    public void ResetForTesting()
    {
        _dailyEventCount = 0;
        _dailyResetTime = 0;
        _monthlyEventCount = 0;
        _monthlyResetTime = 0;
    }

    // ── CV-S2: Tiered ICL Capabilities ──────────────────────────

    /// <summary>
    /// Gets the maximum ICL tier available for this subscription: 0 = no ICL (monitor-only),
    /// 1 = Tier 1 deterministic rules only, 2 = Tier 1 + Tier 2 ML scoring, 3 = all tiers +
    /// air-gap + custom rules.
    /// </summary>
    public int GetMaxICLTier() => _capabilities.IclMaxTier;

    /// <summary>Checks whether a specific ICL tier (1-3) is available.</summary>
    public bool IsICLTierAvailable(int tier) => _capabilities.IclMaxTier >= tier;

    /// <summary>Checks whether air-gap mode is available.</summary>
    public bool IsAirGapEnabled() => _capabilities.AirGapEnabled;

    /// <summary>Checks whether custom ICL rules can be configured.</summary>
    public bool CanConfigureCustomRules() => _capabilities.CustomRulesEnabled;

    // ── CV-S3: Monthly Event Quotas ──────────────────────────────

    /// <summary>Checks the monthly event quota.</summary>
    public MonthlyQuotaResult CheckMonthlyQuota()
    {
        long monthStart = MonthStartMs();
        if (_monthlyResetTime < monthStart)
        {
            _monthlyEventCount = 0;
            _monthlyResetTime = monthStart;
        }

        int limit = _capabilities.MaxEventsPerMonth;
        if (limit == 0)
        {
            return new MonthlyQuotaResult(true, double.PositiveInfinity, 0);
        }

        long remaining = limit - _monthlyEventCount;
        return new MonthlyQuotaResult(remaining > 0, Math.Max(0, remaining), limit);
    }

    /// <summary>Records an event against the monthly quota.</summary>
    public void RecordMonthlyEvent() => _monthlyEventCount++;

    /// <summary>Gets monthly usage stats for the telemetry heartbeat.</summary>
    public MonthlyUsage GetMonthlyUsage()
    {
        int limit = _capabilities.MaxEventsPerMonth;
        int percentUsed = limit > 0 ? (int)Math.Round(_monthlyEventCount / (double)limit * 100) : 0;
        return new MonthlyUsage(_monthlyEventCount, limit, percentUsed);
    }

    // ── CV-S4/S5/S6: Platform Feature Checks ────────────────────

    /// <summary>CV-S4: whether platform alert channels are available (ICL mode can only log to console/filesystem).</summary>
    public bool HasPlatformAlerts() => _capabilities.PlatformAlerts;

    /// <summary>CV-S5: whether shared state across instances is available (ICL maintains per-instance state only).</summary>
    public bool HasSharedState() => _capabilities.SharedState;

    /// <summary>CV-S6: whether compliance evidence generation is available (ICL provides raw logs but no compliance formatting).</summary>
    public bool HasComplianceEvidence() => _capabilities.ComplianceEvidence;

    // ── S15: Usage Metering Persistence ─────────────────────────

    /// <summary>Snapshots mutable state for persistence across restarts. Caller serializes this and stores it in DB/file.</summary>
    public TierGateSnapshot ToSnapshot() => new(
        _tier, _hybridAddonEnabled, _dailyEventCount, _dailyResetTime, _monthlyEventCount, _monthlyResetTime,
        DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    /// <summary>
    /// Restores state from a previously saved snapshot. Ignores the daily/monthly counters if
    /// they are stale (past their reset boundary) — the tier itself always applies.
    /// </summary>
    /// <remarks>
    /// <paramref name="hybridAddonEnabled"/> mirrors Node's <c>options?.hybridAddonEnabled</c>
    /// fallback parameter, but Node's own fallback (<c>snapshot.hybridAddonEnabled ?? options?.hybridAddonEnabled</c>)
    /// is dead code there too: <c>TierGateSnapshot.hybridAddonEnabled</c> is a non-nullable
    /// <c>boolean</c>, so the <c>??</c> never reaches the option. Ported faithfully — the
    /// snapshot's own value always wins; the parameter is accepted for call-shape parity only.
    /// </remarks>
    public static TierGate FromSnapshot(TierGateSnapshot snapshot, bool? hybridAddonEnabled = null)
    {
        _ = hybridAddonEnabled; // accepted for call-shape parity with Node; never consulted (see remarks)
        var gate = new TierGate(snapshot.Tier, snapshot.HybridAddonEnabled);

        long todayStart = TodayStartMs();
        long monthStart = MonthStartMs();

        // Restore the daily count only if the snapshot is from today.
        if (snapshot.DailyResetTime >= todayStart)
        {
            gate._dailyEventCount = snapshot.DailyEventCount;
            gate._dailyResetTime = snapshot.DailyResetTime;
        }

        // Restore the monthly count only if the snapshot is from this month.
        if (snapshot.MonthlyResetTime >= monthStart)
        {
            gate._monthlyEventCount = snapshot.MonthlyEventCount;
            gate._monthlyResetTime = snapshot.MonthlyResetTime;
        }

        return gate;
    }
}
