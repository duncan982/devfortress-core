package net.devfortress;

import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneId;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * DevFortress SDK — Tier Gating &amp; Feature Access Control. Mirrors
 * {@code packages/devfortress-sdk/src/tier-gate.ts}.
 *
 * <p>Enforces feature access based on subscription tier:
 * <ul>
 *   <li>Starter: observe events; response is webhook-dispatched and
 *       self-executed by the customer (no platform-side blocking)</li>
 *   <li>Pro: view + block via external CL only — no internal/hybrid, not
 *       even as an add-on (Package A, 2026-08-28)</li>
 *   <li>Team: external, internal, and hybrid all available as first-class
 *       capabilities (default: hybrid) — the entry point for
 *       internal/hybrid CL under Package A</li>
 *   <li>Enterprise: can select internal, external, or hybrid (default:
 *       hybrid with internal backup, external primary)</li>
 * </ul>
 *
 * <p>Depends on {@link LicenseManager} resolving the active tier — a host
 * reads {@code licenseManager.getLicenseState().tier()} and converts it to
 * this class's own {@link SubscriptionTier} with {@link
 * SubscriptionTier#fromWire}, the same decoupled-by-string-value
 * relationship {@code license-manager.ts} and {@code tier-gate.ts} have in
 * Node (neither file imports the other's tier type).
 */
public final class TierGate {
    /** Subscription tier. Mirrors Node's {@code SubscriptionTier} type. */
    public enum SubscriptionTier {
        STARTER, PRO, TEAM, ENTERPRISE;

        public static SubscriptionTier fromWire(String value) {
            if (value == null) {
                throw new IllegalArgumentException("devfortress: null subscription tier");
            }
            return switch (value.toLowerCase(Locale.ROOT)) {
                case "starter" -> STARTER;
                case "pro" -> PRO;
                case "team" -> TEAM;
                case "enterprise" -> ENTERPRISE;
                default -> throw new IllegalArgumentException("devfortress: unknown subscription tier '" + value + "'");
            };
        }

        public String wireValue() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** Closed-loop mode. Mirrors Node's {@code CLMode} type. */
    public enum CLMode {
        EXTERNAL, INTERNAL, HYBRID;

        public static CLMode fromWire(String value) {
            if (value == null) {
                throw new IllegalArgumentException("devfortress: null CL mode");
            }
            return switch (value.toLowerCase(Locale.ROOT)) {
                case "external" -> EXTERNAL;
                case "internal" -> INTERNAL;
                case "hybrid" -> HYBRID;
                default -> throw new IllegalArgumentException("devfortress: unknown CL mode '" + value + "'");
            };
        }

        public String wireValue() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** Individually checkable capability keys. Mirrors Node's {@code keyof TierCapabilities} used by {@code hasFeature}. */
    public enum Feature {
        CAN_OBSERVE, CAN_BLOCK, ALLOWED_MODES, DEFAULT_MODE, HYBRID_IS_ADDON, INTERNAL_AS_BACKUP_ONLY,
        CAN_CONFIGURE_RULES, CAN_ACCESS_AUDIT, CAN_MANAGE_WEBHOOKS, MAX_EVENTS_PER_DAY, MAX_BLOCKED_IPS,
        ICL_MAX_TIER, AIR_GAP_ENABLED, CUSTOM_RULES_ENABLED, MAX_EVENTS_PER_MONTH, PLATFORM_ALERTS,
        SHARED_STATE, COMPLIANCE_EVIDENCE
    }

    /** Full capability matrix for one tier. */
    public record TierCapabilities(
            boolean canObserve,
            boolean canBlock,
            List<CLMode> allowedModes,
            CLMode defaultMode,
            boolean hybridIsAddon,
            boolean internalAsBackupOnly,
            boolean canConfigureRules,
            boolean canAccessAudit,
            boolean canManageWebhooks,
            /** 0 = unlimited. */
            long maxEventsPerDay,
            /** 0 = unlimited. */
            long maxBlockedIPs,
            /** CV-S2: 0=none, 1=deterministic, 2=ML, 3=full. */
            int iclMaxTier,
            boolean airGapEnabled,
            boolean customRulesEnabled,
            /** CV-S3: 0 = unlimited. */
            long maxEventsPerMonth,
            boolean platformAlerts,
            boolean sharedState,
            boolean complianceEvidence) {
    }

    /** {@code 0} throughout this class means unlimited — see each field's own javadoc, never a literal infinity. */
    public static final long UNLIMITED = 0;

    private static final Map<SubscriptionTier, TierCapabilities> TIER_CAPABILITIES = Map.of(
            SubscriptionTier.STARTER, new TierCapabilities(
                    true, false, List.of(CLMode.EXTERNAL), CLMode.EXTERNAL, false, false,
                    false, false, false, 10_000, 0,
                    1, false, false, 50_000, false, false, false),
            SubscriptionTier.PRO, new TierCapabilities(
                    // Package A (2026-08-28): Pro gets External CL only, at no point in time does
                    // it get ICL/hybrid — differentiation comes from platform-executed response,
                    // post-auth detection, alias isolation, and AI insights, never from CL mode
                    // depth. Internal/Hybrid access starts at Team.
                    true, true, List.of(CLMode.EXTERNAL), CLMode.EXTERNAL, false, false,
                    false, true, true, 100_000, 1_000,
                    0, false, false, 75_000, true, true, false),
            SubscriptionTier.TEAM, new TierCapabilities(
                    // Package A (2026-08-28): Team is the new entry point for Internal/Hybrid CL —
                    // takes on the internal/hybrid capability profile Pro used to have, but as a
                    // first-class capability (no add-on gate, no backup-only limit).
                    true, true, List.of(CLMode.EXTERNAL, CLMode.INTERNAL, CLMode.HYBRID), CLMode.HYBRID, false, false,
                    false, true, true, UNLIMITED, 5_000,
                    2, false, false, 100_000, true, true, true),
            SubscriptionTier.ENTERPRISE, new TierCapabilities(
                    true, true, List.of(CLMode.EXTERNAL, CLMode.INTERNAL, CLMode.HYBRID), CLMode.HYBRID, false, false,
                    true, true, true, UNLIMITED, UNLIMITED,
                    3, true, true, UNLIMITED, true, true, true));

    /** Outcome of {@link #checkEventLimit}. {@code remaining} is {@link #UNLIMITED}'s complement — see field javadoc. */
    public record EventLimitResult(boolean allowed, long remaining) {
    }

    /** Outcome of {@link #checkMonthlyQuota}. */
    public record MonthlyQuotaResult(boolean allowed, long remaining, long limit) {
    }

    /** Monthly usage, for the telemetry heartbeat. */
    public record MonthlyUsage(long used, long limit, int percentUsed) {
    }

    /** S15: serializable snapshot of {@link TierGate} mutable state. */
    public record TierGateSnapshot(SubscriptionTier tier, boolean hybridAddonEnabled, long dailyEventCount,
                                    long dailyResetTime, long monthlyEventCount, long monthlyResetTime,
                                    long snapshotTimestamp) {
    }

    private final SubscriptionTier tier;
    private final TierCapabilities capabilities;
    private final boolean hybridAddonEnabled;
    private long dailyEventCount = 0;
    private long dailyResetTime;
    private long monthlyEventCount = 0;
    private long monthlyResetTime;

    public TierGate(SubscriptionTier tier) {
        this(tier, false);
    }

    public TierGate(SubscriptionTier tier, boolean hybridAddonEnabled) {
        this.tier = tier;
        this.capabilities = TIER_CAPABILITIES.get(tier);
        this.hybridAddonEnabled = hybridAddonEnabled;
        this.dailyResetTime = startOfDayMillis();
        this.monthlyResetTime = startOfMonthMillis();
    }

    /**
     * Get the effective closed-loop mode for this tier. Validates the
     * requested mode against tier permissions. A null {@code requestedMode}
     * returns the tier's default.
     */
    public CLMode getEffectiveMode(CLMode requestedMode) {
        if (requestedMode == null) {
            return capabilities.defaultMode();
        }

        if (!capabilities.allowedModes().contains(requestedMode)) {
            return capabilities.defaultMode();
        }

        // Pro tier: hybrid requires add-on
        if (tier == SubscriptionTier.PRO && requestedMode == CLMode.HYBRID
                && capabilities.hybridIsAddon() && !hybridAddonEnabled) {
            return CLMode.EXTERNAL;
        }

        return requestedMode;
    }

    /** Check if blocking is allowed for this tier. */
    public boolean canBlock() {
        return capabilities.canBlock();
    }

    /** Check if the daily event limit has been reached. */
    public synchronized EventLimitResult checkEventLimit() {
        long dayStart = startOfDayMillis();
        if (dailyResetTime < dayStart) {
            dailyEventCount = 0;
            dailyResetTime = dayStart;
        }

        if (capabilities.maxEventsPerDay() == UNLIMITED) {
            return new EventLimitResult(true, Long.MAX_VALUE);
        }

        long remaining = capabilities.maxEventsPerDay() - dailyEventCount;
        return new EventLimitResult(remaining > 0, Math.max(0, remaining));
    }

    /** Record an event (for limit tracking). */
    public synchronized void recordEvent() {
        dailyEventCount++;
    }

    /** Check if a specific feature is available for this tier. */
    public boolean hasFeature(Feature feature) {
        return switch (feature) {
            case CAN_OBSERVE -> capabilities.canObserve();
            case CAN_BLOCK -> capabilities.canBlock();
            case ALLOWED_MODES -> !capabilities.allowedModes().isEmpty();
            case DEFAULT_MODE -> false; // a single enum value, neither boolean/number/array — Node falls through to false
            case HYBRID_IS_ADDON -> capabilities.hybridIsAddon();
            case INTERNAL_AS_BACKUP_ONLY -> capabilities.internalAsBackupOnly();
            case CAN_CONFIGURE_RULES -> capabilities.canConfigureRules();
            case CAN_ACCESS_AUDIT -> capabilities.canAccessAudit();
            case CAN_MANAGE_WEBHOOKS -> capabilities.canManageWebhooks();
            case MAX_EVENTS_PER_DAY -> true; // number: Node's `value > 0 || value === 0` is true for any non-negative number
            case MAX_BLOCKED_IPS -> true;
            case ICL_MAX_TIER -> true;
            case AIR_GAP_ENABLED -> capabilities.airGapEnabled();
            case CUSTOM_RULES_ENABLED -> capabilities.customRulesEnabled();
            case MAX_EVENTS_PER_MONTH -> true;
            case PLATFORM_ALERTS -> capabilities.platformAlerts();
            case SHARED_STATE -> capabilities.sharedState();
            case COMPLIANCE_EVIDENCE -> capabilities.complianceEvidence();
        };
    }

    /** Get full capabilities for this tier. */
    public TierCapabilities getCapabilities() {
        return capabilities;
    }

    /** Get the current tier. */
    public SubscriptionTier getTier() {
        return tier;
    }

    /**
     * Validate a blocking action against tier permissions. Returns an error
     * message if not allowed, {@code null} if allowed.
     */
    public String validateBlockAction(String action) {
        if (!capabilities.canBlock()) {
            return "Blocking is not available on the " + tier.wireValue()
                    + " tier. Upgrade to Pro or Enterprise to enable blocking.";
        }

        if (capabilities.maxBlockedIPs() > 0 && "block_ip".equals(action)) {
            // Caller should check actual blocked count against this limit
            return null;
        }

        return null;
    }

    /**
     * Validate a mode selection against tier permissions. Returns an error
     * message if not allowed, {@code null} if allowed.
     */
    public String validateMode(CLMode mode) {
        if (!capabilities.allowedModes().contains(mode)) {
            return "The '" + mode.wireValue() + "' mode is not available on the " + tier.wireValue()
                    + " tier. Allowed modes: "
                    + capabilities.allowedModes().stream().map(CLMode::wireValue).reduce((a, c) -> a + ", " + c).orElse("")
                    + ".";
        }

        if (tier == SubscriptionTier.PRO && mode == CLMode.HYBRID
                && capabilities.hybridIsAddon() && !hybridAddonEnabled) {
            return "Hybrid mode requires the hybrid add-on on the Pro tier. Enable it in your subscription settings.";
        }

        return null;
    }

    /**
     * Reset daily and monthly counters. For tests only — mirrors Node's
     * {@code @internal _reset()}.
     */
    public synchronized void resetForTesting() {
        dailyEventCount = 0;
        dailyResetTime = 0;
        monthlyEventCount = 0;
        monthlyResetTime = 0;
    }

    // ── CV-S2: Tiered ICL Capabilities ──────────────────────────

    /**
     * Get the maximum ICL tier available for this subscription.
     * 0: no ICL (monitor-only). 1: Tier 1 deterministic rules only.
     * 2: Tier 1 + Tier 2 ML scoring. 3: all tiers + air-gap + custom rules.
     */
    public int getMaxICLTier() {
        return capabilities.iclMaxTier();
    }

    /** Check if a specific ICL tier (1, 2, or 3) is available. */
    public boolean isICLTierAvailable(int iclTier) {
        return capabilities.iclMaxTier() >= iclTier;
    }

    /** Check if air-gap mode is available. */
    public boolean isAirGapEnabled() {
        return capabilities.airGapEnabled();
    }

    /** Check if custom ICL rules can be configured. */
    public boolean canConfigureCustomRules() {
        return capabilities.customRulesEnabled();
    }

    // ── CV-S3: Monthly Event Quotas ──────────────────────────────

    /** Check monthly event quota. */
    public synchronized MonthlyQuotaResult checkMonthlyQuota() {
        long monthStart = startOfMonthMillis();
        if (monthlyResetTime < monthStart) {
            monthlyEventCount = 0;
            monthlyResetTime = monthStart;
        }

        long limit = capabilities.maxEventsPerMonth();
        if (limit == UNLIMITED) {
            return new MonthlyQuotaResult(true, Long.MAX_VALUE, 0);
        }

        long remaining = limit - monthlyEventCount;
        return new MonthlyQuotaResult(remaining > 0, Math.max(0, remaining), limit);
    }

    /** Record an event against the monthly quota. */
    public synchronized void recordMonthlyEvent() {
        monthlyEventCount++;
    }

    /** Get monthly usage stats for the telemetry heartbeat. */
    public synchronized MonthlyUsage getMonthlyUsage() {
        long limit = capabilities.maxEventsPerMonth();
        int percentUsed = limit > 0 ? (int) Math.round((monthlyEventCount * 100.0) / limit) : 0;
        return new MonthlyUsage(monthlyEventCount, limit, percentUsed);
    }

    // ── CV-S4/S5/S6: Platform Feature Checks ────────────────────

    /** Check if platform alert channels are available. CV-S4: ICL mode can only log to console/filesystem. */
    public boolean hasPlatformAlerts() {
        return capabilities.platformAlerts();
    }

    /** Check if shared state across instances is available. CV-S5: ICL maintains per-instance state only. */
    public boolean hasSharedState() {
        return capabilities.sharedState();
    }

    /** Check if compliance evidence generation is available. CV-S6: ICL provides raw logs but no compliance formatting. */
    public boolean hasComplianceEvidence() {
        return capabilities.complianceEvidence();
    }

    // ── S15: Usage Metering Persistence ─────────────────────────

    /** Snapshot mutable state for persistence across restarts. Caller should serialize and store in DB/file. */
    public synchronized TierGateSnapshot toSnapshot() {
        return new TierGateSnapshot(tier, hybridAddonEnabled, dailyEventCount, dailyResetTime,
                monthlyEventCount, monthlyResetTime, System.currentTimeMillis());
    }

    /**
     * Restore state from a previously saved snapshot. Ignores stale
     * counters past their reset boundary (same rule {@link #checkEventLimit}
     * and {@link #checkMonthlyQuota} already apply on next use).
     *
     * @param hybridAddonEnabledFallback accepted for parity with Node's
     *     {@code options?.hybridAddonEnabled ?? snapshot.hybridAddonEnabled}
     *     fallback, which only matters when the snapshot was deserialized
     *     from a schema version that omitted the field (an
     *     {@code undefined} read in JS). Since {@link TierGateSnapshot#hybridAddonEnabled}
     *     is a non-nullable {@code boolean} here, every snapshot this class
     *     itself produces always carries a real value, so this parameter is
     *     currently unused — same faithful-dead-parameter treatment as
     *     {@code MultiHopTrustChain}'s {@code cascadeTimeoutMs}. ({@code @code},
     *     not {@code @link}, deliberately — this class must not carry a
     *     compile-time dependency on the tier2gated package just to
     *     cross-reference it in a doc comment; an unused {@code @link}-driven
     *     import previously broke the open-core Java SDK's compile outright
     *     once tier2gated is stripped from it — found 2026-11-08,
     *     standalone-build-validation dispatch.)
     */
    @SuppressWarnings("unused")
    public static TierGate fromSnapshot(TierGateSnapshot snapshot, boolean hybridAddonEnabledFallback) {
        TierGate gate = new TierGate(snapshot.tier(), snapshot.hybridAddonEnabled());

        long todayStart = startOfDayMillis();
        long monthStart = startOfMonthMillis();

        if (snapshot.dailyResetTime() >= todayStart) {
            gate.dailyEventCount = snapshot.dailyEventCount();
            gate.dailyResetTime = snapshot.dailyResetTime();
        }

        if (snapshot.monthlyResetTime() >= monthStart) {
            gate.monthlyEventCount = snapshot.monthlyEventCount();
            gate.monthlyResetTime = snapshot.monthlyResetTime();
        }

        return gate;
    }

    private static long startOfDayMillis() {
        return LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    private static long startOfMonthMillis() {
        YearMonth ym = YearMonth.now();
        return ym.atDay(1).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }
}
