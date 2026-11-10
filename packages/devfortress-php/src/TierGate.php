<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use InvalidArgumentException;

/**
 * DevFortress SDK — Tier Gating & Feature Access Control.
 *
 * Enforces feature access based on subscription tier:
 *
 *   Starter:    Observe events; response is webhook-dispatched and
 *               self-executed by the customer (no platform-side blocking)
 *   Pro:        View + block via external CL only — no internal/hybrid,
 *               not even as an add-on (Package A, 2026-08-28)
 *   Team:       External, internal, and hybrid all available as first-class
 *               capabilities (default: hybrid) — the entry point for
 *               internal/hybrid CL under Package A
 *   Enterprise: Can select internal, external, or hybrid
 *               (default: hybrid with internal backup, external primary)
 *
 * Mirrors packages/devfortress-sdk/src/tier-gate.ts, including its
 * TIER_CAPABILITIES matrix values verbatim. Depends on LicenseManager
 * resolving the active tier (see LicenseManager::checkLicense /
 * ::getLicenseState) — the host passes that tier string into the
 * constructor here.
 *
 * @phpstan-type SubscriptionTier 'starter'|'pro'|'team'|'enterprise'
 * @phpstan-type CLMode 'external'|'internal'|'hybrid'
 * @phpstan-type TierCapabilities array{
 *     canObserve: bool,
 *     canBlock: bool,
 *     allowedModes: list<string>,
 *     defaultMode: string,
 *     hybridIsAddon: bool,
 *     internalAsBackupOnly: bool,
 *     canConfigureRules: bool,
 *     canAccessAudit: bool,
 *     canManageWebhooks: bool,
 *     maxEventsPerDay: int,
 *     maxBlockedIPs: int,
 *     iclMaxTier: int,
 *     airGapEnabled: bool,
 *     customRulesEnabled: bool,
 *     maxEventsPerMonth: int,
 *     platformAlerts: bool,
 *     sharedState: bool,
 *     complianceEvidence: bool,
 * }
 * @phpstan-type TierGateSnapshot array{
 *     tier: string,
 *     hybridAddonEnabled: bool,
 *     dailyEventCount: int,
 *     dailyResetTime: int,
 *     monthlyEventCount: int,
 *     monthlyResetTime: int,
 *     snapshotTimestamp: int,
 * }
 */
final class TierGate
{
    /** @var list<string> */
    public const VALID_TIERS = ['starter', 'pro', 'team', 'enterprise'];

    /** @var array<string, TierCapabilities> */
    private const TIER_CAPABILITIES = [
        'starter' => [
            'canObserve' => true,
            'canBlock' => false,
            'allowedModes' => ['external'],
            'defaultMode' => 'external',
            'hybridIsAddon' => false,
            'internalAsBackupOnly' => false,
            'canConfigureRules' => false,
            'canAccessAudit' => false,
            'canManageWebhooks' => false,
            'maxEventsPerDay' => 10_000,
            'maxBlockedIPs' => 0,
            // Starter gets Tier 1 deterministic rules only.
            'iclMaxTier' => 1,
            'airGapEnabled' => false,
            'customRulesEnabled' => false,
            // 50K events/month (matches SUBSCRIPTION_PRICING, Option B pricing).
            'maxEventsPerMonth' => 50_000,
            'platformAlerts' => false,
            'sharedState' => false,
            'complianceEvidence' => false,
        ],
        'pro' => [
            'canObserve' => true,
            'canBlock' => true,
            // Package A (2026-08-28): Pro gets External CL only, at no point
            // in time does it get ICL/hybrid — differentiation comes from
            // platform-executed response, post-auth detection, alias
            // isolation, and AI insights, never from CL mode depth.
            // Internal/Hybrid access starts at Team.
            'allowedModes' => ['external'],
            'defaultMode' => 'external',
            'hybridIsAddon' => false,
            'internalAsBackupOnly' => false,
            'canConfigureRules' => false,
            'canAccessAudit' => true,
            'canManageWebhooks' => true,
            'maxEventsPerDay' => 100_000,
            'maxBlockedIPs' => 1_000,
            // Pro has no ICL access — External CL only (Package A).
            'iclMaxTier' => 0,
            'airGapEnabled' => false,
            'customRulesEnabled' => false,
            // 75K events/month (matches SUBSCRIPTION_PRICING, Option B pricing).
            'maxEventsPerMonth' => 75_000,
            'platformAlerts' => true,
            'sharedState' => true,
            // No compliance evidence (Enterprise only).
            'complianceEvidence' => false,
        ],
        'team' => [
            'canObserve' => true,
            'canBlock' => true,
            // Package A (2026-08-28): Team is the new entry point for
            // Internal/Hybrid CL — takes on the internal/hybrid capability
            // profile Pro used to have, but as a first-class capability (no
            // add-on gate, no backup-only limit).
            'allowedModes' => ['external', 'internal', 'hybrid'],
            'defaultMode' => 'hybrid',
            'hybridIsAddon' => false,
            'internalAsBackupOnly' => false,
            'canConfigureRules' => false,
            'canAccessAudit' => true,
            'canManageWebhooks' => true,
            // Unlimited (ingestion rate; monthly billing quota below still
            // caps flagged events).
            'maxEventsPerDay' => 0,
            'maxBlockedIPs' => 5_000,
            // Team gets Tier 1 + Tier 2 ML (same ceiling Pro used to have).
            'iclMaxTier' => 2,
            'airGapEnabled' => false,
            'customRulesEnabled' => false,
            // 100K events/month (matches SUBSCRIPTION_PRICING, Option B pricing).
            'maxEventsPerMonth' => 100_000,
            'platformAlerts' => true,
            'sharedState' => true,
            // Compliance evidence generation (matches Team's advertised
            // compliance PDF reports).
            'complianceEvidence' => true,
        ],
        'enterprise' => [
            'canObserve' => true,
            'canBlock' => true,
            'allowedModes' => ['external', 'internal', 'hybrid'],
            'defaultMode' => 'hybrid',
            'hybridIsAddon' => false,
            'internalAsBackupOnly' => false,
            'canConfigureRules' => true,
            'canAccessAudit' => true,
            'canManageWebhooks' => true,
            'maxEventsPerDay' => 0, // Unlimited.
            'maxBlockedIPs' => 0, // Unlimited.
            // Enterprise gets all tiers + air-gap + custom rules.
            'iclMaxTier' => 3,
            'airGapEnabled' => true,
            'customRulesEnabled' => true,
            // Unlimited events/month.
            'maxEventsPerMonth' => 0,
            'platformAlerts' => true,
            'sharedState' => true,
            'complianceEvidence' => true,
        ],
    ];

    private string $tier;
    /** @var TierCapabilities */
    private array $capabilities;
    private bool $hybridAddonEnabled;
    private int $dailyEventCount = 0;
    private int $dailyResetTime;
    private int $monthlyEventCount = 0;
    private int $monthlyResetTime;

    public function __construct(string $tier, bool $hybridAddonEnabled = false)
    {
        if (!isset(self::TIER_CAPABILITIES[$tier])) {
            throw new InvalidArgumentException(
                "DevFortress\\Sdk\\TierGate: unknown tier '{$tier}' — expected one of " . implode(', ', self::VALID_TIERS),
            );
        }
        $this->tier = $tier;
        $this->capabilities = self::TIER_CAPABILITIES[$tier];
        $this->hybridAddonEnabled = $hybridAddonEnabled;
        $this->dailyResetTime = self::dayStartMs();
        $this->monthlyResetTime = self::monthStartMs();
    }

    /**
     * Get the effective closed-loop mode for this tier.
     * Validates the requested mode against tier permissions.
     */
    public function getEffectiveMode(?string $requestedMode = null): string
    {
        if ($requestedMode === null) {
            return $this->capabilities['defaultMode'];
        }

        // Check if mode is allowed for this tier.
        if (!in_array($requestedMode, $this->capabilities['allowedModes'], true)) {
            return $this->capabilities['defaultMode'];
        }

        // Pro tier: hybrid requires add-on.
        if (
            $this->tier === 'pro'
            && $requestedMode === 'hybrid'
            && $this->capabilities['hybridIsAddon']
            && !$this->hybridAddonEnabled
        ) {
            return 'external';
        }

        return $requestedMode;
    }

    /** Check if blocking is allowed for this tier. */
    public function canBlock(): bool
    {
        return $this->capabilities['canBlock'];
    }

    /**
     * Check if the daily event limit has been reached.
     *
     * @return array{allowed: bool, remaining: int|float}
     */
    public function checkEventLimit(): array
    {
        // Reset daily counter if new day.
        $dayStart = self::dayStartMs();
        if ($this->dailyResetTime < $dayStart) {
            $this->dailyEventCount = 0;
            $this->dailyResetTime = $dayStart;
        }

        if ($this->capabilities['maxEventsPerDay'] === 0) {
            return ['allowed' => true, 'remaining' => INF];
        }

        $remaining = $this->capabilities['maxEventsPerDay'] - $this->dailyEventCount;

        return [
            'allowed' => $remaining > 0,
            'remaining' => max(0, $remaining),
        ];
    }

    /** Record an event (for limit tracking). */
    public function recordEvent(): void
    {
        $this->dailyEventCount++;
    }

    /** Check if a specific feature is available for this tier. */
    public function hasFeature(string $feature): bool
    {
        if (!array_key_exists($feature, $this->capabilities)) {
            return false;
        }
        $value = $this->capabilities[$feature];
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value)) {
            return $value > 0 || $value === 0;
        }
        if (is_array($value)) {
            return $value !== [];
        }

        return false;
    }

    /**
     * Get full capabilities for this tier.
     *
     * @return TierCapabilities
     */
    public function getCapabilities(): array
    {
        return $this->capabilities;
    }

    /** Get the current tier name. */
    public function getTier(): string
    {
        return $this->tier;
    }

    /**
     * Validate a blocking action against tier permissions.
     * Returns an error message if not allowed, null if allowed.
     */
    public function validateBlockAction(string $action): ?string
    {
        if (!$this->capabilities['canBlock']) {
            return "Blocking is not available on the {$this->tier} tier. Upgrade to Pro or Enterprise to enable blocking.";
        }

        if ($this->capabilities['maxBlockedIPs'] > 0 && $action === 'block_ip') {
            // Caller should check actual blocked count against this limit.
            return null;
        }

        return null;
    }

    /**
     * Validate a mode selection against tier permissions.
     * Returns an error message if not allowed, null if allowed.
     */
    public function validateMode(string $mode): ?string
    {
        if (!in_array($mode, $this->capabilities['allowedModes'], true)) {
            return "The '{$mode}' mode is not available on the {$this->tier} tier. Allowed modes: " . implode(', ', $this->capabilities['allowedModes']) . '.';
        }

        if (
            $this->tier === 'pro'
            && $mode === 'hybrid'
            && $this->capabilities['hybridIsAddon']
            && !$this->hybridAddonEnabled
        ) {
            return 'Hybrid mode requires the hybrid add-on on the Pro tier. Enable it in your subscription settings.';
        }

        return null;
    }

    /**
     * Reset daily/monthly counters (for testing).
     * @internal
     */
    public function _reset(): void
    {
        $this->dailyEventCount = 0;
        $this->dailyResetTime = 0;
        $this->monthlyEventCount = 0;
        $this->monthlyResetTime = 0;
    }

    // ── Tiered ICL Capabilities ──────────────────────────────────

    /**
     * Get the maximum ICL tier available for this subscription.
     * - 0: No ICL (monitor-only)
     * - 1: Tier 1 deterministic rules only
     * - 2: Tier 1 + Tier 2 ML scoring
     * - 3: All tiers + air-gap + custom rules
     */
    public function getMaxICLTier(): int
    {
        return $this->capabilities['iclMaxTier'];
    }

    /** Check if a specific ICL tier is available. */
    public function isICLTierAvailable(int $tier): bool
    {
        return $this->capabilities['iclMaxTier'] >= $tier;
    }

    /** Check if air-gap mode is available. */
    public function isAirGapEnabled(): bool
    {
        return $this->capabilities['airGapEnabled'];
    }

    /** Check if custom ICL rules can be configured. */
    public function canConfigureCustomRules(): bool
    {
        return $this->capabilities['customRulesEnabled'];
    }

    // ── Monthly Event Quotas ─────────────────────────────────────

    /**
     * Check monthly event quota.
     *
     * @return array{allowed: bool, remaining: int|float, limit: int}
     */
    public function checkMonthlyQuota(): array
    {
        // Reset monthly counter if new month.
        $monthStart = self::monthStartMs();
        if ($this->monthlyResetTime < $monthStart) {
            $this->monthlyEventCount = 0;
            $this->monthlyResetTime = $monthStart;
        }

        $limit = $this->capabilities['maxEventsPerMonth'];
        if ($limit === 0) {
            return ['allowed' => true, 'remaining' => INF, 'limit' => 0];
        }

        $remaining = $limit - $this->monthlyEventCount;

        return [
            'allowed' => $remaining > 0,
            'remaining' => max(0, $remaining),
            'limit' => $limit,
        ];
    }

    /** Record an event against the monthly quota. */
    public function recordMonthlyEvent(): void
    {
        $this->monthlyEventCount++;
    }

    /**
     * Get monthly usage stats for telemetry heartbeat.
     *
     * @return array{used: int, limit: int, percentUsed: int}
     */
    public function getMonthlyUsage(): array
    {
        $limit = $this->capabilities['maxEventsPerMonth'];

        return [
            'used' => $this->monthlyEventCount,
            'limit' => $limit,
            'percentUsed' => $limit > 0 ? (int) round(($this->monthlyEventCount / $limit) * 100) : 0,
        ];
    }

    // ── Platform Feature Checks ──────────────────────────────────

    /** Check if platform alert channels are available. ICL mode can only log to console/filesystem. */
    public function hasPlatformAlerts(): bool
    {
        return $this->capabilities['platformAlerts'];
    }

    /** Check if shared state across instances is available. ICL maintains per-instance state only. */
    public function hasSharedState(): bool
    {
        return $this->capabilities['sharedState'];
    }

    /** Check if compliance evidence generation is available. ICL provides raw logs but no compliance formatting. */
    public function hasComplianceEvidence(): bool
    {
        return $this->capabilities['complianceEvidence'];
    }

    // ── Usage Metering Persistence ──────────────────────────────

    /**
     * Snapshot mutable state for persistence across restarts.
     * Caller should serialize to JSON and store in DB/file.
     *
     * @return TierGateSnapshot
     */
    public function toSnapshot(): array
    {
        return [
            'tier' => $this->tier,
            'hybridAddonEnabled' => $this->hybridAddonEnabled,
            'dailyEventCount' => $this->dailyEventCount,
            'dailyResetTime' => $this->dailyResetTime,
            'monthlyEventCount' => $this->monthlyEventCount,
            'monthlyResetTime' => $this->monthlyResetTime,
            'snapshotTimestamp' => self::nowMs(),
        ];
    }

    /**
     * Restore state from a previously saved snapshot.
     * Ignores stale counters (past their reset boundary); the tier itself
     * is always taken from the snapshot.
     *
     * @param TierGateSnapshot $snapshot
     */
    public static function fromSnapshot(array $snapshot, bool $hybridAddonEnabled = false): self
    {
        $gate = new self($snapshot['tier'], $snapshot['hybridAddonEnabled']);

        $todayStart = self::dayStartMs();
        $monthStart = self::monthStartMs();

        // Restore daily count only if snapshot is from today.
        if ($snapshot['dailyResetTime'] >= $todayStart) {
            $gate->dailyEventCount = $snapshot['dailyEventCount'];
            $gate->dailyResetTime = $snapshot['dailyResetTime'];
        }

        // Restore monthly count only if snapshot is from this month.
        if ($snapshot['monthlyResetTime'] >= $monthStart) {
            $gate->monthlyEventCount = $snapshot['monthlyEventCount'];
            $gate->monthlyResetTime = $snapshot['monthlyResetTime'];
        }

        return $gate;
    }

    /** Local midnight, in epoch milliseconds — mirrors Node's `new Date().setHours(0,0,0,0)`. */
    private static function dayStartMs(): int
    {
        return (new \DateTimeImmutable('today midnight'))->getTimestamp() * 1000;
    }

    /** The first instant of the local calendar month, in epoch milliseconds — mirrors Node's `new Date(year, month, 1)`. */
    private static function monthStartMs(): int
    {
        return (new \DateTimeImmutable('first day of this month midnight'))->getTimestamp() * 1000;
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
