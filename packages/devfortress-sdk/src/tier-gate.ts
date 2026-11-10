/**
 * DevFortress SDK — Tier Gating & Feature Access Control
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
 * @packageDocumentation
 */

import type { CLMode } from './types';

// ── Tier Definitions ────────────────────────────────────────

export type SubscriptionTier = 'starter' | 'pro' | 'team' | 'enterprise';

export interface TierCapabilities {
  /** Can observe/collect events */
  canObserve: boolean;
  /** Can execute blocking actions */
  canBlock: boolean;
  /** Allowed closed-loop modes */
  allowedModes: CLMode[];
  /** Default mode for this tier */
  defaultMode: CLMode;
  /** Whether hybrid is an add-on (requires extra payment) */
  hybridIsAddon: boolean;
  /** Internal CL acts as backup only (Pro behavior) */
  internalAsBackupOnly: boolean;
  /** Can configure custom rules */
  canConfigureRules: boolean;
  /** Can access audit trail */
  canAccessAudit: boolean;
  /** Can manage webhook secrets */
  canManageWebhooks: boolean;
  /** Maximum events per day (0 = unlimited) */
  maxEventsPerDay: number;
  /** Maximum blocked IPs (0 = unlimited) */
  maxBlockedIPs: number;
  // ── CV-S2: Tiered ICL Capabilities ──
  /** ICL tiers available: 0=none, 1=deterministic, 2=ML, 3=full */
  iclMaxTier: 0 | 1 | 2 | 3;
  /** Whether air-gap (offline) mode is available */
  airGapEnabled: boolean;
  /** Whether custom ICL rules are available */
  customRulesEnabled: boolean;
  // ── CV-S3: Monthly Event Quotas ──
  /** Maximum events per month (0 = unlimited) */
  maxEventsPerMonth: number;
  // ── CV-S4: Alert Channels ──
  /** Platform alert channels (email/Slack/PagerDuty) available */
  platformAlerts: boolean;
  // ── CV-S5: Shared State ──
  /** Cross-instance shared state (IP blocklists, baselines) via platform */
  sharedState: boolean;
  // ── CV-S6: Compliance Evidence ──
  /** Compliance evidence generation (PDF reports, audit exports) */
  complianceEvidence: boolean;
}

// ── Tier Capability Matrix ──────────────────────────────────

const TIER_CAPABILITIES: Record<SubscriptionTier, TierCapabilities> = {
  starter: {
    canObserve: true,
    canBlock: false,
    allowedModes: ['external'],
    defaultMode: 'external',
    hybridIsAddon: false,
    internalAsBackupOnly: false,
    canConfigureRules: false,
    canAccessAudit: false,
    canManageWebhooks: false,
    maxEventsPerDay: 10_000,
    maxBlockedIPs: 0,
    // CV-S2: Starter gets Tier 1 deterministic rules only
    iclMaxTier: 1,
    airGapEnabled: false,
    customRulesEnabled: false,
    // CV-S3: 50K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
    maxEventsPerMonth: 50_000,
    // CV-S4: No platform alerts
    platformAlerts: false,
    // CV-S5: No shared state
    sharedState: false,
    // CV-S6: No compliance evidence
    complianceEvidence: false,
  },
  pro: {
    canObserve: true,
    canBlock: true,
    // Package A (2026-08-28): Pro gets External CL only, at no point in time
    // does it get ICL/hybrid — differentiation comes from platform-executed
    // response, post-auth detection, alias isolation, and AI insights, never
    // from CL mode depth. Internal/Hybrid access starts at Team.
    allowedModes: ['external'],
    defaultMode: 'external',
    hybridIsAddon: false,
    internalAsBackupOnly: false,
    canConfigureRules: false,
    canAccessAudit: true,
    canManageWebhooks: true,
    maxEventsPerDay: 100_000,
    maxBlockedIPs: 1_000,
    // CV-S2: Pro has no ICL access — External CL only (Package A)
    iclMaxTier: 0,
    airGapEnabled: false,
    customRulesEnabled: false,
    // CV-S3: 75K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
    maxEventsPerMonth: 75_000,
    // CV-S4: Platform alerts enabled
    platformAlerts: true,
    // CV-S5: Shared state enabled
    sharedState: true,
    // CV-S6: No compliance evidence (Enterprise only)
    complianceEvidence: false,
  },
  team: {
    canObserve: true,
    canBlock: true,
    // Package A (2026-08-28): Team is the new entry point for Internal/Hybrid
    // CL — takes on the internal/hybrid capability profile Pro used to have,
    // but as a first-class capability (no add-on gate, no backup-only limit).
    allowedModes: ['external', 'internal', 'hybrid'],
    defaultMode: 'hybrid',
    hybridIsAddon: false,
    internalAsBackupOnly: false,
    canConfigureRules: false,
    canAccessAudit: true,
    canManageWebhooks: true,
    maxEventsPerDay: 0, // Unlimited (ingestion rate; monthly billing quota below still caps flagged events)
    maxBlockedIPs: 5_000,
    // CV-S2: Team gets Tier 1 + Tier 2 ML (same ceiling Pro used to have)
    iclMaxTier: 2,
    airGapEnabled: false,
    customRulesEnabled: false,
    // CV-S3: 100K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
    maxEventsPerMonth: 100_000,
    // CV-S4: Platform alerts enabled
    platformAlerts: true,
    // CV-S5: Shared state enabled
    sharedState: true,
    // CV-S6: Compliance evidence generation (matches Team's advertised compliance PDF reports)
    complianceEvidence: true,
  },
  enterprise: {
    canObserve: true,
    canBlock: true,
    allowedModes: ['external', 'internal', 'hybrid'],
    defaultMode: 'hybrid',
    hybridIsAddon: false,
    internalAsBackupOnly: false,
    canConfigureRules: true,
    canAccessAudit: true,
    canManageWebhooks: true,
    maxEventsPerDay: 0, // Unlimited
    maxBlockedIPs: 0, // Unlimited
    // CV-S2: Enterprise gets all tiers + air-gap + custom rules
    iclMaxTier: 3,
    airGapEnabled: true,
    customRulesEnabled: true,
    // CV-S3: Unlimited events/month
    maxEventsPerMonth: 0,
    // CV-S4: Full alert channels
    platformAlerts: true,
    // CV-S5: Full shared state
    sharedState: true,
    // CV-S6: Compliance evidence generation
    complianceEvidence: true,
  },
};

// ── Tier Gate Enforcer ──────────────────────────────────────

export class TierGate {
  private tier: SubscriptionTier;
  private capabilities: TierCapabilities;
  private hybridAddonEnabled: boolean;
  private dailyEventCount = 0;
  private dailyResetTime: number;
  private monthlyEventCount = 0;
  private monthlyResetTime: number;

  constructor(
    tier: SubscriptionTier,
    options?: { hybridAddonEnabled?: boolean }
  ) {
    this.tier = tier;
    this.capabilities = { ...TIER_CAPABILITIES[tier] };
    this.hybridAddonEnabled = options?.hybridAddonEnabled ?? false;
    this.dailyResetTime = new Date().setHours(0, 0, 0, 0);
    const now = new Date();
    this.monthlyResetTime = new Date(
      now.getFullYear(),
      now.getMonth(),
      1
    ).getTime();
  }

  /**
   * Get the effective closed-loop mode for this tier.
   * Validates the requested mode against tier permissions.
   */
  getEffectiveMode(requestedMode?: CLMode): CLMode {
    if (!requestedMode) {
      return this.capabilities.defaultMode;
    }

    // Check if mode is allowed for this tier
    if (!this.capabilities.allowedModes.includes(requestedMode)) {
      return this.capabilities.defaultMode;
    }

    // Pro tier: hybrid requires add-on
    if (
      this.tier === 'pro' &&
      requestedMode === 'hybrid' &&
      this.capabilities.hybridIsAddon &&
      !this.hybridAddonEnabled
    ) {
      return 'external';
    }

    return requestedMode;
  }

  /**
   * Check if blocking is allowed for this tier.
   */
  canBlock(): boolean {
    return this.capabilities.canBlock;
  }

  /**
   * Check if the daily event limit has been reached.
   */
  checkEventLimit(): { allowed: boolean; remaining: number } {
    // Reset daily counter if new day
    const now = Date.now();
    const dayStart = new Date().setHours(0, 0, 0, 0);
    if (this.dailyResetTime < dayStart) {
      this.dailyEventCount = 0;
      this.dailyResetTime = dayStart;
    }

    if (this.capabilities.maxEventsPerDay === 0) {
      return { allowed: true, remaining: Infinity };
    }

    const remaining = this.capabilities.maxEventsPerDay - this.dailyEventCount;
    return {
      allowed: remaining > 0,
      remaining: Math.max(0, remaining),
    };
  }

  /**
   * Record an event (for limit tracking).
   */
  recordEvent(): void {
    this.dailyEventCount++;
  }

  /**
   * Check if a specific feature is available for this tier.
   */
  hasFeature(feature: keyof TierCapabilities): boolean {
    const value = this.capabilities[feature];
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value > 0 || value === 0;
    if (Array.isArray(value)) return value.length > 0;
    return false;
  }

  /**
   * Get full capabilities for this tier.
   */
  getCapabilities(): Readonly<TierCapabilities> {
    return this.capabilities;
  }

  /**
   * Get the current tier name.
   */
  getTier(): SubscriptionTier {
    return this.tier;
  }

  /**
   * Validate a blocking action against tier permissions.
   * Returns an error message if not allowed, null if allowed.
   */
  validateBlockAction(action: string): string | null {
    if (!this.capabilities.canBlock) {
      return `Blocking is not available on the ${this.tier} tier. Upgrade to Pro or Enterprise to enable blocking.`;
    }

    if (this.capabilities.maxBlockedIPs > 0 && action === 'block_ip') {
      // Caller should check actual blocked count against this limit
      return null;
    }

    return null;
  }

  /**
   * Validate a mode selection against tier permissions.
   * Returns an error message if not allowed, null if allowed.
   */
  validateMode(mode: CLMode): string | null {
    if (!this.capabilities.allowedModes.includes(mode)) {
      return `The '${mode}' mode is not available on the ${this.tier} tier. Allowed modes: ${this.capabilities.allowedModes.join(', ')}.`;
    }

    if (
      this.tier === 'pro' &&
      mode === 'hybrid' &&
      this.capabilities.hybridIsAddon &&
      !this.hybridAddonEnabled
    ) {
      return 'Hybrid mode requires the hybrid add-on on the Pro tier. Enable it in your subscription settings.';
    }

    return null;
  }

  /**
   * Reset daily counters (for testing).
   * @internal
   */
  _reset(): void {
    this.dailyEventCount = 0;
    this.dailyResetTime = 0;
    this.monthlyEventCount = 0;
    this.monthlyResetTime = 0;
  }

  // ── CV-S2: Tiered ICL Capabilities ──────────────────────────

  /**
   * Get the maximum ICL tier available for this subscription.
   * - 0: No ICL (monitor-only)
   * - 1: Tier 1 deterministic rules only
   * - 2: Tier 1 + Tier 2 ML scoring
   * - 3: All tiers + air-gap + custom rules
   */
  getMaxICLTier(): 0 | 1 | 2 | 3 {
    return this.capabilities.iclMaxTier;
  }

  /**
   * Check if a specific ICL tier is available.
   */
  isICLTierAvailable(tier: 1 | 2 | 3): boolean {
    return this.capabilities.iclMaxTier >= tier;
  }

  /**
   * Check if air-gap mode is available.
   */
  isAirGapEnabled(): boolean {
    return this.capabilities.airGapEnabled;
  }

  /**
   * Check if custom ICL rules can be configured.
   */
  canConfigureCustomRules(): boolean {
    return this.capabilities.customRulesEnabled;
  }

  // ── CV-S3: Monthly Event Quotas ──────────────────────────────

  /**
   * Check monthly event quota.
   * Returns { allowed, remaining, limit }.
   */
  checkMonthlyQuota(): { allowed: boolean; remaining: number; limit: number } {
    // Reset monthly counter if new month
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
    if (this.monthlyResetTime < monthStart) {
      this.monthlyEventCount = 0;
      this.monthlyResetTime = monthStart;
    }

    const limit = this.capabilities.maxEventsPerMonth;
    if (limit === 0) {
      return { allowed: true, remaining: Infinity, limit: 0 };
    }

    const remaining = limit - this.monthlyEventCount;
    return {
      allowed: remaining > 0,
      remaining: Math.max(0, remaining),
      limit,
    };
  }

  /**
   * Record an event against the monthly quota.
   */
  recordMonthlyEvent(): void {
    this.monthlyEventCount++;
  }

  /**
   * Get monthly usage stats for telemetry heartbeat.
   */
  getMonthlyUsage(): { used: number; limit: number; percentUsed: number } {
    const limit = this.capabilities.maxEventsPerMonth;
    return {
      used: this.monthlyEventCount,
      limit,
      percentUsed:
        limit > 0 ? Math.round((this.monthlyEventCount / limit) * 100) : 0,
    };
  }

  // ── CV-S4/S5/S6: Platform Feature Checks ────────────────────

  /**
   * Check if platform alert channels are available.
   * CV-S4: ICL mode can only log to console/filesystem.
   */
  hasPlatformAlerts(): boolean {
    return this.capabilities.platformAlerts;
  }

  /**
   * Check if shared state across instances is available.
   * CV-S5: ICL maintains per-instance state only.
   */
  hasSharedState(): boolean {
    return this.capabilities.sharedState;
  }

  /**
   * Check if compliance evidence generation is available.
   * CV-S6: ICL provides raw logs but no compliance formatting.
   */
  hasComplianceEvidence(): boolean {
    return this.capabilities.complianceEvidence;
  }

  // ── S15: Usage Metering Persistence ─────────────────────────

  /**
   * Snapshot mutable state for persistence across restarts.
   * Caller should serialize to JSON and store in DB/file.
   */
  toSnapshot(): TierGateSnapshot {
    return {
      tier: this.tier,
      hybridAddonEnabled: this.hybridAddonEnabled,
      dailyEventCount: this.dailyEventCount,
      dailyResetTime: this.dailyResetTime,
      monthlyEventCount: this.monthlyEventCount,
      monthlyResetTime: this.monthlyResetTime,
      snapshotTimestamp: Date.now(),
    };
  }

  /**
   * Restore state from a previously saved snapshot.
   * Ignores snapshot if tier has changed or if counters are stale (past reset boundary).
   */
  static fromSnapshot(
    snapshot: TierGateSnapshot,
    options?: { hybridAddonEnabled?: boolean }
  ): TierGate {
    const gate = new TierGate(snapshot.tier, {
      hybridAddonEnabled:
        snapshot.hybridAddonEnabled ?? options?.hybridAddonEnabled,
    });

    const now = Date.now();
    const todayStart = new Date().setHours(0, 0, 0, 0);
    const monthStart = new Date(
      new Date().getFullYear(),
      new Date().getMonth(),
      1
    ).getTime();

    // Restore daily count only if snapshot is from today
    if (snapshot.dailyResetTime >= todayStart) {
      gate.dailyEventCount = snapshot.dailyEventCount;
      gate.dailyResetTime = snapshot.dailyResetTime;
    }

    // Restore monthly count only if snapshot is from this month
    if (snapshot.monthlyResetTime >= monthStart) {
      gate.monthlyEventCount = snapshot.monthlyEventCount;
      gate.monthlyResetTime = snapshot.monthlyResetTime;
    }

    return gate;
  }
}

/**
 * S15: Serializable snapshot of TierGate mutable state.
 */
export interface TierGateSnapshot {
  tier: SubscriptionTier;
  hybridAddonEnabled: boolean;
  dailyEventCount: number;
  dailyResetTime: number;
  monthlyEventCount: number;
  monthlyResetTime: number;
  snapshotTimestamp: number;
}
