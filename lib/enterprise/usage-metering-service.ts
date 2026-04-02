/**
 * Usage Metering Service
 *
 * Tracks monthly event and action usage per organization for tier enforcement.
 * Features:
 *  - Per-billing-period counters (events/month, actions/month)
 *  - Soft limit warnings at 80% and 100%
 *  - Hard limit enforcement (blocks or queues)
 *  - Usage summary for dashboards and billing
 *  - Billing period auto-rotation (monthly)
 *
 * Integrates with tier-enforcement.ts to read per-tier limits.
 */

import { logInfo, logWarn, logError } from '@core/lib/logger';

/* ─── Types ─── */

export interface UsagePeriod {
  orgId: string;
  periodStart: Date;
  periodEnd: Date;
  events: number;
  automatedActions: number;
  abuseipdbChecks: number;
  apiGenerations: number;
  lastUpdated: Date;
}

export interface UsageCheckResult {
  allowed: boolean;
  resource: string;
  current: number;
  limit: number;
  remaining: number;
  percentUsed: number;
  warning?: string;
}

export interface UsageSummary {
  orgId: string;
  tier: string;
  billingPeriod: { start: Date; end: Date };
  events: { current: number; limit: number; percentUsed: number };
  automatedActions: { current: number; limit: number; percentUsed: number };
  abuseipdbChecks: { current: number; limit: number; percentUsed: number };
  apiGenerations: { current: number; limit: number; percentUsed: number };
  warnings: string[];
}

/* ─── Tier limits (aligned with pricing) ─── */

const TIER_LIMITS: Record<
  string,
  {
    events: number;
    automatedActions: number;
    abuseipdbChecks: number;
    apiGenerations: number;
  }
> = {
  free: {
    events: 0,
    automatedActions: 0,
    abuseipdbChecks: 0,
    apiGenerations: 0,
  },
  starter: {
    events: 50_000,
    automatedActions: 0,
    abuseipdbChecks: 10_000,
    apiGenerations: 25,
  },
  pro: {
    events: 500_000,
    automatedActions: 500,
    abuseipdbChecks: 100_000,
    apiGenerations: 60,
  },
  enterprise: {
    events: -1, // Unlimited
    automatedActions: -1,
    abuseipdbChecks: -1,
    apiGenerations: -1,
  },
  enterprise_plus: {
    events: -1,
    automatedActions: -1,
    abuseipdbChecks: -1,
    apiGenerations: -1,
  },
};

const WARNING_THRESHOLD = 0.8; // 80%

/* ─── Service class ─── */

export class UsageMeteringService {
  /** In-memory store — production would use Redis or Supabase */
  private periods: Map<string, UsagePeriod> = new Map();

  /* ── Period management ── */

  private getPeriodKey(orgId: string): string {
    const now = new Date();
    const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    return `${orgId}:${monthKey}`;
  }

  private getCurrentPeriod(orgId: string): UsagePeriod {
    const key = this.getPeriodKey(orgId);
    let period = this.periods.get(key);

    if (!period) {
      const now = new Date();
      const start = new Date(now.getFullYear(), now.getMonth(), 1);
      const end = new Date(
        now.getFullYear(),
        now.getMonth() + 1,
        0,
        23,
        59,
        59
      );
      period = {
        orgId,
        periodStart: start,
        periodEnd: end,
        events: 0,
        automatedActions: 0,
        abuseipdbChecks: 0,
        apiGenerations: 0,
        lastUpdated: new Date(),
      };
      this.periods.set(key, period);
    }

    return period;
  }

  /* ── Increment counters ── */

  recordEvent(orgId: string, count: number = 1): UsageCheckResult {
    return this.increment(orgId, 'events', count);
  }

  recordAutomatedAction(orgId: string, count: number = 1): UsageCheckResult {
    return this.increment(orgId, 'automatedActions', count);
  }

  recordAbuseIPDBCheck(orgId: string, count: number = 1): UsageCheckResult {
    return this.increment(orgId, 'abuseipdbChecks', count);
  }

  recordApiGeneration(orgId: string, count: number = 1): UsageCheckResult {
    return this.increment(orgId, 'apiGenerations', count);
  }

  private increment(
    orgId: string,
    resource: keyof Pick<
      UsagePeriod,
      'events' | 'automatedActions' | 'abuseipdbChecks' | 'apiGenerations'
    >,
    count: number
  ): UsageCheckResult {
    const period = this.getCurrentPeriod(orgId);
    period[resource] += count;
    period.lastUpdated = new Date();

    // We don't know the tier here — check must be called separately
    return {
      allowed: true,
      resource,
      current: period[resource],
      limit: -1,
      remaining: -1,
      percentUsed: 0,
    };
  }

  /* ── Limit checking ── */

  /**
   * Check if an org is within its tier limits for a specific resource.
   * Call this BEFORE allowing the action to proceed.
   */
  checkLimit(
    orgId: string,
    tier: string,
    resource:
      | 'events'
      | 'automatedActions'
      | 'abuseipdbChecks'
      | 'apiGenerations'
  ): UsageCheckResult {
    const period = this.getCurrentPeriod(orgId);
    const limits = TIER_LIMITS[tier.toLowerCase()] ?? TIER_LIMITS.free;
    const limit = limits[resource];
    const current = period[resource];

    // Unlimited
    if (limit === -1) {
      return {
        allowed: true,
        resource,
        current,
        limit: -1,
        remaining: -1,
        percentUsed: 0,
      };
    }

    // Zero limit (feature not available)
    if (limit === 0) {
      return {
        allowed: false,
        resource,
        current,
        limit: 0,
        remaining: 0,
        percentUsed: 100,
        warning: `${resource} is not available on the ${tier} plan. Upgrade at /pricing`,
      };
    }

    const percentUsed = Math.round((current / limit) * 100);
    const remaining = Math.max(0, limit - current);
    const allowed = current < limit;

    let warning: string | undefined;
    if (!allowed) {
      warning = `Monthly ${resource} limit reached (${current.toLocaleString()}/${limit.toLocaleString()}). Upgrade for higher limits.`;
      logWarn('Usage limit exceeded', {
        orgId,
        tier,
        resource,
        current,
        limit,
      });
    } else if (current / limit >= WARNING_THRESHOLD) {
      warning = `Approaching ${resource} limit: ${percentUsed}% used (${current.toLocaleString()}/${limit.toLocaleString()}).`;
      logInfo('Usage warning threshold reached', {
        orgId,
        tier,
        resource,
        percentUsed,
      });
    }

    return {
      allowed,
      resource,
      current,
      limit,
      remaining,
      percentUsed,
      warning,
    };
  }

  /* ── Summary ── */

  /**
   * Get full usage summary for an organization — used in dashboards and billing.
   */
  getUsageSummary(orgId: string, tier: string): UsageSummary {
    const period = this.getCurrentPeriod(orgId);
    const limits = TIER_LIMITS[tier.toLowerCase()] ?? TIER_LIMITS.free;

    const makeMetric = (current: number, limit: number) => ({
      current,
      limit,
      percentUsed: limit > 0 ? Math.round((current / limit) * 100) : 0,
    });

    const warnings: string[] = [];
    const resources = [
      'events',
      'automatedActions',
      'abuseipdbChecks',
      'apiGenerations',
    ] as const;

    for (const resource of resources) {
      const limit = limits[resource];
      const current = period[resource];
      if (limit > 0 && current / limit >= WARNING_THRESHOLD) {
        warnings.push(
          `${resource}: ${Math.round((current / limit) * 100)}% of monthly limit used`
        );
      }
    }

    return {
      orgId,
      tier,
      billingPeriod: { start: period.periodStart, end: period.periodEnd },
      events: makeMetric(period.events, limits.events),
      automatedActions: makeMetric(
        period.automatedActions,
        limits.automatedActions
      ),
      abuseipdbChecks: makeMetric(
        period.abuseipdbChecks,
        limits.abuseipdbChecks
      ),
      apiGenerations: makeMetric(period.apiGenerations, limits.apiGenerations),
      warnings,
    };
  }

  /* ── Admin ── */

  /** Reset usage for an org (for testing or billing cycle reset) */
  resetUsage(orgId: string): void {
    const key = this.getPeriodKey(orgId);
    this.periods.delete(key);
    logInfo('Usage reset', { orgId });
  }

  /** Get all active periods (admin view) */
  getAllActivePeriods(): UsagePeriod[] {
    return Array.from(this.periods.values());
  }
}

/** Singleton instance */
export const usageMeteringService = new UsageMeteringService();
