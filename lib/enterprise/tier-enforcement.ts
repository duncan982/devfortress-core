/**
 * Tier Enforcement Middleware
 *
 * Validates that a user's subscription tier permits the requested feature.
 * Used in API routes to gate features by plan (Starter / Pro / Enterprise).
 *
 * Usage in route:
 *   const tierCheck = enforceTier(session.user.tier, 'pro', 'Custom playbooks');
 *   if (tierCheck) return tierCheck; // returns 403 NextResponse if insufficient tier
 */

import { NextResponse } from 'next/server';
import { logWarn } from '@core/lib/logger';

/* ─── Tier hierarchy ─── */
const TIER_RANK: Record<string, number> = {
  free: 0,
  starter: 1,
  pro: 2,
  enterprise: 3,
  enterprise_plus: 4,
};

export type SubscriptionTier =
  | 'free'
  | 'starter'
  | 'pro'
  | 'enterprise'
  | 'enterprise_plus';

/* ─── Feature gates ─── */
export interface FeatureGate {
  feature: string;
  minimumTier: SubscriptionTier;
  /** Optional numeric limit per tier. -1 = unlimited */
  limits?: Partial<Record<SubscriptionTier, number>>;
  /** Description shown in upgrade prompt */
  upgradeMessage?: string;
}

export const FEATURE_GATES: FeatureGate[] = [
  // Core detection
  {
    feature: 'pre_auth_detection',
    minimumTier: 'starter',
    limits: { starter: 2, pro: 8, enterprise: 8, enterprise_plus: 8 },
    upgradeMessage:
      'Starter includes 2 of 8 pre-auth patterns. Upgrade to Pro for all 8.',
  },
  {
    feature: 'post_auth_detection',
    minimumTier: 'pro',
    upgradeMessage: 'Post-authentication detection requires Pro or higher.',
  },

  // Response actions
  {
    feature: 'automated_ip_blocking',
    minimumTier: 'pro',
    upgradeMessage: 'Automated IP blocking requires Pro or higher.',
  },
  {
    feature: 'session_revocation',
    minimumTier: 'pro',
    upgradeMessage: 'Session revocation requires Pro or higher.',
  },
  {
    feature: 'rate_limiting',
    minimumTier: 'pro',
    upgradeMessage: 'Rate limiting actions require Pro or higher.',
  },
  {
    feature: 'account_lock',
    minimumTier: 'pro',
    upgradeMessage: 'Account locking on threats requires Pro or higher.',
  },
  {
    feature: 'custom_playbooks',
    minimumTier: 'enterprise',
    upgradeMessage: 'Custom response playbooks are an Enterprise feature.',
  },

  // Integrations
  {
    feature: 'siem_integration',
    minimumTier: 'enterprise',
    upgradeMessage: 'SIEM integration is an Enterprise feature.',
  },
  {
    feature: 'sso_saml',
    minimumTier: 'pro',
    limits: { pro: 1, enterprise: -1, enterprise_plus: -1 },
    upgradeMessage:
      'SSO/SAML is a Pro add-on ($50/mo) or included with Enterprise.',
  },
  {
    feature: 'mtls',
    minimumTier: 'enterprise',
    upgradeMessage: 'mTLS certificate authentication is an Enterprise feature.',
  },

  // Compliance
  {
    feature: 'compliance_reports',
    minimumTier: 'pro',
    limits: { pro: 1, enterprise: -1, enterprise_plus: -1 },
    upgradeMessage:
      'Compliance reports are a Pro add-on or included with Enterprise.',
  },

  // AbuseIPDB
  {
    feature: 'abuseipdb_checks',
    minimumTier: 'starter',
    limits: {
      starter: 10000,
      pro: 100000,
      enterprise: -1,
      enterprise_plus: -1,
    },
    upgradeMessage:
      'You have reached your AbuseIPDB check limit. Upgrade for more.',
  },
  {
    feature: 'abuseipdb_reporting',
    minimumTier: 'pro',
    upgradeMessage: 'AbuseIPDB attack reporting requires Pro or higher.',
  },
  {
    feature: 'abuseipdb_realtime_sync',
    minimumTier: 'pro',
    upgradeMessage: 'Real-time blacklist sync requires Pro or higher.',
  },

  // Scale
  {
    feature: 'apps_monitored',
    minimumTier: 'starter',
    limits: {
      starter: 1,
      pro: 3,
      enterprise: -1,
      enterprise_plus: -1,
    },
  },
  {
    feature: 'team_seats',
    minimumTier: 'starter',
    limits: {
      starter: 1,
      pro: 5,
      enterprise: -1,
      enterprise_plus: -1,
    },
  },
  {
    feature: 'events_per_month',
    minimumTier: 'starter',
    limits: {
      starter: 50000,
      pro: 500000,
      enterprise: -1,
      enterprise_plus: -1,
    },
  },
  {
    feature: 'honeypots',
    minimumTier: 'pro',
    limits: {
      pro: 3,
      enterprise: -1,
      enterprise_plus: -1,
    },
    upgradeMessage: 'Honeypot deployment requires Pro or higher.',
  },
  {
    feature: 'data_retention_days',
    minimumTier: 'starter',
    limits: {
      starter: 7,
      pro: 30,
      enterprise: 365,
      enterprise_plus: -1,
    },
  },

  // Webhooks
  {
    feature: 'webhook_notifications',
    minimumTier: 'pro',
    upgradeMessage: 'Webhook notifications require Pro or higher.',
  },

  // Closed-loop modes
  {
    feature: 'external_closed_loop_blocking',
    minimumTier: 'pro',
    upgradeMessage:
      'Automated blocking via external closed-loop requires Pro or higher. Starter is view-only.',
  },
  {
    feature: 'internal_closed_loop',
    minimumTier: 'pro',
    limits: { pro: 0, enterprise: -1, enterprise_plus: -1 },
    upgradeMessage:
      'Internal closed-loop as primary mode is an Enterprise feature. Pro uses internal only as backup.',
  },
  {
    feature: 'hybrid_closed_loop',
    minimumTier: 'pro',
    limits: { pro: 1, enterprise: -1, enterprise_plus: -1 },
    upgradeMessage:
      'Hybrid closed-loop is a Pro add-on ($75/mo) or included with Enterprise.',
  },
  {
    feature: 'air_gap_mode',
    minimumTier: 'enterprise',
    upgradeMessage:
      'Air-gap mode (zero external dependencies) is an Enterprise feature.',
  },

  // AI Agent CL
  {
    feature: 'ai_agent_closed_loop',
    minimumTier: 'pro',
    limits: { pro: 10, enterprise: -1, enterprise_plus: -1 },
    upgradeMessage:
      'AI Agent CL Security is a Pro add-on ($100/mo, up to 10 agents) or usage-based on Enterprise.',
  },

  // Enterprise only
  {
    feature: 'uptime_sla',
    minimumTier: 'enterprise',
    upgradeMessage: 'Uptime SLA guarantees are an Enterprise feature.',
  },
  {
    feature: 'dedicated_csm',
    minimumTier: 'enterprise',
    upgradeMessage: 'Dedicated customer success is an Enterprise feature.',
  },
  {
    feature: 'data_residency',
    minimumTier: 'enterprise',
    upgradeMessage: 'Data residency options are an Enterprise feature.',
  },
];

/* ─── Enforcement Functions ─── */

/**
 * Check if a tier has access to a feature.
 * Returns null if allowed, or a NextResponse 403 if denied.
 */
export function enforceTier(
  userTier: string,
  requiredTier: SubscriptionTier,
  featureName: string
): NextResponse | null {
  const userRank = TIER_RANK[userTier?.toLowerCase()] ?? 0;
  const requiredRank = TIER_RANK[requiredTier] ?? 0;

  if (userRank >= requiredRank) return null;

  logWarn('Tier enforcement: access denied', {
    userTier,
    requiredTier,
    feature: featureName,
  });

  return NextResponse.json(
    {
      error: 'Upgrade required',
      feature: featureName,
      currentTier: userTier,
      requiredTier,
      message: `This feature requires ${requiredTier} tier or higher.`,
      upgradeUrl: '/pricing',
    },
    { status: 403 }
  );
}

/**
 * Check if a tier's usage is within limits for a metered feature.
 * Returns { allowed: true, remaining } or { allowed: false, limit, current }.
 */
export function checkFeatureLimit(
  feature: string,
  userTier: string,
  currentUsage: number
): { allowed: boolean; limit: number; remaining: number } {
  const gate = FEATURE_GATES.find(g => g.feature === feature);
  if (!gate) return { allowed: true, limit: -1, remaining: -1 };

  const tierRank = TIER_RANK[userTier?.toLowerCase()] ?? 0;
  const minRank = TIER_RANK[gate.minimumTier] ?? 0;
  if (tierRank < minRank) {
    return { allowed: false, limit: 0, remaining: 0 };
  }

  if (!gate.limits) return { allowed: true, limit: -1, remaining: -1 };

  const tierKey = userTier?.toLowerCase() as SubscriptionTier;
  const limit = gate.limits[tierKey] ?? 0;
  if (limit === -1) return { allowed: true, limit: -1, remaining: -1 };

  const remaining = Math.max(0, limit - currentUsage);
  return {
    allowed: currentUsage < limit,
    limit,
    remaining,
  };
}

/**
 * Get all feature gates and their status for a given tier.
 * Used for the pricing comparison table and dashboard feature indicators.
 */
export function getTierFeatures(
  tier: string
): Array<{ feature: string; available: boolean; limit: number | null }> {
  const tierRank = TIER_RANK[tier?.toLowerCase()] ?? 0;
  return FEATURE_GATES.map(gate => {
    const minRank = TIER_RANK[gate.minimumTier] ?? 0;
    const available = tierRank >= minRank;
    const tierKey = tier?.toLowerCase() as SubscriptionTier;
    const limit = gate.limits?.[tierKey] ?? null;
    return { feature: gate.feature, available, limit };
  });
}
