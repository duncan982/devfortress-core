/**
 * Quota Enforcement Service
 * Enforces tier-based limits for API generations and honeypots
 *
 * Pricing Tiers (aligned with devfortress-pricing-3.html, 6-tier model):
 * - STARTER ($99/mo): 25 API generations, 1 honeypot, alerts only (no automated actions)
 * - PRO ($199/mo): 60 API generations, 3 honeypots, 500 automated actions/mo
 * - TEAM ($499/mo): 250 API generations, 10 honeypots, 5K actions/mo
 * - BUSINESS ($2K/mo): 500 API generations, 25 honeypots, unlimited actions (Coming Soon)
 * - ENTERPRISE_PLUS (custom): Unlimited everything (Coming Soon)
 */

import { SubscriptionPlan, SubscriptionStatus } from '@prisma/client';
import { prisma } from '@core/lib/prisma';
import { logInfo, logWarn, logError } from '@core/lib/logger';
import { hasPrivilegedRole } from '@core/lib/auth/subscription-middleware';
import { getUserTeams, getTeamMembers } from '@core/lib/teams/team-service';

/**
 * Tier limits for API generations (per billing cycle/month)
 * Note: Uses Prisma SubscriptionPlan enum (STARTER/PRO/ENTERPRISE/TEAM/BUSINESS/ENTERPRISE_PLUS)
 * ENTERPRISE in Prisma maps to "Team" plan in pricing v3
 */
export const GENERATION_LIMITS: Record<SubscriptionPlan, number> = {
  STARTER: 25,
  PRO: 60,
  ENTERPRISE: 250, // "Team" plan in pricing v3
  TEAM: 250,
  BUSINESS: 500,
  ENTERPRISE_PLUS: -1, // Unlimited
};

/**
 * Tier limits for honeypots (concurrent active)
 */
export const HONEYPOT_LIMITS: Record<SubscriptionPlan, number> = {
  STARTER: 1,
  PRO: 3,
  ENTERPRISE: 10, // "Team" plan in pricing v3
  TEAM: 10,
  BUSINESS: 25,
  ENTERPRISE_PLUS: -1, // Unlimited
};

/**
 * Tier limits for insight generations (per billing cycle/month)
 * These use AI and cost money, so we need to enforce limits
 */
export const INSIGHT_LIMITS: Record<SubscriptionPlan, number> = {
  STARTER: 10, // 10 insight generations per month
  PRO: 100, // Updated: 100 per month (was 50, aligned with pricing HTML "AI insights 100/mo")
  ENTERPRISE: 200, // 200 insight generations per month ("Team" plan)
  TEAM: 200,
  BUSINESS: 500,
  ENTERPRISE_PLUS: -1, // Unlimited
};

/**
 * Tier limits for automated response actions (per billing cycle/month)
 * Starter = 0 (alerts only, no automated actions)
 * -1 = unlimited
 */
export const AUTOMATED_ACTION_LIMITS: Record<SubscriptionPlan, number> = {
  STARTER: 0, // Alert only — no automated response
  PRO: 500, // 500 automated actions per month
  ENTERPRISE: 5_000, // "Team" plan: 5,000 actions per month
  TEAM: 5_000,
  BUSINESS: -1, // Unlimited
  ENTERPRISE_PLUS: -1, // Unlimited
};

export interface QuotaCheckResult {
  allowed: boolean;
  current: number;
  limit: number;
  remaining: number;
  resetDate?: Date;
  reason?: string;
}

export interface UserQuotaInfo {
  userId: string;
  plan: SubscriptionPlan;
  isPrivileged: boolean;
  apiGenerations: QuotaCheckResult;
  honeypots: QuotaCheckResult;
  insights: QuotaCheckResult;
  billingCycleStart: Date;
  billingCycleEnd: Date;
}

/**
 * Get the current billing cycle dates for a subscription
 */
export function getBillingCycleDates(renewsAt?: Date | null): {
  start: Date;
  end: Date;
} {
  const now = new Date();

  if (renewsAt) {
    // Calculate billing cycle based on renewal date
    const end = new Date(renewsAt);
    const start = new Date(end);
    start.setMonth(start.getMonth() - 1);

    // Adjust if we're past the renewal date
    while (end < now) {
      start.setMonth(start.getMonth() + 1);
      end.setMonth(end.getMonth() + 1);
    }

    return { start, end };
  }

  // Default: current calendar month
  const start = new Date(now.getFullYear(), now.getMonth(), 1);
  const end = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

  return { start, end };
}

/**
 * Count API generations for a user in the current billing cycle
 */
export async function countBillingCycleGenerations(
  userId: string,
  billingCycleStart: Date
): Promise<number> {
  try {
    const count = await prisma.apiProject.count({
      where: {
        createdById: userId,
        createdAt: {
          gte: billingCycleStart,
        },
      },
    });

    return count;
  } catch (error) {
    logError('Failed to count billing cycle generations', { userId, error });
    return 0;
  }
}

/**
 * Count active honeypots for a user
 */
export async function countActiveHoneypots(userId: string): Promise<number> {
  try {
    const count = await prisma.honeypot.count({
      where: {
        ownerId: userId,
        status: {
          in: ['ACTIVE', 'DEPLOYING', 'DEPLOYED'],
        },
      },
    });

    return count;
  } catch (error) {
    logError('Failed to count active honeypots', { userId, error });
    return 0;
  }
}

/**
 * Get the user's active subscription plan
 */
export async function getUserPlan(
  userId: string
): Promise<{ plan: SubscriptionPlan; renewsAt: Date | null } | null> {
  try {
    const subscription = await prisma.subscription.findFirst({
      where: {
        userId,
        status: {
          in: [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING],
        },
      },
      orderBy: { createdAt: 'desc' },
      select: {
        plan: true,
        renewsAt: true,
      },
    });

    return subscription;
  } catch (error) {
    logError('Failed to get user plan', { userId, error });
    return null;
  }
}

/**
 * Check if user can perform an API generation
 */
export async function checkGenerationQuota(
  userId: string
): Promise<QuotaCheckResult> {
  try {
    // Check if user has privileged role (unlimited access)
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { role: true },
    });

    if (user && hasPrivilegedRole(user.role)) {
      logInfo('Generation quota check: privileged user bypass', { userId });
      return {
        allowed: true,
        current: 0,
        limit: -1, // Unlimited
        remaining: -1,
        reason: 'Privileged user - unlimited generations',
      };
    }

    // Check if user is in a team
    const userTeams = await getUserTeams(userId);
    const activeTeam = userTeams.find(team =>
      team.members.some(member => member.userId === userId)
    ); // Any team the user is in

    let quotaUserIds: string[] = [userId];
    let plan: SubscriptionPlan;
    let renewsAt: Date | null;

    if (activeTeam) {
      // Use team owner's subscription and aggregate team usage
      const teamOwnerId = activeTeam.createdById;
      const subscriptionInfo = await getUserPlan(teamOwnerId);
      if (!subscriptionInfo) {
        logWarn(
          'Generation quota check: team owner has no active subscription',
          { userId, teamId: activeTeam.id }
        );
        return {
          allowed: false,
          current: 0,
          limit: 0,
          remaining: 0,
          reason: 'Team subscription required. Please contact your team owner.',
        };
      }
      plan = subscriptionInfo.plan;
      renewsAt = subscriptionInfo.renewsAt;

      // Get all team members for quota aggregation
      const teamMembers = await getTeamMembers(activeTeam.id);
      quotaUserIds = teamMembers.map(member => member.userId);
    } else {
      // Individual user
      const subscriptionInfo = await getUserPlan(userId);
      if (!subscriptionInfo) {
        logWarn('Generation quota check: no active subscription', { userId });
        return {
          allowed: false,
          current: 0,
          limit: 0,
          remaining: 0,
          reason:
            'No active subscription. Please subscribe to use API generation.',
        };
      }
      plan = subscriptionInfo.plan;
      renewsAt = subscriptionInfo.renewsAt;
    }

    const limit = GENERATION_LIMITS[plan];
    const { start, end } = getBillingCycleDates(renewsAt);

    // Count generations for all quota holders (team members or individual)
    let current = 0;
    for (const id of quotaUserIds) {
      current += await countBillingCycleGenerations(id, start);
    }
    const remaining = Math.max(0, limit - current);
    const allowed = current < limit;

    logInfo('Generation quota check', {
      userId,
      quotaUserIds,
      isTeam: !!activeTeam,
      plan,
      current,
      limit,
      remaining,
      allowed,
      billingCycleStart: start.toISOString(),
      billingCycleEnd: end.toISOString(),
    });

    return {
      allowed,
      current,
      limit,
      remaining,
      resetDate: end,
      reason: allowed
        ? undefined
        : `Monthly generation limit reached (${limit}). Upgrade your plan or wait until ${end.toLocaleDateString()} for reset.`,
    };
  } catch (error) {
    logError('Failed to check generation quota', { userId, error });
    return {
      allowed: false,
      current: 0,
      limit: 0,
      remaining: 0,
      reason: 'Failed to verify quota. Please try again.',
    };
  }
}

/**
 * Check if user can create a new honeypot
 */
export async function checkHoneypotQuota(
  userId: string
): Promise<QuotaCheckResult> {
  try {
    // Check if user has privileged role (unlimited access)
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { role: true },
    });

    if (user && hasPrivilegedRole(user.role)) {
      logInfo('Honeypot quota check: privileged user bypass', { userId });
      return {
        allowed: true,
        current: 0,
        limit: -1, // Unlimited
        remaining: -1,
        reason: 'Privileged user - unlimited honeypots',
      };
    }

    // Get user's subscription
    const subscriptionInfo = await getUserPlan(userId);

    if (!subscriptionInfo) {
      logWarn('Honeypot quota check: no active subscription', { userId });
      return {
        allowed: false,
        current: 0,
        limit: 0,
        remaining: 0,
        reason: 'No active subscription. Please subscribe to deploy honeypots.',
      };
    }

    const { plan } = subscriptionInfo;
    const limit = HONEYPOT_LIMITS[plan];

    // Count active honeypots
    const current = await countActiveHoneypots(userId);
    const remaining = Math.max(0, limit - current);
    const allowed = current < limit;

    logInfo('Honeypot quota check', {
      userId,
      plan,
      current,
      limit,
      remaining,
      allowed,
    });

    return {
      allowed,
      current,
      limit,
      remaining,
      reason: allowed
        ? undefined
        : `Honeypot limit reached (${limit}). Delete an existing honeypot or upgrade your plan.`,
    };
  } catch (error) {
    logError('Failed to check honeypot quota', { userId, error });
    return {
      allowed: false,
      current: 0,
      limit: 0,
      remaining: 0,
      reason: 'Failed to verify quota. Please try again.',
    };
  }
}

/**
 * Count insight generations for a user in the current billing cycle
 */
export async function countBillingCycleInsights(
  userId: string,
  billingCycleStart: Date
): Promise<number> {
  try {
    const count = await prisma.flywheelInsight.count({
      where: {
        apiProject: {
          createdById: userId,
        },
        generatedAt: {
          gte: billingCycleStart,
        },
      },
    });

    return count;
  } catch (error) {
    logError('Failed to count billing cycle insights', { userId, error });
    return 0;
  }
}

/**
 * Check if user can generate a new insight (LEARN phase quota)
 */
export async function checkInsightQuota(
  userId: string
): Promise<QuotaCheckResult> {
  try {
    // Check if user has privileged role (unlimited access)
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { role: true },
    });

    if (user && hasPrivilegedRole(user.role)) {
      logInfo('Insight quota check: privileged user bypass', { userId });
      return {
        allowed: true,
        current: 0,
        limit: -1, // Unlimited
        remaining: -1,
        reason: 'Privileged user - unlimited insights',
      };
    }

    // Get user's subscription
    const subscriptionInfo = await getUserPlan(userId);

    if (!subscriptionInfo) {
      logWarn('Insight quota check: no active subscription', { userId });
      return {
        allowed: false,
        current: 0,
        limit: 0,
        remaining: 0,
        reason:
          'No active subscription. Please subscribe to generate insights.',
      };
    }

    const { plan, renewsAt } = subscriptionInfo;

    const limit = INSIGHT_LIMITS[plan];
    const { start, end } = getBillingCycleDates(renewsAt);

    // Count insights in current billing cycle
    const current = await countBillingCycleInsights(userId, start);
    const remaining = Math.max(0, limit - current);
    const allowed = current < limit;

    logInfo('Insight quota check', {
      userId,
      plan,
      current,
      limit,
      remaining,
      allowed,
      billingCycleStart: start.toISOString(),
      billingCycleEnd: end.toISOString(),
    });

    return {
      allowed,
      current,
      limit,
      remaining,
      resetDate: end,
      reason: allowed
        ? undefined
        : `Monthly insight limit reached (${limit}). Upgrade your plan or wait until ${end.toLocaleDateString()} for reset.`,
    };
  } catch (error) {
    logError('Failed to check insight quota', { userId, error });
    return {
      allowed: false,
      current: 0,
      limit: 0,
      remaining: 0,
      reason: 'Failed to verify quota. Please try again.',
    };
  }
}

/**
 * Get complete quota information for a user
 */
export async function getUserQuotaInfo(
  userId: string
): Promise<UserQuotaInfo | null> {
  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { role: true },
    });

    const isPrivileged = user ? hasPrivilegedRole(user.role) : false;
    const subscriptionInfo = await getUserPlan(userId);

    const plan = subscriptionInfo?.plan || SubscriptionPlan.STARTER;
    const { start, end } = getBillingCycleDates(subscriptionInfo?.renewsAt);

    const [apiGenerations, honeypots, insights] = await Promise.all([
      checkGenerationQuota(userId),
      checkHoneypotQuota(userId),
      checkInsightQuota(userId),
    ]);

    return {
      userId,
      plan,
      isPrivileged,
      apiGenerations,
      honeypots,
      insights,
      billingCycleStart: start,
      billingCycleEnd: end,
    };
  } catch (error) {
    logError('Failed to get user quota info', { userId, error });
    return null;
  }
}

/**
 * Enforce generation quota - throws error if limit exceeded
 */
export async function enforceGenerationQuota(userId: string): Promise<void> {
  const quota = await checkGenerationQuota(userId);

  if (!quota.allowed) {
    throw new Error(quota.reason || 'Generation quota exceeded');
  }
}

/**
 * Enforce honeypot quota - throws error if limit exceeded
 */
export async function enforceHoneypotQuota(userId: string): Promise<void> {
  const quota = await checkHoneypotQuota(userId);

  if (!quota.allowed) {
    throw new Error(quota.reason || 'Honeypot quota exceeded');
  }
}

/**
 * Get quota status message for UI display
 */
export function getQuotaStatusMessage(quota: QuotaCheckResult): string {
  if (quota.limit === -1) {
    return 'Unlimited (Admin)';
  }

  if (quota.remaining === 0) {
    return `Limit reached (${quota.current}/${quota.limit})`;
  }

  return `${quota.remaining} remaining (${quota.current}/${quota.limit})`;
}

/**
 * Check if user is approaching quota limit (>80% used)
 */
export function isApproachingLimit(quota: QuotaCheckResult): boolean {
  if (quota.limit === -1) return false;
  if (quota.limit === 0) return true;

  const usagePercent = (quota.current / quota.limit) * 100;
  return usagePercent >= 80;
}
