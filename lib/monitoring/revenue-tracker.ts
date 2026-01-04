/**
 * Revenue Tracking Service
 * Tracks monthly revenue from subscriptions and credits
 * Determines if funds are available for infrastructure upgrades
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';

// Upgrade cost estimates
const UPGRADE_COSTS = {
  vercelPro: 20, // $20/month
  supabasePro: 25, // $25/month
};

interface RevenueMetrics {
  monthlyRevenue: number;
  subscriptionRevenue: number;
  creditRevenue: number;
  projectedRevenue: number;
  fundsAvailable: boolean;
  canUpgradeVercel: boolean;
  canUpgradeSupabase: boolean;
  canUpgradeBoth: boolean;
}

/**
 * Calculate monthly revenue from subscriptions
 */
async function getSubscriptionRevenue(month: Date): Promise<number> {
  try {
    const startOfMonth = new Date(month.getFullYear(), month.getMonth(), 1);
    const endOfMonth = new Date(month.getFullYear(), month.getMonth() + 1, 0);

    const subscriptions = await prisma.subscription.findMany({
      where: {
        status: 'ACTIVE',
        createdAt: {
          lte: endOfMonth,
        },
        OR: [
          { canceledAt: null },
          {
            canceledAt: {
              gte: startOfMonth,
            },
          },
        ],
      },
      select: {
        plan: true,
      },
    });

    // Calculate revenue based on plan prices
    const planPrices: Record<string, number> = {
      STARTER: 69,
      PRO: 129,
      ENTERPRISE: 299,
    };

    const revenue = subscriptions.reduce((sum, sub) => {
      return sum + (planPrices[sub.plan] || 0);
    }, 0);

    logInfo('Subscription revenue calculated', {
      month,
      revenue,
      count: subscriptions.length,
    });
    return revenue;
  } catch (error) {
    logError('Failed to calculate subscription revenue', { error, month });
    return 0;
  }
}

/**
 * Calculate monthly revenue from credit purchases
 */
async function getCreditRevenue(month: Date): Promise<number> {
  try {
    const startOfMonth = new Date(month.getFullYear(), month.getMonth(), 1);
    const endOfMonth = new Date(month.getFullYear(), month.getMonth() + 1, 0);

    const creditPurchases = await prisma.creditTransaction.findMany({
      where: {
        type: 'PURCHASE',
        createdAt: {
          gte: startOfMonth,
          lte: endOfMonth,
        },
      },
      select: {
        amount: true,
      },
    });

    // Assuming $0.75 per credit
    const CREDIT_PRICE = 0.75;
    const revenue = creditPurchases.reduce((sum, purchase) => {
      return sum + purchase.amount * CREDIT_PRICE;
    }, 0);

    logInfo('Credit revenue calculated', {
      month,
      revenue,
      purchases: creditPurchases.length,
    });
    return revenue;
  } catch (error) {
    logError('Failed to calculate credit revenue', { error, month });
    return 0;
  }
}

/**
 * Project next month's revenue based on active subscriptions
 */
async function getProjectedRevenue(): Promise<number> {
  try {
    const activeSubscriptions = await prisma.subscription.findMany({
      where: {
        status: 'ACTIVE',
      },
      select: {
        plan: true,
      },
    });

    const planPrices: Record<string, number> = {
      STARTER: 69,
      PRO: 129,
      ENTERPRISE: 299,
    };

    const projected = activeSubscriptions.reduce((sum, sub) => {
      return sum + (planPrices[sub.plan] || 0);
    }, 0);

    logInfo('Projected revenue calculated', {
      projected,
      subscriptions: activeSubscriptions.length,
    });
    return projected;
  } catch (error) {
    logError('Failed to calculate projected revenue', { error });
    return 0;
  }
}

/**
 * Get comprehensive revenue metrics for the current month
 */
export async function getRevenueMetrics(): Promise<RevenueMetrics> {
  const currentMonth = new Date();

  const subscriptionRevenue = await getSubscriptionRevenue(currentMonth);
  const creditRevenue = await getCreditRevenue(currentMonth);
  const projectedRevenue = await getProjectedRevenue();

  const monthlyRevenue = subscriptionRevenue + creditRevenue;

  // Determine if upgrades are affordable
  // Reserve 30% for operational costs and taxes
  const availableFunds = monthlyRevenue * 0.7;

  const canUpgradeVercel = availableFunds >= UPGRADE_COSTS.vercelPro;
  const canUpgradeSupabase = availableFunds >= UPGRADE_COSTS.supabasePro;
  const canUpgradeBoth =
    availableFunds >= UPGRADE_COSTS.vercelPro + UPGRADE_COSTS.supabasePro;

  const metrics: RevenueMetrics = {
    monthlyRevenue,
    subscriptionRevenue,
    creditRevenue,
    projectedRevenue,
    fundsAvailable: availableFunds > 0,
    canUpgradeVercel,
    canUpgradeSupabase,
    canUpgradeBoth,
  };

  logInfo('Revenue metrics calculated', { metrics });
  return metrics;
}

/**
 * Check if upgrade is recommended based on usage and revenue
 */
export interface UpgradeRecommendation {
  recommended: boolean;
  service: 'vercel' | 'supabase' | 'both' | null;
  reason: string;
  affordable: boolean;
  costPerMonth: number;
}

export async function getUpgradeRecommendation(
  usagePercentage: number,
  service: 'vercel' | 'supabase'
): Promise<UpgradeRecommendation> {
  const revenueMetrics = await getRevenueMetrics();

  let recommended = false;
  let reason = '';
  let affordable = false;
  let costPerMonth = 0;

  if (usagePercentage >= 80) {
    recommended = true;
    reason = `${service.charAt(0).toUpperCase() + service.slice(1)} usage at ${usagePercentage.toFixed(1)}% - upgrade recommended`;

    if (service === 'vercel') {
      affordable = revenueMetrics.canUpgradeVercel;
      costPerMonth = UPGRADE_COSTS.vercelPro;
    } else {
      affordable = revenueMetrics.canUpgradeSupabase;
      costPerMonth = UPGRADE_COSTS.supabasePro;
    }

    if (!affordable) {
      reason += ` (insufficient funds - need $${costPerMonth}/mo, available: $${(revenueMetrics.monthlyRevenue * 0.7).toFixed(2)})`;
    }
  } else {
    reason = `${service.charAt(0).toUpperCase() + service.slice(1)} usage at ${usagePercentage.toFixed(1)}% - no upgrade needed`;
  }

  return {
    recommended,
    service: recommended ? service : null,
    reason,
    affordable,
    costPerMonth,
  };
}

/**
 * Get upgrade cost estimates
 */
export function getUpgradeCosts() {
  return {
    vercel: {
      current: 'Hobby (Free)',
      upgrade: 'Pro',
      cost: UPGRADE_COSTS.vercelPro,
      benefits: [
        'Unlimited bandwidth',
        'Advanced analytics',
        'Team collaboration',
        'Password protection',
      ],
    },
    supabase: {
      current: 'Free',
      upgrade: 'Pro',
      cost: UPGRADE_COSTS.supabasePro,
      benefits: [
        '8GB database',
        '100GB storage',
        '250GB bandwidth',
        'Daily backups',
        'No pausing',
      ],
    },
  };
}
