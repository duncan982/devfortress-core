/**
 * Premium Features Client-Safe Utilities
 * Utilities that can be safely used in both server and client components
 */

import { SubscriptionTier } from '@core/lib/payments/types';

/**
 * Get Tailwind CSS classes for tier badge styling
 */
export function getTierBadgeColor(tier: SubscriptionTier | null): string {
  switch (tier) {
    case SubscriptionTier.STARTER:
      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
    case SubscriptionTier.PRO:
      return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300';
    case SubscriptionTier.ENTERPRISE:
      return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300';
    default:
      return 'bg-neutral-100 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-300';
  }
}

/**
 * Get the lowest tier from an array of tiers
 */
export function getLowestTier(tiers: SubscriptionTier[]): SubscriptionTier {
  const tierOrder: SubscriptionTier[] = [
    SubscriptionTier.STARTER,
    SubscriptionTier.PRO,
    SubscriptionTier.ENTERPRISE,
  ];

  for (const tier of tierOrder) {
    if (tiers.includes(tier)) {
      return tier;
    }
  }

  return SubscriptionTier.STARTER;
}

/**
 * Format tier name for display
 */
export function formatTierName(tier: SubscriptionTier | null): string {
  if (!tier) return 'Free';
  
  switch (tier) {
    case SubscriptionTier.STARTER:
      return 'Starter';
    case SubscriptionTier.PRO:
      return 'Pro';
    case SubscriptionTier.ENTERPRISE:
      return 'Enterprise';
    default:
      return 'Free';
  }
}
