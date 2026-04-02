/**
 * Feature Flags Module
 *
 * Provides feature gating based on subscription tiers.
 * Re-exports from subscription-middleware for convenience.
 *
 * @module lib/features/feature-flags
 */

export {
  PREMIUM_FEATURES,
  type PremiumFeature,
  canAccessFeature,
  requireTier,
  getUserSubscriptionWithPlan,
  hasActiveSubscription,
  hasPrivilegedRole,
} from '@core/lib/auth/subscription-middleware';

import { SubscriptionTier } from '@core/lib/payments/types';

/**
 * MVP Feature Flags
 *
 * These flags control which features are enabled for the MVP launch.
 * Payment providers: Paddle (international) + Paystack (local KES/African markets)
 * Stripe has been removed — not available for Kenya-based businesses without local entity.
 */
export const MVP_FEATURE_FLAGS = {
  /**
   * Enable credit purchasing via Paddle/Paystack
   * Default: false for MVP (GitHub Marketplace subscriptions only)
   * POST-MVP: Set to true when credit purchasing feature is ready
   */
  ENABLE_CREDIT_PURCHASING: process.env.ENABLE_CREDIT_PURCHASING === 'true',

  /**
   * @deprecated Stripe removed — not available for Kenya-based businesses.
   * Use Paddle instead for international payments.
   */
  ENABLE_STRIPE: false,

  /**
   * Enable Paddle payment provider (international — Merchant of Record)
   * Paddle handles VAT/tax compliance, invoicing, and global payments.
   * No local business registration docs required.
   */
  ENABLE_PADDLE: process.env.ENABLE_PADDLE === 'true',

  /**
   * Enable Paystack payment provider (African markets — KES, NGN, GHS, ZAR)
   * Use for local currency payments, M-Pesa, mobile money.
   */
  ENABLE_PAYSTACK: process.env.ENABLE_PAYSTACK === 'true',
} as const;

/**
 * Check if credit purchasing is enabled
 */
export function isCreditPurchasingEnabled(): boolean {
  return MVP_FEATURE_FLAGS.ENABLE_CREDIT_PURCHASING;
}

/**
 * Check if a specific payment provider is enabled
 */
export function isPaymentProviderEnabled(
  provider: 'stripe' | 'paddle' | 'paystack'
): boolean {
  switch (provider) {
    case 'stripe':
      // Stripe removed — always disabled
      return false;
    case 'paddle':
      return MVP_FEATURE_FLAGS.ENABLE_PADDLE;
    case 'paystack':
      return MVP_FEATURE_FLAGS.ENABLE_PAYSTACK;
    default:
      return false;
  }
}

/**
 * Feature limits per tier — Aligned with devfortress-pricing-3.html (6-tier model)
 */
export const FEATURE_LIMITS = {
  // API Generations per month
  apiGenerations: {
    FREE: 0, // Must use own API keys
    [SubscriptionTier.STARTER]: 25,
    [SubscriptionTier.PRO]: 60,
    [SubscriptionTier.ENTERPRISE]: 250, // Legacy alias for TEAM
    [SubscriptionTier.TEAM]: 250,
    [SubscriptionTier.BUSINESS]: 500,
    [SubscriptionTier.ENTERPRISE_PLUS]: -1, // Unlimited
  },

  // Honeypots allowed
  honeypots: {
    FREE: 0, // Must self-host
    [SubscriptionTier.STARTER]: 1,
    [SubscriptionTier.PRO]: 3,
    [SubscriptionTier.ENTERPRISE]: 10, // Legacy alias for TEAM
    [SubscriptionTier.TEAM]: 10,
    [SubscriptionTier.BUSINESS]: 25,
    [SubscriptionTier.ENTERPRISE_PLUS]: -1, // Unlimited
  },

  // Data retention (days) — Fixed to match pricing HTML
  dataRetention: {
    FREE: 0,
    [SubscriptionTier.STARTER]: 7, // Was 30, corrected to 7
    [SubscriptionTier.PRO]: 30, // Was 60, corrected to 30
    [SubscriptionTier.ENTERPRISE]: 365, // 1 year — matches pricing page
    [SubscriptionTier.TEAM]: 365,
    [SubscriptionTier.BUSINESS]: 365,
    [SubscriptionTier.ENTERPRISE_PLUS]: -1, // Custom
  },

  // Events per month
  eventsPerMonth: {
    FREE: 0,
    [SubscriptionTier.STARTER]: 50_000,
    [SubscriptionTier.PRO]: 500_000,
    [SubscriptionTier.ENTERPRISE]: 5_000_000, // Legacy alias for TEAM
    [SubscriptionTier.TEAM]: 5_000_000,
    [SubscriptionTier.BUSINESS]: 20_000_000,
    [SubscriptionTier.ENTERPRISE_PLUS]: -1, // Unlimited
  },

  // Automated actions per month (Starter = 0, alerts only)
  automatedActions: {
    FREE: 0,
    [SubscriptionTier.STARTER]: 0, // Alert only — no automated actions
    [SubscriptionTier.PRO]: 500,
    [SubscriptionTier.ENTERPRISE]: 5_000, // Legacy alias for TEAM
    [SubscriptionTier.TEAM]: 5_000,
    [SubscriptionTier.BUSINESS]: -1, // Unlimited
    [SubscriptionTier.ENTERPRISE_PLUS]: -1, // Unlimited
  },

  // Bandwidth (GB)
  bandwidth: {
    FREE: 0,
    [SubscriptionTier.STARTER]: 10,
    [SubscriptionTier.PRO]: 50,
    [SubscriptionTier.ENTERPRISE]: 500, // Legacy alias for TEAM
    [SubscriptionTier.TEAM]: 500,
    [SubscriptionTier.BUSINESS]: 2000,
    [SubscriptionTier.ENTERPRISE_PLUS]: -1, // Unlimited
  },
} as const;

export type FeatureLimitType = keyof typeof FEATURE_LIMITS;

/**
 * Get the limit for a specific feature at a tier
 */
export function getFeatureLimit(
  feature: FeatureLimitType,
  tier: SubscriptionTier | 'FREE'
): number {
  const limits = FEATURE_LIMITS[feature];
  return limits[tier] ?? 0;
}

/**
 * Check if a user is within their feature limit
 * @param currentUsage - Current usage count
 * @param feature - Feature being checked
 * @param tier - User's subscription tier
 * @returns Object with allowed status and remaining quota
 */
export function checkFeatureLimit(
  currentUsage: number,
  feature: FeatureLimitType,
  tier: SubscriptionTier | 'FREE'
): { allowed: boolean; remaining: number; limit: number } {
  const limit = getFeatureLimit(feature, tier);

  // FREE tier check commented out - FREE tier removed
  // if (tier === 'FREE' && limit === 0) {
  //   return { allowed: false, remaining: 0, limit: 0 };
  // }

  const remaining = Math.max(0, limit - currentUsage);
  const allowed = currentUsage < limit;

  return { allowed, remaining, limit };
}
