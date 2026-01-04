/**
 * Features Module
 *
 * @module lib/features
 */

export {
  PREMIUM_FEATURES,
  type PremiumFeature,
  canAccessFeature,
  requireTier,
  getUserSubscriptionWithPlan,
  hasActiveSubscription,
  hasPrivilegedRole,
  FEATURE_LIMITS,
  type FeatureLimitType,
  getFeatureLimit,
  checkFeatureLimit,
} from './feature-flags';
