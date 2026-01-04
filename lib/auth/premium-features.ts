/**
 * Premium Features Access Control
 * Centralized utilities for checking feature access based on subscription tier
 */

import type { DevFortressSession } from '@core/lib/auth/session';
import { SubscriptionTier } from '@core/lib/payments/types';
import { hasPrivilegedRole, getUserSubscriptionWithPlan } from './subscription-middleware';

/**
 * Premium feature definitions mapped to subscription tiers
 */
export const FEATURE_TIERS: Record<string, SubscriptionTier[]> = {
  // BUILD Phase Premium Features
  'build.patch': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
  'build.customModels': [SubscriptionTier.ENTERPRISE],
  'build.advancedSecurity': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
  'build.aiCodeReview': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],

  // DEFEND Phase Premium Features
  'defend.liveMonitoring': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
  'defend.realTimeAlerts': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
  'defend.wafIntegration': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
  'defend.advancedWaf': [SubscriptionTier.ENTERPRISE],
  'defend.ddosProtection': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
  'defend.threatIntelligence': [SubscriptionTier.ENTERPRISE],

  // LEARN Phase Premium Features
  'learn.mlModels': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
  'learn.predictiveAnalytics': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
  'learn.automatedFixes': [SubscriptionTier.ENTERPRISE],
  'learn.customTraining': [SubscriptionTier.ENTERPRISE],

  // General Premium Features
  'general.prioritySupport': [SubscriptionTier.ENTERPRISE],
  'general.sso': [SubscriptionTier.ENTERPRISE],
  'general.whitelabel': [SubscriptionTier.ENTERPRISE],
  'general.apiExport': [SubscriptionTier.PRO, SubscriptionTier.ENTERPRISE],
};

export type FeatureKey = keyof typeof FEATURE_TIERS;

/**
 * Check if a specific feature is available for the user's subscription tier
 */
export async function hasFeatureAccess(
  session: DevFortressSession | null,
  feature: FeatureKey
): Promise<boolean> {
  if (!session?.user?.id) {
    return false;
  }

  // Privileged roles have access to all features
  if (hasPrivilegedRole(session.user.role)) {
    return true;
  }

  const { hasSubscription, plan } = await getUserSubscriptionWithPlan(session.user.id);

  if (!hasSubscription || !plan) {
    return false;
  }

  const allowedTiers = FEATURE_TIERS[feature];
  return allowedTiers.includes(plan);
}

/**
 * Get all features accessible to the user
 */
export async function getAccessibleFeatures(
  session: DevFortressSession | null
): Promise<FeatureKey[]> {
  if (!session?.user?.id) {
    return [];
  }

  // Privileged roles have access to all features
  if (hasPrivilegedRole(session.user.role)) {
    return Object.keys(FEATURE_TIERS) as FeatureKey[];
  }

  const { hasSubscription, plan } = await getUserSubscriptionWithPlan(session.user.id);

  if (!hasSubscription || !plan) {
    return [];
  }

  const accessibleFeatures: FeatureKey[] = [];
  
  for (const [feature, allowedTiers] of Object.entries(FEATURE_TIERS)) {
    if (allowedTiers.includes(plan)) {
      accessibleFeatures.push(feature as FeatureKey);
    }
  }

  return accessibleFeatures;
}

/**
 * Get user's subscription tier
 */
export async function getUserTier(
  session: DevFortressSession | null
): Promise<SubscriptionTier | 'FREE'> {
  if (!session?.user?.id) {
    return 'FREE';
  }

  if (hasPrivilegedRole(session.user.role)) {
    return SubscriptionTier.ENTERPRISE;
  }

  const { hasSubscription, plan } = await getUserSubscriptionWithPlan(session.user.id);

  if (!hasSubscription || !plan) {
    return 'FREE';
  }

  return plan as SubscriptionTier;
}

/**
 * Feature display names for UI
 */
export const FEATURE_DISPLAY_NAMES: Record<FeatureKey, string> = {
  'build.patch': 'PATCH Mode',
  'build.customModels': 'Custom AI Models',
  'build.advancedSecurity': 'Advanced Security Analysis',
  'build.aiCodeReview': 'AI Code Review',
  'defend.liveMonitoring': 'Live Monitoring',
  'defend.realTimeAlerts': 'Real-time Alerts',
  'defend.wafIntegration': 'WAF Integration',
  'defend.advancedWaf': 'Advanced WAF Rules',
  'defend.ddosProtection': 'DDoS Protection',
  'defend.threatIntelligence': 'Threat Intelligence',
  'learn.mlModels': 'Advanced ML Models',
  'learn.predictiveAnalytics': 'Predictive Analytics',
  'learn.automatedFixes': 'Automated Fixes',
  'learn.customTraining': 'Custom Model Training',
  'general.prioritySupport': 'Priority Support',
  'general.sso': 'SSO/SAML',
  'general.whitelabel': 'White-label Branding',
  'general.apiExport': 'API Export',
};

/**
 * Feature descriptions for tooltips
 */
export const FEATURE_DESCRIPTIONS: Record<FeatureKey, string> = {
  'build.patch': 'Generate PATCH endpoints alongside POST/GET/PUT/DELETE',
  'build.customModels': 'Train and deploy custom AI models for your use case',
  'build.advancedSecurity': 'Enhanced security scanning and vulnerability detection',
  'build.aiCodeReview': 'AI-powered code review and suggestions',
  'defend.liveMonitoring': 'Real-time monitoring of deployed API endpoints',
  'defend.realTimeAlerts': 'Instant notifications for security events',
  'defend.wafIntegration': 'Web Application Firewall with Cloudflare',
  'defend.advancedWaf': 'Custom WAF rules and advanced threat protection',
  'defend.ddosProtection': 'Automated DDoS mitigation and protection',
  'defend.threatIntelligence': 'Global threat intelligence feed integration',
  'learn.mlModels': 'Advanced ML models for threat classification',
  'learn.predictiveAnalytics': 'Predict potential threats before they occur',
  'learn.automatedFixes': 'Automatically apply security fixes',
  'learn.customTraining': 'Train models on your specific threat data',
  'general.prioritySupport': '24/7 priority support with dedicated team',
  'general.sso': 'Single Sign-On with SAML 2.0 support',
  'general.whitelabel': 'Remove branding and customize with your logo',
  'general.apiExport': 'Export APIs in multiple formats (OpenAPI, Postman)',
};

/**
 * Re-export client-safe utilities for backward compatibility
 */
export { getTierBadgeColor, getLowestTier, formatTierName } from './premium-utils';
