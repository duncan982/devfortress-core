/**
 * Subscription Authorization Middleware
 * Verifies that users have active subscriptions or appropriate roles before accessing premium features
 * Used for pages and API routes that consume AI tokens or other premium resources
 *
 * Open-Core Model:
 * - Self-hosted: All features available with user's own API keys (no subscription required)
 * - Managed SaaS: Subscription required for all premium features
 */

import type { DevFortressSession } from '@core/lib/auth/session';
import { PrismaClient, SubscriptionStatus, UserRole } from '@prisma/client';
import { logWarn, logInfo } from '../logger';
import { SubscriptionTier } from '../payments/types';
import {
  canUseAIFeatures,
  getFeatureAccessMessage,
  DeploymentMode,
  getSelfHostedConfig,
} from '../config/self-hosted';

const prisma = new PrismaClient();

/**
 * Roles that bypass subscription checks
 */
const PRIVILEGED_ROLES: UserRole[] = ['ADMIN', 'OWNER', 'DEVELOPER'];

/**
 * Tier order for comparison (higher = more privileges)
 * ENTERPRISE is kept as alias for TEAM for backward compatibility
 */
const TIER_ORDER: Record<SubscriptionTier, number> = {
  [SubscriptionTier.FREE]: 0,
  [SubscriptionTier.STARTER]: 1,
  [SubscriptionTier.PRO]: 2,
  [SubscriptionTier.ENTERPRISE]: 3, // Legacy alias for TEAM
  [SubscriptionTier.TEAM]: 3,
  [SubscriptionTier.BUSINESS]: 4,
  [SubscriptionTier.ENTERPRISE_PLUS]: 5,
};

/**
 * Premium feature flags - defines which features are available at each tier
 * Pricing v3 key gating:
 * - Starter: Alerts only (no automated actions/response)
 * - Pro: Full closed-loop detection + 500 automated actions/mo
 * - Team: Advanced response + compliance + 5K actions/mo
 * - Business+: Everything unlimited (Coming Soon)
 */
export const PREMIUM_FEATURES = {
  // BUILD Phase
  patchMode: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  customModels: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],

  // DEFEND Phase
  liveMonitoring: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  realTimeAlerts: [
    SubscriptionTier.STARTER,
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  wafIntegration: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  advancedWafRules: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  secureHeaders: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],

  // Automated Response — Starter gets alerts only, Pro+ gets automated actions
  automatedResponse: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  autoSessionRevocation: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  autoAccountLock: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  customPlaybooks: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  closedLoopAudit: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],

  // LEARN Phase
  predictiveAlerts: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  advancedPredictive: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  automatedFixes: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],

  // AbuseIPDB — all get basic, Pro+ gets sync, Team+ gets configurable threshold
  abuseipdbBasic: [
    SubscriptionTier.STARTER,
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  abuseipdbSync: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  abuseipdbConfigurableThreshold: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],

  // General
  apiExport: [
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  whitelabelDocs: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  ssoSaml: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  prioritySupport: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  emailNotifications: [
    SubscriptionTier.STARTER,
    SubscriptionTier.PRO,
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  secureFrontendComponents: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],

  // Enterprise-only features (Coming Soon)
  mtlsAuth: [SubscriptionTier.BUSINESS, SubscriptionTier.ENTERPRISE_PLUS],
  siemIntegration: [
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  complianceReports: [
    SubscriptionTier.TEAM,
    SubscriptionTier.ENTERPRISE,
    SubscriptionTier.BUSINESS,
    SubscriptionTier.ENTERPRISE_PLUS,
  ],
  dedicatedCSM: [SubscriptionTier.ENTERPRISE_PLUS],
  onPremiseDeployment: [SubscriptionTier.ENTERPRISE_PLUS],
} as const;

export type PremiumFeature = keyof typeof PREMIUM_FEATURES;

/**
 * Check if user has a privileged role that bypasses subscription requirements
 */
export function hasPrivilegedRole(role?: UserRole | string): boolean {
  if (!role) return false;
  return PRIVILEGED_ROLES.includes(role as UserRole);
}

/**
 * Get user's subscription with plan details
 */
export async function getUserSubscriptionWithPlan(userId: string): Promise<{
  hasSubscription: boolean;
  plan: SubscriptionTier | null;
  status: SubscriptionStatus | null;
}> {
  try {
    const subscription = await prisma.subscription.findFirst({
      where: {
        userId,
        status: {
          in: [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING],
        },
      },
      select: {
        plan: true,
        status: true,
      },
    });

    if (!subscription) {
      return { hasSubscription: false, plan: null, status: null };
    }

    return {
      hasSubscription: true,
      plan: subscription.plan as SubscriptionTier,
      status: subscription.status,
    };
  } catch (error) {
    logWarn('Failed to get subscription with plan', { userId, error });
    return { hasSubscription: false, plan: null, status: null };
  }
}

/**
 * Check if user has an active subscription
 */
export async function hasActiveSubscription(userId: string): Promise<boolean> {
  const { hasSubscription } = await getUserSubscriptionWithPlan(userId);
  return hasSubscription;
}

/**
 * Check if user meets a minimum tier requirement
 * @param userId - User ID
 * @param requiredTier - Minimum required subscription tier
 * @param userRole - Optional user role for privileged bypass
 * @returns Object with authorization status and reason
 */
export async function requireTier(
  userId: string,
  requiredTier: SubscriptionTier,
  userRole?: UserRole | string
): Promise<{
  authorized: boolean;
  reason?: string;
  currentTier?: SubscriptionTier;
}> {
  try {
    // Privileged roles bypass all tier requirements
    if (hasPrivilegedRole(userRole)) {
      logInfo('Privileged role bypassing tier requirement', {
        userId,
        role: userRole,
        requiredTier,
      });
      return { authorized: true, currentTier: SubscriptionTier.STARTER }; // Default to STARTER for privileged users
    }

    const { hasSubscription, plan } = await getUserSubscriptionWithPlan(userId);

    // FREE tier removed - users must have subscription
    if (!hasSubscription || !plan) {
      return {
        authorized: false,
        reason: 'Active subscription required. FREE tier has been removed.',
        currentTier: undefined,
      };
    }

    const currentTier: SubscriptionTier = plan;
    const userTierOrder = TIER_ORDER[currentTier];
    const requiredOrder = TIER_ORDER[requiredTier];

    if (userTierOrder < requiredOrder) {
      logWarn('Tier requirement not met', {
        userId,
        currentTier,
        requiredTier,
      });
      return {
        authorized: false,
        reason: `${requiredTier} plan or higher required. You are on ${currentTier} plan.`,
        currentTier,
      };
    }

    return { authorized: true, currentTier };
  } catch (error) {
    logWarn('Failed to check tier requirement', {
      userId,
      requiredTier,
      error,
    });
    return {
      authorized: false,
      reason: 'Unable to verify subscription status',
    };
  }
}

/**
 * Check if user can access a specific premium feature
 * @param userId - User ID
 * @param feature - Premium feature name
 * @param userRole - Optional user role for privileged bypass
 * @returns Object with authorization status
 */
export async function canAccessFeature(
  userId: string,
  feature: PremiumFeature,
  userRole?: UserRole | string
): Promise<{ authorized: boolean; reason?: string }> {
  // Check if this is self-hosted deployment
  const config = getSelfHostedConfig();

  if (config.mode === DeploymentMode.SELF_HOSTED) {
    // Self-hosted: Check if feature requires AI and if keys are configured
    const aiFeatures: PremiumFeature[] = [
      'patchMode',
      'predictiveAlerts',
      'advancedPredictive',
      'automatedFixes',
    ];
    const requiresAI = aiFeatures.includes(feature);

    if (requiresAI && !canUseAIFeatures()) {
      return {
        authorized: false,
        reason: getFeatureAccessMessage('apiGeneration'),
      };
    }

    // All non-AI features or AI features with keys are available
    return { authorized: true };
  }

  // Managed SaaS: Check subscription and tier
  // Privileged roles can access all features
  if (hasPrivilegedRole(userRole)) {
    return { authorized: true };
  }

  const allowedTiers = PREMIUM_FEATURES[feature];
  if (!allowedTiers) {
    // Unknown feature - deny access
    return { authorized: false, reason: 'Unknown feature' };
  }

  const { hasSubscription, plan } = await getUserSubscriptionWithPlan(userId);

  if (!hasSubscription || !plan) {
    const lowestTier = allowedTiers[0];
    return {
      authorized: false,
      reason: `${lowestTier} plan or higher required for ${feature}. Upgrade or self-host from https://github.com/duncan982/devfortress`,
    };
  }

  // Check if user's plan is in the allowed tiers
  const isAllowed = (allowedTiers as readonly SubscriptionTier[]).includes(
    plan
  );
  if (isAllowed) {
    return { authorized: true };
  }

  const lowestAllowedTier = allowedTiers[0];
  return {
    authorized: false,
    reason: `${lowestAllowedTier} plan or higher required for ${feature}. You are on ${plan} plan.`,
  };
}

/**
 * Verify that user can access premium features (subscription or privileged role required)
 * @returns Object with authorized flag and reason for denial
 */
export async function verifyPremiumAccess(
  session: DevFortressSession | null
): Promise<{ authorized: boolean; reason?: string }> {
  if (!session?.user?.id) {
    return { authorized: false, reason: 'Not authenticated' };
  }

  // Check if this is self-hosted deployment
  const config = getSelfHostedConfig();
  if (config.mode === DeploymentMode.SELF_HOSTED) {
    // Self-hosted: Check if user has configured their own API keys
    if (canUseAIFeatures()) {
      logInfo('Premium access granted - self-hosted with API keys', {
        userId: session.user.id,
      });
      return { authorized: true };
    } else {
      logWarn('Premium access denied - self-hosted without API keys', {
        userId: session.user.id,
      });
      return {
        authorized: false,
        reason:
          'OpenAI API key required for AI features. Set OPENAI_API_KEY environment variable.',
      };
    }
  }

  // Managed SaaS: Check subscription or privileged role
  if (hasPrivilegedRole(session.user.role)) {
    logInfo('Premium access granted via privileged role', {
      userId: session.user.id,
      role: session.user.role,
    });
    return { authorized: true };
  }

  // Check if user has active subscription
  const hasSubscription = await hasActiveSubscription(session.user.id);

  if (!hasSubscription) {
    logWarn('Premium access denied - no active subscription', {
      userId: session.user.id,
      role: session.user.role,
    });
    return {
      authorized: false,
      reason:
        'Active subscription required. Please upgrade your plan or deploy your own instance from https://github.com/duncan982/devfortress',
    };
  }

  logInfo('Premium access granted via active subscription', {
    userId: session.user.id,
  });
  return { authorized: true };
}

/**
 * Quick check for premium access without detailed logging (for API routes)
 */
export async function canAccessPremiumFeatures(
  userId: string,
  userRole?: UserRole | string
): Promise<boolean> {
  // Privileged roles bypass subscription check
  if (hasPrivilegedRole(userRole)) {
    return true;
  }

  // Check subscription status
  return await hasActiveSubscription(userId);
}

/**
 * Check if user can access premium features, throw error if not
 * Useful for API routes that need to fail fast
 */
export async function requirePremiumAccess(
  session: DevFortressSession | null
): Promise<void> {
  const { authorized, reason } = await verifyPremiumAccess(session);

  if (!authorized) {
    throw new Error(reason || 'Premium access required');
  }
}

/**
 * Response helper for unauthorized premium access in API routes
 */
export function createUnauthorizedResponse(reason?: string) {
  return {
    error:
      reason ||
      'Premium subscription or admin access required for this feature',
    code: 'SUBSCRIPTION_REQUIRED',
  };
}
