/**
 * Self-Hosted Configuration
 *
 * APIForge Open-Core Model:
 * - Free: Self-hosted with own API keys (unlimited use)
 * - Paid: Managed SaaS with our infrastructure and support
 *
 * This file detects deployment mode and configures feature access accordingly.
 */

import { logInfo, logWarn } from '../logger';

export enum DeploymentMode {
  SELF_HOSTED = 'self-hosted',
  MANAGED_SAAS = 'managed-saas',
}

export interface SelfHostedConfig {
  mode: DeploymentMode;
  requiresSubscription: boolean;
  hasOwnApiKeys: boolean;
  features: {
    apiGeneration: boolean;
    honeypots: boolean;
    surveillance: boolean;
    insights: boolean;
    autoFix: boolean;
  };
}

/**
 * Detect if this is a self-hosted deployment
 * Self-hosted = User provides their own OpenAI API key
 */
function detectDeploymentMode(): DeploymentMode {
  const hasUserProvidedApiKey = !!process.env.OPENAI_API_KEY;
  const isManagedDomain =
    process.env.NEXT_PUBLIC_APP_URL?.includes('apiforge.app') ||
    process.env.NEXT_PUBLIC_APP_URL?.includes('vortexsecure.app') ||
    process.env.VERCEL_ENV === 'production';

  // If user provided their own API key, it's self-hosted
  if (hasUserProvidedApiKey && !isManagedDomain) {
    return DeploymentMode.SELF_HOSTED;
  }

  // If on our managed domain, it's SaaS
  if (isManagedDomain) {
    return DeploymentMode.MANAGED_SAAS;
  }

  // Default to self-hosted for development
  return DeploymentMode.SELF_HOSTED;
}

/**
 * Get self-hosted configuration
 */
export function getSelfHostedConfig(): SelfHostedConfig {
  const mode = detectDeploymentMode();
  const hasOwnApiKeys = !!process.env.OPENAI_API_KEY;

  const config: SelfHostedConfig = {
    mode,
    requiresSubscription: mode === DeploymentMode.MANAGED_SAAS,
    hasOwnApiKeys,
    features: {
      // All features available in self-hosted mode with own API keys
      apiGeneration: mode === DeploymentMode.SELF_HOSTED ? hasOwnApiKeys : true,
      honeypots: true, // No API key needed
      surveillance: true, // No API key needed
      insights: mode === DeploymentMode.SELF_HOSTED ? hasOwnApiKeys : true,
      autoFix: mode === DeploymentMode.SELF_HOSTED ? hasOwnApiKeys : true,
    },
  };

  // Log configuration on startup
  if (typeof window === 'undefined') {
    logInfo('Self-hosted configuration', {
      mode,
      requiresSubscription: config.requiresSubscription,
      hasOwnApiKeys,
      features: config.features,
    });

    if (mode === DeploymentMode.SELF_HOSTED && !hasOwnApiKeys) {
      logWarn(
        'Self-hosted mode detected but OPENAI_API_KEY not configured. AI features will be disabled.'
      );
      logWarn(
        'Set OPENAI_API_KEY environment variable to enable API generation, insights, and auto-fix features.'
      );
    }
  }

  return config;
}

/**
 * Check if subscription is required for this deployment
 */
export function requiresSubscription(): boolean {
  return getSelfHostedConfig().requiresSubscription;
}

/**
 * Check if user can use AI features (either via subscription or self-hosted with own keys)
 */
export function canUseAIFeatures(): boolean {
  const config = getSelfHostedConfig();

  if (config.mode === DeploymentMode.SELF_HOSTED) {
    return config.hasOwnApiKeys;
  }

  // In managed SaaS, subscription check happens separately
  return true;
}

/**
 * Get user-friendly message about feature access
 */
export function getFeatureAccessMessage(
  feature: keyof SelfHostedConfig['features']
): string {
  const config = getSelfHostedConfig();

  if (config.mode === DeploymentMode.SELF_HOSTED) {
    if (!config.features[feature]) {
      return 'This feature requires an OpenAI API key. Set OPENAI_API_KEY in your environment variables.';
    }
    return 'Feature available in self-hosted mode with your API keys.';
  }

  return 'Subscription required for managed SaaS.';
}

/**
 * Check if this is a development environment
 */
export function isDevelopmentEnvironment(): boolean {
  return (
    process.env.NODE_ENV === 'development' ||
    process.env.NEXT_PUBLIC_DEVELOPMENT_MODE === 'true'
  );
}

/**
 * Get deployment info for UI display
 */
export function getDeploymentInfo() {
  const config = getSelfHostedConfig();

  return {
    mode: config.mode,
    displayName:
      config.mode === DeploymentMode.SELF_HOSTED
        ? 'Self-Hosted (Open Source)'
        : 'Managed SaaS',
    description:
      config.mode === DeploymentMode.SELF_HOSTED
        ? 'You are running your own instance of APIForge. Unlimited usage with your API keys.'
        : 'Fully managed service with enterprise support and infrastructure.',
    requiresSubscription: config.requiresSubscription,
    features: config.features,
  };
}
