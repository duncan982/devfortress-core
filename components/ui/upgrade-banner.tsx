'use client';

/**
 * Upgrade Banner Component
 *
 * Shows prompts for free users to upgrade or self-host.
 * Displays different messaging based on context.
 *
 * @module components/ui/upgrade-banner
 */

import { useState } from 'react';
import Link from 'next/link';
import { X, Sparkles, Server, ExternalLink } from 'lucide-react';

interface UpgradeBannerProps {
  /**
   * Type of banner to show
   * - 'upgrade': Standard upgrade prompt
   * - 'self-host': Prompt with self-hosting option
   * - 'feature-gate': Specific feature is blocked
   */
  variant?: 'upgrade' | 'self-host' | 'feature-gate';

  /**
   * Feature name when variant is 'feature-gate'
   */
  featureName?: string;

  /**
   * Required tier for the feature
   */
  requiredTier?: string;

  /**
   * Allow dismissing the banner
   */
  dismissible?: boolean;

  /**
   * CSS class name
   */
  className?: string;
}

export function UpgradeBanner({
  variant = 'self-host',
  featureName,
  requiredTier = 'STARTER',
  dismissible = true,
  className = '',
}: UpgradeBannerProps) {
  const [isDismissed, setIsDismissed] = useState(false);

  if (isDismissed) {
    return null;
  }

  const renderContent = () => {
    switch (variant) {
      case 'feature-gate':
        return (
          <>
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-yellow-500" />
              <span className="font-medium">Premium Feature</span>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
              <strong>{featureName}</strong> requires a {requiredTier}{' '}
              subscription or higher.
            </p>
            <div className="flex items-center gap-4 mt-3">
              <Link
                href="/pricing"
                className="inline-flex items-center gap-1 text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400"
              >
                View Plans
                <ExternalLink className="h-3 w-3" />
              </Link>
              <Link
                href="/docs/self-hosting"
                className="inline-flex items-center gap-1 text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <Server className="h-3 w-3" />
                Self-Host for Free
              </Link>
            </div>
          </>
        );

      case 'upgrade':
        return (
          <>
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-primary-500" />
              <span className="font-medium">Unlock More Features</span>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
              Upgrade to access unlimited API generations, honeypot deployments,
              and priority support.
            </p>
            <div className="flex items-center gap-4 mt-3">
              <Link
                href="/pricing"
                className="inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
              >
                Upgrade Now
              </Link>
            </div>
          </>
        );

      case 'self-host':
      default:
        return (
          <>
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-blue-500" />
              <span className="font-medium">Free Tier Limits Apply</span>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
              You&apos;re on the free tier with limited features. Upgrade for
              full access, or self-host with your own API keys for unlimited
              usage.
            </p>
            <div className="flex items-center gap-4 mt-3">
              <Link
                href="/pricing"
                className="inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
              >
                View Plans
              </Link>
              <Link
                href="/docs/self-hosting"
                className="inline-flex items-center gap-1 text-sm font-medium text-gray-700 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white"
              >
                <Server className="h-4 w-4" />
                Self-Host Guide
                <ExternalLink className="h-3 w-3" />
              </Link>
            </div>
          </>
        );
    }
  };

  return (
    <div
      className={`relative bg-gradient-to-r from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4 ${className}`}
    >
      {dismissible && (
        <button
          onClick={() => setIsDismissed(true)}
          className="absolute top-2 right-2 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded"
          aria-label="Dismiss banner"
        >
          <X className="h-4 w-4" />
        </button>
      )}
      {renderContent()}
    </div>
  );
}

/**
 * Inline feature gate message
 * For use within cards or smaller spaces
 */
export function FeatureGateMessage({
  featureName,
  requiredTier = 'STARTER',
}: {
  featureName: string;
  requiredTier?: string;
}) {
  return (
    <div className="flex items-center gap-2 text-sm text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 px-3 py-2 rounded-md">
      <Sparkles className="h-4 w-4 flex-shrink-0" />
      <span>
        {featureName} requires{' '}
        <Link href="/pricing" className="underline font-medium">
          {requiredTier}+
        </Link>{' '}
        or{' '}
        <Link href="/docs/self-hosting" className="underline">
          self-host
        </Link>
      </span>
    </div>
  );
}

export default UpgradeBanner;
