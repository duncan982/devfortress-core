/**
 * GitHub Marketplace Subscription Component
 * Directs users to subscribe via GitHub Marketplace
 */

'use client';

import { useState } from 'react';
import { SubscriptionTier, SUBSCRIPTION_PRICING } from '@core/lib/payments/types';

interface GitHubMarketplaceSubscriptionProps {
  currentTier?: SubscriptionTier;
  className?: string;
}

export function GitHubMarketplaceSubscription({
  currentTier,
  className = '',
}: GitHubMarketplaceSubscriptionProps) {
  const [selectedTier, setSelectedTier] = useState<SubscriptionTier>(
    currentTier || SubscriptionTier.PRO // Default to PRO since STARTER is commented out
  );

  const tiers = [
    SubscriptionTier.STARTER,
    SubscriptionTier.PRO,
    SubscriptionTier.ENTERPRISE,
  ];

  const handleSubscribe = () => {
    // Redirect to GitHub Marketplace with tier selection
    const marketplaceUrl = `https://github.com/marketplace/devfortress?plan=${selectedTier.toLowerCase()}`;
    window.location.href = marketplaceUrl;
  };

  return (
    <div className={`space-y-6 ${className}`}>
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
          Subscribe via GitHub Marketplace
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Choose your plan and complete payment through GitHub
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {tiers.map(tier => {
          const pricing = SUBSCRIPTION_PRICING[tier as keyof typeof SUBSCRIPTION_PRICING];
          const isCurrent = currentTier === tier;
          const isSelected = selectedTier === tier;

          return (
            <button
              key={tier}
              onClick={() => setSelectedTier(tier)}
              className={`
                relative rounded-lg border-2 p-6 text-left transition-all
                ${
                  isSelected
                    ? 'border-blue-600 bg-blue-50 dark:bg-blue-900/20'
                    : 'border-gray-300 dark:border-gray-600 hover:border-gray-400'
                }
                ${isCurrent ? 'ring-2 ring-green-500' : ''}
              `}
            >
              {isCurrent && (
                <span className="absolute top-2 right-2 inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                  Current Plan
                </span>
              )}

              <h4 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                {tier}
              </h4>

              <div className="mt-2 mb-4">
                <span className="text-3xl font-bold text-gray-900 dark:text-gray-100">
                  ${pricing.monthlyPrice}
                </span>
                <span className="text-gray-600 dark:text-gray-400">/month</span>
              </div>

              <ul className="space-y-2 mb-4">
                <li className="flex items-center text-sm text-gray-600 dark:text-gray-400">
                  <svg
                    className="w-4 h-4 mr-2 text-green-500"
                    fill="currentColor"
                    viewBox="0 0 20 20"
                  >
                    <path
                      fillRule="evenodd"
                      d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                      clipRule="evenodd"
                    />
                  </svg>
                  {pricing.apiGenerations} API generations
                </li>
                <li className="flex items-center text-sm text-gray-600 dark:text-gray-400">
                  <svg
                    className="w-4 h-4 mr-2 text-green-500"
                    fill="currentColor"
                    viewBox="0 0 20 20"
                  >
                    <path
                      fillRule="evenodd"
                      d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                      clipRule="evenodd"
                    />
                  </svg>
                  {pricing.honeypots} honeypots
                </li>
                <li className="flex items-center text-sm text-gray-600 dark:text-gray-400">
                  <svg
                    className="w-4 h-4 mr-2 text-green-500"
                    fill="currentColor"
                    viewBox="0 0 20 20"
                  >
                    <path
                      fillRule="evenodd"
                      d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                      clipRule="evenodd"
                    />
                  </svg>
                  {pricing.seats} seats
                </li>
                {pricing.features.slice(0, 3).map((feature, idx) => (
                  <li
                    key={idx}
                    className="flex items-center text-sm text-gray-600 dark:text-gray-400"
                  >
                    <svg
                      className="w-4 h-4 mr-2 text-green-500"
                      fill="currentColor"
                      viewBox="0 0 20 20"
                    >
                      <path
                        fillRule="evenodd"
                        d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                        clipRule="evenodd"
                      />
                    </svg>
                    {feature}
                  </li>
                ))}
              </ul>
            </button>
          );
        })}
      </div>

      <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
        <div>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Selected: <span className="font-semibold">{selectedTier}</span>
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-500">
            Billed monthly through GitHub
          </p>
        </div>

        <button
          onClick={handleSubscribe}
          disabled={currentTier === selectedTier}
          className={`
            inline-flex items-center px-6 py-3 rounded-lg font-medium transition-colors
            ${
              currentTier === selectedTier
                ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }
          `}
        >
          {currentTier === selectedTier ? (
            'Current Plan'
          ) : (
            <>
              <svg
                className="w-5 h-5 mr-2"
                fill="currentColor"
                viewBox="0 0 24 24"
              >
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
              </svg>
              Subscribe on GitHub
            </>
          )}
        </button>
      </div>

      <div className="rounded-lg bg-blue-50 dark:bg-blue-900/20 p-4">
        <h4 className="text-sm font-semibold text-blue-900 dark:text-blue-200 mb-2">
          Why GitHub Marketplace?
        </h4>
        <ul className="text-sm text-blue-800 dark:text-blue-300 space-y-1">
          <li>✓ Secure payment through GitHub</li>
          <li>✓ Unified billing with your GitHub account</li>
          <li>✓ Easy upgrades and cancellations</li>
          <li>✓ No additional payment processing fees</li>
        </ul>
      </div>
    </div>
  );
}
