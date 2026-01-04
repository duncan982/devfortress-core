/**
 * Payment provider selection component
 * Allows users to choose their preferred payment processor
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import { logInfo } from '@core/lib/logger/client';
import { PaymentProvider } from '@core/lib/payments/types';

interface PaymentProviderInfo {
  primary: PaymentProvider;
  alternatives: PaymentProvider[];
  reason: string;
}

interface ProviderOption {
  id: PaymentProvider;
  name: string;
  description: string;
  logo?: string;
  recommended?: boolean;
}

const PROVIDER_INFO: Partial<
  Record<PaymentProvider, Omit<ProviderOption, 'id' | 'recommended'>>
> = {
  // Credit purchasing disabled for MVP
  // [PaymentProvider.STRIPE]: {
  //   name: 'Credit/Debit Card',
  //   description: 'Visa, Mastercard, Amex - Global coverage',
  //   logo: '💳',
  // },
  // [PaymentProvider.PAYSTACK]: {
  //   name: 'Paystack',
  //   description: 'Cards & Mobile Money - Optimized for Africa',
  //   logo: '📱',
  // },
  [PaymentProvider.GITHUB_MARKETPLACE]: {
    name: 'GitHub Marketplace',
    description: 'Pay through GitHub - For subscriptions',
    logo: '🐙',
  },
};

export interface PaymentProviderSelectorProps {
  onSelect: (provider: PaymentProvider) => void;
  selectedProvider?: PaymentProvider;
  className?: string;
}

export function PaymentProviderSelector({
  onSelect,
  selectedProvider,
  className = '',
}: PaymentProviderSelectorProps) {
  const [recommendation, setRecommendation] =
    useState<PaymentProviderInfo | null>(null);
  const [availableProviders, setAvailableProviders] = useState<
    PaymentProvider[]
  >([]);
  const [loading, setLoading] = useState(true);

  const fetchRecommendation = useCallback(async () => {
    try {
      const response = await fetch('/api/credits/purchase');
      if (response.ok) {
        const data = await response.json();
        setRecommendation(data.recommendedProvider);
        setAvailableProviders(data.availableProviders || []);

        // Auto-select recommended provider if none selected
        if (!selectedProvider && data.recommendedProvider?.primary) {
          onSelect(data.recommendedProvider.primary);
        }
      }
    } catch (error) {
      logInfo('Failed to fetch payment recommendation', { error });
      // POST-MVP: Fallback to Stripe for credit purchasing
      setAvailableProviders([PaymentProvider.STRIPE, PaymentProvider.PAYSTACK, PaymentProvider.GITHUB_MARKETPLACE]);
      if (!selectedProvider) {
        onSelect(PaymentProvider.STRIPE);
      }
    } finally {
      setLoading(false);
    }
  }, [selectedProvider, onSelect]);

  useEffect(() => {
    fetchRecommendation();
  }, [fetchRecommendation]);

  const providerOptions: ProviderOption[] = availableProviders
    .map(providerId => {
      const info = PROVIDER_INFO[providerId];
      if (!info) return null;
      return {
        id: providerId,
        ...info,
        recommended: providerId === recommendation?.primary,
      };
    })
    .filter(Boolean) as ProviderOption[];

  if (loading) {
    return (
      <div className={`space-y-2 ${className}`}>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Payment Method
        </label>
        <div className="animate-pulse">
          <div className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
        </div>
      </div>
    );
  }

  return (
    <div className={`space-y-2 ${className}`}>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
        Payment Method
      </label>
      {recommendation && (
        <p className="text-xs text-gray-600 dark:text-gray-400">
          {recommendation.reason}
        </p>
      )}
      <div className="space-y-2">
        {providerOptions.map(provider => (
          <button
            key={provider.id}
            type="button"
            onClick={() => onSelect(provider.id)}
            className={`
              w-full p-4 rounded-lg border-2 transition-all
              flex items-center justify-between
              ${
                selectedProvider === provider.id
                  ? 'border-blue-600 bg-blue-50 dark:bg-blue-900/20'
                  : 'border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500'
              }
            `}
          >
            <div className="flex items-center space-x-3">
              <span className="text-2xl">{provider.logo}</span>
              <div className="text-left">
                <div className="font-medium text-gray-900 dark:text-gray-100 flex items-center space-x-2">
                  <span>{provider.name}</span>
                  {provider.recommended && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                      Recommended
                    </span>
                  )}
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {provider.description}
                </p>
              </div>
            </div>
            <div
              className={`
              w-5 h-5 rounded-full border-2 flex items-center justify-center
              ${
                selectedProvider === provider.id
                  ? 'border-blue-600 bg-blue-600'
                  : 'border-gray-300 dark:border-gray-600'
              }
            `}
            >
              {selectedProvider === provider.id && (
                <div className="w-2 h-2 rounded-full bg-white"></div>
              )}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
