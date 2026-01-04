/**
 * Credit purchase form component
 * Handles credit purchases with multi-provider support
 */

'use client';

import { useState } from 'react';
// POST-MVP: Enable Stripe for credit purchasing
import { loadStripe } from '@stripe/stripe-js';
import { Elements } from '@stripe/react-stripe-js';
import { PaymentProviderSelector } from './PaymentProviderSelector';
import { StripePaymentForm } from './StripePaymentForm';
import { PaymentProvider } from '@core/lib/payments/types';
import { logInfo, logError } from '@core/lib/logger/client';

interface CreditPurchaseFormProps {
  onSuccess?: (credits: number) => void;
  onCancel?: () => void;
  initialCredits?: number;
}

export function CreditPurchaseForm({
  onSuccess: _onSuccess,
  onCancel,
  initialCredits = 10,
}: CreditPurchaseFormProps) {
  const [credits, setCredits] = useState(initialCredits);
  const [selectedProvider, setSelectedProvider] = useState<
    PaymentProvider | undefined
  >();
  const [clientSecret, setClientSecret] = useState<string | null>(null); // POST-MVP: Enable for Stripe payments
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checkoutUrl, setCheckoutUrl] = useState<string | null>(null);
  const [priceInfo] = useState({ pricePerCredit: 0.75, minimumPurchase: 10 });

  const totalCost = credits * priceInfo.pricePerCredit;

  const handleInitiatePayment = async () => {
    if (!selectedProvider) {
      setError('Please select a payment method');
      return;
    }

    if (credits < priceInfo.minimumPurchase) {
      setError(`Minimum purchase is ${priceInfo.minimumPurchase} credits`);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/credits/purchase', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          credits,
          provider: selectedProvider,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to create payment');
      }

      const data = await response.json();

      logInfo('Payment intent created', { provider: data.provider });

      // POST-MVP: Enable Stripe and Paystack for credit purchasing
      if (data.provider === PaymentProvider.STRIPE && data.clientSecret) {
        setClientSecret(data.clientSecret);
      } else if (data.checkoutUrl) {
        // For Paystack, redirect to checkout
        setCheckoutUrl(data.checkoutUrl);
        window.location.href = data.checkoutUrl;
      }
      
      // GitHub Marketplace redirect (fallback)
      if (data.checkoutUrl && data.provider === PaymentProvider.GITHUB_MARKETPLACE) {
        setCheckoutUrl(data.checkoutUrl);
        window.location.href = data.checkoutUrl;
      }
    } catch (err) {
      logError('Payment initiation failed', { error: err });
      setError(
        err instanceof Error ? err.message : 'Failed to initiate payment'
      );
    } finally {
      setLoading(false);
    }
  };

  // POST-MVP: Enable Stripe inline payment form
  if (clientSecret) {
    const stripePromise = loadStripe(
      process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY || ''
    );

    return (
      <Elements stripe={stripePromise} options={{ clientSecret }}>
        <StripePaymentForm
          credits={credits}
          totalCost={totalCost}
          onSuccess={_onSuccess || (() => {})}
          onCancel={() => {
            setClientSecret(null);
            if (onCancel) onCancel();
          }}
        />
      </Elements>
    );
  }

  // If redirecting to external checkout, show loading
  if (checkoutUrl) {
    return (
      <div className="text-center py-8">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
        <p className="text-gray-600 dark:text-gray-400">
          Redirecting to payment provider...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
          Purchase Credits
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Add credits to your account for API generations
        </p>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
          <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
        </div>
      )}

      <div>
        <label
          htmlFor="credits"
          className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
        >
          Number of Credits
        </label>
        <input
          type="number"
          id="credits"
          min={priceInfo.minimumPurchase}
          step="1"
          value={credits}
          onChange={e =>
            setCredits(
              parseInt(e.target.value, 10) || priceInfo.minimumPurchase
            )
          }
          className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 dark:bg-gray-800 dark:text-gray-100"
        />
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
          Minimum: {priceInfo.minimumPurchase} credits
        </p>
      </div>

      <PaymentProviderSelector
        selectedProvider={selectedProvider}
        onSelect={setSelectedProvider}
      />

      <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
        <div className="flex justify-between text-lg font-semibold text-gray-900 dark:text-gray-100">
          <span>Total:</span>
          <span>${totalCost.toFixed(2)}</span>
        </div>
        <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
          ${priceInfo.pricePerCredit} per credit
        </p>
      </div>

      <div className="flex space-x-3">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50"
          >
            Cancel
          </button>
        )}
        <button
          type="button"
          onClick={handleInitiatePayment}
          disabled={loading || !selectedProvider}
          className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Processing...' : 'Continue to Payment'}
        </button>
      </div>
    </div>
  );
}

/**
 * Stripe payment form (shown after payment intent is created)
 * Commented out for MVP - will be used for credit purchasing post-MVP
 */
/*
function StripePaymentForm({
  credits,
  totalCost,
  onSuccess,
  onCancel,
}: {
  credits: number;
  totalCost: number;
  onSuccess?: (credits: number) => void;
  onCancel?: () => void;
}) {
  const stripe = useStripe();
  const elements = useElements();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!stripe || !elements) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const { error: submitError } = await stripe.confirmPayment({
        elements,
        confirmParams: {
          return_url: `${window.location.origin}/dashboard?payment=success`,
        },
        redirect: 'if_required',
      });

      if (submitError) {
        setError(submitError.message || 'Payment failed');
        logError('Stripe payment failed', { error: submitError });
      } else {
        logInfo('Payment successful', { credits });
        if (onSuccess) onSuccess(credits);
      }
    } catch (err) {
      logError('Payment submission error', { error: err });
      setError('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
          Complete Payment
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          {credits} credits for ${totalCost.toFixed(2)}
        </p>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
          <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
        </div>
      )}

      <PaymentElement />

      <div className="flex space-x-3">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50"
          >
            Cancel
          </button>
        )}
        <button
          type="submit"
          disabled={!stripe || loading}
          className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Processing...' : `Pay $${totalCost.toFixed(2)}`}
        </button>
      </div>
    </form>
  );
}
*/
