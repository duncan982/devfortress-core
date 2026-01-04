/**
 * Stripe Payment Form Component
 * Handles inline Stripe payment processing
 */

'use client';

import { useState } from 'react';
import {
  PaymentElement,
  useStripe,
  useElements,
} from '@stripe/react-stripe-js';
import { logInfo, logError } from '@core/lib/logger/client';

interface StripePaymentFormProps {
  credits: number;
  totalCost: number;
  onSuccess: (credits: number) => void;
  onCancel: () => void;
}

export function StripePaymentForm({
  credits,
  totalCost,
  onSuccess: _onSuccess,
  onCancel,
}: StripePaymentFormProps) {
  const stripe = useStripe();
  const elements = useElements();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    if (!stripe || !elements) {
      setError('Stripe not loaded');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const { error: submitError } = await elements.submit();

      if (submitError) {
        setError(submitError.message || 'Payment failed');
        return;
      }

      const { error: confirmError } = await stripe.confirmPayment({
        elements,
        confirmParams: {
          return_url: `${window.location.origin}/dashboard?payment=success&credits=${credits}`,
        },
      });

      if (confirmError) {
        setError(confirmError.message || 'Payment confirmation failed');
        logError('Stripe payment confirmation failed', { error: confirmError });
      } else {
        logInfo('Stripe payment initiated', { credits, totalCost });
        // Payment will redirect to return_url on success
      }
    } catch (err) {
      logError('Stripe payment error', { error: err });
      setError('Payment failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
          Complete Payment
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
          {credits} credits for ${(totalCost / 100).toFixed(2)}
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <PaymentElement />

        {error && (
          <div className="text-red-600 dark:text-red-400 text-sm">
            {error}
          </div>
        )}

        <div className="flex gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="flex-1 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!stripe || loading}
            className="flex-1 px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Processing...' : `Pay $${(totalCost / 100).toFixed(2)}`}
          </button>
        </div>
      </form>
    </div>
  );
}