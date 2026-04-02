/**
 * Stripe Payment Form Component — DEPRECATED
 * Stripe has been removed. This stub is kept so existing imports don't break.
 */

'use client';

import { logWarn } from '@core/lib/logger/client';

interface StripePaymentFormProps {
  credits: number;
  totalCost: number;
  onSuccess: (credits: number) => void;
  onCancel: () => void;
}

/**
 * @deprecated Stripe removed — renders a "coming soon" placeholder.
 */
export function StripePaymentForm({
  onCancel,
}: StripePaymentFormProps) {
  logWarn('StripePaymentForm rendered but Stripe has been removed');

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
          Payment Unavailable
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
          Stripe payments have been removed. An alternative payment method is
          coming soon.
        </p>
      </div>

      <div className="flex gap-3">
        <button
          type="button"
          onClick={onCancel}
          className="flex-1 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500"
        >
          Go Back
        </button>
      </div>
    </div>
  );
}