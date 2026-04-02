/**
 * @deprecated Stripe service — REMOVED
 *
 * Stripe has been removed as a payment provider.
 * Kenya-based businesses cannot use Stripe without local registration.
 *
 * Replacement: Paddle (international MoR) — see lib/payments/paddle-service.ts
 * Local payments: Paystack — see lib/payments/provider-router.ts
 *
 * This file is kept for reference only. All functions throw deprecation errors.
 */

import { logWarn } from '../../logger';
import { SubscriptionTier } from '../../payments/types';

const DEPRECATION_MSG =
  'Stripe has been removed. Use Paddle or Paystack instead.';

/**
 * @deprecated — Stripe removed. Throws on every call.
 */
export async function createCheckoutSession(_params: {
  tier: SubscriptionTier;
  userId: string;
  userEmail: string;
  successUrl: string;
  cancelUrl: string;
}): Promise<never> {
  logWarn(DEPRECATION_MSG, { attempted: 'createCheckoutSession' });
  throw new Error(DEPRECATION_MSG);
}

/**
 * @deprecated — Stripe removed. Throws on every call.
 */
export async function handleWebhookEvent(_event: unknown): Promise<never> {
  logWarn(DEPRECATION_MSG, { attempted: 'handleWebhookEvent' });
  throw new Error(DEPRECATION_MSG);
}
