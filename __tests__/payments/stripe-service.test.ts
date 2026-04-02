/**
 * Tests for deprecated Stripe subscription service
 * Verifies all functions throw deprecation errors after Stripe removal.
 */

import {
  createCheckoutSession,
  handleWebhookEvent,
} from '../../lib/stripe/services/stripe-service';
import { SubscriptionTier } from '../../lib/payments/types';

describe('Stripe Service (deprecated)', () => {
  it('createCheckoutSession should throw deprecation error', async () => {
    await expect(
      createCheckoutSession({
        tier: SubscriptionTier.PRO,
        userId: 'user123',
        userEmail: 'test@example.com',
        successUrl: 'https://example.com/success',
        cancelUrl: 'https://example.com/cancel',
      })
    ).rejects.toThrow('Stripe has been removed');
  });

  it('handleWebhookEvent should throw deprecation error', async () => {
    await expect(handleWebhookEvent({ type: 'test' })).rejects.toThrow(
      'Stripe has been removed'
    );
  });
});