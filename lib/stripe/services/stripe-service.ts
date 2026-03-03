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

import { logInfo, logError } from '../../logger';
import { SubscriptionTier } from '../../payments/types';
import Stripe from 'stripe';

let stripeClient: Stripe | null = null;

function getStripeClient() {
  if (!stripeClient) {
    const secretKey = process.env.STRIPE_SECRET_KEY;
    if (!secretKey) {
      throw new Error('Stripe secret key not configured');
    }
    stripeClient = new Stripe(secretKey, {
      apiVersion: '2025-12-15.clover',
    });
  }
  return stripeClient;
}

/**
 * Create a Stripe checkout session for subscription
 */
export async function createCheckoutSession(params: {
  tier: SubscriptionTier;
  userId: string;
  userEmail: string;
  successUrl: string;
  cancelUrl: string;
}) {
  const client = getStripeClient();

  const prices = {
    [SubscriptionTier.FREE]: '', // No Stripe price for FREE tier
    [SubscriptionTier.STARTER]:
      process.env.STRIPE_PRICE_STARTER || 'price_starter_placeholder',
    [SubscriptionTier.PRO]:
      process.env.STRIPE_PRICE_PRO || 'price_pro_placeholder',
    [SubscriptionTier.ENTERPRISE]:
      process.env.STRIPE_PRICE_ENTERPRISE || 'price_enterprise_placeholder',
  };

  // FREE tier cannot create checkout sessions
  if (params.tier === SubscriptionTier.FREE) {
    throw new Error('Cannot create checkout session for FREE tier');
  }

  const session = await client.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [
      {
        price: prices[params.tier],
        quantity: 1,
      },
    ],
    customer_email: params.userEmail,
    metadata: {
      userId: params.userId,
      tier: params.tier,
    },
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
  });

  logInfo('Stripe checkout session created', {
    sessionId: session.id,
    userId: params.userId,
    tier: params.tier,
  });

  return session;
}

/**
 * Handle Stripe webhook events for subscriptions
 */
export async function handleWebhookEvent(event: Stripe.Event) {
  const { type, data } = event;

  switch (type) {
    case 'checkout.session.completed':
      await handleCheckoutCompleted(data.object);
      break;
    case 'customer.subscription.deleted':
      await handleSubscriptionDeleted(data.object);
      break;
    case 'invoice.payment_failed':
      await handlePaymentFailed(data.object);
      break;
    default:
      logInfo('Unhandled webhook event', { type });
  }
}

async function handleCheckoutCompleted(session: Stripe.Checkout.Session) {
  const { userId, tier } = session.metadata || {};

  // Update user role in database
  // This would typically update the user's subscription tier in Supabase
  logInfo('Subscription activated', { userId, tier });

  // TODO: Update user role in database
}

async function handleSubscriptionDeleted(subscription: Stripe.Subscription) {
  const customerId = subscription.customer;

  // Find user by customer ID and downgrade role
  logInfo('Subscription cancelled', { customerId });

  // TODO: Update user role in database
}

async function handlePaymentFailed(invoice: Stripe.Invoice) {
  const customerId = invoice.customer;

  // Handle failed payment - could suspend access or notify user
  logError('Subscription payment failed', {
    customerId,
    invoiceId: invoice.id,
  });

  // TODO: Handle failed payment
}
