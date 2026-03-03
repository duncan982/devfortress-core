/**
 * Paddle Payment Service
 *
 * Replaces Stripe for subscription and credit payment processing.
 * Paddle acts as Merchant of Record, handling VAT/tax compliance globally.
 *
 * Advantages for Kenya-based business:
 * - No local business registration docs required (Paddle is the MoR)
 * - Handles international payments, tax compliance, invoicing
 * - Supports both subscription and one-time payments
 * - Works worldwide including African markets
 *
 * Note: Paystack is retained for local KES payments (M-Pesa, mobile money)
 * Paddle handles all international USD/EUR/GBP subscriptions
 */

import { logInfo, logError, logWarn } from '../logger';
import { SubscriptionTier } from './types';

// ============================================================
// Types
// ============================================================

export interface PaddleConfig {
  vendorId: string;
  apiKey: string;
  environment: 'sandbox' | 'production';
  webhookSecret: string;
  publicKey: string;
}

export interface PaddleCheckoutParams {
  priceId: string;
  userId: string;
  userEmail: string;
  tier: SubscriptionTier;
  successUrl: string;
  cancelUrl?: string;
  customData?: Record<string, string>;
  /** Optional trial period in days */
  trialDays?: number;
}

export interface PaddleCheckoutResult {
  transactionId: string;
  checkoutUrl?: string;
  status: string;
}

export interface PaddleSubscriptionEvent {
  eventType:
    | 'subscription.created'
    | 'subscription.updated'
    | 'subscription.canceled'
    | 'subscription.past_due'
    | 'subscription.paused'
    | 'subscription.resumed'
    | 'subscription.activated'
    | 'transaction.completed'
    | 'transaction.payment_failed';
  subscriptionId?: string;
  transactionId?: string;
  customerId?: string;
  userId?: string;
  tier?: SubscriptionTier;
  status?: string;
  currentBillingPeriod?: {
    startsAt: string;
    endsAt: string;
  };
  scheduledChange?: {
    action: string;
    effectiveAt: string;
  } | null;
}

// ============================================================
// Price mapping
// ============================================================

/**
 * Map subscription tiers to Paddle price IDs.
 * Set these in environment variables:
 *   PADDLE_PRICE_STARTER, PADDLE_PRICE_PRO, PADDLE_PRICE_ENTERPRISE
 */
function getPaddlePriceId(tier: SubscriptionTier): string {
  const prices: Record<SubscriptionTier, string> = {
    [SubscriptionTier.FREE]: '',
    [SubscriptionTier.STARTER]:
      process.env.PADDLE_PRICE_STARTER || 'pri_starter_placeholder',
    [SubscriptionTier.PRO]:
      process.env.PADDLE_PRICE_PRO || 'pri_pro_placeholder',
    [SubscriptionTier.ENTERPRISE]:
      process.env.PADDLE_PRICE_ENTERPRISE || 'pri_enterprise_placeholder',
  };

  return prices[tier];
}

// ============================================================
// Client
// ============================================================

function getPaddleConfig(): PaddleConfig {
  const vendorId = process.env.PADDLE_VENDOR_ID;
  const apiKey = process.env.PADDLE_API_KEY;
  const webhookSecret = process.env.PADDLE_WEBHOOK_SECRET;
  const publicKey = process.env.NEXT_PUBLIC_PADDLE_CLIENT_TOKEN || '';
  const environment =
    process.env.PADDLE_ENVIRONMENT === 'production' ? 'production' : 'sandbox';

  if (!vendorId || !apiKey) {
    throw new Error(
      'Paddle configuration missing: PADDLE_VENDOR_ID and PADDLE_API_KEY are required'
    );
  }

  return {
    vendorId,
    apiKey,
    environment,
    webhookSecret: webhookSecret || '',
    publicKey,
  };
}

function getPaddleBaseUrl(environment: 'sandbox' | 'production'): string {
  return environment === 'production'
    ? 'https://api.paddle.com'
    : 'https://sandbox-api.paddle.com';
}

// ============================================================
// API Functions
// ============================================================

/**
 * Create a Paddle checkout/transaction for subscription
 */
export async function createPaddleCheckout(
  params: PaddleCheckoutParams
): Promise<PaddleCheckoutResult> {
  const config = getPaddleConfig();
  const baseUrl = getPaddleBaseUrl(config.environment);

  const priceId = params.priceId || getPaddlePriceId(params.tier);
  if (!priceId) {
    throw new Error(`No Paddle price configured for tier: ${params.tier}`);
  }

  const body: Record<string, unknown> = {
    items: [{ price_id: priceId, quantity: 1 }],
    customer: {
      email: params.userEmail,
    },
    custom_data: {
      userId: params.userId,
      tier: params.tier,
      ...params.customData,
    },
    checkout: {
      url: params.successUrl,
    },
  };

  if (params.trialDays && params.trialDays > 0) {
    // Paddle Billing API v2 trial handling
    body.collection_mode = 'automatic';
  }

  try {
    const response = await fetch(`${baseUrl}/transactions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text();
      logError('Paddle checkout creation failed', {
        status: response.status,
        error: errorText,
      });
      throw new Error(`Paddle API error: ${response.status} — ${errorText}`);
    }

    const data = await response.json();
    const transaction = data.data;

    logInfo('Paddle checkout created', {
      transactionId: transaction.id,
      userId: params.userId,
      tier: params.tier,
    });

    return {
      transactionId: transaction.id,
      checkoutUrl: transaction.checkout?.url || undefined,
      status: transaction.status,
    };
  } catch (error) {
    logError('Failed to create Paddle checkout', {
      error,
      userId: params.userId,
    });
    throw error;
  }
}

/**
 * Cancel a Paddle subscription
 */
export async function cancelPaddleSubscription(
  subscriptionId: string,
  effectiveFrom: 'immediately' | 'next_billing_period' = 'next_billing_period'
): Promise<void> {
  const config = getPaddleConfig();
  const baseUrl = getPaddleBaseUrl(config.environment);

  try {
    const response = await fetch(
      `${baseUrl}/subscriptions/${subscriptionId}/cancel`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${config.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ effective_from: effectiveFrom }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Paddle cancel failed: ${response.status} — ${errorText}`
      );
    }

    logInfo('Paddle subscription cancelled', { subscriptionId, effectiveFrom });
  } catch (error) {
    logError('Failed to cancel Paddle subscription', { error, subscriptionId });
    throw error;
  }
}

/**
 * Get Paddle subscription details
 */
export async function getPaddleSubscription(
  subscriptionId: string
): Promise<Record<string, unknown>> {
  const config = getPaddleConfig();
  const baseUrl = getPaddleBaseUrl(config.environment);

  const response = await fetch(`${baseUrl}/subscriptions/${subscriptionId}`, {
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Paddle API error: ${response.status} — ${errorText}`);
  }

  const data = await response.json();
  return data.data;
}

/**
 * Update a Paddle subscription (e.g., upgrade/downgrade tier)
 */
export async function updatePaddleSubscription(
  subscriptionId: string,
  newTier: SubscriptionTier,
  prorate: boolean = true
): Promise<void> {
  const config = getPaddleConfig();
  const baseUrl = getPaddleBaseUrl(config.environment);
  const newPriceId = getPaddlePriceId(newTier);

  if (!newPriceId) {
    throw new Error(`No Paddle price configured for tier: ${newTier}`);
  }

  try {
    const response = await fetch(`${baseUrl}/subscriptions/${subscriptionId}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        items: [{ price_id: newPriceId, quantity: 1 }],
        proration_billing_mode: prorate
          ? 'prorated_immediately'
          : 'full_immediately',
        custom_data: { tier: newTier },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Paddle update failed: ${response.status} — ${errorText}`
      );
    }

    logInfo('Paddle subscription updated', { subscriptionId, newTier });
  } catch (error) {
    logError('Failed to update Paddle subscription', { error, subscriptionId });
    throw error;
  }
}

/**
 * Verify Paddle webhook signature (Paddle Billing v2)
 */
export function verifyPaddleWebhook(
  rawBody: string,
  signature: string
): boolean {
  try {
    const config = getPaddleConfig();
    if (!config.webhookSecret) {
      logWarn('Paddle webhook secret not configured');
      return false;
    }

    // Paddle Billing uses ts;h1=<hash> format
    const parts = signature.split(';');
    if (parts.length < 2) return false;

    const tsPart = parts.find(p => p.startsWith('ts='));
    const h1Part = parts.find(p => p.startsWith('h1='));
    if (!tsPart || !h1Part) return false;

    const ts = tsPart.replace('ts=', '');
    const h1 = h1Part.replace('h1=', '');

    // Verify using HMAC SHA256
    // In production, use Node.js crypto:
    const crypto = require('crypto');
    const signedPayload = `${ts}:${rawBody}`;
    const expectedSignature = crypto
      .createHmac('sha256', config.webhookSecret)
      .update(signedPayload)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(h1, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch (error) {
    logError('Paddle webhook verification failed', { error });
    return false;
  }
}

/**
 * Parse Paddle webhook event into standardized format
 */
export function parsePaddleWebhookEvent(
  body: Record<string, unknown>
): PaddleSubscriptionEvent | null {
  try {
    const eventType = body.event_type as string;
    const data = body.data as Record<string, unknown>;

    if (!eventType || !data) return null;

    const customData = (data.custom_data || {}) as Record<string, string>;

    return {
      eventType: eventType as PaddleSubscriptionEvent['eventType'],
      subscriptionId: data.subscription_id as string | undefined,
      transactionId: data.id as string | undefined,
      customerId: data.customer_id as string | undefined,
      userId: customData.userId,
      tier: customData.tier as SubscriptionTier | undefined,
      status: data.status as string | undefined,
      currentBillingPeriod: data.current_billing_period as
        | { startsAt: string; endsAt: string }
        | undefined,
      scheduledChange: data.scheduled_change as
        | { action: string; effectiveAt: string }
        | null
        | undefined,
    };
  } catch (error) {
    logError('Failed to parse Paddle webhook event', { error });
    return null;
  }
}
