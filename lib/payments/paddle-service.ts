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
import { SubscriptionTier, CreditPack, ProAddon } from './types';

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
  /** One-time purchase metadata (credit packs) */
  purchaseType?: 'subscription' | 'credit_purchase' | 'addon';
  creditPack?: CreditPack;
  creditsAmount?: number;
  addonId?: ProAddon;
  addonQuantity?: number;
}

// ============================================================
// One-time purchase types (credit packs, add-ons)
// ============================================================

export interface PaddleCreditPurchaseParams {
  userId: string;
  userEmail: string;
  creditPack: CreditPack;
  successUrl: string;
  cancelUrl?: string;
  customData?: Record<string, string>;
}

export interface PaddleAddonCheckoutParams {
  userId: string;
  userEmail: string;
  addonId: ProAddon;
  quantity: number;
  subscriptionId: string; // Paddle subscription ID to add items to
  successUrl: string;
  customData?: Record<string, string>;
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
    [SubscriptionTier.STARTER]: process.env.PADDLE_PRICE_STARTER || '',
    [SubscriptionTier.PRO]: process.env.PADDLE_PRICE_PRO || '',
    [SubscriptionTier.ENTERPRISE]: process.env.PADDLE_PRICE_ENTERPRISE || '', // Legacy alias for TEAM
    [SubscriptionTier.TEAM]:
      process.env.PADDLE_PRICE_TEAM ||
      process.env.PADDLE_PRICE_ENTERPRISE ||
      '',
    [SubscriptionTier.BUSINESS]: process.env.PADDLE_PRICE_BUSINESS || '',
    [SubscriptionTier.ENTERPRISE_PLUS]:
      process.env.PADDLE_PRICE_ENTERPRISE_PLUS || '',
  };

  const priceId = prices[tier];
  if (!priceId) {
    throw new Error(
      `Paddle price ID not configured for tier: ${tier}. ` +
        `Set PADDLE_PRICE_${tier} in your environment variables.`
    );
  }
  return priceId;
}

/**
 * Map credit packs to Paddle price IDs (one-time products).
 * Set these in environment variables:
 *   PADDLE_PRICE_CREDITS_SMALL, PADDLE_PRICE_CREDITS_MEDIUM,
 *   PADDLE_PRICE_CREDITS_LARGE, PADDLE_PRICE_CREDITS_MEGA
 */
function getPaddleCreditPriceId(pack: CreditPack): string {
  const prices: Record<CreditPack, string> = {
    [CreditPack.SMALL]: process.env.PADDLE_PRICE_CREDITS_SMALL || '',
    [CreditPack.MEDIUM]: process.env.PADDLE_PRICE_CREDITS_MEDIUM || '',
    [CreditPack.LARGE]: process.env.PADDLE_PRICE_CREDITS_LARGE || '',
    [CreditPack.MEGA]: process.env.PADDLE_PRICE_CREDITS_MEGA || '',
  };

  const priceId = prices[pack];
  if (!priceId) {
    throw new Error(
      `Paddle price ID not configured for credit pack: ${pack}. ` +
        `Set PADDLE_PRICE_CREDITS_${pack} in your environment variables.`
    );
  }
  return priceId;
}

/**
 * Map pro add-ons to Paddle price IDs (recurring items added to subscriptions).
 * Set these in environment variables:
 *   PADDLE_PRICE_ADDON_SEAT, PADDLE_PRICE_ADDON_APP,
 *   PADDLE_PRICE_ADDON_HONEYPOT, PADDLE_PRICE_ADDON_SSO,
 *   PADDLE_PRICE_ADDON_COMPLIANCE, PADDLE_PRICE_ADDON_EVENTS
 */
function getPaddleAddonPriceId(addon: ProAddon): string {
  const prices: Record<ProAddon, string> = {
    [ProAddon.EXTRA_SEAT]: process.env.PADDLE_PRICE_ADDON_SEAT || '',
    [ProAddon.EXTRA_APP]: process.env.PADDLE_PRICE_ADDON_APP || '',
    [ProAddon.EXTRA_HONEYPOT]: process.env.PADDLE_PRICE_ADDON_HONEYPOT || '',
    [ProAddon.SSO_SAML]: process.env.PADDLE_PRICE_ADDON_SSO || '',
    [ProAddon.COMPLIANCE_PACK]: process.env.PADDLE_PRICE_ADDON_COMPLIANCE || '',
    [ProAddon.EXTRA_EVENTS]: process.env.PADDLE_PRICE_ADDON_EVENTS || '',
  };

  const priceId = prices[addon];
  if (!priceId) {
    throw new Error(
      `Paddle price ID not configured for add-on: ${addon}. ` +
        `Set the corresponding PADDLE_PRICE_ADDON_* environment variable.`
    );
  }
  return priceId;
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
 * Create a one-time Paddle transaction for AI credit/token pack purchase.
 * Uses Paddle's one-time pricing (not subscriptions).
 */
export async function createPaddleCreditPurchase(
  params: PaddleCreditPurchaseParams
): Promise<PaddleCheckoutResult> {
  const config = getPaddleConfig();
  const baseUrl = getPaddleBaseUrl(config.environment);

  const priceId = getPaddleCreditPriceId(params.creditPack);

  const { CREDIT_PACKS } = await import('./types');
  const packInfo = CREDIT_PACKS[params.creditPack];

  const body: Record<string, unknown> = {
    items: [{ price_id: priceId, quantity: 1 }],
    customer: {
      email: params.userEmail,
    },
    custom_data: {
      userId: params.userId,
      purchaseType: 'credit_purchase',
      creditPack: params.creditPack,
      creditsAmount: String(packInfo.credits),
      ...params.customData,
    },
    checkout: {
      url: params.successUrl,
    },
  };

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
      logError('Paddle credit purchase creation failed', {
        status: response.status,
        error: errorText,
      });
      throw new Error(`Paddle API error: ${response.status} — ${errorText}`);
    }

    const data = await response.json();
    const transaction = data.data;

    logInfo('Paddle credit purchase created', {
      transactionId: transaction.id,
      userId: params.userId,
      creditPack: params.creditPack,
      credits: packInfo.credits,
      price: packInfo.price,
    });

    return {
      transactionId: transaction.id,
      checkoutUrl: transaction.checkout?.url || undefined,
      status: transaction.status,
    };
  } catch (error) {
    logError('Failed to create Paddle credit purchase', {
      error,
      userId: params.userId,
      creditPack: params.creditPack,
    });
    throw error;
  }
}

/**
 * Add a recurring add-on item to an existing Paddle subscription.
 * Uses Paddle's subscription update API to add line items.
 */
export async function createPaddleAddonCheckout(
  params: PaddleAddonCheckoutParams
): Promise<void> {
  const config = getPaddleConfig();
  const baseUrl = getPaddleBaseUrl(config.environment);

  const addonPriceId = getPaddleAddonPriceId(params.addonId);

  try {
    // First, get the current subscription to preserve existing items
    const subResponse = await fetch(
      `${baseUrl}/subscriptions/${params.subscriptionId}`,
      {
        headers: {
          Authorization: `Bearer ${config.apiKey}`,
          'Content-Type': 'application/json',
        },
      }
    );

    if (!subResponse.ok) {
      const errorText = await subResponse.text();
      throw new Error(
        `Failed to fetch subscription: ${subResponse.status} — ${errorText}`
      );
    }

    const subData = await subResponse.json();
    const currentItems: Array<{ price_id: string; quantity: number }> = (
      subData.data.items || []
    ).map((item: { price: { id: string }; quantity: number }) => ({
      price_id: item.price.id,
      quantity: item.quantity,
    }));

    // Check if this addon price already exists — update quantity instead
    const existingIdx = currentItems.findIndex(
      item => item.price_id === addonPriceId
    );
    if (existingIdx >= 0) {
      currentItems[existingIdx].quantity = params.quantity;
    } else if (params.quantity > 0) {
      currentItems.push({ price_id: addonPriceId, quantity: params.quantity });
    }

    // Remove items with 0 quantity
    const updatedItems = currentItems.filter(item => item.quantity > 0);

    const response = await fetch(
      `${baseUrl}/subscriptions/${params.subscriptionId}`,
      {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${config.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          items: updatedItems,
          proration_billing_mode: 'prorated_immediately',
          custom_data: {
            userId: params.userId,
            lastAddonChange: params.addonId,
            addonQuantity: String(params.quantity),
            ...params.customData,
          },
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      logError('Paddle add-on update failed', {
        status: response.status,
        error: errorText,
      });
      throw new Error(`Paddle API error: ${response.status} — ${errorText}`);
    }

    logInfo('Paddle subscription add-on updated', {
      subscriptionId: params.subscriptionId,
      userId: params.userId,
      addonId: params.addonId,
      quantity: params.quantity,
    });
  } catch (error) {
    logError('Failed to update Paddle subscription add-on', {
      error,
      userId: params.userId,
      addonId: params.addonId,
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
      // One-time purchase metadata
      purchaseType:
        (customData.purchaseType as
          | 'subscription'
          | 'credit_purchase'
          | 'addon') || undefined,
      creditPack: customData.creditPack as CreditPack | undefined,
      creditsAmount: customData.creditsAmount
        ? parseInt(customData.creditsAmount, 10)
        : undefined,
      addonId: customData.lastAddonChange as ProAddon | undefined,
      addonQuantity: customData.addonQuantity
        ? parseInt(customData.addonQuantity, 10)
        : undefined,
    };
  } catch (error) {
    logError('Failed to parse Paddle webhook event', { error });
    return null;
  }
}
