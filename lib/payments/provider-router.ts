/**
 * Payment provider router
 * Routes payment requests to appropriate payment processor
 *
 * Providers: Paddle (international) + Paystack (local African markets) + GitHub Marketplace
 * Stripe removed — not available for Kenya-based businesses without local entity.
 */

import { logInfo, logError } from '../logger';
import { PaymentProvider, SubscriptionTier } from './types';
import {
  detectUserLocation,
  recommendPaymentProvider,
  getCurrencyForCountry,
} from './geo-detector';
import { calculateTax } from './tax-service';
import type { TaxCalculationResult } from './tax-service';

export interface PaymentIntentParams {
  amount: number; // Amount in cents
  currency?: string;
  userId: string;
  organizationId?: string;
  credits: number;
  customerEmail: string;
  provider?: PaymentProvider; // User can override recommended provider
  metadata?: Record<string, string>;
  billingAddress?: {
    country?: string;
    state?: string;
  };
  isBusiness?: boolean;
  taxId?: string;
  nexusOverrides?: string[];
}

export interface PaymentIntentResult {
  provider: PaymentProvider;
  clientSecret?: string; // Stripe/Paystack client secret
  paymentIntentId?: string;
  checkoutUrl?: string; // For Paystack or other redirect-based flows
  publicKey?: string; // For client-side SDK initialization
  taxSummary?: TaxCalculationResult;
}

/**
 * Create a payment intent using the appropriate provider
 */
export async function createPaymentIntent(
  params: PaymentIntentParams,
  request?: Request
): Promise<PaymentIntentResult> {
  try {
    const {
      amount,
      credits,
      provider,
      billingAddress,
      isBusiness,
      taxId,
      nexusOverrides,
    } = params;

    // Detect location and recommend provider if not specified
    let selectedProvider = provider;
    let currency = params.currency;
    let location;

    if (request) {
      location = await detectUserLocation(request);
    }

    if (!selectedProvider && location) {
      const recommendation = recommendPaymentProvider(location);
      selectedProvider = recommendation.primary;

      // Set currency based on location if not provided
      if (!currency && location.country) {
        currency = getCurrencyForCountry(location.country);
      }

      logInfo('Auto-selected payment provider based on location', {
        provider: selectedProvider,
        country: location.country,
        reason: recommendation.reason,
      });
    }

    // Default to GitHub Marketplace if no provider selected (MVP)
    selectedProvider = selectedProvider || PaymentProvider.GITHUB_MARKETPLACE;
    currency = currency || 'USD';

    const taxSummary = calculateTax({
      amount,
      currency,
      country: billingAddress?.country,
      stateOrProvince: billingAddress?.state,
      isBusiness,
      taxId,
      locationEvidence: location,
      nexusOverrides,
    });

    const finalAmount = taxSummary.totalAmount;

    logInfo('Creating payment intent', {
      provider: selectedProvider,
      baseAmount: amount,
      amountWithTax: finalAmount,
      currency,
      credits,
      taxAmount: taxSummary.taxAmount,
      taxRate: taxSummary.rate,
    });

    // Metadata for Paddle/Paystack providers

    let providerResult: PaymentIntentResult;

    // Route to appropriate provider
    switch (selectedProvider) {
      case PaymentProvider.STRIPE:
        // Stripe removed — not available for Kenya-based businesses
        throw new Error(
          'Stripe payments are no longer supported. Use Paddle for international payments.'
        );

      case PaymentProvider.PADDLE:
        // Paddle is Merchant of Record — handles tax/VAT itself
        // Pass base amount, NOT tax-inclusive amount, to avoid double-taxation
        providerResult = await createPaddleIntent({
          amount,
          currency,
          customerEmail: params.customerEmail,
          userId: params.userId,
          metadata: params.metadata || {},
        });
        break;

      case PaymentProvider.PAYSTACK:
        providerResult = await createPaystackIntent({
          amount: finalAmount,
          currency,
          customerEmail: params.customerEmail,
          metadata: params.metadata || {},
        });
        break;

      // POST-MVP: Whop integration removed for MVP launch
      // Re-add when marketplace payments are needed

      case PaymentProvider.GITHUB_MARKETPLACE:
      default:
        // MVP: GitHub Marketplace handles payments through its own system
        // No payment intent needed - GitHub processes payment directly
        providerResult = {
          provider: PaymentProvider.GITHUB_MARKETPLACE,
          paymentIntentId: `github_marketplace_${Date.now()}`,
        };
        break;
    }

    return {
      ...providerResult,
      taxSummary,
    };
  } catch (error) {
    logError('Failed to create payment intent', { error, params });
    throw error;
  }
}

/**
 * Create Paddle transaction/checkout
 * Paddle is the Merchant of Record — handles VAT, invoicing, global compliance.
 * Supports both subscription checkouts and one-time credit purchases.
 */
async function createPaddleIntent(params: {
  amount: number;
  currency: string;
  customerEmail: string;
  userId: string;
  metadata: Record<string, string>;
}): Promise<PaymentIntentResult> {
  const { createPaddleCheckout, createPaddleCreditPurchase } = await import(
    './paddle-service'
  );

  // If this is a credit purchase with a named pack, use the one-time transaction flow
  if (
    params.metadata.type === 'credit_purchase' &&
    params.metadata.creditPack
  ) {
    const { CreditPack } = await import('./types');
    const pack = params.metadata
      .creditPack as (typeof CreditPack)[keyof typeof CreditPack];
    const result = await createPaddleCreditPurchase({
      userId: params.userId,
      userEmail: params.customerEmail,
      creditPack: pack,
      successUrl:
        params.metadata.successUrl ||
        'https://devfortress.net/dashboard?payment=success',
    });

    logInfo('Paddle credit purchase transaction created', {
      transactionId: result.transactionId,
      creditPack: pack,
      amount: params.amount,
    });

    return {
      provider: PaymentProvider.PADDLE,
      paymentIntentId: result.transactionId,
      checkoutUrl: result.checkoutUrl,
      publicKey: process.env.NEXT_PUBLIC_PADDLE_CLIENT_TOKEN,
    };
  }

  // Default: subscription checkout
  const result = await createPaddleCheckout({
    priceId: '', // Will be resolved from tier in paddle-service
    userId: params.userId,
    userEmail: params.customerEmail,
    tier:
      (params.metadata.tier as SubscriptionTier) || SubscriptionTier.STARTER,
    successUrl:
      params.metadata.successUrl ||
      'https://devfortress.net/dashboard?payment=success',
    customData: params.metadata,
  });

  logInfo('Paddle transaction created', {
    transactionId: result.transactionId,
    amount: params.amount,
  });

  return {
    provider: PaymentProvider.PADDLE,
    paymentIntentId: result.transactionId,
    checkoutUrl: result.checkoutUrl,
    publicKey: process.env.NEXT_PUBLIC_PADDLE_CLIENT_TOKEN,
  };
}

/**
 * Create Paystack payment intent
 */
async function createPaystackIntent(params: {
  amount: number;
  currency: string;
  customerEmail: string;
  metadata: Record<string, string>;
}): Promise<PaymentIntentResult> {
  const secretKey = process.env.PAYSTACK_SECRET_KEY;

  if (!secretKey) {
    throw new Error('Paystack secret key not configured');
  }

  // Paystack amount is in kobo (or pesewas, cents depending on currency)
  // Already in cents from input
  const paystackAmount = params.amount;

  // Initialize transaction via Paystack API
  const response = await fetch(
    'https://api.paystack.co/transaction/initialize',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${secretKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: params.customerEmail,
        amount: paystackAmount,
        currency: params.currency.toUpperCase(),
        metadata: params.metadata,
      }),
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Paystack initialization failed: ${error}`);
  }

  const data = await response.json();

  logInfo('Paystack transaction initialized', {
    reference: data.data.reference,
    amount: paystackAmount,
  });

  return {
    provider: PaymentProvider.PAYSTACK,
    checkoutUrl: data.data.authorization_url,
    paymentIntentId: data.data.reference,
    publicKey: process.env.NEXT_PUBLIC_PAYSTACK_PUBLIC_KEY,
  };
}

// POST-MVP: Whop integration removed for MVP launch
// Re-add createWhopIntent function when marketplace payments are needed
