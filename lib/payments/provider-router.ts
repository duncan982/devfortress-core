/**
 * Payment provider router
 * Routes payment requests to appropriate payment processor
 * 
 * NOTE: Disabled for MVP - GitHub Marketplace subscriptions only
 * POST-MVP: Enable for credit purchasing with Stripe/Paystack
 */

import { logInfo, logError } from '../logger';
import { PaymentProvider } from './types';
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

    // Metadata for future providers (Stripe/Paystack) intentionally not used until those integrations are enabled

    let providerResult: PaymentIntentResult;

    // Route to appropriate provider
    // POST-MVP: Enable Stripe and Paystack for credit purchasing
    switch (selectedProvider) {
      case PaymentProvider.STRIPE:
        providerResult = await createStripeIntent({
          amount: finalAmount,
          currency,
          customerEmail: params.customerEmail,
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
 * Create Stripe payment intent
 */
async function createStripeIntent(params: {
  amount: number;
  currency: string;
  customerEmail: string;
  metadata: Record<string, string>;
}): Promise<PaymentIntentResult> {
  const stripe = await import('stripe').then(m => m.default);
  const secretKey = process.env.STRIPE_SECRET_KEY;

  if (!secretKey) {
    throw new Error('Stripe secret key not configured');
  }

  const stripeClient = new stripe(secretKey, {
    apiVersion: '2025-12-15.clover',
  });

  const paymentIntent = await stripeClient.paymentIntents.create({
    amount: params.amount,
    currency: params.currency.toLowerCase(),
    metadata: params.metadata,
    receipt_email: params.customerEmail,
    automatic_payment_methods: {
      enabled: true,
    },
  });

  logInfo('Stripe payment intent created', {
    paymentIntentId: paymentIntent.id,
    amount: params.amount,
  });

  return {
    provider: PaymentProvider.STRIPE,
    paymentIntentId: paymentIntent.id,
    clientSecret: paymentIntent.client_secret || undefined,
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
