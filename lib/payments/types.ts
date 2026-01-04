/**
 * Payment types and interfaces for VortexSecure
 * MVP: GitHub Marketplace for subscriptions
 * POST-MVP: Stripe/Paystack for credit purchasing
 */

export enum PaymentProvider {
  GITHUB_MARKETPLACE = 'github_marketplace',
  // Commented out for MVP - will be used for credit purchasing post-MVP
  STRIPE = 'stripe',
  PAYSTACK = 'paystack',
}

export enum SubscriptionTier {
  STARTER = 'STARTER',
  PRO = 'PRO',
  ENTERPRISE = 'ENTERPRISE',
}

export enum SubscriptionEventType {
  CREATED = 'created',
  UPDATED = 'updated',
  CANCELLED = 'cancelled',
  PAYMENT_SUCCESS = 'payment_success',
  PAYMENT_FAILED = 'payment_failed',
}

export interface SubscriptionPricing {
  tier: SubscriptionTier;
  monthlyPrice: number;
  seats: number;
  apiGenerations: number;
  honeypots: number;
  features: string[];
}

export interface CreditPurchase {
  amount: number;
  cost: number;
  provider: PaymentProvider;
  userId: string;
  organizationId?: string;
}

export interface WebhookPayload {
  provider: PaymentProvider;
  eventType: SubscriptionEventType;
  subscriptionId: string;
  userId?: string;
  organizationId?: string;
  metadata?: Record<string, unknown>;
}

export interface GitHubMarketplacePayload {
  action: string;
  marketplace_purchase: {
    account: {
      login: string;
      id: number;
      type: string;
    };
    billing_cycle: string;
    unit_count: number;
    plan: {
      id: number;
      name: string;
      description: string;
      monthly_price_in_cents: number;
      yearly_price_in_cents: number;
    };
  };
}

export interface StripeWebhookPayload {
  type: string;
  data: {
    object: {
      id: string;
      customer: string;
      amount: number;
      currency: string;
      status: string;
      metadata?: Record<string, string>;
    };
  };
}

export interface PaystackWebhookPayload {
  event: string;
  data: {
    reference: string;
    amount: number;
    currency: string;
    customer: {
      email: string;
      customer_code: string;
    };
    status: string;
    metadata?: Record<string, string>;
  };
}

export interface WhopWebhookPayload {
  action: string;
  data: {
    id: string;
    user: {
      id: string;
      email: string;
    };
    product: {
      id: string;
      name: string;
    };
    amount: number;
    status: string;
    metadata?: Record<string, string>;
  };
}

// Pricing constants - Aligned with GitHub Marketplace pricing (Updated Dec 2025 for sustainability)
export const SUBSCRIPTION_PRICING: Record<
  SubscriptionTier,
  SubscriptionPricing
> = {
  [SubscriptionTier.STARTER]: {
    tier: SubscriptionTier.STARTER,
    monthlyPrice: 99,
    seats: 1,
    apiGenerations: 25, // 25 API generations per month
    honeypots: 1,
    features: [
      'AI-powered API generation',
      '25 API generations per month',
      '1 active honeypot',
      'Basic security scans (OWASP)',
      // 'Community support', // Commented out - paying customers get dedicated support
      '1 GitHub repository connection',
      '5 premium requests per month (limited access) - Coming Soon',
    ],
  },
  [SubscriptionTier.PRO]: {
    tier: SubscriptionTier.PRO,
    monthlyPrice: 199,
    seats: 5,
    apiGenerations: 60, // 60 API generations per month
    honeypots: 3,
    features: [
      'Everything in Starter',
      '60 API generations per month',
      '3 active honeypots',
      'Advanced security scanning',
      '5 team seats included ($40/month per additional user)',
      'Priority support (24h response)',
      'Unlimited GitHub repositories',
      'Real-time threat intelligence',
    ],
  },
  [SubscriptionTier.ENTERPRISE]: {
    tier: SubscriptionTier.ENTERPRISE,
    monthlyPrice: 499,
    seats: 10,
    apiGenerations: 250, // 250 API generations per month
    honeypots: 10,
    features: [
      'Everything in Pro',
      '250 API generations per month',
      '10 active honeypots',
      'Enterprise security + compliance',
      '10 team seats included ($50/month per additional user)',
      'SSO / SAML authentication',
      'Dedicated support + SLA',
      'Audit logs & compliance reports',
      'Custom integrations (Slack, Jira)',
    ],
  },
};

export const CREDIT_OVERAGE_PRICE = 0.75; // $0.75 per API generation
export const CREDIT_PURCHASE_MINIMUM = 10; // Minimum 10 credits
