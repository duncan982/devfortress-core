/**
 * Payment types and interfaces for DevFortress
 * MVP: GitHub Marketplace for subscriptions
 * Direct payments: Paddle (international) + Paystack (local KES/African markets)
 * Stripe removed — not available for Kenya-based businesses without local entity.
 */

export enum PaymentProvider {
  GITHUB_MARKETPLACE = 'github_marketplace',
  /** @deprecated Stripe removed — not available for Kenya-based businesses. Use PADDLE instead. */
  STRIPE = 'stripe',
  /** Paddle — Merchant of Record for international payments (no local docs needed) */
  PADDLE = 'paddle',
  /** Paystack — local African market payments (KES, NGN, GHS, ZAR, M-Pesa) */
  PAYSTACK = 'paystack',
}

export enum SubscriptionTier {
  FREE = 'FREE',
  STARTER = 'STARTER',
  PRO = 'PRO',
  /** @deprecated Renamed to TEAM in pricing v3. Kept for backward compatibility with existing DB records. */
  ENTERPRISE = 'ENTERPRISE',
  /** Team plan ($499/mo) — renamed from Enterprise in pricing v3 */
  TEAM = 'TEAM',
  /** Business plan ($2,000/mo) — Coming Soon, annual billing, endpoint-based pricing */
  BUSINESS = 'BUSINESS',
  /** Enterprise Plus (custom pricing) — Coming Soon, multi-year contracts */
  ENTERPRISE_PLUS = 'ENTERPRISE_PLUS',
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
  price: number; // Changed from monthlyPrice for consistency
  monthlyPrice: number; // Keep for backwards compatibility
  annualPrice?: number; // Annual price per month (17% discount)
  seats: number;
  apiGenerations: number;
  honeypots: number;
  dataRetentionDays: number;
  eventsPerMonth: number; // SDK events per month
  automatedActionsPerMonth: number; // Automated response actions (-1 = unlimited)
  apps: number; // Number of monitored apps/endpoints (-1 = unlimited)
  features: string[];
  comingSoon?: boolean; // Enterprise tiers not yet available
  billingType?: 'monthly' | 'annual' | 'multi-year'; // Billing cycle
  paymentMethod?: 'paddle' | 'invoice'; // Payment method
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

// Pricing constants — Aligned with devfortress-pricing-3.html (6-tier model, Jan 2026)
// Developer plans: Starter/Pro/Team — self-serve via Paddle
// Enterprise plans: Business/Enterprise/Enterprise Plus — annual invoice (Coming Soon)
export const SUBSCRIPTION_PRICING: Record<
  SubscriptionTier,
  SubscriptionPricing
> = {
  [SubscriptionTier.FREE]: {
    tier: SubscriptionTier.FREE,
    price: 0,
    monthlyPrice: 0,
    seats: 1,
    apiGenerations: 0,
    honeypots: 1,
    dataRetentionDays: 7,
    eventsPerMonth: 0,
    automatedActionsPerMonth: 0,
    apps: 0,
    billingType: 'monthly',
    features: [
      'Self-hosted deployment via GitHub',
      '1 honeypot for threat intelligence',
      'Community support & discussions',
      'Basic threat data aggregation',
      'AI security insights (limited)',
      'Open source - contribute & customize',
    ],
  },
  [SubscriptionTier.STARTER]: {
    tier: SubscriptionTier.STARTER,
    price: 99,
    monthlyPrice: 99,
    annualPrice: 82,
    seats: 1,
    apiGenerations: 25,
    honeypots: 1,
    dataRetentionDays: 7,
    eventsPerMonth: 50_000,
    automatedActionsPerMonth: 0, // Alert only — no automated actions
    apps: 1,
    billingType: 'monthly',
    paymentMethod: 'paddle',
    features: [
      'AI-powered API generation',
      '25 API generations per month',
      '1 active honeypot',
      'Basic OWASP security scans',
      '1 GitHub repository connection',
      '5 premium requests per month',
      '50K events per month',
      'Pre-auth detection (brute force & credential stuffing)',
      'AbuseIPDB live IP check (10K/mo)',
      'Composite threat score dashboard',
      'Live API Surveillance SDK',
      'Real-time SSE alerts',
      'Token alias security',
      'HMAC-SHA256 webhook signing',
      '7-day event history',
    ],
  },
  [SubscriptionTier.PRO]: {
    tier: SubscriptionTier.PRO,
    price: 199,
    monthlyPrice: 199,
    annualPrice: 165,
    seats: 5,
    apiGenerations: 60,
    honeypots: 3,
    dataRetentionDays: 30,
    eventsPerMonth: 500_000,
    automatedActionsPerMonth: 500,
    apps: 3,
    billingType: 'monthly',
    paymentMethod: 'paddle',
    features: [
      'Everything in Starter',
      '60 API generations per month',
      '3 active honeypots',
      'Advanced security scanning',
      '5 team seats included (+$40/mo per additional)',
      'Priority support (24h response)',
      'Unlimited GitHub repositories',
      'AI insights (100/mo)',
      'Patch mode (automated security patches)',
      'AI code review (0-100 scoring)',
      '500K events per month',
      '500 automated actions per month',
      'All 8 pre-auth threat types',
      'Post-auth detection (token replay, privilege escalation)',
      'AbuseIPDB blacklist sync every 6h (100K/mo)',
      'Composite score inline blocking (threshold: 85)',
      'Honeypot + tarpit',
      'Auto session revocation (<2s)',
      'Auto IP block + rate-limit + tarpit',
      'User notification on security event',
      'df.onThreatDetected() callback SDK',
      'Closed-loop audit trail + df.reportActionTaken()',
      'HMAC-SHA256 + timestamp anti-replay',
      '30-day history + CSV export',
    ],
  },
  /** @deprecated Use TEAM instead. Kept for backward compatibility with existing DB records. */
  [SubscriptionTier.ENTERPRISE]: {
    tier: SubscriptionTier.ENTERPRISE,
    price: 499,
    monthlyPrice: 499,
    annualPrice: 415,
    seats: 10,
    apiGenerations: 250,
    honeypots: 10,
    dataRetentionDays: 365,
    eventsPerMonth: 5_000_000,
    automatedActionsPerMonth: 5_000,
    apps: 10,
    billingType: 'monthly',
    paymentMethod: 'paddle',
    features: [
      'Everything in Pro',
      '250 API generations per month',
      '10 active honeypots',
      '10 team seats included (+$50/mo per additional)',
      'SSO / SAML authentication',
      'Dedicated support + SLA',
      'Custom integrations (Slack, Jira)',
      'Security review and onboarding',
      'Private Slack/Teams channel',
      '5M events per month',
      '5K automated actions per month',
      'Auto account lock on critical threats',
      'Custom response playbooks per threat type',
      'AbuseIPDB configurable threshold (60-95)',
      'Webhook IP allowlist',
      '1-year history + compliance PDF reports',
      'Audit logs — SOC2 / GDPR ready',
      'Compliance collaboration (HIPAA / SOC2)',
    ],
  },
  [SubscriptionTier.TEAM]: {
    tier: SubscriptionTier.TEAM,
    price: 499,
    monthlyPrice: 499,
    annualPrice: 415,
    seats: 10,
    apiGenerations: 250,
    honeypots: 10,
    dataRetentionDays: 365,
    eventsPerMonth: 5_000_000,
    automatedActionsPerMonth: 5_000,
    apps: 10,
    billingType: 'monthly',
    paymentMethod: 'paddle',
    features: [
      'Everything in Pro',
      '250 API generations per month',
      '10 active honeypots',
      '10 team seats included (+$50/mo per additional)',
      'SSO / SAML authentication',
      'Dedicated support + SLA',
      'Custom integrations (Slack, Jira)',
      'Security review and onboarding',
      'Private Slack/Teams channel',
      '5M events per month',
      '5K automated actions per month',
      'Auto account lock on critical threats',
      'Custom response playbooks per threat type',
      'AbuseIPDB configurable threshold (60-95)',
      'Webhook IP allowlist',
      '1-year history + compliance PDF reports',
      'Audit logs — SOC2 / GDPR ready',
      'Compliance collaboration (HIPAA / SOC2)',
    ],
  },
  [SubscriptionTier.BUSINESS]: {
    tier: SubscriptionTier.BUSINESS,
    price: 2000,
    monthlyPrice: 2000,
    seats: 25,
    apiGenerations: 500,
    honeypots: 25,
    dataRetentionDays: 365,
    eventsPerMonth: 20_000_000,
    automatedActionsPerMonth: -1, // Unlimited
    apps: 100, // 100 API endpoints
    billingType: 'annual',
    paymentMethod: 'invoice',
    comingSoon: true,
    features: [
      'All Team plan features',
      'Priced per API endpoint — not apps',
      'Unlimited automated response actions',
      'mTLS mutual certificate auth',
      'SIEM integration (Splunk, Datadog)',
      'Compliance PDF reports — SOC2 / GDPR',
      '1-year event history',
      'Email + Slack support · 4h SLA',
      'Annual invoice / PO billing',
      'GDPR Data Processing Agreement (DPA)',
      '99.9% uptime SLA',
    ],
  },
  [SubscriptionTier.ENTERPRISE_PLUS]: {
    tier: SubscriptionTier.ENTERPRISE_PLUS,
    price: 0, // Custom/negotiated
    monthlyPrice: 0,
    seats: -1, // Unlimited
    apiGenerations: -1, // Unlimited
    honeypots: -1, // Unlimited
    dataRetentionDays: -1, // Custom
    eventsPerMonth: -1, // Unlimited
    automatedActionsPerMonth: -1, // Unlimited
    apps: -1, // Unlimited
    billingType: 'multi-year',
    paymentMethod: 'invoice',
    comingSoon: true,
    features: [
      'Everything in Business',
      'On-premise / private cloud deployment',
      'Multi-region support with data residency',
      'Custom SLA — response time negotiated',
      'Fully custom AbuseIPDB signal weighting',
      'Dedicated DevFortress security engineer',
      'Multi-year contract with volume pricing',
      'Custom compliance frameworks',
      'Air-gap deployment option',
      '15-minute SLA response time',
      'Executive security briefing — quarterly',
    ],
  },
};

export const CREDIT_OVERAGE_PRICE = 0.75; // $0.75 per API generation
export const CREDIT_PURCHASE_MINIMUM = 10; // Minimum 10 credits

// ============================================================
// AI Token / Credit Packs (one-time purchase via Paddle)
// ============================================================

export enum CreditPack {
  SMALL = 'SMALL', // 25 credits — $15
  MEDIUM = 'MEDIUM', // 60 credits — $30
  LARGE = 'LARGE', // 150 credits — $60
  MEGA = 'MEGA', // 500 credits — $150
}

export interface CreditPackPricing {
  pack: CreditPack;
  credits: number;
  price: number; // USD
  pricePerCredit: number; // Effective cost per credit
  savings: string; // Discount vs overage rate
}

export const CREDIT_PACKS: Record<CreditPack, CreditPackPricing> = {
  [CreditPack.SMALL]: {
    pack: CreditPack.SMALL,
    credits: 25,
    price: 15,
    pricePerCredit: 0.6,
    savings: '20% off',
  },
  [CreditPack.MEDIUM]: {
    pack: CreditPack.MEDIUM,
    credits: 60,
    price: 30,
    pricePerCredit: 0.5,
    savings: '33% off',
  },
  [CreditPack.LARGE]: {
    pack: CreditPack.LARGE,
    credits: 150,
    price: 60,
    pricePerCredit: 0.4,
    savings: '47% off',
  },
  [CreditPack.MEGA]: {
    pack: CreditPack.MEGA,
    credits: 500,
    price: 150,
    pricePerCredit: 0.3,
    savings: '60% off',
  },
};

// ============================================================
// Pro Add-On Identifiers (recurring via Paddle subscription items)
// ============================================================

export enum ProAddon {
  EXTRA_SEAT = 'extra_seat',
  EXTRA_APP = 'extra_app',
  EXTRA_HONEYPOT = 'extra_honeypot',
  SSO_SAML = 'sso_saml',
  COMPLIANCE_PACK = 'compliance_pack',
  EXTRA_EVENTS = 'extra_events',
}

export interface ProAddonPricing {
  addon: ProAddon;
  name: string;
  pricePerUnit: number; // USD/month per unit
  unit: string;
  maxUnits: number;
  proOnly: boolean;
}
