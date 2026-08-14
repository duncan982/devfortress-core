/**
 * Pricing page component
 * Self-Host banner replaces Free tier
 * Developer plans via hosted checkout · Enterprise via annual invoice
 * MVP focus: Application & API security
 * Redesigned to match DevFortress design system (semantic tokens, dark mode, Geist font)
 */

'use client';

import {
  Fragment,
  useState,
  useCallback,
  useMemo,
  useEffect,
  useRef,
} from 'react';
import Link from 'next/link';

// ── Inline replacements for private-repo path-alias imports (open-core compatibility) ────────

/** Render a JSON-LD script tag for structured data. */
function renderJsonLd(data: unknown) {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}

/** Generate FAQ schema for structured data. */
function generateFAQSchema(faqs: Array<{ question: string; answer: string }>) {
  return {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: faqs.map(faq => ({
      '@type': 'Question',
      name: faq.question,
      acceptedAnswer: { '@type': 'Answer', text: faq.answer },
    })),
  };
}

/** No-op logger for open-core (closed platform handles error logging). */
const logError = (message: string, context?: unknown) => {
  if (process.env.NODE_ENV === 'development') {
    console.error('[devfortress]', message, context);
  }
};

/** Subscription tier — mirrors closed platform values. */
const SubscriptionTier = {
  STARTER: 'STARTER',
  PRO: 'PRO',
  TEAM: 'TEAM',
  ENTERPRISE: 'ENTERPRISE',
} as const;
type SubscriptionTier =
  (typeof SubscriptionTier)[keyof typeof SubscriptionTier];

/**
 * Subscription pricing constants.
 * Monthly prices in USD. Annual prices are monthly × 10 (2 months free).
 * These are public-facing prices shown on devfortress.net/pricing.
 */
const SUBSCRIPTION_PRICING: Record<
  SubscriptionTier,
  { monthlyPrice: number; annualPrice: number }
> = {
  [SubscriptionTier.STARTER]: { monthlyPrice: 49, annualPrice: 39 },
  [SubscriptionTier.PRO]: { monthlyPrice: 99, annualPrice: 79 },
  [SubscriptionTier.TEAM]: { monthlyPrice: 399, annualPrice: 319 },
  [SubscriptionTier.ENTERPRISE]: { monthlyPrice: 0, annualPrice: 0 },
};

// ─────────────────────────────────────────────────────────────────────────────

/* ─── Types ─── */
type BillingCycle = 'monthly' | 'annual';

/* ─── Tier base resources (mirrors TIER_BASE_RESOURCES in types.ts) ─── */
const TIER_RESOURCES = {
  starter: {
    apps: 1,
    agents: 1,
    seats: 1,
    events: '100K',
    maxApps: 1,
    maxAgents: 1,
    maxSeats: 1,
  },
  pro: {
    apps: 1,
    agents: 1,
    seats: 1,
    events: '500K',
    maxApps: 5,
    maxAgents: 5,
    maxSeats: 5,
  },
  teams: {
    apps: 5,
    agents: 5,
    seats: 5,
    events: '2M',
    maxApps: 20,
    maxAgents: 20,
    maxSeats: 20,
  },
};

/* ─── Add-on prices ─── */
const PRO_ADDONS = [
  { label: '+$30/app/mo', detail: 'Additional app (up to 5 total)' },
  { label: '+$25/agent/mo', detail: 'Additional AI agent (up to 5 total)' },
  { label: '+$20/seat/mo', detail: 'Additional seat (up to 5 total)' },
  { label: '+$0.20/1K events', detail: 'Overage beyond 500K/mo' },
];

const TEAMS_ADDONS = [
  { label: '+$25/app/mo', detail: 'Additional app (up to 20 total)' },
  { label: '+$20/agent/mo', detail: 'Additional AI agent (up to 20 total)' },
  { label: '+$15/seat/mo', detail: 'Additional seat (up to 20 total)' },
  { label: '+$0.15/1K events', detail: 'Overage beyond 2M/mo' },
  {
    label: '+$80/mo',
    detail: 'Advanced compliance bundle (audit export + CSV reports)',
  },
  { label: '+$50/mo', detail: 'Priority support upgrade (4h → 1h SLA)' },
];
/* ─── Add-on stepper state ─── */
interface AddonItem {
  id: string;
  name: string;
  description: string;
  pricePerUnit: number;
  unit: string;
  maxUnits: number;
  proOnly: boolean;
}

const ADDON_CATALOGUE: AddonItem[] = [
  {
    id: 'extra_app',
    name: 'Extra App',
    description: 'Monitor an additional application',
    pricePerUnit: 30,
    unit: 'app',
    maxUnits: 4,
    proOnly: true,
  },
  {
    id: 'extra_agent',
    name: 'Extra AI Agent',
    description: 'Monitor an additional AI agent',
    pricePerUnit: 25,
    unit: 'agent',
    maxUnits: 4,
    proOnly: true,
  },
  {
    id: 'extra_seat',
    name: 'Extra Seat',
    description: 'Add a team member to your plan',
    pricePerUnit: 20,
    unit: 'seat',
    maxUnits: 4,
    proOnly: true,
  },
  // POST_MVP: extra_honeypot — uncomment when honeypot feature is live and pricing is configured
  // {
  //   id: 'extra_honeypot',
  //   name: 'Extra Honeypot',
  //   description: 'Deploy an additional honeypot endpoint',
  //   pricePerUnit: 20,
  //   unit: 'honeypot',
  //   maxUnits: 20,
  //   proOnly: true,
  // },
  // POST_MVP: sso_saml — uncomment when SSO feature is live and pricing is configured
  // {
  //   id: 'sso_saml',
  //   name: 'SSO / SAML',
  //   description: 'Single sign-on with Okta, Azure AD, SAML',
  //   pricePerUnit: 50,
  //   unit: 'flat',
  //   maxUnits: 1,
  //   proOnly: true,
  // },
  {
    id: 'compliance_pack',
    name: 'Compliance Pack',
    description: 'PCI-DSS, SOC2, GDPR compliance evidence reports',
    pricePerUnit: 80,
    unit: 'flat',
    maxUnits: 1,
    proOnly: true,
  },
  {
    id: 'extra_events',
    name: 'Extra Events',
    description: 'Additional 100K SDK events per month',
    pricePerUnit: 9,
    unit: '100K events',
    maxUnits: 100,
    proOnly: false,
  },
  {
    id: 'priority_support',
    name: 'Priority Support',
    description: 'Upgrade support SLA from 4h to 1h response time',
    pricePerUnit: 50,
    unit: 'flat',
    maxUnits: 1,
    proOnly: true,
  },
];

/* ─── FAQs ─── */
const faqs = [
  {
    question: 'Why is Enterprise custom-priced?',
    answer:
      'Enterprise requirements vary too widely to set a fixed price. A bank with 50 endpoints and GDPR-only needs a completely different package than a fintech with 500 endpoints needing PCI-DSS, HIPAA, mTLS, and on-premise deployment. Custom pricing means you pay for exactly what you need — nothing more. Use the calculator above for an indicative estimate, then email support@devfortress.net to finalise.',
  },
  {
    question: 'Can Team plans scale without going Enterprise?',
    answer:
      'Yes. Team add-ons let you scale seats (+$40/mo), apps (+$30/mo), and compliance features (+$80/mo) without a tier change. Most growing teams stay on Team with add-ons until they need mTLS, a dedicated CSM, SLA guarantees, or endpoint-based billing — those are the triggers to move to Enterprise.',
  },
  {
    question: 'How does DevFortress protect my session tokens and credentials?',
    answer:
      'DevFortress is architecturally incapable of leaking your real session tokens or API keys. Our session security architecture transmits only cryptographically isolated identifiers to the platform — your actual credentials never leave your application. If our platform were ever breached, attackers would get meaningless strings. This is a trust foundation built into the core architecture, not a premium feature. Every plan includes it by default.',
  },
  {
    question: 'Do I need mTLS, or is HMAC-SHA256 enough?',
    answer:
      "HMAC-SHA256 is secure and sufficient for most teams — it signs every webhook so forged requests are impossible. mTLS adds mutual X.509 certificate authentication at the transport layer itself. It's required for PCI-DSS Level 1 and recommended for any regulated industry. It's an optional add-on in Enterprise, not forced on everyone.",
  },
  {
    question: 'Does self-hosted devfortress-core include billing?',
    answer:
      'No. Self-hosted devfortress-core has no billing or checkout built in — it is free and unlicensed to run. For the hosted, paid version with managed billing, see devfortress.net/pricing.',
  },
  {
    question:
      'What is the difference between external, internal, and hybrid Unified Application Security?',
    answer:
      'DevFortress offers three security response modes under its Unified Application Security architecture. External mode (Starter alert-only, Pro automated blocking) detects threats on the DevFortress platform and delivers responses via HMAC-signed webhooks. Internal mode runs entirely inside your application process with zero external round-trip latency — threats are blocked inline before a response is sent. Hybrid mode (Pro add-on, Enterprise default) combines both: your application blocks threats instantly using the local engine, while the platform enriches decisions with global threat intelligence asynchronously. If the platform is ever unreachable, protection continues uninterrupted.',
  },
  {
    question: 'What does the implementation fee cover?',
    answer:
      "Enterprise onboarding is a structured 4-week process: endpoint mapping, SDK installation, mTLS certificate issuance, playbook configuration, and SIEM integration. The one-time implementation fee covers this hands-on work. It's quoted separately based on the complexity of your environment — typically $5,000–$25,000.",
  },
  {
    question: 'How quickly can I get started?',
    answer:
      'Starter and Pro plans are self-service — install the SDK, paste your API key, and you are protected in under 5 minutes. Team plans include onboarding guidance. Enterprise customers go through a structured 4-week implementation process with dedicated engineering support.',
  },
];

/* ─── Comparison table data ─── */
type CompareCell =
  | string
  | { type: 'check' | 'cross' | 'check-g' | 'partial' | 'ent'; text?: string };

interface CompareRow {
  feature: string;
  note?: string;
  starter: CompareCell;
  pro: CompareCell;
  teams: CompareCell;
  enterprise: CompareCell;
}

interface CompareGroup {
  group: string;
  rows: CompareRow[];
}

const comparisonData: CompareGroup[] = [
  {
    group: 'Billing',
    rows: [
      {
        feature: 'Contract',
        starter: 'Monthly',
        pro: 'Monthly',
        teams: 'Monthly',
        enterprise: 'Annual',
      },
      {
        feature: 'Priced by',
        starter: 'App',
        pro: 'Apps + add-ons',
        teams: 'Apps + add-ons',
        enterprise: 'API endpoints',
      },
    ],
  },
  {
    group: 'Scale',
    rows: [
      {
        feature: 'Apps monitored',
        note: 'Base included; Pro add-ons to 5, Teams add-ons to 20',
        starter: '1 (fixed)',
        pro: '1 base (+$30/app, max 5)',
        teams: '5 base (+$25/app, max 20)',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'AI agents monitored',
        note: 'Base included; Pro add-ons to 5, Teams add-ons to 20',
        starter: '1 (fixed)',
        pro: '1 base (+$25/agent, max 5)',
        teams: '5 base (+$20/agent, max 20)',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'Events / month',
        note: 'Hard cap on Starter; overage billing on Pro and Teams',
        starter: '100K (hard cap)',
        pro: '500K (+$0.20/1K overage)',
        teams: '2M (+$0.15/1K overage)',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'User seats',
        note: 'Base included; Pro add-ons to 5, Teams add-ons to 20',
        starter: '1 (fixed)',
        pro: '1 base (+$20/seat, max 5)',
        teams: '5 base (+$15/seat, max 20)',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'Automated actions / month',
        starter: { type: 'cross' },
        pro: '500',
        teams: '5,000',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
    ],
  },
  {
    group: 'Threat Detection',
    rows: [
      {
        feature: 'Pre-auth detection',
        note: 'Brute force, credential stuffing, injection, path traversal, XSS, CSRF, rate abuse, scanner fingerprinting',
        starter: { type: 'check-g', text: 'All 8' },
        pro: { type: 'check-g', text: 'All 8' },
        teams: { type: 'check-g', text: 'All 8' },
        enterprise: { type: 'check-g', text: 'All 8 + custom' },
      },
      {
        feature: 'Post-auth detection',
        note: 'Token replay, privilege escalation, anomalous volume',
        starter: { type: 'cross' },
        pro: { type: 'check' },
        teams: { type: 'check' },
        enterprise: { type: 'check' },
      },
      {
        feature: 'AbuseIPDB live IP checks',
        starter: '10K/mo',
        pro: '100K/mo',
        teams: { type: 'ent', text: 'Unlimited' },
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'AbuseIPDB blacklist sync',
        note: 'Auto-sync confirmed attacker IPs',
        starter: { type: 'cross' },
        pro: { type: 'check-g', text: 'Every 6h' },
        teams: { type: 'check-g', text: 'Real-time' },
        enterprise: { type: 'check-g', text: 'Real-time' },
      },
      {
        feature: 'Composite threat scoring',
        starter: 'Dashboard view',
        pro: { type: 'check-g', text: 'Drives inline blocking' },
        teams: { type: 'check-g', text: 'Custom thresholds' },
        enterprise: { type: 'check-g', text: 'Custom thresholds' },
      },
    ],
  },
  {
    group: 'Automated Response',
    rows: [
      {
        feature: 'Response mode',
        starter: { type: 'partial', text: 'Alert-only (no blocking)' },
        pro: { type: 'check-g', text: 'External CL (automated)' },
        teams: { type: 'check-g', text: 'Hybrid CL (default)' },
        enterprise: { type: 'check-g', text: 'All modes (selectable)' },
      },
      {
        feature: 'Session revocation (<2s)',
        starter: { type: 'cross' },
        pro: { type: 'check' },
        teams: { type: 'check' },
        enterprise: { type: 'check' },
      },
      {
        feature: 'IP block · rate-limit · tarpit',
        starter: { type: 'cross' },
        pro: { type: 'check' },
        teams: { type: 'check' },
        enterprise: { type: 'check' },
      },
      {
        feature: 'External closed-loop security mode',
        note: 'Platform detects → webhook delivers → SDK executes → confirmation',
        starter: { type: 'partial', text: 'Alert only' },
        pro: { type: 'check-g', text: 'Primary blocking' },
        teams: { type: 'check-g', text: 'Selectable' },
        enterprise: { type: 'check-g', text: 'Selectable' },
      },
      {
        feature: 'Internal closed-loop security engine',
        note: 'Zero-latency inline protection — no external round-trip',
        starter: { type: 'cross' },
        pro: { type: 'partial', text: 'Backup only' },
        teams: { type: 'check-g', text: 'Full engine' },
        enterprise: { type: 'check-g', text: 'Full engine' },
      },
      {
        feature: 'Hybrid closed-loop security mode',
        note: 'Internal evaluates first; external enriches with global intelligence.',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'check-g', text: 'Default mode' },
        enterprise: { type: 'check-g', text: 'Default mode' },
      },
      {
        feature: 'Air-gap mode',
        note: 'Full protection with zero network dependencies',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'cross' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Custom response playbooks',
        note: 'Per-endpoint, time-of-day, severity-based rules',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'cross' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Security audit trail',
        note: 'Full chain: detect → respond → confirm',
        starter: { type: 'cross' },
        pro: { type: 'check' },
        teams: { type: 'check' },
        enterprise: { type: 'check' },
      },
      {
        feature: 'AI Agent CL Security',
        note: 'Per-agent credential isolation, behavioral baselines, anomaly detection',
        starter: { type: 'partial', text: '1 agent included' },
        pro: { type: 'partial', text: '1 incl. (+$25/agent, max 5)' },
        teams: { type: 'partial', text: '5 incl. (+$20/agent, max 20)' },
        enterprise: { type: 'check-g', text: 'Unlimited' },
      },
    ],
  },
  {
    group: 'Security',
    rows: [
      {
        feature: 'API Key & Payload Protection',
        note: 'Alias indirection, zero-downtime rotation, payload signing & field encryption. Teams+ only.',
        starter: { type: 'cross' },
        pro: { type: 'partial', text: 'SDK-validated · Dashboard included' },
        teams: {
          type: 'partial',
          text: 'SDK-validated · Dashboard included',
        },
        enterprise: { type: 'partial', text: 'SDK-validated · Contact sales' },
      },
      {
        feature: 'Session privacy (zero token exposure)',
        note: 'Real tokens never leave your application',
        starter: { type: 'check-g', text: 'All plans' },
        pro: { type: 'check-g', text: 'All plans' },
        teams: { type: 'check-g', text: 'All plans' },
        enterprise: { type: 'check-g', text: 'All plans' },
      },
      {
        feature: 'HMAC-SHA256 webhook signing',
        note: 'Timestamp + anti-replay',
        starter: { type: 'check' },
        pro: { type: 'check' },
        teams: { type: 'check' },
        enterprise: { type: 'check' },
      },
      {
        feature: 'mTLS certificate authentication',
        note: 'Mutual X.509 transport-layer auth',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'cross' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'SSO / SAML',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'partial', text: 'Coming Soon' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
    ],
  },
  {
    group: 'Compliance & Support',
    rows: [
      {
        feature: 'Event history',
        starter: '7 days',
        pro: '30 days',
        teams: '1 year',
        enterprise: { type: 'ent', text: '1 year' },
      },
      {
        feature: 'Compliance reports',
        note: 'PCI-DSS, SOC2, GDPR, HIPAA',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'cross' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'SIEM integration',
        note: 'Splunk, Datadog, Microsoft Sentinel',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'partial', text: 'Coming Soon' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'GDPR DPA · HIPAA BAA',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'cross' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Uptime SLA',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'cross' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Support',
        starter: 'Email (48h)',
        pro: 'Email (24h)',
        teams: 'Priority (4h)',
        enterprise: { type: 'ent', text: 'Dedicated CSM' },
      },
      {
        feature: 'On-premise deployment',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'cross' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
    ],
  },
  {
    group: 'Insights & Analytics',
    rows: [
      {
        feature: 'AI-powered security insights',
        note: 'Automated threat analysis, pattern detection, and actionable recommendations',
        starter: { type: 'cross' },
        pro: { type: 'partial', text: '50/mo' },
        teams: { type: 'ent', text: 'Unlimited' },
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'Platform Intelligence — B1 Cross-Customer Intel',
        note: 'Anonymized cross-customer threat feed, IP reputation enrichment, attack campaign detection',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'partial', text: 'Coming Soon' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Platform Intelligence — B2 ML Classifier',
        note: 'SDK-embedded ML for real-time threat classification, sub-5ms inference, offline capable',
        starter: { type: 'cross' },
        pro: { type: 'partial', text: 'Own traffic only' },
        teams: { type: 'check-g', text: 'Own + cross-customer enrichment' },
        enterprise: { type: 'check-g', text: 'Full + custom models' },
      },
      {
        feature: 'Platform Intelligence — B3 Consent Lifecycle',
        note: 'Consent-scoped alias TTL, automatic revocation on withdrawal, GDPR/CCPA audit trail',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'partial', text: 'Coming Soon' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Platform Intelligence — B4 Multi-Hop Agent Trust',
        note: 'Trust attenuation across AI agent delegation chains, cascading revocation',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'cross' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Platform Intelligence — B10 Shadow Agent Detection',
        note: 'Distributed agent registry, behavioral fingerprinting, cross-customer shadow agent correlation',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'partial', text: 'Coming Soon' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Platform Intelligence — B12 Predictive Trajectories',
        note: 'Bayesian multi-stage attack prediction, pre-emptive countermeasures, cross-customer trajectory graph',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'partial', text: 'Coming Soon' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Predictive threat intelligence',
        note: 'ML-driven predictions of emerging attack vectors',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'partial', text: 'Coming Soon' },
        enterprise: { type: 'partial', text: 'Coming Soon' },
      },
      {
        feature: 'Security report exports',
        note: 'PDF and CSV compliance-ready security reports',
        starter: { type: 'cross' },
        pro: { type: 'partial', text: 'CSV only' },
        teams: { type: 'partial', text: 'CSV only' },
        enterprise: { type: 'partial', text: 'CSV (PDF Coming Soon)' },
      },
      {
        feature: 'Custom insight queries',
        note: 'Query threat data with custom filters, timeframes, and groupings',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: { type: 'check' },
        enterprise: { type: 'check' },
      },
    ],
  },
  {
    group: 'Add-ons',
    rows: [
      {
        feature: 'Additional apps',
        starter: { type: 'cross' },
        pro: '+$30/app/mo (max 5)',
        teams: '+$25/app/mo (max 20)',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'Additional AI agents',
        starter: { type: 'cross' },
        pro: '+$25/agent/mo (max 5)',
        teams: '+$20/agent/mo (max 20)',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'Additional seats',
        starter: { type: 'cross' },
        pro: '+$20/seat/mo (max 5)',
        teams: '+$15/seat/mo (max 20)',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'Events overage',
        starter: { type: 'cross' },
        pro: '+$0.20 / 1K events',
        teams: '+$0.15 / 1K events',
        enterprise: { type: 'ent', text: 'Unlimited' },
      },
      {
        feature: 'Advanced compliance bundle',
        note: 'Audit export + CSV reports',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: '+$80/mo',
        enterprise: { type: 'check-g', text: 'Included' },
      },
      {
        feature: 'Priority support upgrade',
        note: '4h → 1h SLA',
        starter: { type: 'cross' },
        pro: { type: 'cross' },
        teams: '+$50/mo',
        enterprise: { type: 'ent', text: 'Dedicated CSM' },
      },
    ],
  },
];

/* ─── Helper: render comparison cell ─── */
function renderCompareCell(cell: CompareCell) {
  if (typeof cell === 'string')
    return (
      <span className="text-xs text-neutral-600 dark:text-neutral-400">
        {cell}
      </span>
    );
  switch (cell.type) {
    case 'check':
      return <span className="text-base text-success-500">✓</span>;
    case 'check-g':
      return (
        <span className="text-base text-success-500">{cell.text || '✓'}</span>
      );
    case 'cross':
      return (
        <span className="text-base font-bold text-red-400 dark:text-red-500">
          ✗
        </span>
      );
    case 'partial':
      return (
        <span className="inline-block rounded bg-warning-500/10 px-2 py-0.5 font-mono text-[10px] text-warning-500 dark:text-warning-400">
          {cell.text}
        </span>
      );
    case 'ent':
      return (
        <span className="inline-block rounded bg-success-500/10 px-2 py-0.5 font-mono text-[10px] text-success-600 dark:text-success-400">
          {cell.text}
        </span>
      );
    default:
      return null;
  }
}

/* ═══════════════════════════════════════════
   MAIN COMPONENT
═══════════════════════════════════════════ */
export default function PricingPage() {

  const [billing, setBilling] = useState<BillingCycle>('monthly');

  /* ─── Pricing display ─── */
  const starterPrice =
    billing === 'annual'
      ? (SUBSCRIPTION_PRICING[SubscriptionTier.STARTER].annualPrice ?? 39)
      : SUBSCRIPTION_PRICING[SubscriptionTier.STARTER].monthlyPrice;
  const proPrice =
    billing === 'annual'
      ? (SUBSCRIPTION_PRICING[SubscriptionTier.PRO].annualPrice ?? 79)
      : SUBSCRIPTION_PRICING[SubscriptionTier.PRO].monthlyPrice;
  const teamsPrice =
    billing === 'annual'
      ? (SUBSCRIPTION_PRICING[SubscriptionTier.TEAM].annualPrice ?? 319)
      : SUBSCRIPTION_PRICING[SubscriptionTier.TEAM].monthlyPrice;

  const faqSchema = generateFAQSchema(faqs);

  return (
    <>
      {renderJsonLd(faqSchema)}


      {/* ─── Trust Bar ─── */}
      <div className="border-b border-primary-200 bg-primary-50 py-2.5 text-center text-xs tracking-wide text-primary-700 dark:border-primary-900/40 dark:bg-primary-950/60 dark:text-primary-400">
        <strong className="font-semibold">
          🔒 Session privacy included on all plans.
        </strong>{' '}
        <span className="text-primary-600 dark:text-primary-500/80">
          DevFortress never stores your real session tokens — on any tier, ever.
        </span>
      </div>

      <main className="min-h-screen bg-neutral-50 font-sans text-neutral-900 transition-colors duration-200 dark:bg-neutral-950 dark:text-neutral-100">
        {/* ─── Hero ─── */}
        <section className="relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-600/5 via-transparent to-success-600/5 dark:from-primary-500/10 dark:to-success-500/10" />
          <div className="relative mx-auto max-w-6xl px-6 pb-12 pt-20 text-center sm:px-8 lg:px-12">
            <p className="mb-4 text-sm font-semibold uppercase tracking-widest text-primary-500">
              Pricing
            </p>
            {/* Book CTA — top of pricing hero */}
            <div className="mx-auto mb-6 flex flex-col items-center gap-1">
              <p className="text-xs text-neutral-500 dark:text-neutral-400">
                Want to understand the security architecture behind each tier?
              </p>
              <a
                href="https://devfortress.gumroad.com/l/master-edition"
                className="inline-flex items-center gap-1.5 text-sm font-medium text-blue-600 underline underline-offset-2 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300"
              >
                Read the Textbook: Credential Isolation Closed-Loop Security →
              </a>
            </div>
            <h1 className="mx-auto mb-5 max-w-2xl text-4xl font-bold tracking-tight sm:text-5xl lg:text-[52px] lg:leading-[1.1]">
              Application, API and AI agent security that{' '}
              <span className="bg-gradient-to-r from-primary-500 via-secondary-500 to-success-500 bg-clip-text text-transparent">
                acts
              </span>
              ,
              <br />
              not just alerts.
            </h1>
            <p className="mx-auto mb-12 max-w-xl text-base leading-relaxed text-neutral-600 dark:text-neutral-400 sm:text-lg">
              Surveillance → Credential Isolation → Session Revocation → IP
              Blocking. Full unified application security from the first probe
              at your login page to abuse inside authenticated sessions. Plans
              for every stage of growth.
            </p>
          </div>
        </section>

        {/* ═══════════════════════════════════════════
           DEVELOPER PLANS
        ═══════════════════════════════════════════ */}
        <section
          id="developer-track"
          className="mx-auto max-w-7xl px-6 sm:px-8 lg:px-12"
        >
          {/* Billing toggle */}
          <div className="mb-10 text-center">
            <div className="inline-flex gap-0.5 rounded-full border border-neutral-200 bg-neutral-100 p-1 dark:border-neutral-800 dark:bg-neutral-900">
              <button
                onClick={() => setBilling('monthly')}
                className={`rounded-full px-5 py-2 text-sm font-medium transition-all ${
                  billing === 'monthly'
                    ? 'bg-primary-500 text-white shadow-md'
                    : 'text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-neutral-200'
                }`}
              >
                Monthly
              </button>
              <button
                onClick={() => setBilling('annual')}
                className={`rounded-full px-5 py-2 text-sm font-medium transition-all ${
                  billing === 'annual'
                    ? 'bg-primary-500 text-white shadow-md'
                    : 'text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-neutral-200'
                }`}
              >
                Annual{' '}
                <span className="ml-1.5 inline-block rounded-full bg-warning-500 px-2 py-px align-middle font-mono text-[10px] font-semibold text-neutral-900">
                  Save 20%
                </span>
              </button>
            </div>
          </div>

          {/* ─── Self-Host Banner ─── */}
          <div className="mb-10 flex items-center justify-between rounded-2xl border border-neutral-200 bg-neutral-50 px-8 py-5 dark:border-neutral-800 dark:bg-neutral-900">
            <div>
              <p className="text-sm font-semibold text-neutral-900 dark:text-white flex items-center gap-2">
                🏠 Want to self-host?
                <span className="rounded-full bg-success-500/15 px-2.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-success-600 dark:text-success-400">
                  Free Forever
                </span>
              </p>
              <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
                Run DevFortress on your own infrastructure with our open-core
                edition. Free forever, MIT-licensed, community-supported.
              </p>
            </div>
            <a
              href="https://github.com/duncan982/devfortress-core"
              target="_blank"
              rel="noopener noreferrer"
              className="flex-shrink-0 rounded-xl border border-neutral-300 bg-white px-5 py-2.5 text-sm font-semibold text-neutral-800 shadow-sm transition-all hover:border-neutral-400 hover:shadow-md dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-100 dark:hover:border-neutral-500"
            >
              View on GitHub →
            </a>
          </div>

          {/* ─── Tier Cards ─── */}
          <div className="mb-5 grid items-stretch gap-8 md:grid-cols-2 xl:grid-cols-4">
            {/* ── STARTER ── */}
            <div className="group relative flex flex-col overflow-hidden rounded-2xl border border-neutral-200 bg-white transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-neutral-200/50 dark:border-neutral-800 dark:bg-neutral-900 dark:hover:shadow-neutral-900/50">
              {/* Header */}
              <div className="border-b border-neutral-200 p-8 pb-7 dark:border-neutral-800">
                <p className="mb-3 text-sm font-bold uppercase tracking-widest text-neutral-500 dark:text-neutral-400">
                  Starter
                </p>
                <div className="mb-1.5 flex items-baseline gap-1">
                  <span className="text-xl font-light text-neutral-400">$</span>
                  <span className="text-5xl font-extrabold tracking-tight text-neutral-900 dark:text-white">
                    {starterPrice}
                  </span>
                  <span className="text-sm font-light text-neutral-500 dark:text-neutral-400">
                    /month
                  </span>
                </div>
                {billing === 'annual' && (
                  <p className="mb-4 font-mono text-xs text-neutral-500 dark:text-neutral-400">
                    Billed $468/yr — saves $120
                  </p>
                )}
                <p className="mb-5 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                  Solo developers and indie projects. Real-time threat
                  visibility, alert-only mode, and full session privacy for one
                  application.
                </p>
                <a
                  href="https://devfortress.net/pricing"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block w-full rounded-xl border border-neutral-300 bg-transparent py-3.5 text-center text-sm font-semibold text-neutral-700 transition-all hover:border-primary-500 hover:text-primary-600 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-200 dark:hover:border-primary-500 dark:hover:text-primary-400"
                >
                  View hosted plans &amp; pricing →
                </a>
              </div>

              {/* Body */}
              <div className="flex-1 p-7 pt-6">
                <p className="mb-2.5 border-b border-neutral-200 pb-1.5 font-mono text-[9px] uppercase tracking-widest text-neutral-500 dark:border-neutral-800">
                  Included
                </p>
                {/* Usage strip */}
                <div className="mb-3 grid grid-cols-4 overflow-hidden rounded-xl border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950">
                  {[
                    { val: '100K', label: 'events/mo' },
                    { val: '1', label: 'app' },
                    { val: '1', label: 'AI agent' },
                    { val: '1', label: 'seat' },
                  ].map((u, i) => (
                    <div
                      key={u.label}
                      className={`py-3.5 text-center ${i < 3 ? 'border-r border-neutral-200 dark:border-neutral-800' : ''}`}
                    >
                      <p className="text-lg font-bold leading-none text-primary-500">
                        {u.val}
                      </p>
                      <p className="mt-1 font-mono text-[10px] text-neutral-500">
                        {u.label}
                      </p>
                    </div>
                  ))}
                </div>

                {/* Features */}
                <ul className="mt-3.5 space-y-1.5">
                  {(
                    [
                      {
                        text: 'Live SDK Surveillance',
                        icon: 'check',
                      },
                      {
                        text: 'Pre-auth detection — all 8 threat types',
                        icon: 'check',
                        badgeGreen: 'All 8',
                      },
                      {
                        text: 'AbuseIPDB live IP checks',
                        icon: 'check',
                        badge: '10K/mo',
                      },
                      {
                        text: 'Composite threat scoring — dashboard view',
                        icon: 'check',
                      },
                      {
                        text: 'Real-time event alerts + SSE',
                        icon: 'check',
                      },
                      {
                        text: '1 AI agent monitored',
                        icon: 'check' as const,
                        badgeGreen: 'Included',
                      },
                      {
                        text: 'Session privacy (zero token exposure)',
                        icon: 'check',
                        badgeGreen: 'All plans',
                      },
                      {
                        text: 'HMAC-SHA256 webhook signing',
                        icon: 'check',
                      },
                      { text: '7-day event history', icon: 'check' },
                      { text: 'Email support (48h)', icon: 'check' },
                      {
                        text: 'Session revocation / IP blocking',
                        icon: 'cross',
                      },
                      { text: 'AI insights', icon: 'cross' },
                      {
                        text: 'API Key & Payload Protection',
                        icon: 'cross' as const,
                      },
                    ] as {
                      text: string;
                      icon: 'check' | 'cross' | 'partial';
                      badge?: string;
                      badgeGreen?: string;
                    }[]
                  ).map(f => (
                    <li
                      key={f.text}
                      className="flex items-start gap-2.5 py-1.5 text-sm leading-snug text-neutral-700 dark:text-neutral-200"
                    >
                      <span
                        className={`mt-0.5 flex h-4 w-4 flex-shrink-0 items-center justify-center text-[11px] ${
                          f.icon === 'check'
                            ? 'text-success-500'
                            : f.icon === 'partial'
                              ? 'text-warning-500'
                              : 'text-error-400'
                        }`}
                      >
                        {f.icon === 'check'
                          ? '✓'
                          : f.icon === 'partial'
                            ? '◐'
                            : '✗'}
                      </span>
                      <span className="flex-1">{f.text}</span>
                      {f.badge && (
                        <span className="mt-0.5 flex-shrink-0 rounded bg-warning-500/10 px-1.5 py-px font-mono text-[10px] text-warning-500 dark:text-warning-400">
                          {f.badge}
                        </span>
                      )}
                      {f.badgeGreen && (
                        <span className="mt-0.5 flex-shrink-0 rounded bg-success-500/10 px-1.5 py-px font-mono text-[10px] text-success-600 dark:text-success-400">
                          {f.badgeGreen}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>

                <div className="mt-3.5 rounded-lg border border-warning-500/20 bg-warning-50 px-3 py-2.5 text-[11px] leading-relaxed text-warning-700 dark:bg-warning-500/5 dark:text-warning-400">
                  <strong className="font-semibold">
                    ⚠ Alert-only — no blocking
                  </strong>{' '}
                  — threats detected and alerted, but not actioned
                  automatically. Upgrade to Pro for automated session revocation
                  and IP blocking.{' '}
                  <strong className="font-semibold">
                    Avg. human response: 4 hours. Pro responds in &lt;2 seconds.
                  </strong>
                </div>
              </div>
            </div>

            {/* ── PRO ── */}
            <div className="group relative flex flex-col overflow-hidden rounded-2xl border-2 border-primary-500 bg-gradient-to-br from-primary-50 to-white shadow-xl shadow-primary-500/10 transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl hover:shadow-primary-500/15 dark:from-primary-950/30 dark:to-neutral-900">
              {/* Popular badge */}
              <div className="absolute -top-px left-1/2 -translate-x-1/2 rounded-b-xl bg-primary-500 px-5 py-1.5 font-mono text-[10px] font-semibold uppercase tracking-widest text-white">
                Most Popular
              </div>

              {/* Header */}
              <div className="border-b border-primary-200 p-8 pb-7 pt-11 dark:border-primary-900/50">
                <p className="mb-3 text-sm font-bold uppercase tracking-widest text-primary-500">
                  Pro
                </p>
                <div className="mb-1.5 flex items-baseline gap-1">
                  <span className="text-xl font-light text-neutral-400">$</span>
                  <span className="text-5xl font-extrabold tracking-tight text-neutral-900 dark:text-white">
                    {proPrice}
                  </span>
                  <span className="text-sm font-light text-neutral-500 dark:text-neutral-400">
                    /month
                  </span>
                </div>
                {billing === 'annual' && (
                  <p className="mb-4 font-mono text-xs text-neutral-500 dark:text-neutral-400">
                    Billed $948/yr — saves $240
                  </p>
                )}
                <p className="mb-5 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                  Entry point for automated protection. Starts with 1 app, 1 AI
                  agent, 1 seat — scale with add-ons up to 5 each. External
                  closed-loop security, automated session revocation, and IP
                  blocking.
                </p>
                <a
                  href="https://devfortress.net/pricing"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block w-full rounded-xl bg-primary-500 py-3.5 text-center text-sm font-semibold text-white shadow-md transition-all hover:bg-primary-600 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-50"
                >
                  View hosted plans &amp; pricing →
                </a>
              </div>

              {/* Body */}
              <div className="flex-1 p-7 pt-6">
                <p className="mb-2.5 border-b border-neutral-200 pb-1.5 font-mono text-[9px] uppercase tracking-widest text-neutral-500 dark:border-neutral-800">
                  Included
                </p>
                {/* Usage strip */}
                <div className="mb-3 grid grid-cols-4 overflow-hidden rounded-xl border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950">
                  {[
                    { val: '500K', label: 'events/mo' },
                    { val: '1→5', label: 'apps' },
                    { val: '1→5', label: 'AI agents' },
                    { val: '1→5', label: 'seats' },
                  ].map((u, i) => (
                    <div
                      key={u.label}
                      className={`py-3.5 text-center ${i < 3 ? 'border-r border-neutral-200 dark:border-neutral-800' : ''}`}
                    >
                      <p className="text-lg font-bold leading-none text-primary-500">
                        {u.val}
                      </p>
                      <p className="mt-1 font-mono text-[10px] text-neutral-500">
                        {u.label}
                      </p>
                    </div>
                  ))}
                </div>

                <p className="mb-2.5 border-b border-neutral-200 pb-1.5 font-mono text-[9px] uppercase tracking-widest text-neutral-500 dark:border-neutral-800">
                  Everything in Starter, plus
                </p>

                {/* Features */}
                <ul className="space-y-1.5">
                  {[
                    {
                      text: 'Session revocation (<2s) — automated',
                      icon: 'check' as const,
                      bold: true,
                    },
                    {
                      text: 'IP blocking · rate-limit · tarpit',
                      icon: 'check' as const,
                      bold: true,
                    },
                    {
                      text: 'External closed-loop security mode — automated blocking',
                      icon: 'check' as const,
                    },
                    {
                      text: 'Post-auth detection (token replay, privilege escalation)',
                      icon: 'check' as const,
                    },
                    {
                      text: 'AbuseIPDB blacklist sync every 6h',
                      icon: 'check' as const,
                    },
                    {
                      text: 'Composite threat score drives inline blocking',
                      icon: 'check' as const,
                    },
                    {
                      text: '1 AI agent included (+$25/agent, up to 5)',
                      icon: 'check' as const,
                      badgeGreen: 'Included',
                    },
                    {
                      text: 'API Key & Payload Protection',
                      icon: 'cross' as const,
                    },
                    {
                      text: 'AI security insights',
                      icon: 'check' as const,
                      badge: '50/mo',
                    },
                    {
                      text: 'Security report exports (CSV)',
                      icon: 'check' as const,
                    },
                    {
                      text: 'Internal CL engine (backup only)',
                      icon: 'partial' as const,
                    },
                    {
                      text: 'Security audit trail',
                      icon: 'check' as const,
                    },
                    {
                      text: '30-day event history',
                      icon: 'check' as const,
                    },
                    {
                      text: 'Email support (24h)',
                      icon: 'check' as const,
                    },
                  ].map(f => (
                    <li
                      key={f.text}
                      className="flex items-start gap-2.5 py-1.5 text-sm leading-snug text-neutral-700 dark:text-neutral-200"
                    >
                      <span
                        className={`mt-0.5 flex h-4 w-4 flex-shrink-0 items-center justify-center text-[11px] ${
                          f.icon === 'check'
                            ? 'text-success-500'
                            : f.icon === 'partial'
                              ? 'text-warning-500'
                              : 'text-error-400'
                        }`}
                      >
                        {f.icon === 'check'
                          ? '✓'
                          : f.icon === 'partial'
                            ? '◐'
                            : '✗'}
                      </span>
                      <span
                        className={`flex-1 ${f.bold ? 'font-semibold text-neutral-900 dark:text-white' : ''}`}
                      >
                        {f.text}
                      </span>
                      {f.badge && (
                        <span className="mt-0.5 flex-shrink-0 rounded bg-warning-500/10 px-1.5 py-px font-mono text-[10px] text-warning-500 dark:text-warning-400">
                          {f.badge}
                        </span>
                      )}
                      {f.badgeGreen && (
                        <span className="mt-0.5 flex-shrink-0 rounded bg-success-500/10 px-1.5 py-px font-mono text-[10px] text-success-600 dark:text-success-400">
                          {f.badgeGreen}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>

                <div className="mt-4 rounded-lg border border-primary-200/50 bg-primary-50/50 px-3 py-2.5 dark:border-primary-900/30 dark:bg-primary-950/20">
                  <p className="mb-1.5 font-mono text-[9px] uppercase tracking-widest text-primary-600 dark:text-primary-400">
                    Add-ons available
                  </p>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-neutral-600 dark:text-neutral-400">
                    {PRO_ADDONS.map(a => (
                      <span key={a.label}>
                        <span className="font-semibold text-neutral-700 dark:text-neutral-300">
                          {a.label}
                        </span>{' '}
                        — {a.detail}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* ── TEAMS ── */}
            <div className="group relative flex flex-col overflow-hidden rounded-2xl border border-neutral-200 bg-white transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-neutral-200/50 dark:border-neutral-800 dark:bg-neutral-900 dark:hover:shadow-neutral-900/50">
              {/* Header */}
              <div className="border-b border-neutral-200 p-8 pb-7 dark:border-neutral-800">
                <p className="mb-3 text-sm font-bold uppercase tracking-widest text-violet-500">
                  Teams
                </p>
                <div className="mb-1.5 flex items-baseline gap-1">
                  <span className="text-xl font-light text-neutral-400">$</span>
                  <span className="text-5xl font-extrabold tracking-tight text-neutral-900 dark:text-white">
                    {teamsPrice}
                  </span>
                  <span className="text-sm font-light text-neutral-500 dark:text-neutral-400">
                    /month
                  </span>
                </div>
                {billing === 'annual' && (
                  <p className="mb-4 font-mono text-xs text-neutral-500 dark:text-neutral-400">
                    Billed $3,828/yr — saves $960
                  </p>
                )}
                <p className="mb-5 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                  For growing product teams. Starts with 5 apps, 5 AI agents, 5
                  seats — scale with add-ons up to 20 each. Hybrid closed-loop
                  mode by default. Unlocks Platform Intelligence and API Key
                  &amp; Payload Protection.
                </p>
                <a
                  href="https://devfortress.net/pricing"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block w-full rounded-xl border border-violet-300 bg-transparent py-3.5 text-center text-sm font-semibold text-violet-700 transition-all hover:border-violet-500 hover:bg-violet-500 hover:text-white disabled:cursor-not-allowed disabled:opacity-50 dark:border-violet-700 dark:text-violet-300 dark:hover:border-violet-500 dark:hover:text-white"
                >
                  View hosted plans &amp; pricing →
                </a>
              </div>

              {/* Body */}
              <div className="flex-1 p-7 pt-6">
                <p className="mb-2.5 border-b border-neutral-200 pb-1.5 font-mono text-[9px] uppercase tracking-widest text-neutral-500 dark:border-neutral-800">
                  Included
                </p>
                {/* Usage strip */}
                <div className="mb-3 grid grid-cols-4 overflow-hidden rounded-xl border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950">
                  {[
                    { val: '2M', label: 'events/mo' },
                    { val: '5→20', label: 'apps' },
                    { val: '5→20', label: 'AI agents' },
                    { val: '5→20', label: 'seats' },
                  ].map((u, i) => (
                    <div
                      key={u.label}
                      className={`py-3.5 text-center ${i < 3 ? 'border-r border-neutral-200 dark:border-neutral-800' : ''}`}
                    >
                      <p className="text-lg font-bold leading-none text-violet-500">
                        {u.val}
                      </p>
                      <p className="mt-1 font-mono text-[10px] text-neutral-500">
                        {u.label}
                      </p>
                    </div>
                  ))}
                </div>

                <p className="mb-2.5 border-b border-neutral-200 pb-1.5 font-mono text-[9px] uppercase tracking-widest text-neutral-500 dark:border-neutral-800">
                  Everything in Pro, plus
                </p>

                {/* Features */}
                <ul className="space-y-1.5">
                  {[
                    {
                      text: 'Hybrid closed-loop security mode (default)',
                      bold: true,
                    },
                    {
                      text: 'Internal CL engine — Full inline',
                      bold: true,
                    },
                    {
                      text: 'Predictive threat intelligence (Coming Soon)',
                    },
                    {
                      text: 'Custom threat score thresholds',
                    },
                    {
                      text: 'AbuseIPDB real-time blacklist sync',
                    },
                    {
                      text: 'SSO / SAML authentication (Coming Soon)',
                    },
                    {
                      text: 'SIEM integration (Coming Soon)',
                    },
                    {
                      text: 'Unlimited AI security insights',
                    },
                    {
                      text: 'Custom insight queries',
                    },
                    {
                      text: '5,000 automated actions/mo',
                    },
                    {
                      text: '1-year event history',
                    },
                    {
                      text: 'Priority support (4h)',
                    },
                    {
                      text: '5 AI agents included (+$20/agent, up to 20)',
                      bold: false,
                    },
                    {
                      text: 'API Key & Payload Protection',
                      bold: false,
                    },
                    {
                      text: 'Platform Intelligence — B2 SDK-Embedded ML',
                      bold: true,
                    },
                    {
                      text: 'Platform Intelligence — B1/B3/B12 (Coming Soon)',
                      bold: false,
                    },
                  ].map(f => (
                    <li
                      key={f.text}
                      className="flex items-start gap-2.5 py-1.5 text-sm leading-snug text-neutral-700 dark:text-neutral-200"
                    >
                      <span className="mt-0.5 flex h-4 w-4 flex-shrink-0 items-center justify-center text-[11px] text-success-500">
                        ✓
                      </span>
                      <span
                        className={`flex-1 ${f.bold ? 'font-semibold text-neutral-900 dark:text-white' : ''}`}
                      >
                        {f.text}
                      </span>
                    </li>
                  ))}
                </ul>

                <div className="mt-4 rounded-lg border border-violet-200/50 bg-violet-50/50 px-3 py-2.5 dark:border-violet-900/30 dark:bg-violet-950/20">
                  <p className="mb-1.5 font-mono text-[9px] uppercase tracking-widest text-violet-600 dark:text-violet-400">
                    Add-ons available
                  </p>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-neutral-600 dark:text-neutral-400">
                    {TEAMS_ADDONS.map(a => (
                      <span key={a.label}>
                        <span className="font-semibold text-neutral-700 dark:text-neutral-300">
                          {a.label}
                        </span>{' '}
                        — {a.detail}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* ── ENTERPRISE CARD ── */}
            <div className="group relative flex flex-col overflow-hidden rounded-2xl border border-neutral-200 bg-white transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-success-100/50 dark:border-neutral-800 dark:bg-neutral-900 dark:hover:shadow-success-900/20">
              {/* Header */}
              <div className="border-b border-neutral-200 p-8 pb-7 dark:border-neutral-800">
                <p className="mb-3 text-sm font-bold uppercase tracking-widest text-success-500">
                  Enterprise
                </p>
                <p className="mb-2 text-sm text-neutral-600 dark:text-neutral-400">
                  From{' '}
                  <strong className="font-semibold text-neutral-900 dark:text-white">
                    $2,000
                  </strong>
                  /month · Annual contract · Invoice/PO
                </p>
                <p className="mb-5 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                  For regulated industries and large organisations. Air-gap
                  mode, mTLS, custom playbooks, compliance evidence, dedicated
                  SLA, and full onboarding.
                </p>
                <a
                  href="mailto:support@devfortress.net?subject=Enterprise%20inquiry"
                  className="mb-2 block w-full rounded-xl bg-success-500 py-3.5 text-center text-sm font-semibold text-white shadow-md transition-all hover:bg-success-600 hover:shadow-lg"
                >
                  Get a Quote →
                </a>
                <a
                  href="mailto:support@devfortress.net"
                  className="block w-full rounded-xl border border-neutral-300 bg-transparent py-3.5 text-center text-sm font-semibold text-neutral-700 transition-all hover:border-success-500 hover:text-success-600 dark:border-neutral-700 dark:text-neutral-200 dark:hover:border-success-500 dark:hover:text-success-400"
                >
                  Contact Sales
                </a>
              </div>

              {/* Body */}
              <div className="flex-1 p-7 pt-6">
                <p className="mb-2.5 border-b border-neutral-200 pb-1.5 font-mono text-[9px] uppercase tracking-widest text-neutral-500 dark:border-neutral-800">
                  Everything in Teams, plus
                </p>
                <ul className="space-y-1.5">
                  {[
                    'Unlimited scale — apps, seats, events',
                    'Priced per API endpoint, not per app',
                    'All 3 CL modes — External, Internal, Hybrid',
                    'Advanced threat scoring + cross-credential correlation',
                    'Annual invoice / Purchase Order billing',
                    'Dedicated CSM + structured onboarding',
                    // 'AI Agent CL — usage-based pricing',
                    'AI Agent CL — unlimited, usage-based pricing',
                    'API Key & Payload Protection',
                    '🔜 Air-gap mode (Coming Soon)',
                    '🔜 mTLS certificate authentication (Coming Soon)',
                    '🔜 SIEM — Splunk, Datadog, Sentinel (Coming Soon)',
                    '🔜 Compliance PDF reports (Coming Soon)',
                    '🔜 On-premise deployment (Coming Soon)',
                    '🔜 99.95% uptime SLA (Coming Soon)',
                  ].map(f => (
                    <li
                      key={f}
                      className="flex items-start gap-2.5 py-1.5 text-sm leading-snug text-neutral-700 dark:text-neutral-200"
                    >
                      <span className="mt-0.5 flex h-4 w-4 flex-shrink-0 items-center justify-center text-[11px] text-success-500">
                        ✓
                      </span>
                      <span className="flex-1">{f}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Overage note */}
          <p className="mb-16 text-center text-sm text-neutral-500 dark:text-neutral-400">
            All paid plans billed monthly. Annual billing saves 20%.
            Enterprise via annual invoice.
          </p>
        </section>

        {/* ═══════════════════════════════════════════
           ENTERPRISE SECTION
        ═══════════════════════════════════════════ */}
        <section
          id="enterprise"
          className="relative overflow-hidden border-y border-success-200 bg-success-50/50 py-20 dark:border-success-900/30 dark:bg-success-950/20"
        >
          {/* Subtle gradient overlay */}
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-success-500/5 via-transparent to-primary-500/5" />

          <div className="relative mx-auto max-w-6xl px-6 sm:px-8 lg:px-12">
            {/* Header */}
            <div className="mb-16 text-center">
              <p className="mb-3 text-sm font-semibold uppercase tracking-widest text-success-500">
                Enterprise
              </p>
              <h2 className="mb-4 text-3xl font-bold tracking-tight sm:text-4xl lg:text-[40px] lg:leading-[1.15]">
                Custom pricing for
                <br />
                <span className="bg-gradient-to-r from-success-500 to-primary-500 bg-clip-text text-transparent">
                  businesses, corporations &amp; regulated industries
                </span>
                .
              </h2>
              <p className="mx-auto mb-6 max-w-xl text-base leading-relaxed text-neutral-600 dark:text-neutral-400">
                No fixed price. Enterprise is scoped to your exact requirements
                — API endpoints, compliance frameworks, SLA tier, and deployment
                model. Click &ldquo;Get a Quote&rdquo; to configure and get an
                indicative estimate, or email{' '}
                <strong className="text-success-600 dark:text-success-400">
                  support@devfortress.net
                </strong>{' '}
                to finalise.
              </p>
              <div className="mt-5 flex flex-wrap justify-center gap-2">
                {[
                  'HYBRID CL',
                  'INTERNAL CL',
                  'EXTERNAL CL',
                  'AI AGENT CL',
                  'THREAT SCORING',
                  'ANNUAL CONTRACT',
                  'INVOICE / PO',
                  'UNLIMITED SCALE',
                ].map(chip => (
                  <span
                    key={chip}
                    className="rounded-full border border-success-300 bg-success-100/50 px-3 py-1 font-mono text-[10px] tracking-wider text-success-700 dark:border-success-800/50 dark:bg-success-500/10 dark:text-success-400"
                  >
                    {chip}
                  </span>
                ))}
              </div>
            </div>

            {/* ─── Book & Beta Offer ─── */}
            <div className="mt-12 text-center">
              <p className="text-sm text-gray-400">
                Want to understand the security architecture behind each tier?
              </p>
              <a
                href="https://devfortress.gumroad.com/l/master-edition"
                className="text-blue-400 underline text-sm"
              >
                Read the Textbook: Credential Isolation Closed-Loop Security →
              </a>
            </div>

            {/* All Enterprise plans include */}
            <div className="mx-auto mb-16 max-w-[820px]">
              <h3 className="mb-6 text-center text-base font-bold text-neutral-900 dark:text-white">
                All Enterprise plans include
              </h3>
              <div className="grid gap-3 sm:grid-cols-2">
                {[
                  'Everything in Teams — at unlimited scale',
                  'Priced per API endpoint — not per app',
                  'Unlimited automated response actions',
                  'All 3 CL modes — External, Internal, Hybrid',
                  '1-year event history + CSV exports',
                  'Annual invoice / Purchase Order billing',
                  'Dedicated CSM + structured onboarding',
                  'Session privacy on all plans — always',
                ].map(f => (
                  <div
                    key={f}
                    className="flex items-start gap-2.5 rounded-xl border border-success-200 bg-white/60 px-4 py-3.5 dark:border-success-900/30 dark:bg-neutral-900/50"
                  >
                    <span className="mt-0.5 flex-shrink-0 text-sm text-success-500">
                      ✓
                    </span>
                    <span className="text-sm text-neutral-700 dark:text-neutral-200">
                      {f}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Enterprise CTA */}
            <div className="mx-auto max-w-[820px] rounded-2xl border border-success-300/30 bg-success-50/50 px-8 py-10 text-center dark:border-success-500/20 dark:bg-success-500/5 sm:px-10">
              <h3 className="mb-2.5 text-xl font-bold text-neutral-900 dark:text-white sm:text-2xl">
                Ready to protect your production application, APIs or AI Agents?
              </h3>
              <p className="mx-auto mb-7 max-w-lg text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                Contact our sales team. We&apos;ll map your endpoints,
                compliance requirements, and deployment model — and deliver a
                fixed-price proposal within 48 hours.
              </p>
              <div className="flex flex-wrap justify-center gap-3">
                <a
                  href="mailto:support@devfortress.net?subject=Enterprise%20inquiry"
                  className="rounded-xl bg-success-500 px-8 py-3.5 text-sm font-semibold text-white shadow-md transition-colors hover:bg-success-600 hover:shadow-lg"
                >
                  Get a Quote →
                </a>
                <Link
                  href="/enterprise"
                  className="rounded-xl border border-neutral-300 px-8 py-3.5 text-sm font-medium text-neutral-700 transition-all hover:border-success-500 dark:border-neutral-700 dark:text-neutral-200 dark:hover:border-success-500"
                >
                  Preview Enterprise Features
                </Link>
              </div>
              <a
                href="mailto:support@devfortress.net"
                className="mt-3.5 inline-block font-mono text-xs tracking-wide text-success-600 hover:underline dark:text-success-400"
              >
                support@devfortress.net
              </a>
            </div>
          </div>
        </section>

        {/* ═══════════════════════════════════════════
           PLAN COMPARISON TABLE
        ═══════════════════════════════════════════ */}
        <section className="mx-auto max-w-6xl px-6 py-20 sm:px-8 lg:px-12">
          <h2 className="mb-2 text-center text-2xl font-bold text-neutral-900 dark:text-white">
            Plan Comparison
          </h2>
          <p className="mb-8 text-center text-sm text-neutral-600 dark:text-neutral-400">
            All paid tiers compared. Everything clearly listed.
          </p>

          <div className="overflow-x-auto rounded-2xl border border-neutral-200 dark:border-neutral-800">
            <table className="w-full border-collapse text-[12.5px]">
              <thead>
                <tr className="bg-neutral-50 dark:bg-neutral-900">
                  <th className="w-[32%] border-b border-neutral-200 px-4 py-3.5 text-left text-[11px] font-bold uppercase tracking-wider text-neutral-500 dark:border-neutral-800 dark:text-neutral-400">
                    Feature
                  </th>
                  <th className="w-[14%] border-b border-neutral-200 px-4 py-3.5 text-center text-[11px] font-bold uppercase tracking-wider text-neutral-500 dark:border-neutral-800 dark:text-neutral-400">
                    Starter
                    <br />
                    <span className="text-[10px] font-light">$49/mo</span>
                  </th>
                  <th className="w-[14%] border-b border-neutral-200 px-4 py-3.5 text-center text-[11px] font-bold uppercase tracking-wider text-primary-500 dark:border-neutral-800">
                    Pro
                    <br />
                    <span className="text-[10px] font-light text-neutral-500 dark:text-neutral-400">
                      $99/mo
                    </span>
                  </th>
                  <th className="w-[14%] border-b border-neutral-200 px-4 py-3.5 text-center text-[11px] font-bold uppercase tracking-wider text-violet-500 dark:border-neutral-800">
                    Teams
                    <br />
                    <span className="text-[10px] font-light text-neutral-500 dark:text-neutral-400">
                      $399/mo
                    </span>
                  </th>
                  <th className="w-[20%] border-b border-neutral-200 px-4 py-3.5 text-center text-[11px] font-bold uppercase tracking-wider text-success-500 dark:border-neutral-800">
                    Enterprise
                    <br />
                    <span className="text-[10px] font-light text-neutral-500 dark:text-neutral-400">
                      Custom / Annual
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {comparisonData.map(group => (
                  <Fragment key={`group-${group.group}`}>
                    <tr>
                      <td
                        colSpan={5}
                        className="border-b border-neutral-200 bg-neutral-100 px-4 py-2 font-mono text-[10px] uppercase tracking-widest text-neutral-700 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300"
                      >
                        {group.group}
                      </td>
                    </tr>
                    {group.rows.map(row => (
                      <tr
                        key={row.feature}
                        className="bg-white transition-colors hover:bg-neutral-50 dark:bg-neutral-950 dark:hover:bg-neutral-900/50"
                      >
                        <td className="border-b border-neutral-200/70 px-4 py-2.5 text-[12.5px] text-neutral-700 dark:border-neutral-800/50 dark:text-neutral-200">
                          {row.feature}
                          {row.note && (
                            <span className="mt-0.5 block text-[10px] font-light text-neutral-500">
                              {row.note}
                            </span>
                          )}
                        </td>
                        <td className="border-b border-neutral-200/70 px-4 py-2.5 text-center dark:border-neutral-800/50">
                          {renderCompareCell(row.starter)}
                        </td>
                        <td className="border-b border-neutral-200/70 px-4 py-2.5 text-center dark:border-neutral-800/50">
                          {renderCompareCell(row.pro)}
                        </td>
                        <td className="border-b border-neutral-200/70 px-4 py-2.5 text-center dark:border-neutral-800/50">
                          {renderCompareCell(row.teams)}
                        </td>
                        <td className="border-b border-neutral-200/70 px-4 py-2.5 text-center dark:border-neutral-800/50">
                          {renderCompareCell(row.enterprise)}
                        </td>
                      </tr>
                    ))}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-2 text-center">
            * Credential Isolation and Payload Protection are active in SDK
            v4.8+. The self-service management dashboard is active.
          </p>
        </section>

        {/* ═══════════════════════════════════════════
           ADD-ONS
        ═══════════════════════════════════════════ */}
        <section
          id="addons"
          className="mx-auto max-w-6xl px-6 py-20 sm:px-8 lg:px-12"
        >
          <h2 className="mb-2 text-center text-2xl font-bold text-neutral-900 dark:text-white">
            Extend Your Plan
          </h2>
          <p className="mb-10 text-center text-sm text-neutral-600 dark:text-neutral-400">
            Add capacity, compliance, and SSO to any paid plan. Billed monthly
            alongside your subscription.
          </p>
          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {ADDON_CATALOGUE.map(addon => {
              const isFlat = addon.maxUnits === 1;
              const isPostMvp = false; // POST_MVP: set to addon.id === 'sso_saml' || addon.id === 'extra_honeypot' when re-enabled
              return (
                <div
                  key={addon.id}
                  className="flex flex-col rounded-2xl border border-neutral-200 bg-white p-6 transition-all duration-300 hover:-translate-y-0.5 hover:shadow-md dark:border-neutral-800 dark:bg-neutral-900"
                >
                  <h3 className="mb-1 flex items-center gap-2 text-sm font-bold text-neutral-900 dark:text-white">
                    {addon.name}
                    {isPostMvp && (
                      <span className="inline-block rounded-full bg-neutral-200 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wide text-neutral-500 dark:bg-neutral-800 dark:text-neutral-400">
                        Coming Soon
                      </span>
                    )}
                  </h3>
                  <p className="mb-4 text-xs leading-relaxed text-neutral-500 dark:text-neutral-400">
                    {addon.description}
                  </p>
                  <p className="mb-4 font-mono text-base font-semibold text-primary-600 dark:text-primary-400">
                    {isFlat
                      ? `$${addon.pricePerUnit}/mo`
                      : `$${addon.pricePerUnit}/${addon.unit}/mo`}
                  </p>
                  {isPostMvp ? (
                    <p className="mb-4 font-mono text-sm text-neutral-500 dark:text-neutral-400">
                      Coming soon
                    </p>
                  ) : (
                    <a
                      href="https://devfortress.net/pricing"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block w-full rounded-xl border border-primary-300 bg-transparent py-2.5 text-center text-sm font-semibold text-primary-700 transition-all hover:border-primary-500 hover:bg-primary-500 hover:text-white dark:border-primary-700 dark:text-primary-300 dark:hover:border-primary-500 dark:hover:text-white"
                    >
                      View hosted plans &amp; pricing →
                    </a>
                  )}
                  {addon.proOnly && (
                    <p className="mt-1.5 text-center font-mono text-[10px] text-neutral-400 dark:text-neutral-600">
                      Requires Pro or higher
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        {/* ═══════════════════════════════════════════
           BUILT FOR YOUR INDUSTRY
        ═══════════════════════════════════════════ */}
        <section className="mx-auto max-w-6xl px-6 pb-4 pt-12 sm:px-8 lg:px-12">
          <h2 className="mb-2 text-center text-2xl font-bold text-neutral-900 dark:text-white">
            Built for Your Industry
          </h2>
          <p className="mb-10 text-center text-sm text-neutral-600 dark:text-neutral-400">
            DevFortress protects applications and APIs across every sector.
          </p>
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 items-stretch">
            {[
              {
                emoji: '🔐',
                title: 'API Security',
                desc: 'Protect REST, GraphQL, and gRPC endpoints with automated threat detection, session revocation, and IP blocking. Full unified security coverage from first probe to post-auth abuse.',
              },
              {
                emoji: '🤖',
                title: 'AI Agent Security',
                desc: 'Per-agent credential isolation, behavioral baselines, anomaly detection, and scope enforcement. Closed-loop protection for autonomous AI systems and MCP servers.',
              },
              {
                emoji: '🔑',
                title: 'API Key & Payload Protection',
                desc: 'Replace real API keys with short-lived aliases. Payload signing, selective field encryption, and inbound response verification. Real keys never leave your infrastructure. Teams+ only. Coming Soon.',
              },
              {
                emoji: '💳',
                title: 'E-commerce & Fintech',
                desc: 'Prevent account takeover, payment fraud, and credential stuffing. AbuseIPDB enrichment, composite threat scoring, and sub-2-second session revocation.',
              },
              {
                emoji: '🏛️',
                title: 'Regulated Industries',
                desc: 'PCI-DSS, SOC2, GDPR, HIPAA compliance evidence. Air-gap mode, mTLS, SIEM integration, and 1-year audit trail for healthcare, finance, and government.',
              },
              {
                emoji: '🏗️',
                title: 'SaaS & Multi-Tenant Platforms',
                desc: 'Per-tenant isolation, cross-tenant abuse detection, and API rate enforcement. Credential isolation and closed-loop session revocation protect shared infrastructure without exposing tenant boundaries.',
              },
            ].map(card => (
              <div
                key={card.title}
                className="flex flex-col h-full rounded-2xl border border-neutral-200 bg-white p-6 transition-all duration-300 hover:-translate-y-1 hover:shadow-lg dark:border-neutral-800 dark:bg-neutral-900"
              >
                <p className="mb-3 text-2xl">{card.emoji}</p>
                <h3 className="mb-2 text-sm font-bold text-neutral-900 dark:text-white">
                  {card.title}
                </h3>
                <p className="flex-1 text-xs leading-relaxed text-neutral-600 dark:text-neutral-400">
                  {card.desc}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* ═══════════════════════════════════════════
           FAQ
        ═══════════════════════════════════════════ */}
        <section className="mx-auto max-w-6xl px-6 pb-20 sm:px-8 lg:px-12">
          <h2 className="mb-8 text-center text-xl font-bold text-neutral-900 dark:text-white sm:text-2xl">
            Common Questions
          </h2>
          <div className="grid gap-4 md:grid-cols-2">
            {faqs.map(faq => (
              <div
                key={faq.question}
                className="rounded-2xl border border-neutral-200 bg-white px-5 py-5 transition-all duration-300 hover:shadow-md dark:border-neutral-800 dark:bg-neutral-900"
              >
                <h3 className="mb-2 text-sm font-semibold text-neutral-900 dark:text-white">
                  {faq.question}
                </h3>
                <p className="text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                  {faq.answer}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* ─── Footer CTA ─── */}
        <section className="border-t border-neutral-200 dark:border-neutral-800">
          <div className="mx-auto max-w-6xl px-6 py-16 text-center sm:px-8 lg:px-12">
            <h2 className="mb-4 text-3xl font-bold text-neutral-900 dark:text-white">
              Ready to secure your Applications, APIs or AI agents?
            </h2>
            <p className="mx-auto mb-8 max-w-2xl text-base text-neutral-600 dark:text-neutral-400">
              Start with Starter, Pro, or Teams — or talk to us about
              Enterprise. Every plan includes session-safe unified security and
              real-time threat detection.
            </p>
            <div className="flex items-center justify-center gap-4">
              <a
                href="https://devfortress.net/pricing"
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-xl bg-primary-500 px-8 py-3 font-semibold text-white shadow-md transition-all hover:bg-primary-600 hover:shadow-lg"
              >
                View hosted plans &amp; pricing →
              </a>
              <a
                href="mailto:support@devfortress.net"
                className="rounded-xl border border-neutral-300 px-8 py-3 font-semibold text-neutral-700 transition-colors hover:border-success-500 dark:border-neutral-700 dark:text-neutral-200 dark:hover:border-success-500"
              >
                Contact Sales
              </a>
            </div>
            <p className="mt-4 text-xs text-neutral-400 dark:text-neutral-600">
              Starter, Pro &amp; Teams via hosted checkout · Enterprise via
              annual invoice
            </p>
          </div>
        </section>
      </main>

    </>
  );
}
