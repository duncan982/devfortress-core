/**
 * Enterprise Landing Page — Client Component
 * Phase 1 pre-launch: interest capture + feature showcase
 */

'use client';

import { useState, FormEvent } from 'react';
import Link from 'next/link';
import { EnterpriseIntakeModal } from '@/app/components/pricing/EnterpriseIntakeModal';

/* ─── Feature data ─── */
const FEATURES = [
  {
    icon: '🔐',
    title: 'mTLS Certificate Authentication',
    desc: 'Mutual X.509 certificate authentication on all SDK ↔ Platform traffic. Required for PCI-DSS Level 1.',
    status: 'Phase 1',
  },
  {
    icon: '📋',
    title: 'Compliance Evidence Generation',
    desc: 'Automated PDF reports for PCI-DSS v4.0, SOC2 Type II, GDPR, and HIPAA. Audit-ready, timestamped, immutable.',
    status: 'Phase 1',
  },
  {
    icon: '📡',
    title: 'SIEM Integration',
    desc: 'Real-time event forwarding to Splunk, Datadog, Microsoft Sentinel, and IBM QRadar.',
    status: 'Phase 2',
  },
  {
    icon: '🎯',
    title: 'Custom Response Playbooks',
    desc: 'Define per-endpoint threat response rules. Auto-block, rate-limit, challenge, or escalate based on severity.',
    status: 'Phase 2',
  },
  {
    icon: '🌍',
    title: 'Data Residency & On-Premise',
    desc: 'Choose EU, US, or Africa data regions. Docker Compose and Helm chart for private cloud / air-gap deployments.',
    status: 'Phase 3',
  },
  {
    icon: '⚖️',
    title: 'Legal & Compliance Documents',
    desc: 'GDPR DPA, HIPAA BAA, custom MSA. Signed and countersigned within 48 hours of contract acceptance.',
    status: 'Phase 1',
  },
  {
    icon: '📊',
    title: 'Endpoint-Based Billing',
    desc: 'Priced by API endpoints monitored — not apps or seats. Automatic endpoint discovery via SDK.',
    status: 'Phase 1',
  },
  {
    icon: '🛡️',
    title: '99.9%–99.95% Uptime SLA',
    desc: 'Status page, proactive incident response, and financial credits for any SLA breach.',
    status: 'Phase 1',
  },
  {
    icon: '🤝',
    title: 'Dedicated CSM + Onboarding',
    desc: 'Structured 4-week onboarding: endpoint mapping, SDK install, mTLS certs, playbook config, SIEM hookup.',
    status: 'Phase 1',
  },
];

const COMPLIANCE_CHIPS = [
  'PCI-DSS v4.0',
  'SOC2 Type II',
  'GDPR / DPA',
  'HIPAA BAA',
  'ISO 27001',
  'mTLS',
];

const TRUST_STATS = [
  { value: '99.95%', label: 'Uptime SLA' },
  { value: '<1s', label: 'Avg Response Time' },
  { value: '24/7', label: 'Support Coverage' },
  { value: '48h', label: 'Quote Turnaround' },
];

export default function EnterprisePageClient() {
  const [isBookModalOpen, setIsBookModalOpen] = useState(false);
  const [formState, setFormState] = useState({
    companyName: '',
    contactName: '',
    contactEmail: '',
    teamSize: 10,
    expectedAPIs: 50,
    expectedEventsPerMonth: 100000,
    complianceNeeds: [] as string[],
    securityLevel: 'hmac-mtls',
    deploymentModel: 'cloud',
    slaRequired: '99.9',
    requiresSupport: true,
    requiresSLA: true,
    requiresCustomIntegration: false,
    additionalNotes: '',
    agreementAccepted: false,
  });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [quoteBreakdown, setQuoteBreakdown] = useState<Record<
    string,
    number
  > | null>(null);

  const toggleCompliance = (val: string) => {
    setFormState(prev => ({
      ...prev,
      complianceNeeds: prev.complianceNeeds.includes(val)
        ? prev.complianceNeeds.filter(c => c !== val)
        : [...prev.complianceNeeds, val],
    }));
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const payload = {
        companyName: formState.companyName,
        legalEntityName: formState.companyName,
        contactName: formState.contactName,
        contactEmail: formState.contactEmail,
        jobTitle: 'Not specified',
        estimatedEndpoints: formState.expectedAPIs,
        deploymentType: formState.deploymentModel as
          | 'cloud'
          | 'on_prem'
          | 'hybrid',
        complianceFrameworks: formState.complianceNeeds,
        aiAgentCount: undefined as number | undefined,
        billingCycle: 'annual' as const,
        preferredPayment: 'wire' as const,
        estimatedAnnualUsd: 24997,
        invoiceType: 'book_tier3' as const,
        agreementAccepted: true as const,
        agreementAcceptedAt: new Date().toISOString(),
        message: formState.additionalNotes || undefined,
      };
      const res = await fetch('/api/enterprise/intake', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Submission failed');
      setSubmitted(true);
      setQuoteBreakdown(data.breakdown || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070B14] text-white">
      {/* ─── Hero ─── */}
      <section className="relative overflow-hidden border-b border-[#1E2845] pb-20 pt-24">
        <div
          className="pointer-events-none absolute inset-0 opacity-30"
          style={{
            background:
              'radial-gradient(ellipse 60% 40% at 50% 20%, rgba(16,185,129,0.08), transparent)',
          }}
        />
        <div className="relative mx-auto max-w-[1100px] px-6 text-center">
          <p className="mb-3 font-mono text-[11px] uppercase tracking-[3px] text-emerald-500">
            Enterprise Security
          </p>
          <h1 className="mb-5 text-[clamp(32px,5vw,56px)] font-extrabold leading-[1.1] tracking-tight">
            Application, API &amp; AI Agent Security — Automated
            <br />
            <em className="not-italic text-emerald-500">
              Enterprise-grade protection at unlimited scale.
            </em>
          </h1>
          <p className="mx-auto mb-8 max-w-[700px] text-[17px] font-light leading-relaxed text-[#8B90A8]">
            DevFortress Enterprise deploys the Closed-Loop Automated Response
            system across your entire organization — protecting web
            applications, REST/GraphQL APIs, and AI agent pipelines with
            HMAC-signed webhook callbacks, zero-trust session aliasing, and
            cross-customer threat intelligence.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <a
              href="#interest-form"
              className="rounded-xl bg-emerald-500 px-8 py-4 text-[15px] font-semibold text-white transition-colors hover:bg-emerald-600"
            >
              Register Your Interest →
            </a>
            <a
              href="mailto:support@devfortress.net"
              className="rounded-xl border border-[#1E2845] px-8 py-4 text-[15px] font-medium text-[#E8EAF2] transition-all hover:border-emerald-500"
            >
              Contact Sales
            </a>
          </div>

          {/* Compliance chips */}
          <div className="mt-10 flex flex-wrap justify-center gap-2.5">
            {COMPLIANCE_CHIPS.map(chip => (
              <span
                key={chip}
                className="rounded-full border border-emerald-500/20 px-3 py-1 font-mono text-[10px] tracking-wider text-emerald-500"
              >
                {chip}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ─── Trust Stats ─── */}
      <section className="border-b border-[#1E2845] py-12">
        <div className="mx-auto grid max-w-[900px] grid-cols-2 gap-6 px-6 md:grid-cols-4">
          {TRUST_STATS.map(stat => (
            <div key={stat.label} className="text-center">
              <p className="text-3xl font-extrabold text-emerald-500">
                {stat.value}
              </p>
              <p className="mt-1 text-[13px] text-[#6B7194]">{stat.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ─── Three Pillars ─── */}
      <section className="border-b border-[#1E2845] py-16">
        <div className="mx-auto grid max-w-[1100px] grid-cols-1 gap-6 px-6 md:grid-cols-3">
          {[
            {
              icon: '🛡️',
              title: 'Application Security',
              desc: 'Real-time threat detection, session revocation, and IP blocking across all your web applications.',
            },
            {
              icon: '🔌',
              title: 'API Security',
              desc: 'Token Alias Security, payload validation, and rate-limit enforcement for REST and GraphQL APIs.',
            },
            {
              icon: '🤖',
              title: 'AI Agent Security',
              desc: 'MCP server protection, prompt injection detection, and agent session isolation for your AI pipelines.',
            },
          ].map(pillar => (
            <div
              key={pillar.title}
              className="rounded-2xl border border-[#1E2845] bg-[#0E1428] p-6"
            >
              <span className="mb-3 block text-3xl">{pillar.icon}</span>
              <h3 className="mb-2 text-[16px] font-semibold">{pillar.title}</h3>
              <p className="text-[13px] font-light leading-relaxed text-[#6B7194]">
                {pillar.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* ─── Features Grid ─── */}
      <section className="py-20">
        <div className="mx-auto max-w-[1100px] px-6">
          <h2 className="mb-3 text-center text-[28px] font-bold">
            Enterprise-Grade Capabilities
          </h2>
          <p className="mb-12 text-center text-[15px] text-[#6B7194]">
            Everything in Pro — plus these enterprise-exclusive features.
          </p>
          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(f => (
              <div
                key={f.title}
                className="rounded-2xl border border-[#1E2845] bg-[#0E1428] p-6 transition-all hover:border-emerald-500/30"
              >
                <div className="mb-3 flex items-center justify-between">
                  <span className="text-2xl">{f.icon}</span>
                  <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 font-mono text-[9px] tracking-wider text-emerald-500">
                    {f.status}
                  </span>
                </div>
                <h3 className="mb-1.5 text-[15px] font-semibold">{f.title}</h3>
                <p className="text-[13px] font-light leading-relaxed text-[#6B7194]">
                  {f.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── How It Works ─── */}
      <section className="border-y border-[#1E2845] bg-[#0A0F1A] py-20">
        <div className="mx-auto max-w-[900px] px-6">
          <h2 className="mb-12 text-center text-[28px] font-bold">
            Enterprise Onboarding
          </h2>
          <div className="grid gap-6 md:grid-cols-4">
            {[
              {
                step: '1',
                title: 'Scoping Call',
                desc: '30-min call to map your endpoints, compliance frameworks, and deployment model.',
              },
              {
                step: '2',
                title: 'Custom Proposal',
                desc: 'Fixed-price proposal delivered within 48 hours. No surprises.',
              },
              {
                step: '3',
                title: 'Contract & Setup',
                desc: 'Sign annual contract. We begin 4-week structured onboarding.',
              },
              {
                step: '4',
                title: 'Go Live',
                desc: 'SDK installed, mTLS certs issued, playbooks configured, SIEM connected.',
              },
            ].map(s => (
              <div key={s.step} className="text-center">
                <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/20 font-mono text-sm font-bold text-emerald-500">
                  {s.step}
                </div>
                <h3 className="mb-1 text-[14px] font-semibold">{s.title}</h3>
                <p className="text-[12px] leading-relaxed text-[#6B7194]">
                  {s.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── Textbook Purchase ─── */}
      <section id="book-tier3" className="py-16">
        <div className="mx-auto max-w-[1100px] px-6">
          <div className="mx-auto max-w-3xl rounded-2xl border border-amber-200 bg-amber-50/40 px-8 py-10 dark:border-amber-800/40 dark:bg-amber-900/10">
            <div className="flex items-start gap-4">
              <span className="text-3xl">📖</span>
              <div className="flex-1">
                <p className="mb-1 text-xs font-semibold uppercase tracking-widest text-amber-600 dark:text-amber-400">
                  Textbook — Tier 3
                </p>
                <h3 className="mb-2 text-xl font-bold text-neutral-900 dark:text-white">
                  Token-Aliased Closed-Loop Security
                </h3>
                <p className="mb-4 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                  The definitive reference on TAS and CLAR architecture. 12
                  chapters, 5 volumes — covering session aliasing, behavioral
                  detection, credential protection, payload security, and
                  platform intelligence. Includes integration examples,
                  patent-aligned architecture diagrams, and SDK implementation
                  guides.
                </p>
                <div className="mb-6 flex items-center gap-3">
                  <span className="text-2xl font-bold text-neutral-900 dark:text-white">
                    $24,997
                  </span>
                  <span className="text-sm text-neutral-500">
                    · one-time · invoice / wire transfer
                  </span>
                </div>

                {/* 5-step purchase flow */}
                <div className="mb-6 space-y-2.5">
                  <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-neutral-500">
                    How to purchase
                  </p>
                  {[
                    'Click "Get Invoice" below and complete the short intake form.',
                    'Receive a formal invoice with bank wire instructions within 24 hours.',
                    'Submit payment and your delivery email to support@devfortress.net.',
                    'Receive all materials (PDF, epub, integration guide) within 24 hours of payment confirmation.',
                    'Receive your integration onboarding kickoff link.',
                  ].map((step, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <span className="mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-amber-100 text-xs font-bold text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
                        {i + 1}
                      </span>
                      <p className="text-sm text-neutral-600 dark:text-neutral-400">
                        {step}
                      </p>
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => setIsBookModalOpen(true)}
                  className="rounded-xl bg-amber-500 px-8 py-3 text-sm font-semibold text-white shadow-md transition-colors hover:bg-amber-600"
                >
                  Get Invoice →
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── Interest Form ─── */}
      <section id="interest-form" className="py-20">
        <div className="mx-auto max-w-[680px] px-6">
          <h2 className="mb-2 text-center text-[28px] font-bold">
            Register Your Interest — Enterprise Subscription
          </h2>
          <p className="mb-10 text-center text-[15px] text-[#6B7194]">
            We&apos;ll scope your requirements and deliver a custom proposal
            within 48 hours.
          </p>

          {submitted ? (
            <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-10 text-center">
              <div className="mb-4 text-5xl">✅</div>
              <h3 className="mb-2 text-xl font-bold">Inquiry Received</h3>
              <p className="mb-6 text-[15px] text-[#6B7194]">
                We&apos;ve received your Tier 3 Enterprise Blueprint inquiry.
              </p>

              <div className="mb-8 rounded-xl border border-[#1E2845] bg-[#0E1428] p-6 text-left">
                <p className="mb-4 font-mono text-[11px] uppercase tracking-wider text-emerald-500">
                  What Happens Next
                </p>
                <ol className="space-y-3">
                  {[
                    {
                      n: '1',
                      text: 'You will receive an invoice by email within 24–48 hours.',
                    },
                    {
                      n: '2',
                      text: 'Pay by bank wire transfer, including your invoice reference number in the payment details.',
                    },
                    {
                      n: '3',
                      text: 'Email your payment confirmation / transfer receipt to support@devfortress.net.',
                    },
                    {
                      n: '4',
                      text: 'We confirm receipt and provision your access within 24 hours of cleared funds.',
                    },
                    {
                      n: '5',
                      text: 'You receive a sign-in link with download access to all Tier 3 files.',
                    },
                  ].map(step => (
                    <li key={step.n} className="flex items-start gap-3">
                      <span className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-emerald-500/20 font-mono text-[11px] font-bold text-emerald-500">
                        {step.n}
                      </span>
                      <span className="text-[13px] text-[#9CA3AF]">
                        {step.text}
                      </span>
                    </li>
                  ))}
                </ol>
              </div>

              <div className="flex flex-wrap justify-center gap-3">
                <a
                  href="mailto:support@devfortress.net"
                  className="rounded-lg bg-emerald-500 px-6 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-emerald-600"
                >
                  Email Us Now
                </a>
                <Link
                  href="/pricing"
                  className="rounded-lg border border-[#1E2845] px-6 py-2.5 text-sm font-medium transition-all hover:border-emerald-500"
                >
                  View Pricing
                </Link>
              </div>
            </div>
          ) : (
            <form
              onSubmit={handleSubmit}
              className="rounded-2xl border border-[#1E2845] bg-[#0E1428] p-8"
            >
              {error && (
                <div className="mb-6 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
                  {error}
                </div>
              )}

              {/* Company & Contact */}
              <div className="mb-6 grid gap-4 md:grid-cols-2">
                <div>
                  <label className="mb-1 block text-[12px] font-medium text-[#6B7194]">
                    Company Name *
                  </label>
                  <input
                    required
                    type="text"
                    value={formState.companyName}
                    onChange={e =>
                      setFormState(p => ({
                        ...p,
                        companyName: e.target.value,
                      }))
                    }
                    className="w-full rounded-lg border border-[#1E2845] bg-[#070B14] px-3 py-2.5 text-sm text-white placeholder-[#3A4060] focus:border-emerald-500 focus:outline-none"
                    placeholder="Acme Bank Ltd"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[12px] font-medium text-[#6B7194]">
                    Contact Email *
                  </label>
                  <input
                    required
                    type="email"
                    value={formState.contactEmail}
                    onChange={e =>
                      setFormState(p => ({
                        ...p,
                        contactEmail: e.target.value,
                      }))
                    }
                    className="w-full rounded-lg border border-[#1E2845] bg-[#070B14] px-3 py-2.5 text-sm text-white placeholder-[#3A4060] focus:border-emerald-500 focus:outline-none"
                    placeholder="cto@acmebank.com"
                  />
                </div>
              </div>

              <div className="mb-6">
                <label className="mb-1 block text-[12px] font-medium text-[#6B7194]">
                  Contact Name *
                </label>
                <input
                  required
                  type="text"
                  value={formState.contactName}
                  onChange={e =>
                    setFormState(p => ({ ...p, contactName: e.target.value }))
                  }
                  className="w-full rounded-lg border border-[#1E2845] bg-[#070B14] px-3 py-2.5 text-sm text-white placeholder-[#3A4060] focus:border-emerald-500 focus:outline-none"
                  placeholder="Jane Doe"
                />
              </div>

              {/* Scale */}
              <div className="mb-6 grid gap-4 md:grid-cols-3">
                <div>
                  <label className="mb-1 block text-[12px] font-medium text-[#6B7194]">
                    Team Size
                  </label>
                  <input
                    type="number"
                    min={1}
                    value={formState.teamSize}
                    onChange={e =>
                      setFormState(p => ({
                        ...p,
                        teamSize: parseInt(e.target.value) || 1,
                      }))
                    }
                    className="w-full rounded-lg border border-[#1E2845] bg-[#070B14] px-3 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[12px] font-medium text-[#6B7194]">
                    API Endpoints
                  </label>
                  <input
                    type="number"
                    min={1}
                    value={formState.expectedAPIs}
                    onChange={e =>
                      setFormState(p => ({
                        ...p,
                        expectedAPIs: parseInt(e.target.value) || 1,
                      }))
                    }
                    className="w-full rounded-lg border border-[#1E2845] bg-[#070B14] px-3 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[12px] font-medium text-[#6B7194]">
                    Events/Month
                  </label>
                  <input
                    type="number"
                    min={0}
                    value={formState.expectedEventsPerMonth}
                    onChange={e =>
                      setFormState(p => ({
                        ...p,
                        expectedEventsPerMonth: parseInt(e.target.value) || 0,
                      }))
                    }
                    className="w-full rounded-lg border border-[#1E2845] bg-[#070B14] px-3 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none"
                  />
                </div>
              </div>

              {/* Compliance needs */}
              <div className="mb-6">
                <label className="mb-2 block text-[12px] font-medium text-[#6B7194]">
                  Compliance Requirements
                </label>
                <div className="flex flex-wrap gap-2">
                  {[
                    'PCI-DSS',
                    'SOC2',
                    'GDPR',
                    'HIPAA',
                    'ISO 27001',
                    'None yet',
                  ].map(opt => (
                    <button
                      key={opt}
                      type="button"
                      onClick={() => toggleCompliance(opt)}
                      className={`rounded-lg border px-3 py-2 text-[12px] font-medium transition-all ${
                        formState.complianceNeeds.includes(opt)
                          ? 'border-emerald-500 bg-emerald-500/15 text-emerald-500'
                          : 'border-[#1E2845] text-[#6B7194] hover:border-emerald-500/50'
                      }`}
                    >
                      {opt}
                    </button>
                  ))}
                </div>
              </div>

              {/* Options */}
              <div className="mb-6 space-y-3">
                {[
                  {
                    key: 'requiresSupport' as const,
                    label: 'Dedicated support & CSM',
                  },
                  { key: 'requiresSLA' as const, label: 'Uptime SLA required' },
                  {
                    key: 'requiresCustomIntegration' as const,
                    label: 'Custom integration / on-premise needed',
                  },
                ].map(opt => (
                  <label
                    key={opt.key}
                    className="flex items-center gap-2.5 text-sm text-[#8B90A8]"
                  >
                    <input
                      type="checkbox"
                      checked={formState[opt.key]}
                      onChange={e =>
                        setFormState(p => ({
                          ...p,
                          [opt.key]: e.target.checked,
                        }))
                      }
                      className="h-4 w-4 rounded border-[#1E2845] bg-[#070B14] text-emerald-500 focus:ring-emerald-500"
                    />
                    {opt.label}
                  </label>
                ))}
              </div>

              {/* Notes */}
              <div className="mb-8">
                <label className="mb-1 block text-[12px] font-medium text-[#6B7194]">
                  Additional Notes (optional)
                </label>
                <textarea
                  rows={3}
                  value={formState.additionalNotes}
                  onChange={e =>
                    setFormState(p => ({
                      ...p,
                      additionalNotes: e.target.value,
                    }))
                  }
                  className="w-full rounded-lg border border-[#1E2845] bg-[#070B14] px-3 py-2.5 text-sm text-white placeholder-[#3A4060] focus:border-emerald-500 focus:outline-none"
                  placeholder="Tell us about your environment, timeline, or any specific requirements..."
                />
              </div>

              <div className="flex items-start gap-3 rounded-xl border border-[#1E2845] bg-[#0E1428] p-4">
                <input
                  type="checkbox"
                  id="esa-agree"
                  checked={formState.agreementAccepted}
                  onChange={e =>
                    setFormState(prev => ({
                      ...prev,
                      agreementAccepted: e.target.checked,
                    }))
                  }
                  className="mt-0.5 h-4 w-4 rounded border-[#1E2845] accent-emerald-500"
                />
                <label
                  htmlFor="esa-agree"
                  className="text-[13px] text-[#9CA3AF]"
                >
                  I have read and agree to the{' '}
                  <a
                    href="/legal/enterprise-services-agreement"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-emerald-400 underline"
                  >
                    Enterprise Services Agreement
                  </a>
                  . I understand that all sales are final after provisioning and
                  that 100% of the fee is due before access is granted.
                </label>
              </div>

              <button
                type="submit"
                disabled={submitting || !formState.agreementAccepted}
                className="w-full rounded-xl bg-emerald-500 py-3.5 text-[15px] font-semibold text-white transition-colors hover:bg-emerald-600 disabled:opacity-50"
              >
                {submitting
                  ? 'Submitting...'
                  : 'Submit Subscription Interest →'}
              </button>

              <p className="mt-4 text-center text-[11px] text-[#3A4060]">
                By submitting, you agree to be contacted about DevFortress
                Enterprise. We never share your data with third parties.
              </p>
            </form>
          )}
        </div>
      </section>

      <EnterpriseIntakeModal
        isOpen={isBookModalOpen}
        onClose={() => setIsBookModalOpen(false)}
        invoiceType="book_tier3"
        fixedEstimate={24997}
      />

      {/* ─── Pricing Link ─── */}
      <section className="border-t border-[#1E2845] py-16">
        <div className="mx-auto max-w-[900px] px-6 text-center">
          <h2 className="mb-3 text-[22px] font-bold">
            Looking for Starter or Pro?
          </h2>
          <p className="mb-6 text-[15px] text-[#6B7194]">
            Not every team needs Enterprise. Starter ($99/mo) and Pro ($149/mo)
            cover most development teams with full threat detection and
            automated response.
          </p>
          <Link
            href="/pricing"
            className="rounded-xl border border-[#1E2845] px-8 py-3.5 text-sm font-medium text-[#E8EAF2] transition-all hover:border-emerald-500"
          >
            View All Plans →
          </Link>
        </div>
      </section>
    </div>
  );
}
