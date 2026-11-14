// Version: v9.0.0 - IP-Protected Homepage: Credential Isolation, Agent Security, No Mechanism Disclosure
import Link from 'next/link';
import { Metadata } from 'next';
import { ValidationBadge } from './components/ValidationBadge';

// devfortress-core has no @core/lib/seo/structured-data or
// @core/components/home/auth-aware-content modules (private-repo only, and
// this page is independently maintained here rather than synced from
// source — see scripts/sync-open-core-local.sh's app/page.tsx stash/restore
// comment in the private repo). Inlined equivalents below: the schema
// objects are plain, non-sensitive schema.org JSON-LD; the auth-aware
// components degrade to their always-unauthenticated fallback, since this
// checkout has no session-provider hook to light up the authenticated
// branch with.
const organizationSchema = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'DevFortress',
  url: 'https://devfortress.net',
  logo: 'https://devfortress.net/logo.png',
  description:
    'Enterprise-grade API security platform with AI-powered generation, threat intelligence, and automated defense systems.',
  sameAs: [
    'https://twitter.com/devfortress',
    'https://github.com/devfortress',
    'https://linkedin.com/company/devfortress',
  ],
  contactPoint: {
    '@type': 'ContactPoint',
    contactType: 'Customer Support',
    email: 'support@devfortress.net',
    url: 'https://devfortress.net/contact',
  },
};

const webApplicationSchema = {
  '@context': 'https://schema.org',
  '@type': 'WebApplication',
  name: 'DevFortress Platform',
  url: 'https://devfortress.net',
  description:
    'Build secure APIs with AI assistance, deploy honeypots for threat intelligence, and continuously improve security posture.',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Web Browser',
  offers: { '@type': 'Offer', price: '69', priceCurrency: 'USD' },
};

function renderJsonLd(data: unknown) {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}

function AuthAwareHomeContent() {
  return null;
}

function AuthAwareFeatureLink({
  unauthenticatedHref,
  unauthenticatedLabel,
  className,
}: {
  authenticatedHref: string;
  authenticatedLabel: string;
  unauthenticatedHref: string;
  unauthenticatedLabel: string;
  className?: string;
  showSignUpHint?: boolean;
}) {
  return (
    <Link href={unauthenticatedHref} className={className}>
      {unauthenticatedLabel}
    </Link>
  );
}

function AuthAwareGetStartedButton() {
  return (
    <Link
      href="/login"
      className="rounded-lg bg-primary-600 px-6 py-3 font-semibold text-white hover:bg-primary-700"
    >
      Get Started
    </Link>
  );
}

/** Page metadata for the home page, including SEO and Open Graph data. */
export const metadata: Metadata = {
  title: 'DevFortress — Application, API & AI Agent Security',
  description:
    'Application, API, and AI agent security platform that detects attacks, responds automatically in under 1ms, and confirms every outcome with a full audit trail.',
  keywords: [
    'API security',
    'application security',
    'AI agent security',
    'automated threat response',
    'credential isolation',
    'session revocation',
    'OWASP compliance',
    'pre-auth attack detection',
    'unified security platform',
  ],
  openGraph: {
    title: 'DevFortress — Application, API & AI Agent Security',
    description:
      'Stop attacks across applications, APIs, and AI agents automatically. Unified detection, response, and confirmation with a full audit trail.',
    type: 'website',
    url: 'https://devfortress.net',
    images: [
      {
        url: 'https://devfortress.net/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'DevFortress — Application, API & AI Agent Security Platform',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'DevFortress — Application, API & AI Agent Security',
    description:
      'Stop attacks across applications, APIs, and AI agents automatically. Unified detection, response, and confirmation with a full audit trail.',
    images: ['https://devfortress.net/opengraph-image'],
  },
};

/** Dynamic rendering configuration to force dynamic rendering for session handling. */
export const dynamic = 'force-dynamic';

/** Home page component for the DevFortress platform. @returns {JSX.Element} The home page JSX. */
export default async function Home() {
  return (
    <>
      {renderJsonLd(organizationSchema)}
      {renderJsonLd(webApplicationSchema)}
      <div className="bg-neutral-50 font-sans text-neutral-900 transition-colors duration-200 dark:bg-neutral-950 dark:text-neutral-100">
        {/* Hero Section */}
        <section className="relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-blue-600/5 via-transparent to-green-600/5 dark:from-blue-500/10 dark:to-green-500/10" />
          <div className="absolute left-1/2 top-0 -z-10 h-[600px] w-[600px] -translate-x-1/2 rounded-full bg-blue-500/5 blur-3xl dark:bg-blue-500/10" />
          <div className="relative mx-auto max-w-6xl px-6 pb-16 pt-20 sm:px-8 lg:px-12">
            <div className="flex flex-col items-center text-center">
              <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50/80 px-4 py-1.5 text-sm font-medium text-blue-700 backdrop-blur-sm dark:border-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue-400 opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-blue-500" />
                </span>
                Unified Application Security — Multi-Language SDKs · Patent
                Pending
              </div>
              <h1 className="max-w-4xl text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">
                Application, API and AI Agent Security —{' '}
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-green-600 bg-clip-text text-transparent dark:from-blue-400 dark:via-purple-400 dark:to-green-400">
                  Automated.
                </span>
              </h1>
              {/* Akamai 2026 stat — MI-01 */}
              <p className="mt-4 text-sm font-medium text-amber-700 dark:text-amber-400">
                96% of financial services organisations experienced an API
                security incident in the past year. — Akamai, 2026
              </p>
              <p className="mt-4 max-w-2xl text-lg text-neutral-600 dark:text-neutral-400 sm:text-xl">
                Stop attacks before login and inside sessions. DevFortress
                detects threats across applications, APIs, and AI agents in real
                time and responds automatically — session revocation, IP
                blocking, and credential isolation — in under 2 seconds. No
                human intervention required.
              </p>
              <p className="mt-2 text-base font-semibold text-neutral-800 dark:text-neutral-200">
                DevFortress is the kill switch for your AI agents.
              </p>
              {/* Hero CTAs — single group keeps dashboard button above the fold */}
              <div className="mt-6 flex flex-col items-center gap-4 w-full">
                <a
                  href="https://devfortress.gumroad.com/l/master-edition"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded-md border border-blue-400/30 bg-blue-500/10 px-4 py-2 text-sm text-blue-300 hover:bg-blue-500/20 transition-colors"
                >
                  📖 Read the Book: Credential Isolation Closed-Loop Security
                  <span className="text-blue-400/60">→</span>
                </a>
                <ValidationBadge />
                <AuthAwareHomeContent />
              </div>
            </div>
          </div>
        </section>

        {/* Core Capability Cards */}
        <section className="mx-auto max-w-6xl px-6 pb-20 sm:px-8 lg:px-12">
          <div className="mb-10 text-center">
            <h2 className="text-3xl font-bold text-neutral-900 dark:text-white">
              Everything you need to defend your stack
            </h2>
            <p className="mt-3 text-neutral-600 dark:text-neutral-400">
              Six integrated capabilities — activated by a single SDK
              integration.
            </p>
          </div>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {/* SURVEILLANCE */}
            <div className="group relative flex flex-col rounded-2xl border border-blue-200/60 bg-gradient-to-b from-blue-50/80 to-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-blue-500/10 dark:border-blue-800/60 dark:from-blue-900/20 dark:to-neutral-950">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-100 shadow-sm dark:bg-blue-900/50">
                  <svg
                    className="h-5 w-5 text-blue-600 dark:text-blue-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-blue-500 dark:text-blue-400">
                    Core
                  </p>
                  <h2 className="text-lg font-bold text-blue-900 dark:text-blue-100">
                    SURVEILLANCE
                  </h2>
                </div>
              </div>
              <p className="flex-1 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                Deploy the SDK and activate live surveillance across your entire
                stack. Every request — pre-authentication and
                post-authentication — is observed, scored, and acted upon
                automatically.
              </p>
              <ul className="mt-4 space-y-2 text-xs text-neutral-600 dark:text-neutral-400">
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900/50">
                    <svg
                      className="h-3 w-3 text-blue-600 dark:text-blue-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Real-time event collection from apps and APIs
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900/50">
                    <svg
                      className="h-3 w-3 text-blue-600 dark:text-blue-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Pre-auth and post-auth threat detection
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900/50">
                    <svg
                      className="h-3 w-3 text-blue-600 dark:text-blue-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  AbuseIPDB global threat intelligence enrichment
                </li>
              </ul>
              <AuthAwareFeatureLink
                authenticatedHref="/dashboard/surveillance"
                authenticatedLabel="View Live Surveillance →"
                unauthenticatedHref="/features/surveillance"
                unauthenticatedLabel="Learn More →"
                className="mt-5 inline-flex text-sm font-semibold text-blue-700 transition-colors hover:text-blue-800 dark:text-blue-300 dark:hover:text-blue-200"
              />
            </div>

            {/* CREDENTIAL ISOLATION */}
            <div className="group relative flex flex-col rounded-2xl border border-purple-200/60 bg-gradient-to-b from-purple-50/80 to-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-purple-500/10 dark:border-purple-800/60 dark:from-purple-900/20 dark:to-neutral-950">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-100 shadow-sm dark:bg-purple-900/50">
                  <svg
                    className="h-5 w-5 text-purple-600 dark:text-purple-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-purple-500 dark:text-purple-400">
                    Core
                  </p>
                  <h2 className="text-lg font-bold text-purple-900 dark:text-purple-100">
                    CREDENTIAL ISOLATION
                  </h2>
                </div>
              </div>
              <p className="flex-1 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                Your real credentials never leave your infrastructure.
                DevFortress operates on isolated identifiers — your real session
                tokens and API keys never reach our servers. Revocation is
                instant and complete.
              </p>
              <ul className="mt-4 space-y-2 text-xs text-neutral-600 dark:text-neutral-400">
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900/50">
                    <svg
                      className="h-3 w-3 text-purple-600 dark:text-purple-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Real credentials stay inside your application
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900/50">
                    <svg
                      className="h-3 w-3 text-purple-600 dark:text-purple-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Instant revocation across all connected services
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900/50">
                    <svg
                      className="h-3 w-3 text-purple-600 dark:text-purple-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Compliance-ready audit trail with timestamped evidence
                </li>
              </ul>
              <AuthAwareFeatureLink
                authenticatedHref="/dashboard/surveillance"
                authenticatedLabel="Learn About Credential Isolation →"
                unauthenticatedHref="/features/credential-isolation"
                unauthenticatedLabel="Learn More →"
                className="mt-5 inline-flex text-sm font-semibold text-purple-700 transition-colors hover:text-purple-800 dark:text-purple-300 dark:hover:text-purple-200"
              />
            </div>

            {/* SESSION REVOCATION */}
            <div className="group relative flex flex-col rounded-2xl border border-orange-200/60 bg-gradient-to-b from-orange-50/80 to-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-orange-500/10 dark:border-orange-800/60 dark:from-orange-900/20 dark:to-neutral-950">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-orange-100 shadow-sm dark:bg-orange-900/50">
                  <svg
                    className="h-5 w-5 text-orange-600 dark:text-orange-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-orange-500 dark:text-orange-400">
                    Core
                  </p>
                  <h2 className="text-lg font-bold text-orange-900 dark:text-orange-100">
                    SESSION REVOCATION
                  </h2>
                </div>
              </div>
              <p className="flex-1 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                When a threat is detected, DevFortress fires a signed webhook to
                your application. Your application revokes the session. The
                entire loop — detection to verified revocation — closes
                automatically. No alert fatigue. No 2am incidents.
              </p>
              <ul className="mt-4 space-y-2 text-xs text-neutral-600 dark:text-neutral-400">
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-orange-100 dark:bg-orange-900/50">
                    <svg
                      className="h-3 w-3 text-orange-600 dark:text-orange-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Forced logout triggered automatically on threat detection
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-orange-100 dark:bg-orange-900/50">
                    <svg
                      className="h-3 w-3 text-orange-600 dark:text-orange-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Webhook-delivered revocation with HMAC verification
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-orange-100 dark:bg-orange-900/50">
                    <svg
                      className="h-3 w-3 text-orange-600 dark:text-orange-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Every action timestamped and auditable
                </li>
              </ul>
              <AuthAwareFeatureLink
                authenticatedHref="/dashboard/surveillance"
                authenticatedLabel="Manage Sessions →"
                unauthenticatedHref="/features/session-revocation"
                unauthenticatedLabel="Learn More →"
                className="mt-5 inline-flex text-sm font-semibold text-orange-700 transition-colors hover:text-orange-800 dark:text-orange-300 dark:hover:text-orange-200"
              />
            </div>

            {/* IP BLOCKING */}
            <div className="group relative flex flex-col rounded-2xl border border-teal-200/60 bg-gradient-to-b from-teal-50/80 to-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-teal-500/10 dark:border-teal-800/60 dark:from-teal-900/20 dark:to-neutral-950">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-teal-100 shadow-sm dark:bg-teal-900/50">
                  <svg
                    className="h-5 w-5 text-teal-600 dark:text-teal-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-teal-500 dark:text-teal-400">
                    Core
                  </p>
                  <h2 className="text-lg font-bold text-teal-900 dark:text-teal-100">
                    IP BLOCKING
                  </h2>
                </div>
              </div>
              <p className="flex-1 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                Every flagged IP is scored using a composite of global community
                reputation and application-specific behavioral signals. Blocks
                happen automatically at the right threshold. Confirmed attacks
                are reported back, making protection stronger for everyone.
              </p>
              <ul className="mt-4 space-y-2 text-xs text-neutral-600 dark:text-neutral-400">
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-teal-100 dark:bg-teal-900/50">
                    <svg
                      className="h-3 w-3 text-teal-600 dark:text-teal-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Composite scoring: global reputation + live behavioral signals
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-teal-100 dark:bg-teal-900/50">
                    <svg
                      className="h-3 w-3 text-teal-600 dark:text-teal-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Automatic blocking with configurable thresholds
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-teal-100 dark:bg-teal-900/50">
                    <svg
                      className="h-3 w-3 text-teal-600 dark:text-teal-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Community reporting creates a network effect
                </li>
              </ul>
              <AuthAwareFeatureLink
                authenticatedHref="/dashboard/surveillance"
                authenticatedLabel="Manage IP Rules →"
                unauthenticatedHref="/features/ip-blocking"
                unauthenticatedLabel="Learn More →"
                className="mt-5 inline-flex text-sm font-semibold text-teal-700 transition-colors hover:text-teal-800 dark:text-teal-300 dark:hover:text-teal-200"
              />
            </div>

            {/* API KEY & PAYLOAD PROTECTION */}
            <div className="group relative flex flex-col rounded-2xl border border-amber-200/60 bg-gradient-to-b from-amber-50/80 to-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-amber-500/10 dark:border-amber-800/60 dark:from-amber-900/20 dark:to-neutral-950">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-100 shadow-sm dark:bg-amber-900/50">
                  <svg
                    className="h-5 w-5 text-amber-600 dark:text-amber-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-amber-500 dark:text-amber-400">
                    Core
                  </p>
                  <h2 className="text-lg font-bold text-amber-900 dark:text-amber-100">
                    API KEY &amp; PAYLOAD PROTECTION
                  </h2>
                </div>
              </div>
              <p className="flex-1 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                Real API keys never reach third-party services, logs, or
                monitoring tools. Payload integrity is verified on every request
                — inbound and outbound — so tampered or replayed payloads are
                rejected before they reach your application logic.
              </p>
              <ul className="mt-4 space-y-2 text-xs text-neutral-600 dark:text-neutral-400">
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/50">
                    <svg
                      className="h-3 w-3 text-amber-600 dark:text-amber-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Real keys stay inside your infrastructure boundary
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/50">
                    <svg
                      className="h-3 w-3 text-amber-600 dark:text-amber-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Payload integrity verified end-to-end on every request
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/50">
                    <svg
                      className="h-3 w-3 text-amber-600 dark:text-amber-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Inbound response verification — spoofed responses blocked
                </li>
              </ul>
              <Link
                href="/features/api-key-protection"
                className="mt-5 inline-flex text-sm font-semibold text-amber-700 transition-colors hover:text-amber-800 dark:text-amber-300 dark:hover:text-amber-200"
              >
                Learn More →
              </Link>
            </div>

            {/* ACTIONABLE INSIGHTS */}
            <div className="group relative flex flex-col rounded-2xl border border-indigo-200/60 bg-gradient-to-b from-indigo-50/80 to-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-indigo-500/10 dark:border-indigo-800/60 dark:from-indigo-900/20 dark:to-neutral-950">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-100 shadow-sm dark:bg-indigo-900/50">
                  <svg
                    className="h-5 w-5 text-indigo-600 dark:text-indigo-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-indigo-500 dark:text-indigo-400">
                    Core
                  </p>
                  <h2 className="text-lg font-bold text-indigo-900 dark:text-indigo-100">
                    ACTIONABLE INSIGHTS
                  </h2>
                </div>
              </div>
              <p className="flex-1 text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                AI analyzes every threat event across your applications and APIs
                to surface patterns, priorities, and next steps automatically.
                Turn your live surveillance data into a security improvement
                plan.
              </p>
              <ul className="mt-4 space-y-2 text-xs text-neutral-600 dark:text-neutral-400">
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50">
                    <svg
                      className="h-3 w-3 text-indigo-600 dark:text-indigo-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  AI-powered recommendations from your collected events
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50">
                    <svg
                      className="h-3 w-3 text-indigo-600 dark:text-indigo-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Pattern analysis, threat trends, and priority ranking
                </li>
                <li className="flex items-center gap-2">
                  <span className="flex h-4 w-4 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/50">
                    <svg
                      className="h-3 w-3 text-indigo-600 dark:text-indigo-400"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={3}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </span>
                  Exportable reports for compliance and security reviews
                </li>
              </ul>
              <AuthAwareFeatureLink
                authenticatedHref="/dashboard/insights"
                authenticatedLabel="View Insights →"
                unauthenticatedHref="/pricing"
                unauthenticatedLabel="See Plans →"
                className="mt-5 inline-flex text-sm font-semibold text-indigo-700 transition-colors hover:text-indigo-800 dark:text-indigo-300 dark:hover:text-indigo-200"
              />
            </div>
          </div>
        </section>

        {/* Metrics Bar */}
        <section className="border-y border-neutral-200 bg-white py-12 dark:border-neutral-800 dark:bg-neutral-900/50">
          <div className="mx-auto grid max-w-4xl grid-cols-2 gap-8 px-6 text-center sm:px-8 md:grid-cols-4">
            <div>
              <p className="text-3xl font-bold text-neutral-900 dark:text-white">
                &lt;2s
              </p>
              <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                Automated Response Time
              </p>
            </div>
            <div>
              <p className="text-3xl font-bold text-neutral-900 dark:text-white">
                21+
              </p>
              <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                Attack Patterns Detected
              </p>
            </div>
            <div>
              <p className="text-3xl font-bold text-neutral-900 dark:text-white">
                0
              </p>
              <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                Real Credentials Exposed to Platform
              </p>
            </div>
            <div>
              <p className="text-3xl font-bold text-neutral-900 dark:text-white">
                100%
              </p>
              <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                OWASP Top 10 Coverage
              </p>
            </div>
          </div>
        </section>

        {/* How It Works - Step by Step */}
        <section className="mx-auto max-w-6xl px-6 py-20 sm:px-8 lg:px-12">
          <div className="text-center">
            <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Get Started in Three Steps
            </h2>
            <p className="mx-auto mt-4 max-w-2xl text-neutral-600 dark:text-neutral-400">
              Three steps to unified security for your applications and APIs
            </p>
          </div>
          <div className="mt-12 grid gap-8 md:grid-cols-3">
            <div className="relative text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-100 text-2xl font-bold text-blue-600 dark:bg-blue-900/30 dark:text-blue-400">
                1
              </div>
              <h3 className="mt-4 text-lg font-semibold">Install the SDK</h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                Add the DevFortress SDK to your application or API. One import.
                Your API key from the dashboard. Done.
              </p>
              {/* Connector line - hidden on mobile */}
              <div className="absolute right-0 top-7 hidden h-0.5 w-[calc(50%-2rem)] bg-gradient-to-r from-blue-200 to-transparent dark:from-blue-800 md:block" />
            </div>
            <div className="relative text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-green-100 text-2xl font-bold text-green-600 dark:bg-green-900/30 dark:text-green-400">
                2
              </div>
              <h3 className="mt-4 text-lg font-semibold">
                Collect &amp; Detect
              </h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                The SDK observes every request in real time — authentication
                failures, injection attempts, rate limit breaches, scope
                violations, and anomalous behavior — and reports them
                automatically.
              </p>
              <div className="absolute left-0 top-7 hidden h-0.5 w-[calc(50%-2rem)] bg-gradient-to-l from-green-200 to-transparent dark:from-green-800 md:block" />
              <div className="absolute right-0 top-7 hidden h-0.5 w-[calc(50%-2rem)] bg-gradient-to-r from-green-200 to-transparent dark:from-green-800 md:block" />
            </div>
            <div className="relative text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-purple-100 text-2xl font-bold text-purple-600 dark:bg-purple-900/30 dark:text-purple-400">
                3
              </div>
              <h3 className="mt-4 text-lg font-semibold">
                Block &amp; Respond
              </h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                Malicious IPs are blocked. Compromised sessions are revoked.
                Credentials are isolated. Webhook callbacks confirm every
                action. A full audit trail is created — all without a human in
                the loop.
              </p>
              <div className="absolute left-0 top-7 hidden h-0.5 w-[calc(50%-2rem)] bg-gradient-to-l from-purple-200 to-transparent dark:from-purple-800 md:block" />
            </div>
          </div>
        </section>

        {/* Why DevFortress */}
        <section className="mx-auto max-w-6xl px-6 py-20 sm:px-8 lg:px-12">
          <div className="text-center">
            <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Why DevFortress
            </h2>
            <p className="mx-auto mt-4 max-w-2xl text-neutral-600 dark:text-neutral-400">
              Enterprise-grade security for applications, APIs and AI agents
            </p>
          </div>
          <div className="mt-12 grid gap-8 sm:grid-cols-2">
            {/* One SDK — Three Environments */}
            <div className="flex flex-col items-center rounded-xl border border-neutral-200 bg-white p-6 text-center shadow-sm dark:border-neutral-800 dark:bg-neutral-900/50">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900/30">
                <svg
                  className="h-6 w-6 text-blue-600 dark:text-blue-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M13 10V3L4 14h7v7l9-11h-7z"
                  />
                </svg>
              </div>
              <h3 className="mt-4 font-semibold">
                One SDK — Three Environments
              </h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                The same SDK protects traditional applications, REST and GraphQL
                APIs, and AI agents (LangChain, OpenAI, MCP). One integration,
                full coverage across all three environments.
              </p>
            </div>

            {/* Closed-Loop by Design */}
            <div className="flex flex-col items-center rounded-xl border border-neutral-200 bg-white p-6 text-center shadow-sm dark:border-neutral-800 dark:bg-neutral-900/50">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/30">
                <svg
                  className="h-6 w-6 text-green-600 dark:text-green-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
              </div>
              <h3 className="mt-4 font-semibold">
                Unified Application Security
              </h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                Most security tools detect and alert. DevFortress detects,
                responds, and confirms. Every threat has a documented outcome —
                remediated, blocked, or escalated — with the timestamp to prove
                it.
              </p>
            </div>

            {/* Global Threat Intelligence */}
            <div className="flex flex-col items-center rounded-xl border border-neutral-200 bg-white p-6 text-center shadow-sm dark:border-neutral-800 dark:bg-neutral-900/50">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-orange-100 dark:bg-orange-900/30">
                <svg
                  className="h-6 w-6 text-orange-600 dark:text-orange-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </div>
              <h3 className="mt-4 font-semibold">Global Threat Intelligence</h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                AbuseIPDB integration enriches every event with community threat
                data from hundreds of thousands of contributors.
                Application-specific signals are combined with global reputation
                for accurate, low-noise scoring.
              </p>
            </div>

            {/* Built for Compliance */}
            <div className="flex flex-col items-center rounded-xl border border-neutral-200 bg-white p-6 text-center shadow-sm dark:border-neutral-800 dark:bg-neutral-900/50">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-teal-100 dark:bg-teal-900/30">
                <svg
                  className="h-6 w-6 text-teal-600 dark:text-teal-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"
                  />
                </svg>
              </div>
              <h3 className="mt-4 font-semibold">Built for Compliance</h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                Every security decision — detection, action, confirmation — is
                logged with a timestamp and audit identifier. Export evidence
                for PCI-DSS, SOC 2, GDPR, and HIPAA requirements directly from
                the dashboard.
              </p>
            </div>

            {/* Deploy in Minutes */}
            <div className="flex flex-col items-center rounded-xl border border-neutral-200 bg-white p-6 text-center shadow-sm dark:border-neutral-800 dark:bg-neutral-900/50">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/30">
                <svg
                  className="h-6 w-6 text-indigo-600 dark:text-indigo-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
                  />
                </svg>
              </div>
              <h3 className="mt-4 font-semibold">Deploy in Minutes</h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                The SDK installs with one command. No infrastructure changes. No
                gateway configuration. No agent to manage. Security runs inside
                your existing application.
              </p>
            </div>

            <div className="flex flex-col items-center rounded-xl border border-neutral-200 bg-white p-6 text-center shadow-sm dark:border-neutral-800 dark:bg-neutral-900/50">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30">
                <svg
                  className="h-6 w-6 text-red-600 dark:text-red-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"
                  />
                </svg>
              </div>
              <h3 className="mt-4 font-semibold">
                Credential Isolation for AI Agents
              </h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                Protect autonomous AI agents from credential theft and prompt
                injection. Replace raw keys with stateful aliases and enforce
                strict operational scope limits in real-time.
              </p>
            </div>

            {/* API Key & Payload Protection */}
            <div className="flex flex-col items-center rounded-xl border border-neutral-200 bg-white p-6 text-center shadow-sm dark:border-neutral-800 dark:bg-neutral-900/50">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/30">
                <svg
                  className="h-6 w-6 text-amber-600 dark:text-amber-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                  />
                </svg>
              </div>
              <h3 className="mt-4 font-semibold">
                API Key &amp; Payload Protection
              </h3>
              <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                Real API keys never reach third-party services, logs, or
                monitoring tools. Payload integrity is verified on every
                request. Teams+ only. Patent Pending.
              </p>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="border-t border-neutral-200 bg-gradient-to-b from-neutral-50 to-white py-20 dark:border-neutral-800 dark:from-neutral-900/50 dark:to-neutral-950">
          <div className="mx-auto max-w-3xl px-6 text-center sm:px-8">
            <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Ready to Secure Your Applications, APIs and AI Agents?
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-lg text-neutral-600 dark:text-neutral-400">
              DevFortress gives you real-time threat detection across
              applications, APIs, and AI agents — automated response and a full
              audit trail, starting with a single SDK integration.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
              <AuthAwareGetStartedButton />
              <Link
                href="/pricing"
                className="rounded-xl border border-neutral-300 bg-white px-8 py-3 font-semibold text-neutral-900 shadow-sm transition-colors hover:bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-900 dark:text-white dark:hover:bg-neutral-800"
              >
                View Pricing
              </Link>
              <Link
                href="/help"
                className="rounded-xl border border-neutral-300 bg-white px-8 py-3 font-semibold text-neutral-900 shadow-sm transition-colors hover:bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-900 dark:text-white dark:hover:bg-neutral-800"
              >
                Read the Docs
              </Link>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}
