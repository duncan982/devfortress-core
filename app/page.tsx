// Open-core home page — @core/* imports replaced with inline equivalents
import Link from 'next/link';
import { Metadata } from 'next';
import { readFileSync } from 'fs';
import { join } from 'path';

// ── Inline structured data (replaces @core/lib/seo/structured-data) ──────────

function renderJsonLd(data: unknown) {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}

const organizationSchema = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'DevFortress',
  url: 'https://devfortress.net',
  logo: 'https://devfortress.net/logo.png',
  description:
    'Application and API security platform with AI-powered threat detection and automated response.',
};

const webApplicationSchema = {
  '@context': 'https://schema.org',
  '@type': 'WebApplication',
  name: 'DevFortress Platform',
  url: 'https://devfortress.net',
  description:
    'Real-time threat detection across applications, APIs, and AI agents — automated response and full audit trail.',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Web Browser',
  offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
};

// ── Inline auth-aware components (replaces @core/components/home/auth-aware-content) ─

function AuthAwareHomeContent() {
  return (
    <div className="mt-4 flex flex-wrap gap-4 justify-center">
      <Link
        href="/dashboard"
        className="inline-flex items-center rounded-lg bg-primary-600 px-6 py-3 text-sm font-semibold text-white hover:bg-primary-700"
      >
        Go to Dashboard →
      </Link>
    </div>
  );
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
      href="/auth/signin"
      className="rounded-lg bg-primary-600 px-6 py-3 font-semibold text-white hover:bg-primary-700"
    >
      Get Started
    </Link>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

/** Read SDK version from the devfortress-sdk package.json at build time. */
function getSdkVersion(): string {
  try {
    const pkgPath = join(
      process.cwd(),
      'packages',
      'devfortress-sdk',
      'package.json'
    );
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    return pkg.version || '4.0.0';
  } catch {
    return '4.0.0';
  }
}

/** Page metadata for the home page, including SEO and Open Graph data. */
export const metadata: Metadata = {
  title: 'DevFortress - Application and API Security Platform',
  description:
    'Application and API security platform that protects APIs, applications, and AI agents — stops attacks automatically before login and inside sessions, with zero human lag.',
  keywords: [
    'API security',
    'automated threat response',
    'credential isolation',
    'unified application security',
    'OWASP compliance',
    'pre-auth attack detection',
    'session revocation',
  ],
  openGraph: {
    title: 'DevFortress - Application and API Security Platform',
    description:
      'Stop attacks across applications and APIs automatically. Unified detection, response, and confirmation with a full audit trail.',
    type: 'website',
  },
};

/** Dynamic rendering configuration to force dynamic rendering for session handling. */
export const dynamic = 'force-dynamic';

/** Home page component for the DevFortress platform. @returns {JSX.Element} The home page JSX. */
export default async function Home() {
  const sdkVersion = getSdkVersion();
  return (
    <>
      {renderJsonLd(organizationSchema)}
      {renderJsonLd(webApplicationSchema)}
      <main className="bg-neutral-50 font-sans text-neutral-900 transition-colors duration-200 dark:bg-neutral-950 dark:text-neutral-100">
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
                Unified Application Security — SDK v{sdkVersion} · Patent
                Pending
              </div>
              <h1 className="max-w-4xl text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">
                Application, API and AI Agent Security —{' '}
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-green-600 bg-clip-text text-transparent dark:from-blue-400 dark:via-purple-400 dark:to-green-400">
                  Automated.
                </span>
              </h1>
              <p className="mt-6 max-w-2xl text-lg text-neutral-600 dark:text-neutral-400 sm:text-xl">
                Stop attacks before login and inside sessions. DevFortress
                detects threats across applications, APIs, and AI agents in real
                time and responds automatically — session revocation, IP
                blocking, and credential isolation — in under 2 seconds. No
                human intervention required.
              </p>
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
                <AuthAwareHomeContent />
              </div>
            </div>
          </div>
        </section>

        {/* Core Capabilities Visual */}
        <section className="mx-auto max-w-6xl px-6 pb-8 sm:px-8 lg:px-12">
          <div className="mb-10 text-center">
            <p className="text-sm font-semibold uppercase tracking-widest text-neutral-400 dark:text-neutral-500">
              Four Core Capabilities
            </p>
            <div className="mx-auto mt-4 flex max-w-3xl items-center justify-center gap-2 text-sm text-neutral-500 sm:gap-4 sm:text-base">
              <span className="font-bold text-blue-600 dark:text-blue-400">
                SURVEILLANCE
              </span>
              <svg
                className="h-4 w-4 text-neutral-300 dark:text-neutral-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5l7 7-7 7"
                />
              </svg>
              <span className="font-bold text-purple-600 dark:text-purple-400">
                CREDENTIAL ISOLATION
              </span>
              <svg
                className="h-4 w-4 text-neutral-300 dark:text-neutral-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5l7 7-7 7"
                />
              </svg>
              <span className="font-bold text-orange-600 dark:text-orange-400">
                SESSION REVOCATION
              </span>
              <svg
                className="h-4 w-4 text-neutral-300 dark:text-neutral-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5l7 7-7 7"
                />
              </svg>
              <span className="font-bold text-teal-600 dark:text-teal-400">
                IP BLOCKING
              </span>
            </div>
          </div>
        </section>

        {/* Core Capability Cards */}
        <section className="mx-auto max-w-6xl px-6 pb-20 sm:px-8 lg:px-12">
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
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
                  Global threat intelligence enrichment
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

        {/* How It Works */}
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
      </main>
    </>
  );
}
