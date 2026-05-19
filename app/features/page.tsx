import Link from 'next/link';
import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Features - DevFortress',
  description:
    'Explore DevFortress features: Build production-ready APIs, Defend with threat intelligence, and Learn from continuous security insights.',
  keywords: [
    'API features',
    'API security',
    'API generation',
    'threat intelligence',
    'honeypots',
  ],
  openGraph: {
    title: 'Features - DevFortress',
    description:
      'Build, secure, and learn from your APIs with AI-powered generation and threat intelligence.',
    type: 'website',
  },
};

// This page requires session authentication which uses headers()
export const dynamic = 'force-dynamic';

export default function FeaturesPage() {
  return (
    <main className="flex min-h-screen flex-col bg-neutral-50 px-6 py-12 font-sans text-neutral-900 transition-colors duration-200 dark:bg-neutral-950 dark:text-neutral-100">
      <div className="mx-auto w-full max-w-6xl">
        <div className="mb-12 text-center">
          <h1 className="mb-4 text-5xl font-bold leading-tight">
            DevFortress Features
          </h1>
          <p className="mt-4 text-xl text-neutral-600 dark:text-neutral-400">
            Complete API security lifecycle: Build, Defend, Collect, and Learn
          </p>
        </div>

        {/* Core Phases */}
        <div className="mb-16 grid gap-8 md:grid-cols-2 lg:grid-cols-4">
          {/* Build Phase */}
          <Link
            href="/features/build"
            className="group rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm transition-all hover:shadow-lg dark:border-neutral-800 dark:bg-neutral-900"
          >
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900">
              <svg
                className="h-6 w-6 text-blue-600 dark:text-blue-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"
                />
              </svg>
            </div>
            <h2 className="text-xl font-semibold group-hover:text-blue-600 dark:group-hover:text-blue-400">
              BUILD
            </h2>
            <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
              AI-powered API generation from natural language
            </p>
          </Link>

          {/* Defend Phase */}
          <Link
            href="/features/defend"
            className="group rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm transition-all hover:shadow-lg dark:border-neutral-800 dark:bg-neutral-900"
          >
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-green-100 dark:bg-green-900">
              <svg
                className="h-6 w-6 text-green-600 dark:text-green-400"
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
            <h2 className="text-xl font-semibold group-hover:text-green-600 dark:group-hover:text-green-400">
              DEFEND
            </h2>
            <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
              Deploy honeypots and monitor for threats
            </p>
          </Link>

          {/* Collect Phase */}
          <Link
            href="/features/collect"
            className="group rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm transition-all hover:shadow-lg dark:border-neutral-800 dark:bg-neutral-900"
          >
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-orange-100 dark:bg-orange-900">
              <svg
                className="h-6 w-6 text-orange-600 dark:text-orange-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"
                />
              </svg>
            </div>
            <h2 className="text-xl font-semibold group-hover:text-orange-600 dark:group-hover:text-orange-400">
              COLLECT
            </h2>
            <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
              Aggregate threat intelligence data
            </p>
          </Link>

          {/* Learn Phase */}
          <Link
            href="/features/learn"
            className="group rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm transition-all hover:shadow-lg dark:border-neutral-800 dark:bg-neutral-900"
          >
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-purple-100 dark:bg-purple-900">
              <svg
                className="h-6 w-6 text-purple-600 dark:text-purple-400"
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
            <h2 className="text-xl font-semibold group-hover:text-purple-600 dark:group-hover:text-purple-400">
              LEARN
            </h2>
            <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
              AI-powered insights and predictive analytics
            </p>
          </Link>
        </div>

        {/* Advanced Features */}
        <div className="mb-16">
          <h2 className="mb-6 text-3xl font-bold">Advanced Features</h2>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {/* Anomaly Detection */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">Anomaly Detection</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                ML-powered anomaly detection with isolation forest algorithm for
                real-time threat identification
              </p>
            </div>

            {/* API Monitoring */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">API Monitoring</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Multi-region uptime tracking with performance metrics (p50, p95,
                p99) and incident management
              </p>
            </div>

            {/* Team Collaboration */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">Team Collaboration</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Role-based access control with team workspaces, permissions, and
                activity audit trails
              </p>
            </div>

            {/* Honeypot Premium Services */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">
                HPS (Honeypot Premium)
              </h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Advanced honeypot features with quota tracking, webhook
                integration, and cost estimation
              </p>
            </div>

            {/* Incident Management */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">
                Incident Management
              </h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Complete incident workflow with severity levels, SLA tracking,
                and resolution management
              </p>
            </div>

            {/* Real-Time Alerts */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">Real-Time Alerts</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Server-Sent Events (SSE) streaming with multi-channel
                notifications and intelligent grouping
              </p>
            </div>

            {/* Security Scanning */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">Security Scanning</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Automated OWASP Top 10 vulnerability detection with AST-based
                code analysis
              </p>
            </div>

            {/* Patch Mode */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">Patch Mode</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                AI-powered security patch generation for existing codebases with
                non-breaking changes
              </p>
            </div>

            {/* SDK Integration */}
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-2 text-lg font-semibold">SDK Integration</h3>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Live API surveillance SDK for monitoring production APIs with
                automatic threat detection
              </p>
            </div>
          </div>
        </div>

        {/* Supported Frameworks */}
        <div className="mb-16">
          <h2 className="mb-6 text-3xl font-bold">Supported Frameworks</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <div className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
              <span className="text-2xl">✅</span>
              <div>
                <p className="font-semibold">Node.js/Express</p>
                <p className="text-xs text-neutral-600 dark:text-neutral-400">
                  TypeScript, Zod, Prisma, Jest
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
              <span className="text-2xl">✅</span>
              <div>
                <p className="font-semibold">Python/FastAPI</p>
                <p className="text-xs text-neutral-600 dark:text-neutral-400">
                  Pydantic, SQLAlchemy, pytest
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
              <span className="text-2xl">✅</span>
              <div>
                <p className="font-semibold">Go/Gin</p>
                <p className="text-xs text-neutral-600 dark:text-neutral-400">
                  Go modules, GORM, testify
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
              <span className="text-2xl">✅</span>
              <div>
                <p className="font-semibold">Java/Spring Boot</p>
                <p className="text-xs text-neutral-600 dark:text-neutral-400">
                  Available
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
              <span className="text-2xl">✅</span>
              <div>
                <p className="font-semibold">Ruby/Rails</p>
                <p className="text-xs text-neutral-600 dark:text-neutral-400">
                  Available
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
              <span className="text-2xl">✅</span>
              <div>
                <p className="font-semibold">C#/ASP.NET Core</p>
                <p className="text-xs text-neutral-600 dark:text-neutral-400">
                  Available
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Key Benefits */}
        <div className="mb-16">
          <h2 className="mb-6 text-3xl font-bold">Why DevFortress?</h2>
          <div className="grid gap-6 md:grid-cols-2">
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-3 text-xl font-semibold">
                🚀 Fast Development
              </h3>
              <p className="text-neutral-600 dark:text-neutral-400">
                Generate production-ready APIs in 30-60 seconds with
                comprehensive tests, security scanning, and documentation
                included
              </p>
            </div>
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-3 text-xl font-semibold">🔒 Security First</h3>
              <p className="text-neutral-600 dark:text-neutral-400">
                Every generated API includes JWT authentication, input
                validation, rate limiting, CORS configuration, and OWASP Top 10
                coverage
              </p>
            </div>
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-3 text-xl font-semibold">
                🧠 Continuous Learning
              </h3>
              <p className="text-neutral-600 dark:text-neutral-400">
                AI-powered threat intelligence aggregation feeds insights back
                into API generation for constantly improving security
              </p>
            </div>
            <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-3 text-xl font-semibold">👥 Team Ready</h3>
              <p className="text-neutral-600 dark:text-neutral-400">
                Built-in team collaboration with role-based permissions,
                activity audits, and multi-workspace support
              </p>
            </div>
          </div>
        </div>

        {/* Call to Action */}
        <div className="rounded-2xl border border-neutral-200 bg-gradient-to-br from-primary-50 to-primary-100 p-8 text-center dark:border-neutral-800 dark:from-primary-950 dark:to-primary-900">
          <h2 className="text-3xl font-bold">Ready to Get Started?</h2>
          <p className="mt-3 text-lg text-neutral-600 dark:text-neutral-400">
            Sign up today and build your first secure API in minutes
          </p>
          <div className="mt-6 flex justify-center gap-4">
            <Link
              href="/auth/signin"
              className="inline-flex items-center rounded-lg bg-primary-600 px-8 py-3 text-sm font-semibold text-white hover:bg-primary-700"
            >
              Sign Up Free →
            </Link>
            <Link
              href="/pricing"
              className="inline-flex items-center rounded-lg border border-primary-600 px-8 py-3 text-sm font-semibold text-primary-600 hover:bg-primary-50 dark:border-primary-400 dark:text-primary-400 dark:hover:bg-primary-950"
            >
              View Pricing
            </Link>
          </div>
        </div>
      </div>
    </main>
  );
}
