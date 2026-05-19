import { redirect } from 'next/navigation';
import { getServerSession } from '@core/lib/auth/session';
import { getUserTier, hasFeatureAccess } from '@core/lib/auth/premium-features';
import Link from 'next/link';
import { PhaseTabs } from '@core/components/phase/PhaseTabs';

/**
 * COLLECT Phase Overview
 * Core Service: Threat Data Aggregation from Honeypots
 * Premium: Surveillance, Extended Retention, Data Export
 */
export const dynamic = 'force-dynamic';

export default async function CollectPage() {
  const session = await getServerSession();

  if (!session?.user?.id) {
    redirect('/auth/signin?next=/collect');
  }

  // Get user tier and feature access - only checking implemented features
  const userTier = await getUserTier(session);
  const hasApiMonitoring = await hasFeatureAccess(
    session,
    'defend.liveMonitoring'
  );

  return (
    <main className="flex min-h-screen flex-col bg-neutral-50 px-4 py-8 sm:px-6 sm:py-12 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
      <div className="mx-auto w-full max-w-7xl space-y-12">
        {/* Header */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-sm text-neutral-500">
              <Link href="/dashboard" className="hover:text-primary-600">
                Dashboard
              </Link>
              <span>/</span>
              <span className="text-neutral-900 dark:text-white">
                COLLECT Phase
              </span>
            </div>
            <h1 className="mt-4 text-2xl sm:text-4xl font-bold text-neutral-900 dark:text-white">
              📥 COLLECT Phase
            </h1>
            <p className="mt-2 text-lg text-neutral-600 dark:text-neutral-400">
              Aggregate threat intelligence from honeypots and production APIs
            </p>
          </div>
          <div className="text-sm">
            <span className="text-neutral-600 dark:text-neutral-400">
              Current Tier:
            </span>{' '}
            <span className="font-semibold text-primary-600 dark:text-primary-400">
              {userTier}
            </span>
          </div>
        </div>

        {/* Phase Navigation */}
        <PhaseTabs
          theme="amber"
          coreTitle="Threat Data Aggregation"
          premiumTitle="Live API Surveillance"
          coreContent={
            <Link
              href="/dashboard/threats"
              className="group block rounded-xl border-2 border-green-200 bg-gradient-to-br from-green-50 to-emerald-50 p-8 shadow-xl transition-all hover:shadow-2xl dark:border-green-800 dark:from-green-950/20 dark:to-emerald-950/20"
            >
              <div className="flex items-start gap-4">
                <div className="flex h-16 w-16 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/50">
                  <span className="text-3xl">📊</span>
                </div>
                <div className="flex-1">
                  <h3 className="text-xl font-bold text-neutral-900 dark:text-white">
                    Threat Data Dashboard
                  </h3>
                  <p className="mt-2 text-neutral-600 dark:text-neutral-400">
                    View all collected threat events from your honeypots with
                    real-time updates via webhooks
                  </p>
                  <div className="mt-4 grid grid-cols-1 gap-2 text-sm text-neutral-600 dark:text-neutral-400 md:grid-cols-2">
                    <div className="flex items-center gap-2">
                      <svg
                        className="h-5 w-5 text-green-600"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                      Webhook-based collection
                    </div>
                    <div className="flex items-center gap-2">
                      <svg
                        className="h-5 w-5 text-green-600"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                      OWASP Top 10 categorization
                    </div>
                    <div className="flex items-center gap-2">
                      <svg
                        className="h-5 w-5 text-green-600"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                      IP reputation tracking
                    </div>
                    <div className="flex items-center gap-2">
                      <svg
                        className="h-5 w-5 text-green-600"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                      7-day retention (FREE)
                    </div>
                  </div>
                  <div className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-primary-600 group-hover:text-primary-700 dark:text-primary-400">
                    Access Dashboard
                    <svg
                      className="h-4 w-4"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M9 5l7 7-7 7"
                      />
                    </svg>
                  </div>
                </div>
              </div>
            </Link>
          }
          premiumContent={
            hasApiMonitoring ? (
              <Link
                href="/dashboard/collect/surveillance"
                className="group block rounded-xl border-2 border-green-200 bg-gradient-to-br from-green-50 to-emerald-50 p-8 shadow-xl transition-all hover:shadow-2xl dark:border-green-800 dark:from-green-950/20 dark:to-emerald-950/20"
              >
                <div className="flex items-start gap-4">
                  <div className="flex h-16 w-16 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/50">
                    <span className="text-3xl">📡</span>
                  </div>
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-neutral-900 dark:text-white">
                      Production API Monitoring
                    </h3>
                    <p className="mt-2 text-neutral-600 dark:text-neutral-400">
                      Monitor production APIs with SDK integration for real-time
                      threat collection and analysis
                    </p>
                    <div className="mt-4 grid grid-cols-1 gap-2 text-sm text-neutral-600 dark:text-neutral-400 md:grid-cols-2">
                      <div className="flex items-center gap-2">
                        <svg
                          className="h-5 w-5 text-green-600"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        @apiforge/sdk integration
                      </div>
                      <div className="flex items-center gap-2">
                        <svg
                          className="h-5 w-5 text-green-600"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        Real-time event ingestion
                      </div>
                      <div className="flex items-center gap-2">
                        <svg
                          className="h-5 w-5 text-green-600"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        Tier-based data retention
                      </div>
                      <div className="flex items-center gap-2">
                        <svg
                          className="h-5 w-5 text-green-600"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        Production threat analytics
                      </div>
                    </div>
                    <div className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-primary-600 group-hover:text-primary-700 dark:text-primary-400">
                      Get Started →
                    </div>
                  </div>
                </div>
              </Link>
            ) : (
              <div className="group block rounded-xl border-2 border-amber-200 bg-gradient-to-br from-amber-50 to-orange-50 p-8 shadow-xl dark:border-amber-800 dark:from-amber-950/20 dark:to-orange-950/20 opacity-75 cursor-not-allowed">
                <div className="flex items-start gap-4">
                  <div className="flex h-16 w-16 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/50">
                    <span className="text-3xl">🔒</span>
                  </div>
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-neutral-900 dark:text-white">
                      Production API Monitoring
                    </h3>
                    <p className="mt-2 text-neutral-600 dark:text-neutral-400">
                      Monitor production APIs with SDK integration for real-time
                      threat collection and analysis
                    </p>
                    <div className="mt-4 grid grid-cols-1 gap-2 text-sm text-neutral-600 dark:text-neutral-400 md:grid-cols-2">
                      <div className="flex items-center gap-2">
                        <svg
                          className="h-5 w-5 text-amber-600"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        @apiforge/sdk integration
                      </div>
                      <div className="flex items-center gap-2">
                        <svg
                          className="h-5 w-5 text-amber-600"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        Real-time event ingestion
                      </div>
                      <div className="flex items-center gap-2">
                        <svg
                          className="h-5 w-5 text-amber-600"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        Tier-based data retention
                      </div>
                      <div className="flex items-center gap-2">
                        <svg
                          className="h-5 w-5 text-amber-600"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        Production threat analytics
                      </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 rounded-lg bg-amber-100 px-4 py-2 dark:bg-amber-900/30">
                      <svg
                        className="h-5 w-5 text-amber-600"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                        />
                      </svg>
                      <span className="text-sm font-semibold text-amber-800 dark:text-amber-400">
                        Upgrade to PRO to unlock
                      </span>
                    </div>
                    <div className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-amber-600 dark:text-amber-400 opacity-50">
                      Upgrade to Unlock
                    </div>
                  </div>
                </div>
              </div>
            )
          }
        />
      </div>
    </main>
  );
}
