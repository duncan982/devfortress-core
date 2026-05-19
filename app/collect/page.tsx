import { redirect } from 'next/navigation';
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
import Link from 'next/link';

export const dynamic = 'force-dynamic';

export default async function CollectPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll() {
          /* read-only in server component */
        },
      },
    }
  );
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user?.id) {
    redirect('/auth/signin?next=/collect');
  }

  return (
    <main className="flex min-h-screen flex-col bg-neutral-50 px-4 py-8 sm:px-6 sm:py-12 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
      <div className="mx-auto w-full max-w-7xl space-y-8">
        {/* Header */}
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
            COLLECT Phase
          </h1>
          <p className="mt-2 text-lg text-neutral-600 dark:text-neutral-400">
            Aggregate threat intelligence from production APIs
          </p>
        </div>

        <div className="grid gap-6 sm:grid-cols-2">
          {/* Threat Data Dashboard */}
          <Link
            href="/dashboard/threats"
            className="group block rounded-xl border-2 border-green-200 bg-gradient-to-br from-green-50 to-emerald-50 p-8 shadow-sm transition-all hover:shadow-xl dark:border-green-800 dark:from-green-950/20 dark:to-emerald-950/20"
          >
            <div className="flex items-start gap-4">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/50">
                <span className="text-3xl">📊</span>
              </div>
              <div className="flex-1">
                <h3 className="text-xl font-bold text-neutral-900 dark:text-white">
                  Threat Data Dashboard
                </h3>
                <p className="mt-2 text-neutral-600 dark:text-neutral-400">
                  View all collected threat events with real-time updates
                </p>
                <ul className="mt-4 space-y-1 text-sm text-neutral-600 dark:text-neutral-400">
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Webhook-based collection
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    OWASP Top 10 categorization
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    IP reputation tracking
                  </li>
                </ul>
                <div className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-primary-600 group-hover:text-primary-700 dark:text-primary-400">
                  Access Dashboard →
                </div>
              </div>
            </div>
          </Link>

          {/* Production API Monitoring */}
          <Link
            href="/dashboard/collect/surveillance"
            className="group block rounded-xl border-2 border-green-200 bg-gradient-to-br from-green-50 to-emerald-50 p-8 shadow-sm transition-all hover:shadow-xl dark:border-green-800 dark:from-green-950/20 dark:to-emerald-950/20"
          >
            <div className="flex items-start gap-4">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/50">
                <span className="text-3xl">📡</span>
              </div>
              <div className="flex-1">
                <h3 className="text-xl font-bold text-neutral-900 dark:text-white">
                  Production API Monitoring
                </h3>
                <p className="mt-2 text-neutral-600 dark:text-neutral-400">
                  Monitor production APIs with SDK integration for real-time
                  threat collection
                </p>
                <ul className="mt-4 space-y-1 text-sm text-neutral-600 dark:text-neutral-400">
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    devfortress-sdk integration
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Real-time event ingestion
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Production threat analytics
                  </li>
                </ul>
                <div className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-primary-600 group-hover:text-primary-700 dark:text-primary-400">
                  Get Started →
                </div>
              </div>
            </div>
          </Link>
        </div>

        {/* SDK Setup link */}
        <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Need SDK credentials?{' '}
            <Link
              href="/dashboard/credentials"
              className="font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400"
            >
              Manage SDK credentials →
            </Link>
          </p>
        </div>
      </div>
    </main>
  );
}
