import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Dashboard — DevFortress',
  description:
    'SDK-first API & Agent security: collect events, detect threats, revoke sessions, block IPs — all in real time.',
};

export const dynamic = 'force-dynamic';

export default async function DashboardPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect('/auth/signin?next=/dashboard');
  }

  const userTier = 'STARTER' as const;
  const userName =
    (user.user_metadata?.full_name as string | undefined) ??
    (user.user_metadata?.name as string | undefined) ??
    user.email ??
    'User';

  return (
    <main className="bg-neutral-50 px-4 py-6 font-sans text-neutral-900 transition-colors duration-200 sm:px-6 sm:py-12 dark:bg-neutral-950 dark:text-neutral-100">
      <section className="mx-auto w-full max-w-7xl rounded-2xl border border-neutral-200 bg-white px-4 py-6 shadow-xl sm:rounded-3xl sm:px-10 sm:py-14 dark:border-neutral-800 dark:bg-neutral-950">
        <div className="flex flex-col gap-8">

          {/* Header */}
          <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
            <div className="space-y-4">
              <p className="text-sm uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                DevFortress Dashboard
              </p>
              <h1 className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl lg:text-4xl">
                Welcome back, {userName}
              </h1>
              <p className="mt-4 max-w-2xl text-base text-neutral-600 dark:text-neutral-400">
                SDK-first security for Applications, APIs and AI Agents —
                real-time threat collection, automated session revocation, IP
                blocking, and unified application protection. Credential
                isolation ensures your real credentials are never exposed.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Link
                href="/help"
                className="inline-flex items-center justify-center rounded-xl border border-neutral-200 px-4 py-2 text-sm font-semibold text-neutral-700 transition-colors hover:border-primary-200 hover:text-primary-600 dark:border-neutral-700 dark:text-neutral-200 dark:hover:border-primary-500 dark:hover:text-primary-300"
              >
                Need Help?
              </Link>
              <Link
                href="/"
                className="inline-flex items-center justify-center rounded-xl bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700"
              >
                Home
              </Link>
            </div>
          </div>

          {/* Collect Phase */}
          <div className="space-y-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-xl font-semibold text-neutral-900 sm:text-2xl dark:text-white">
                  Collect — Live Threat Intelligence, generate insights and get
                  automated security actions
                </h2>
                <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
                  Real-time events from your SDK-integrated applications.
                  Automated threat detection and response.
                </p>
              </div>
              <span className="rounded-full bg-green-100 px-3 py-1 text-xs font-semibold text-green-800 dark:bg-green-900/40 dark:text-green-300">
                Tier: {userTier}
              </span>
            </div>

            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
              <ActionCard
                icon="⚡"
                title="Quick Setup"
                description="Create projects, generate API keys, configure the SDK, and start collecting events in under 60 seconds."
                href="/dashboard/credentials"
                cta="Generate Credentials →"
                accent="amber"
              />
              <ActionCard
                icon="📡"
                title="Live Surveillance"
                description="View real-time events from your SDK — Auth Phase, Method, Path, IP, Severity, Action Taken, Latency, CL Mode."
                href="/dashboard/collect/surveillance"
                cta="Open Surveillance →"
                accent="purple"
              />
              <ActionCard
                icon="📊"
                title="Insights"
                description="AI-powered recommendations from your collected events — pattern analysis, threat trends, and actionable next steps."
                href="/dashboard/insights"
                cta="View Insights →"
                accent="purple"
              />
            </div>

            <div className="rounded-2xl border border-neutral-200 bg-gradient-to-br from-neutral-50 to-neutral-100 p-6 dark:border-neutral-700 dark:from-neutral-900 dark:to-neutral-800">
              <h3 className="mb-4 text-lg font-semibold text-neutral-900 dark:text-white">
                What DevFortress Protects
              </h3>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
                <CapabilityBadge emoji="🛡️" title="Session Revocation"
                  detail="Automatically revoke compromised sessions on threat detection" />
                <CapabilityBadge emoji="🚫" title="IP Blocking"
                  detail="Block malicious IPs in real time with composite scoring" />
                <CapabilityBadge emoji="🔐" title="Credential Isolation"
                  detail="Your real tokens are never stored or transmitted" />
                <CapabilityBadge emoji="🤖" title="AI Agent Security"
                  detail="Detect prompt injection, token replay, and malicious agent behavior" />
              </div>
            </div>

            <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
              <ModeCard
                mode="Applications and APIs"
                emoji="🌐"
                features={[
                  'Pre-auth: brute force, credential stuffing, recon scan',
                  'Post-auth: token replay, privilege escalation, anomalous volume',
                  'Session revocation & forced logout on abuse',
                  'IP blocking with AbuseIPDB scoring',
                  'Closed-loop: external, internal, or hybrid',
                ]}
                color="indigo"
              />
              <ModeCard
                mode="AI Agent / Agentic"
                emoji="🤖"
                features={[
                  'Agent scope enforcement — allowed paths/actions per agent',
                  'Trajectory validation — block dangerous tool-call sequences',
                  'Real-time agent observability — monitor every tool call with threat scoring',
                  'Agent quarantine on violation',
                  'Per-agent session aliases & audit trail',
                ]}
                color="violet"
              />
            </div>
          </div>

          {/* Security Events */}
          <div className="rounded-2xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
            <h3 className="mb-3 text-lg font-semibold text-neutral-900 dark:text-white">
              Security Events
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Connect your application with the DevFortress SDK to start
              collecting real-time security events.
            </p>
            <Link
              href="/dashboard/collect/surveillance"
              className="mt-4 inline-block text-sm font-semibold text-primary-600 hover:underline dark:text-primary-400"
            >
              Open Surveillance →
            </Link>
          </div>

          {/* CL Status & Retention */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div className="rounded-2xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <h3 className="mb-3 text-lg font-semibold text-neutral-900 dark:text-white">
                Closed-Loop Status
              </h3>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">
                Run your application with the DevFortress SDK to see
                closed-loop protection status per project.
              </p>
            </div>
            <div className="rounded-2xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-neutral-900 dark:text-white">
                  Data Retention
                </h3>
                <span className="rounded-full bg-primary-100 px-2 py-0.5 text-[10px] font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">
                  Hosted Platform
                </span>
              </div>
              <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-400">
                Advanced data retention policies and audit logs available on
                the hosted platform.
              </p>
              <a
                href="https://devfortress.net/pricing"
                target="_blank"
                rel="noopener noreferrer"
                className="mt-3 inline-block text-sm font-semibold text-primary-600 hover:underline dark:text-primary-400"
              >
                View plans →
              </a>
            </div>
          </div>

          {/* Account & Management */}
          <div className="space-y-6 border-t border-neutral-200 pt-8 dark:border-neutral-800">
            <h2 className="text-xl font-semibold text-neutral-900 sm:text-2xl dark:text-white">
              Account &amp; Management
            </h2>
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
              <LockedManagementCard
                icon={<ProjectsIcon />}
                title="API Key & Payload Protection"
                description="Alias indirection, zero-downtime key rotation, payload signing and field encryption."
              />
              <LockedManagementCard
                icon={<MonitoringIcon />}
                title="Platform Intelligence"
                description="Cross-customer threat feed, ML classifier decisions, and predictive attack trajectories."
              />
              <ManagementCard
                icon={<SettingsIcon />}
                title="Settings"
                description="Configure account preferences"
                href="/dashboard/settings"
              />
            </div>
          </div>

        </div>
      </section>
    </main>
  );
}

/* ── Supporting Components ──────────────────────────────────── */

interface ActionCardProps {
  icon: string;
  title: string;
  description: string;
  href: string;
  cta: string;
  accent: 'purple' | 'blue' | 'amber' | 'green' | 'red';
}

function ActionCard({ icon, title, description, href, cta, accent }: ActionCardProps) {
  const colors: Record<string, string> = {
    purple: 'border-purple-200 dark:border-purple-800 from-purple-50 to-purple-100 dark:from-purple-950/20 dark:to-purple-900/10',
    blue:   'border-blue-200 dark:border-blue-800 from-blue-50 to-blue-100 dark:from-blue-950/20 dark:to-blue-900/10',
    amber:  'border-amber-200 dark:border-amber-800 from-amber-50 to-amber-100 dark:from-amber-950/20 dark:to-amber-900/10',
    green:  'border-green-200 dark:border-green-800 from-green-50 to-green-100 dark:from-green-950/20 dark:to-green-900/10',
    red:    'border-red-200 dark:border-red-800 from-red-50 to-red-100 dark:from-red-950/20 dark:to-red-900/10',
  };
  return (
    <Link href={href} className={`group flex flex-col rounded-2xl border-2 bg-gradient-to-br p-6 transition-all hover:shadow-lg ${colors[accent]}`}>
      <span className="mb-3 text-3xl">{icon}</span>
      <h3 className="text-lg font-bold text-neutral-900 dark:text-white">{title}</h3>
      <p className="mt-2 flex-1 text-sm text-neutral-600 dark:text-neutral-400">{description}</p>
      <span className="mt-4 text-sm font-semibold text-primary-600 group-hover:underline dark:text-primary-400">{cta}</span>
    </Link>
  );
}

function CapabilityBadge({ emoji, title, detail }: { emoji: string; title: string; detail: string }) {
  return (
    <div className="rounded-xl bg-white p-4 shadow-sm dark:bg-neutral-900">
      <span className="text-2xl">{emoji}</span>
      <h4 className="mt-2 text-sm font-semibold text-neutral-900 dark:text-white">{title}</h4>
      <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">{detail}</p>
    </div>
  );
}

function ModeCard({ mode, emoji, features, color }: {
  mode: string; emoji: string; features: string[]; color: 'indigo' | 'violet';
}) {
  const border = color === 'indigo'
    ? 'border-indigo-200 dark:border-indigo-800'
    : 'border-violet-200 dark:border-violet-800';
  return (
    <div className={`rounded-2xl border-2 ${border} bg-white p-6 dark:bg-neutral-900`}>
      <div className="mb-3 flex items-center gap-2">
        <span className="text-2xl">{emoji}</span>
        <h3 className="text-lg font-bold text-neutral-900 dark:text-white">{mode}</h3>
      </div>
      <ul className="space-y-2 text-sm text-neutral-600 dark:text-neutral-400">
        {features.map((f, i) => (
          <li key={i} className="flex items-start gap-2">
            <span className="mt-0.5 text-green-600 dark:text-green-400">✓</span>
            {f}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ManagementCard({ icon, title, description, href }: {
  icon: React.ReactNode; title: string; description: string; href: string;
}) {
  return (
    <Link href={href} className="flex flex-col rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm transition-all hover:shadow-md dark:border-neutral-800 dark:bg-neutral-900">
      <div className="mb-3 flex items-center gap-3">
        <div className="text-neutral-600 dark:text-neutral-400">{icon}</div>
        <h3 className="text-lg font-semibold text-neutral-900 dark:text-white">{title}</h3>
      </div>
      <p className="flex-1 text-sm text-neutral-600 dark:text-neutral-400">{description}</p>
      <span className="mt-4 text-sm font-semibold text-primary-600 dark:text-primary-400">Manage →</span>
    </Link>
  );
}

function LockedManagementCard({ icon, title, description }: {
  icon: React.ReactNode; title: string; description: string;
}) {
  return (
    <div className="relative flex flex-col rounded-2xl border border-neutral-200 bg-neutral-50 p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-900/50">
      <div className="absolute inset-0 flex items-center justify-center rounded-2xl bg-neutral-100/80 dark:bg-neutral-800/80">
        <div className="flex flex-col items-center gap-2 text-center px-4">
          <svg className="h-8 w-8 text-neutral-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <p className="text-sm font-semibold text-neutral-600 dark:text-neutral-400">Hosted platform feature</p>
          <a href="https://devfortress.net/pricing" target="_blank" rel="noopener noreferrer"
            className="text-xs font-semibold text-primary-600 hover:text-primary-700 dark:text-primary-400">
            View plans →
          </a>
        </div>
      </div>
      <div className="mb-3 flex items-center gap-3 opacity-50">
        <div className="text-neutral-400 dark:text-neutral-500">{icon}</div>
        <h3 className="text-lg font-semibold text-neutral-500 dark:text-neutral-400">{title}</h3>
      </div>
      <p className="flex-1 text-sm text-neutral-400 dark:text-neutral-500">{description}</p>
      <span className="mt-4 text-sm font-semibold text-neutral-400 dark:text-neutral-500">Locked</span>
    </div>
  );
}

function ProjectsIcon() {
  return (
    <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
    </svg>
  );
}

function MonitoringIcon() {
  return (
    <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  );
}
