/**
 * Portal Dashboard Component
 * Displays customized portal sections based on user role and subscription tier
 */

'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { logError } from '@core/lib/logger/client';

interface PortalSection {
  id: string;
  title: string;
  description: string;
  icon: string;
  href: string;
  category: string;
  access: {
    hasAccess: boolean;
    reason?: string;
    upgradeRequired?: boolean;
    requiredTier?: string;
  };
}

interface DashboardData {
  user: {
    email: string;
    name: string;
    role: string;
    tier: string;
  };
  sections: PortalSection[];
  accessibleSections: PortalSection[];
  permissions: Record<string, boolean>;
  featureLimits: {
    maxAPIs: number;
    maxHoneypots: number;
    maxTeamMembers: number;
    maxMonitors: number;
    hasAdvancedSecurity: boolean;
    hasAnalytics: boolean;
  };
  data: {
    security: {
      totalHoneypots: number;
      activeHoneypots: number;
      recentThreats: number;
      securityScore: number;
    } | null;
    monitoring: {
      totalMonitors: number;
      activeMonitors: number;
      openIncidents: number;
      avgUptime: number;
    } | null;
    flywheel: {
      totalAPIs: number;
      totalGenerations: number;
      activeUsers: number;
      revenueThisMonth: number;
    } | null;
  };
}

export function PortalDashboard({ teamId }: { teamId?: string }) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchData() {
      try {
        const url = teamId
          ? `/api/portal/dashboard?teamId=${teamId}`
          : '/api/portal/dashboard';
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error('Failed to fetch portal data');
        }
        const result = await response.json();
        setData(result);
      } catch (err) {
        const errorMessage =
          err instanceof Error ? err.message : 'Unknown error';
        setError(errorMessage);
        logError('Failed to fetch portal dashboard data', { error: err });
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [teamId]);

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-neutral-300 border-t-primary-600"></div>
          <p className="mt-4 text-sm text-neutral-600 dark:text-neutral-400">
            Loading portal...
          </p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-lg border border-error-200 bg-error-50 p-6 dark:border-error-900 dark:bg-error-950">
        <h3 className="text-lg font-semibold text-error-900 dark:text-error-100">
          Error
        </h3>
        <p className="mt-2 text-sm text-error-700 dark:text-error-300">
          {error || 'Failed to load portal data'}
        </p>
      </div>
    );
  }

  const getIconForSection = (icon: string) => {
    const icons: Record<string, string> = {
      book: '📚',
      shield: '🛡️',
      bug: '🐛',
      activity: '📊',
      'trending-up': '📈',
      server: '🖥️',
      users: '👥',
      code: '💻',
      lock: '🔒',
      'credit-card': '💳',
    };
    return icons[icon] || '📄';
  };

  const getCategoryColor = (category: string) => {
    const colors: Record<string, string> = {
      docs: 'blue',
      security: 'red',
      monitoring: 'green',
      data: 'purple',
      admin: 'orange',
    };
    return colors[category] || 'zinc';
  };

  return (
    <div className="space-y-6">
      {/* User Info Card */}
      <div className="rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-950">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold">{data.user.name}</h2>
            <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
              {data.user.email}
            </p>
          </div>
          <div className="flex gap-4">
            <div className="rounded-lg bg-primary-50 px-4 py-2 dark:bg-primary-950">
              <p className="text-xs uppercase tracking-wide text-primary-600 dark:text-primary-400">
                Role
              </p>
              <p className="mt-1 font-semibold">{data.user.role}</p>
            </div>
            <div className="rounded-lg bg-purple-50 px-4 py-2 dark:bg-purple-950">
              <p className="text-xs uppercase tracking-wide text-purple-600 dark:text-purple-400">
                Tier
              </p>
              <p className="mt-1 font-semibold">{data.user.tier}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Feature Limits */}
      {data.user.tier !== 'ENTERPRISE' && (
        <div className="rounded-2xl border border-neutral-200 bg-gradient-to-r from-primary-50 to-purple-50 p-6 dark:border-neutral-800 dark:from-primary-950 dark:to-purple-950">
          <h3 className="text-lg font-semibold">Your Plan Limits</h3>
          <div className="mt-4 grid gap-4 md:grid-cols-4">
            <div>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Max APIs
              </p>
              <p className="mt-1 text-2xl font-bold">
                {data.featureLimits.maxAPIs === -1
                  ? '∞'
                  : data.featureLimits.maxAPIs}
              </p>
            </div>
            <div>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Max Honeypots
              </p>
              <p className="mt-1 text-2xl font-bold">
                {data.featureLimits.maxHoneypots === -1
                  ? '∞'
                  : data.featureLimits.maxHoneypots}
              </p>
            </div>
            <div>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Team Members
              </p>
              <p className="mt-1 text-2xl font-bold">
                {data.featureLimits.maxTeamMembers === -1
                  ? '∞'
                  : data.featureLimits.maxTeamMembers}
              </p>
            </div>
            <div>
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Monitors
              </p>
              <p className="mt-1 text-2xl font-bold">
                {data.featureLimits.maxMonitors === -1
                  ? '∞'
                  : data.featureLimits.maxMonitors}
              </p>
            </div>
          </div>
          <Link
            href="/pricing"
            className="mt-4 inline-flex items-center text-sm font-semibold text-primary-600 hover:underline dark:text-primary-400"
          >
            Upgrade for more features →
          </Link>
        </div>
      )}

      {/* Portal Sections */}
      <div>
        <h3 className="mb-4 text-xl font-semibold">Available Tools</h3>
        <div className="grid gap-4 md:grid-cols-3">
          {data.sections.map(section => {
            const color = getCategoryColor(section.category);
            const isLocked = !section.access.hasAccess;

            return (
              <div
                key={section.id}
                className={`rounded-lg border p-6 ${
                  isLocked
                    ? 'border-neutral-300 bg-neutral-100 opacity-60 dark:border-neutral-700 dark:bg-neutral-900'
                    : 'border-neutral-200 bg-white shadow-sm hover:shadow-md dark:border-neutral-800 dark:bg-neutral-950'
                } transition-all`}
              >
                <div className="flex items-start justify-between">
                  <div className="text-3xl">
                    {getIconForSection(section.icon)}
                  </div>
                  {isLocked && (
                    <span className="rounded bg-neutral-200 px-2 py-1 text-xs font-semibold text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300">
                      🔒 Locked
                    </span>
                  )}
                </div>
                <h4 className="mt-4 text-lg font-semibold">{section.title}</h4>
                <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                  {section.description}
                </p>
                {isLocked ? (
                  <div className="mt-4">
                    <p className="text-xs text-error-600 dark:text-error-400">
                      {section.access.reason}
                    </p>
                    {section.access.upgradeRequired && (
                      <Link
                        href="/pricing"
                        className="mt-2 inline-flex text-xs font-semibold text-primary-600 hover:underline dark:text-primary-400"
                      >
                        Upgrade to {section.access.requiredTier} →
                      </Link>
                    )}
                  </div>
                ) : (
                  <Link
                    href={section.href}
                    className={`mt-4 inline-flex text-sm font-semibold text-${color}-600 hover:underline dark:text-${color}-400`}
                  >
                    Access →
                  </Link>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Quick Stats */}
      {(data.data.security || data.data.monitoring) && (
        <div className="space-y-4">
          <h3 className="text-xl font-semibold">Quick Stats</h3>
          <div className="grid gap-4 md:grid-cols-3">
            {data.data.security && (
              <div className="rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-950">
                <h4 className="text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Security Score
                </h4>
                <p className="mt-2 text-3xl font-bold">
                  {data.data.security.securityScore}/100
                </p>
                <p className="mt-2 text-xs text-neutral-500">
                  {data.data.security.activeHoneypots} active honeypots
                </p>
              </div>
            )}
            {data.data.monitoring && (
              <>
                <div className="rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-950">
                  <h4 className="text-sm font-medium text-neutral-600 dark:text-neutral-400">
                    API Uptime
                  </h4>
                  <p className="mt-2 text-3xl font-bold">
                    {data.data.monitoring.avgUptime.toFixed(1)}%
                  </p>
                  <p className="mt-2 text-xs text-neutral-500">
                    {data.data.monitoring.activeMonitors} active monitors
                  </p>
                </div>
                <div className="rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-950">
                  <h4 className="text-sm font-medium text-neutral-600 dark:text-neutral-400">
                    Open Incidents
                  </h4>
                  <p className="mt-2 text-3xl font-bold text-error-600">
                    {data.data.monitoring.openIncidents}
                  </p>
                  <p className="mt-2 text-xs text-neutral-500">
                    {data.data.monitoring.totalMonitors} total monitors
                  </p>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
