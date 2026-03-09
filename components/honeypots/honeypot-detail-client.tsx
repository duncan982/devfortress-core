'use client';

/**
 * Client component for honeypot detail page with tabs
 */

import { useState } from 'react';
import Link from 'next/link';
import { Honeypot, HoneypotStatus } from '@prisma/client';
import HoneypotActions from '@core/components/honeypots/honeypot-actions';
import HoneypotLogs from '@core/components/honeypots/honeypot-logs';
import { BreadcrumbNav } from '@core/components/navigation/BreadcrumbNav';
import { BREADCRUMB_PATHS } from '@core/components/navigation/breadcrumb-constants';

interface HoneypotWithProject extends Honeypot {
  apiProject?: {
    id: string;
    name: string;
    description: string | null;
    framework: string | null;
    language: string | null;
    specification: unknown;
  } | null;
}

interface HoneypotDetailClientProps {
  honeypot: HoneypotWithProject;
}

export default function HoneypotDetailClient({
  honeypot,
}: HoneypotDetailClientProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'logs'>('overview');

  const statusColors: Record<HoneypotStatus, string> = {
    [HoneypotStatus.ACTIVE]:
      'bg-success-100 text-success-800 dark:bg-success-900 dark:text-success-200',
    [HoneypotStatus.INACTIVE]:
      'bg-neutral-100 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200',
    [HoneypotStatus.DEPLOYING]:
      'bg-primary-100 text-primary-800 dark:bg-primary-900 dark:text-primary-200',
    [HoneypotStatus.DEPLOYED]:
      'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    [HoneypotStatus.PAUSED]:
      'bg-warning-100 text-warning-800 dark:bg-warning-900 dark:text-warning-200',
    [HoneypotStatus.SUSPENDED]:
      'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
    [HoneypotStatus.DECOMMISSIONED]:
      'bg-error-100 text-error-800 dark:bg-error-900 dark:text-error-200',
    [HoneypotStatus.ERROR]:
      'bg-error-100 text-error-800 dark:bg-error-900 dark:text-error-200',
  };

  return (
    <main className="bg-neutral-50 px-6 py-12 font-sans text-neutral-900 transition-colors duration-200 dark:bg-neutral-950 dark:text-neutral-100">
      <section className="mx-auto w-full max-w-5xl rounded-3xl border border-neutral-200 bg-white px-10 py-14 shadow-xl dark:border-neutral-800 dark:bg-neutral-950">
        <div className="flex flex-col gap-6">
          {/* Breadcrumb */}
          <BreadcrumbNav
            items={[BREADCRUMB_PATHS.dashboard, BREADCRUMB_PATHS.honeypots]}
            currentPage={honeypot.name}
          />

          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link
                href="/dashboard/honeypots"
                className="rounded-lg border border-neutral-200 px-3 py-2 text-sm font-semibold text-neutral-900 hover:bg-neutral-50 dark:border-neutral-800 dark:text-neutral-100 dark:hover:bg-neutral-900"
              >
                ← Back to Honeypots
              </Link>
              <div>
                <p className="text-sm uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                  Honeypot Details
                </p>
                <h1 className="mt-2 text-3xl font-semibold tracking-tight">
                  {honeypot.name}
                </h1>
              </div>
            </div>
            <div
              className={`rounded-full px-3 py-1 text-xs font-medium ${statusColors[honeypot.status]}`}
            >
              {honeypot.status}
            </div>
          </div>

          {/* Tabs */}
          <div className="border-b border-neutral-200 dark:border-neutral-700">
            <nav className="-mb-px flex space-x-8">
              <button
                onClick={() => setActiveTab('overview')}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'overview'
                    ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                    : 'border-transparent text-neutral-500 hover:text-neutral-700 hover:border-neutral-300 dark:text-neutral-400 dark:hover:text-neutral-300'
                }`}
              >
                Overview
              </button>
              <button
                onClick={() => setActiveTab('logs')}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'logs'
                    ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                    : 'border-transparent text-neutral-500 hover:text-neutral-700 hover:border-neutral-300 dark:text-neutral-400 dark:hover:text-neutral-300'
                }`}
              >
                Threat Logs
              </button>
            </nav>
          </div>

          {/* Tab Content */}
          {activeTab === 'overview' ? (
            <>
              {/* Success Message for Newly Created Honeypots */}
              {honeypot.status === HoneypotStatus.INACTIVE && (
                <div className="rounded-2xl border border-success-200 bg-success-50 p-6 dark:border-success-800 dark:bg-success-900">
                  <div className="flex items-start gap-3">
                    <div className="text-2xl text-success-900 dark:text-white">
                      ✅
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-success-900 dark:text-white mb-2">
                        Honeypot Created Successfully!
                      </h3>
                      <p className="text-success-800 dark:text-white mb-4">
                        Your honeypot configuration has been saved. To start
                        detecting threats, deploy it to Vercel using the button
                        below.
                      </p>
                      <div className="text-sm text-success-700 dark:text-white">
                        <strong>Next step:</strong> Click &quot;Deploy
                        Honeypot&quot; to activate your security monitoring.
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Honeypot Information */}
              <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-6 dark:border-neutral-800 dark:bg-neutral-900">
                  <h3 className="text-lg font-semibold mb-4">Configuration</h3>
                  <dl className="space-y-3">
                    <div>
                      <dt className="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                        Framework
                      </dt>
                      <dd className="text-sm text-neutral-900 dark:text-neutral-100">
                        {honeypot.apiProject?.framework || 'N/A'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                        Language
                      </dt>
                      <dd className="text-sm text-neutral-900 dark:text-neutral-100">
                        {honeypot.apiProject?.language || 'N/A'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                        Created
                      </dt>
                      <dd className="text-sm text-neutral-900 dark:text-neutral-100">
                        {new Date(honeypot.createdAt).toLocaleDateString()}
                      </dd>
                    </div>
                  </dl>
                </div>

                <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-6 dark:border-neutral-800 dark:bg-neutral-900">
                  <h3 className="text-lg font-semibold mb-4">Status</h3>
                  <dl className="space-y-3">
                    <div>
                      <dt className="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                        Deployment Status
                      </dt>
                      <dd className="text-sm text-neutral-900 dark:text-neutral-100">
                        <span
                          className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                            (
                              [
                                HoneypotStatus.ACTIVE,
                                HoneypotStatus.DEPLOYED,
                                HoneypotStatus.PAUSED,
                                HoneypotStatus.SUSPENDED,
                                HoneypotStatus.DECOMMISSIONED,
                                HoneypotStatus.ERROR,
                              ] as HoneypotStatus[]
                            ).includes(honeypot.status)
                              ? 'bg-success-100 text-success-800 dark:bg-success-900 dark:text-success-200'
                              : 'bg-neutral-100 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200'
                          }`}
                        >
                          {(
                            [
                              HoneypotStatus.ACTIVE,
                              HoneypotStatus.DEPLOYED,
                              HoneypotStatus.PAUSED,
                              HoneypotStatus.SUSPENDED,
                              HoneypotStatus.DECOMMISSIONED,
                              HoneypotStatus.ERROR,
                            ] as HoneypotStatus[]
                          ).includes(honeypot.status)
                            ? 'Deployed'
                            : 'Not Deployed'}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt className="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                        Operational Status
                      </dt>
                      <dd className="text-sm text-neutral-900 dark:text-neutral-100">
                        <span
                          className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${statusColors[honeypot.status]}`}
                        >
                          {(() => {
                            switch (honeypot.status) {
                              case HoneypotStatus.ACTIVE:
                                return 'Active';
                              case HoneypotStatus.INACTIVE:
                                return 'Inactive';
                              case HoneypotStatus.DEPLOYING:
                                return 'Deploying';
                              case HoneypotStatus.DEPLOYED:
                                return 'Deployed';
                              case HoneypotStatus.PAUSED:
                                return 'Paused';
                              case HoneypotStatus.SUSPENDED:
                                return 'Suspended';
                              case HoneypotStatus.DECOMMISSIONED:
                                return 'Decommissioned';
                              case HoneypotStatus.ERROR:
                                return 'Error';
                              default:
                                return honeypot.status;
                            }
                          })()}
                        </span>
                      </dd>
                    </div>
                  </dl>
                </div>
              </div>

              {/* Associated Project */}
              {honeypot.apiProject && (
                <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-6 dark:border-neutral-800 dark:bg-neutral-900">
                  <h3 className="text-lg font-semibold mb-4">
                    Associated API Project
                  </h3>
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium text-neutral-900 dark:text-neutral-100">
                        {honeypot.apiProject.name}
                      </h4>
                      <p className="text-sm text-neutral-600 dark:text-neutral-400">
                        {honeypot.apiProject.description ||
                          'No description available'}
                      </p>
                    </div>
                    <Link
                      href={`/dashboard/projects/${honeypot.apiProject.id}`}
                      className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white hover:bg-primary-700"
                    >
                      View Project
                    </Link>
                  </div>
                </div>
              )}

              {/* Actions */}
              <HoneypotActions honeypot={honeypot} />
            </>
          ) : (
            <HoneypotLogs
              honeypotId={honeypot.id}
              honeypotName={honeypot.name}
            />
          )}
        </div>
      </section>
    </main>
  );
}
