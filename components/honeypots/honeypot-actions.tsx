'use client';

import { useState } from 'react';
import Link from 'next/link';
import { HoneypotStatus } from '@prisma/client';
import DeployHoneypotButton from '@core/components/DeployHoneypotButton';
import HoneypotLogs from '@core/components/honeypots/honeypot-logs';

type Honeypot = {
  id: string;
  name: string;
  status: HoneypotStatus;
};

type Props = {
  honeypot: Honeypot;
};

type StatsData = {
  stats: {
    totalRequests: number;
    uniqueIps: number;
    threatsDetected: number;
    blockedIps: number;
    topPaths: string[];
    threatsByType: Record<string, number>;
  };
  timeRange: {
    start: string;
    end: string;
    days: number;
  };
};

type ThreatsData = {
  honeypotId: string;
  honeypotName: string;
  totalEvents: number;
  uniqueIPs: number;
  severityDistribution: Record<string, number>;
  patternDistribution: Record<string, number>;
  topAttackIPs: string[];
  recentTrends: unknown[];
};

export default function HoneypotActions({ honeypot }: Props) {
  const [activeTab, setActiveTab] = useState<'actions' | 'logs'>('actions');
  const [showStats, setShowStats] = useState(false);
  const [showThreats, setShowThreats] = useState(false);
  const [statsData, setStatsData] = useState<StatsData | null>(null);
  const [threatsData, setThreatsData] = useState<ThreatsData | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);
  const [loadingThreats, setLoadingThreats] = useState(false);
  const [loadingTest, setLoadingTest] = useState(false);
  const [loadingWebhookUpdate, setLoadingWebhookUpdate] = useState(false);
  const [loadingRedeploy, setLoadingRedeploy] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [webhookUpdateResult, setWebhookUpdateResult] = useState<string | null>(
    null
  );
  const [redeployResult, setRedeployResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = async () => {
    if (statsData) {
      setShowStats(!showStats);
      return;
    }

    setLoadingStats(true);
    setError(null);

    try {
      const response = await fetch(`/api/honeypots/${honeypot.id}/stats`);
      if (!response.ok) {
        throw new Error('Failed to fetch stats');
      }
      const data = await response.json();
      setStatsData(data);
      setShowStats(true);
    } catch {
      setError('Failed to load stats');
    } finally {
      setLoadingStats(false);
    }
  };

  const fetchThreats = async () => {
    if (threatsData) {
      setShowThreats(!showThreats);
      return;
    }

    setLoadingThreats(true);
    setError(null);

    try {
      const response = await fetch(`/api/honeypots/${honeypot.id}/threats`);
      if (!response.ok) {
        throw new Error('Failed to fetch threats');
      }
      const data = await response.json();
      setThreatsData(data);
      setShowThreats(true);
    } catch {
      setError('Failed to load threats');
    } finally {
      setLoadingThreats(false);
    }
  };

  const testHoneypot = async () => {
    setLoadingTest(true);
    setError(null);
    setTestResult(null);

    try {
      const response = await fetch(`/api/honeypots/${honeypot.id}/test`, {
        method: 'POST',
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to test honeypot');
      }
      const data = await response.json();
      const metadata = data.testMetadata;
      setTestResult(
        `✅ Test completed successfully!\n\n` +
          `📊 Results: ${data.results.successful}/${data.results.total} requests successful\n` +
          `👤 Tested by: ${metadata.testedBy.name} (${metadata.testedBy.role})\n` +
          `🕒 Tested at: ${new Date(metadata.testedAt).toLocaleString()}\n\n` +
          `Check the "Threat Logs" tab to see test events marked with test metadata.`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed');
    } finally {
      setLoadingTest(false);
    }
  };

  const updateWebhookUrl = async () => {
    setLoadingWebhookUpdate(true);
    setError(null);
    setWebhookUpdateResult(null);

    try {
      const response = await fetch(
        `/api/honeypots/${honeypot.id}/update-webhook`,
        {
          method: 'POST',
        }
      );
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to update webhook URL');
      }
      const data = await response.json();
      setWebhookUpdateResult(
        `✅ ${data.message}\n\n` + `New webhook URL: ${data.newWebhookUrl}`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Update failed');
    } finally {
      setLoadingWebhookUpdate(false);
    }
  };

  const redeployHoneypot = async () => {
    setLoadingRedeploy(true);
    setError(null);
    setRedeployResult(null);

    try {
      const response = await fetch(`/api/honeypots/${honeypot.id}/redeploy`, {
        method: 'POST',
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to redeploy honeypot');
      }
      const data = await response.json();
      setRedeployResult(
        `✅ ${data.message}\n\n` +
          `🌐 New deployment: ${data.deploymentUrl}\n` +
          `⏳ The honeypot is being redeployed with the latest code. This may take a minute.`
      );
      // Refresh the page after a delay to show the updated status
      setTimeout(() => {
        window.location.reload();
      }, 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Redeploy failed');
    } finally {
      setLoadingRedeploy(false);
    }
  };

  return (
    <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-6 dark:border-neutral-800 dark:bg-neutral-900">
      {/* Tabs */}
      <div className="flex border-b border-neutral-200 dark:border-neutral-700 mb-4">
        <button
          onClick={() => setActiveTab('actions')}
          className={`py-2 px-4 text-sm font-medium border-b-2 -mb-px transition-colors ${
            activeTab === 'actions'
              ? 'border-primary-500 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-neutral-500 hover:text-neutral-700 hover:border-neutral-300 dark:text-neutral-400 dark:hover:text-neutral-300'
          }`}
        >
          Actions
        </button>
        <button
          onClick={() => setActiveTab('logs')}
          className={`py-2 px-4 text-sm font-medium border-b-2 -mb-px transition-colors ${
            activeTab === 'logs'
              ? 'border-primary-500 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-neutral-500 hover:text-neutral-700 hover:border-neutral-300 dark:text-neutral-400 dark:hover:text-neutral-300'
          }`}
        >
          Threat Logs
        </button>
      </div>

      {activeTab === 'logs' ? (
        <HoneypotLogs honeypotId={honeypot.id} honeypotName={honeypot.name} />
      ) : (
        <>
          {error && (
            <div className="mb-4 rounded-lg border border-error-200 bg-error-50 p-3 dark:border-error-800 dark:bg-error-950">
              <p className="text-sm text-error-800 dark:text-error-200">
                {error}
              </p>
            </div>
          )}

          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap gap-4">
              <button
                onClick={fetchStats}
                disabled={loadingStats}
                className="rounded-lg border border-neutral-200 px-4 py-2 text-sm font-semibold text-neutral-900 hover:bg-neutral-50 disabled:opacity-50 disabled:cursor-not-allowed dark:border-neutral-800 dark:text-neutral-100 dark:hover:bg-neutral-900"
              >
                {loadingStats ? 'Loading...' : 'View Stats'}
              </button>

              <button
                onClick={fetchThreats}
                disabled={loadingThreats}
                className="rounded-lg border border-neutral-200 px-4 py-2 text-sm font-semibold text-neutral-900 hover:bg-neutral-50 disabled:opacity-50 disabled:cursor-not-allowed dark:border-neutral-800 dark:text-neutral-100 dark:hover:bg-neutral-900"
              >
                {loadingThreats ? 'Loading...' : 'View Threats'}
              </button>

              {(honeypot.status === HoneypotStatus.ACTIVE ||
                honeypot.status === HoneypotStatus.DEPLOYED) && (
                <button
                  onClick={testHoneypot}
                  disabled={loadingTest}
                  className="rounded-lg border border-neutral-200 px-4 py-2 text-sm font-semibold text-neutral-900 hover:bg-neutral-50 disabled:opacity-50 disabled:cursor-not-allowed dark:border-neutral-800 dark:text-neutral-100 dark:hover:bg-neutral-900"
                >
                  {loadingTest ? 'Testing...' : 'Test Honeypot'}
                </button>
              )}

              {(honeypot.status === HoneypotStatus.ACTIVE ||
                honeypot.status === HoneypotStatus.DEPLOYED) && (
                <button
                  onClick={updateWebhookUrl}
                  disabled={loadingWebhookUpdate}
                  className="rounded-lg border border-primary-200 bg-primary-50 px-4 py-2 text-sm font-semibold text-primary-900 hover:bg-primary-100 disabled:opacity-50 disabled:cursor-not-allowed dark:border-primary-800 dark:bg-primary-950 dark:text-primary-100 dark:hover:bg-primary-900"
                  title="Update the honeypot's webhook URL to point to the current deployment"
                >
                  {loadingWebhookUpdate
                    ? 'Updating...'
                    : '🔄 Update Webhook URL'}
                </button>
              )}

              {(honeypot.status === HoneypotStatus.ACTIVE ||
                honeypot.status === HoneypotStatus.DEPLOYED ||
                honeypot.status === HoneypotStatus.ERROR) && (
                <button
                  onClick={redeployHoneypot}
                  disabled={loadingRedeploy}
                  className="rounded-lg border border-warning-200 bg-warning-50 px-4 py-2 text-sm font-semibold text-warning-900 hover:bg-warning-100 disabled:opacity-50 disabled:cursor-not-allowed dark:border-warning-800 dark:bg-warning-950 dark:text-warning-100 dark:hover:bg-warning-900"
                  title="Redeploy the honeypot with the latest code (fixes routing issues)"
                >
                  {loadingRedeploy
                    ? 'Redeploying...'
                    : '🚀 Redeploy with Latest Code'}
                </button>
              )}

              {honeypot.status === HoneypotStatus.PAUSED && (
                <Link
                  href={`/api/honeypots/${honeypot.id}/resume`}
                  className="rounded-lg bg-success-600 px-4 py-2 text-sm font-semibold text-white hover:bg-success-700"
                >
                  Resume
                </Link>
              )}

              {honeypot.status === HoneypotStatus.ERROR && (
                <Link
                  href={`/api/honeypots/${honeypot.id}/redeploy`}
                  className="rounded-lg bg-warning-600 px-4 py-2 text-sm font-semibold text-white hover:bg-warning-700"
                >
                  Retry Deployment
                </Link>
              )}
            </div>

            {/* Stats Display */}
            {showStats && statsData && (
              <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-800">
                <h4 className="font-medium text-neutral-900 dark:text-neutral-100 mb-3">
                  Honeypot Statistics
                </h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium text-neutral-600 dark:text-neutral-400">
                      Total Requests:
                    </span>
                    <span className="ml-2 text-neutral-900 dark:text-neutral-100">
                      {statsData.stats.totalRequests}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-neutral-600 dark:text-neutral-400">
                      Unique IPs:
                    </span>
                    <span className="ml-2 text-neutral-900 dark:text-neutral-100">
                      {statsData.stats.uniqueIps}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-neutral-600 dark:text-neutral-400">
                      Threats Detected:
                    </span>
                    <span className="ml-2 text-neutral-900 dark:text-neutral-100">
                      {statsData.stats.threatsDetected}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-neutral-600 dark:text-neutral-400">
                      Blocked IPs:
                    </span>
                    <span className="ml-2 text-neutral-900 dark:text-neutral-100">
                      {statsData.stats.blockedIps}
                    </span>
                  </div>
                </div>
                <div className="mt-3 text-xs text-neutral-500 dark:text-neutral-400">
                  Time Range: {statsData.timeRange.days} days
                </div>
              </div>
            )}

            {/* Threats Display */}
            {showThreats && threatsData && (
              <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-800">
                <h4 className="font-medium text-neutral-900 dark:text-neutral-100 mb-3">
                  Threat Analysis
                </h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium text-neutral-600 dark:text-neutral-400">
                      Total Events:
                    </span>
                    <span className="ml-2 text-neutral-900 dark:text-neutral-100">
                      {threatsData.totalEvents}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-neutral-600 dark:text-neutral-400">
                      Unique IPs:
                    </span>
                    <span className="ml-2 text-neutral-900 dark:text-neutral-100">
                      {threatsData.uniqueIPs}
                    </span>
                  </div>
                </div>
                <div className="mt-3">
                  <h5 className="text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2">
                    Severity Distribution:
                  </h5>
                  <div className="flex gap-4 text-xs">
                    {Object.entries(threatsData.severityDistribution).map(
                      ([severity, count]) => (
                        <span
                          key={severity}
                          className="text-neutral-600 dark:text-neutral-400"
                        >
                          {severity}: {count}
                        </span>
                      )
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Test Result */}
            {testResult && (
              <div className="rounded-lg border border-success-200 bg-success-50 p-4 dark:border-success-800 dark:bg-success-950">
                <p className="text-sm text-success-800 dark:text-success-200 whitespace-pre-line">
                  {testResult}
                </p>
              </div>
            )}

            {/* Webhook Update Result */}
            {webhookUpdateResult && (
              <div className="rounded-lg border border-primary-200 bg-primary-50 p-4 dark:border-primary-800 dark:bg-primary-950">
                <p className="text-sm text-primary-800 dark:text-primary-200 whitespace-pre-line">
                  {webhookUpdateResult}
                </p>
              </div>
            )}

            {/* Redeploy Result */}
            {redeployResult && (
              <div className="rounded-lg border border-warning-200 bg-warning-50 p-4 dark:border-warning-800 dark:bg-warning-950">
                <p className="text-sm text-warning-800 dark:text-warning-200 whitespace-pre-line">
                  {redeployResult}
                </p>
              </div>
            )}

            {/* Deploy Button for Inactive Honeypots */}
            <DeployHoneypotButton
              honeypotId={honeypot.id}
              currentStatus={honeypot.status}
            />
          </div>
        </>
      )}
    </div>
  );
}
