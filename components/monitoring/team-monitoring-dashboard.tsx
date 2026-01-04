/**
 * Team Monitoring Dashboard Component
 * Displays API monitoring data for team members
 */

'use client';

import { useEffect, useState } from 'react';
import { logError } from '@core/lib/logger/client';

interface MonitorStats {
  uptime: number;
  avgResponseTime: number;
  totalChecks: number;
  successfulChecks: number;
  failedChecks: number;
  lastCheckTime?: Date;
  currentStatus: 'UP' | 'DOWN' | 'DEGRADED';
}

interface Incident {
  id: string;
  severity: string;
  status: string;
  message: string;
  detectedAt: Date;
  resolvedAt?: Date;
}

interface Monitor {
  id: string;
  name: string;
  endpoint: string;
  method: string;
  status: string;
  frequency: string;
  createdAt: Date;
  lastCheckedAt: Date;
  stats: MonitorStats;
  recentIncidents: Incident[];
  openIncidentsCount: number;
}

interface TeamStats {
  totalMonitors: number;
  activeMonitors: number;
  totalIncidents: number;
  avgUptime: number;
  avgResponseTime: number;
}

interface TeamMonitoringData {
  team: {
    id: string;
    name: string;
    role: string;
  };
  monitors: Monitor[];
  teamStats: TeamStats;
}

export function TeamMonitoringDashboard({ teamId }: { teamId: string }) {
  const [data, setData] = useState<TeamMonitoringData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchData() {
      try {
        const response = await fetch(`/api/monitoring/team?teamId=${teamId}`);
        if (!response.ok) {
          throw new Error('Failed to fetch monitoring data');
        }
        const result = await response.json();
        setData(result);
      } catch (err) {
        const errorMessage =
          err instanceof Error ? err.message : 'Unknown error';
        setError(errorMessage);
        logError('Failed to fetch team monitoring data', { error: err });
      } finally {
        setLoading(false);
      }
    }

    fetchData();
    // Refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [teamId]);

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-neutral-300 dark:border-neutral-700 border-t-primary-600 dark:border-t-primary-500"></div>
          <p className="mt-4 text-sm text-neutral-600 dark:text-neutral-400">
            Loading team monitoring data...
          </p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-lg border border-error-200 bg-error-50 p-6 dark:border-error-800 dark:bg-error-950">
        <h3 className="text-lg font-semibold text-error-900 dark:text-error-100">
          Error Loading Data
        </h3>
        <p className="mt-2 text-sm text-error-700 dark:text-error-300">
          {error}
        </p>
      </div>
    );
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'UP':
        return 'bg-success-500';
      case 'DOWN':
        return 'bg-error-500';
      case 'DEGRADED':
        return 'bg-warning-500';
      default:
        return 'bg-neutral-500';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'text-error-600 bg-error-50 dark:text-error-400 dark:bg-error-950';
      case 'HIGH':
        return 'text-warning-600 bg-warning-50 dark:text-warning-400 dark:bg-orange-950';
      case 'MEDIUM':
        return 'text-warning-600 bg-warning-50 dark:text-warning-400 dark:bg-yellow-950';
      case 'LOW':
        return 'text-primary-600 bg-primary-50 dark:text-primary-400 dark:bg-primary-950';
      default:
        return 'text-neutral-600 bg-neutral-50 dark:text-neutral-400 dark:bg-neutral-950';
    }
  };

  return (
    <div className="space-y-6">
      {/* Team Header */}
      <div className="rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-950">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-semibold">{data.team.name}</h2>
            <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
              Your role: <span className="font-medium">{data.team.role}</span>
            </p>
          </div>
          <div className="rounded-lg bg-primary-50 px-4 py-2 dark:bg-primary-950">
            <p className="text-xs uppercase tracking-wide text-primary-600 dark:text-primary-400">
              Team Monitoring
            </p>
          </div>
        </div>
      </div>

      {/* Team Stats */}
      <div className="grid gap-4 md:grid-cols-5">
        <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-950">
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Total Monitors
          </p>
          <p className="mt-2 text-3xl font-bold">
            {data.teamStats.totalMonitors}
          </p>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-950">
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Active
          </p>
          <p className="mt-2 text-3xl font-bold text-success-600">
            {data.teamStats.activeMonitors}
          </p>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-950">
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Open Incidents
          </p>
          <p className="mt-2 text-3xl font-bold text-error-600">
            {data.teamStats.totalIncidents}
          </p>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-950">
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Avg Uptime
          </p>
          <p className="mt-2 text-3xl font-bold text-primary-600">
            {data.teamStats.avgUptime.toFixed(1)}%
          </p>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-950">
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Avg Response
          </p>
          <p className="mt-2 text-3xl font-bold text-purple-600">
            {data.teamStats.avgResponseTime}ms
          </p>
        </div>
      </div>

      {/* Monitors List */}
      <div className="space-y-4">
        <h3 className="text-xl font-semibold">Monitors</h3>
        {data.monitors.length === 0 ? (
          <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-8 text-center dark:border-neutral-800 dark:bg-neutral-900">
            <p className="text-neutral-600 dark:text-neutral-400">
              No monitors configured for this team yet.
            </p>
          </div>
        ) : (
          data.monitors.map(monitor => (
            <div
              key={monitor.id}
              className="rounded-lg border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-950"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <div
                      className={`h-3 w-3 rounded-full ${getStatusColor(monitor.stats.currentStatus)}`}
                    />
                    <h4 className="text-lg font-semibold">{monitor.name}</h4>
                    <span className="rounded-full bg-neutral-100 px-2 py-1 text-xs font-medium dark:bg-neutral-800">
                      {monitor.method}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                    {monitor.endpoint}
                  </p>
                  <div className="mt-4 grid gap-4 md:grid-cols-4">
                    <div>
                      <p className="text-xs text-neutral-500 dark:text-neutral-500">
                        Uptime
                      </p>
                      <p className="mt-1 text-lg font-semibold">
                        {monitor.stats.uptime.toFixed(1)}%
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-neutral-500 dark:text-neutral-500">
                        Avg Response
                      </p>
                      <p className="mt-1 text-lg font-semibold">
                        {monitor.stats.avgResponseTime}ms
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-neutral-500 dark:text-neutral-500">
                        Total Checks
                      </p>
                      <p className="mt-1 text-lg font-semibold">
                        {monitor.stats.totalChecks}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-neutral-500 dark:text-neutral-500">
                        Open Incidents
                      </p>
                      <p className="mt-1 text-lg font-semibold text-error-600">
                        {monitor.openIncidentsCount}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Recent Incidents */}
              {monitor.recentIncidents.length > 0 && (
                <div className="mt-6 border-t border-neutral-200 pt-4 dark:border-neutral-800">
                  <h5 className="mb-3 text-sm font-semibold">
                    Recent Incidents
                  </h5>
                  <div className="space-y-2">
                    {monitor.recentIncidents.slice(0, 3).map(incident => (
                      <div
                        key={incident.id}
                        className="flex items-start gap-3 rounded-lg border border-neutral-200 bg-neutral-50 p-3 dark:border-neutral-800 dark:bg-neutral-900"
                      >
                        <span
                          className={`rounded px-2 py-1 text-xs font-semibold ${getSeverityColor(incident.severity)}`}
                        >
                          {incident.severity}
                        </span>
                        <div className="flex-1">
                          <p className="text-sm">{incident.message}</p>
                          <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-500">
                            {new Date(incident.detectedAt).toLocaleString()}
                            {incident.resolvedAt && (
                              <span className="ml-2 text-success-600">
                                • Resolved
                              </span>
                            )}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
