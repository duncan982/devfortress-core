'use client';

import { useState, useEffect, useCallback } from 'react';

interface Monitor {
  id: string;
  name: string;
  endpoint: string;
  method: string;
  status: string;
  frequency: string;
  expectedStatusCode: number;
  expectedResponseTime: number;
  alertEmail: string | null;
  lastCheckAt: string | null;
  createdAt: string;
}

interface MonitorStats {
  uptime: number;
  avgResponseTime: number;
  totalChecks: number;
  successfulChecks: number;
  failedChecks: number;
  lastCheckTime: string | null;
  currentStatus: 'UP' | 'DOWN' | 'DEGRADED';
}

interface Incident {
  id: string;
  monitorId: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  startedAt: string;
  resolvedAt: string | null;
}

const FREQUENCY_LABELS: Record<string, string> = {
  ONE_MINUTE: '1 min',
  FIVE_MINUTES: '5 min',
  FIFTEEN_MINUTES: '15 min',
  THIRTY_MINUTES: '30 min',
  ONE_HOUR: '1 hour',
};

const STATUS_COLORS: Record<string, string> = {
  UP: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
  DOWN: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
  DEGRADED:
    'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
};

const SEVERITY_COLORS: Record<string, string> = {
  LOW: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
  MEDIUM:
    'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
  HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
  CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
};

export function LiveApiMonitoringClient() {
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [stats, setStats] = useState<Record<string, MonitorStats>>({});
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [executing, setExecuting] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Create form state
  const [formName, setFormName] = useState('');
  const [formEndpoint, setFormEndpoint] = useState('');
  const [formMethod, setFormMethod] = useState('GET');
  const [formFrequency, setFormFrequency] = useState('FIVE_MINUTES');
  const [formExpectedStatus, setFormExpectedStatus] = useState(200);
  const [formExpectedResponseTime, setFormExpectedResponseTime] =
    useState(5000);
  const [formAlertEmail, setFormAlertEmail] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const fetchMonitors = useCallback(async () => {
    try {
      const res = await fetch('/api/monitoring/monitors');
      if (!res.ok) {
        setError('Failed to load monitors');
        return;
      }
      const data = await res.json();
      setMonitors(data.monitors || []);
    } catch {
      setError('Failed to load monitors');
    }
  }, []);

  const fetchIncidents = useCallback(async () => {
    try {
      const res = await fetch('/api/monitoring/incidents');
      if (!res.ok) return;
      const data = await res.json();
      setIncidents(data.incidents || []);
    } catch {
      // Non-critical
    }
  }, []);

  const fetchStats = useCallback(async (monitorId: string) => {
    try {
      const res = await fetch(`/api/monitoring/checks?monitorId=${monitorId}`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.statistics) {
        setStats(prev => ({ ...prev, [monitorId]: data.statistics }));
      }
    } catch {
      // Non-critical
    }
  }, []);

  // Initial load
  useEffect(() => {
    async function load() {
      setLoading(true);
      await Promise.all([fetchMonitors(), fetchIncidents()]);
      setLoading(false);
    }
    load();
  }, [fetchMonitors, fetchIncidents]);

  // Fetch stats for each monitor
  useEffect(() => {
    monitors.forEach(m => fetchStats(m.id));
  }, [monitors, fetchStats]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchMonitors();
      fetchIncidents();
      monitors.forEach(m => fetchStats(m.id));
    }, 30000);
    return () => clearInterval(interval);
  }, [autoRefresh, monitors, fetchMonitors, fetchIncidents, fetchStats]);

  const executeCheck = useCallback(
    async (monitorId: string) => {
      setExecuting(monitorId);
      try {
        const res = await fetch('/api/monitoring/checks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ monitorId }),
        });
        if (res.ok) {
          // Refresh stats after check
          await fetchStats(monitorId);
        }
      } catch {
        // Silent
      } finally {
        setExecuting(null);
      }
    },
    [fetchStats]
  );

  const handleCreateMonitor = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setCreating(true);
      setCreateError(null);

      try {
        const res = await fetch('/api/monitoring/monitors', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: formName,
            endpoint: formEndpoint,
            method: formMethod,
            frequency: formFrequency,
            expectedStatusCode: formExpectedStatus,
            expectedResponseTime: formExpectedResponseTime,
            alertEmail: formAlertEmail || undefined,
          }),
        });

        if (!res.ok) {
          const data = await res.json();
          setCreateError(data.error || 'Failed to create monitor');
          return;
        }

        // Reset form and refresh
        setFormName('');
        setFormEndpoint('');
        setFormMethod('GET');
        setFormFrequency('FIVE_MINUTES');
        setFormExpectedStatus(200);
        setFormExpectedResponseTime(5000);
        setFormAlertEmail('');
        setShowCreateForm(false);
        await fetchMonitors();
      } catch {
        setCreateError('Failed to create monitor');
      } finally {
        setCreating(false);
      }
    },
    [
      formName,
      formEndpoint,
      formMethod,
      formFrequency,
      formExpectedStatus,
      formExpectedResponseTime,
      formAlertEmail,
      fetchMonitors,
    ]
  );

  const handleDeleteMonitor = useCallback(
    async (monitorId: string) => {
      try {
        const res = await fetch(
          `/api/monitoring/monitors?monitorId=${monitorId}`,
          { method: 'DELETE' }
        );
        if (res.ok) {
          await fetchMonitors();
        }
      } catch {
        // Silent
      }
    },
    [fetchMonitors]
  );

  const acknowledgeIncident = useCallback(async (incidentId: string) => {
    try {
      await fetch('/api/monitoring/incidents', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incidentId, action: 'acknowledge' }),
      });
      setIncidents(prev =>
        prev.map(i =>
          i.id === incidentId ? { ...i, status: 'ACKNOWLEDGED' } : i
        )
      );
    } catch {
      // Silent
    }
  }, []);

  // Summary stats
  const totalMonitors = monitors.length;
  const upMonitors = Object.values(stats).filter(
    s => s.currentStatus === 'UP'
  ).length;
  const downMonitors = Object.values(stats).filter(
    s => s.currentStatus === 'DOWN'
  ).length;
  const avgUptime =
    Object.values(stats).length > 0
      ? Object.values(stats).reduce((sum, s) => sum + s.uptime, 0) /
        Object.values(stats).length
      : 0;
  const openIncidents = incidents.filter(i => i.status === 'OPEN').length;

  if (loading) {
    return (
      <div className="space-y-4">
        {[...Array(4)].map((_, i) => (
          <div
            key={i}
            className="h-24 animate-pulse rounded-xl bg-neutral-200 dark:bg-neutral-800"
          />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-6 dark:border-red-800 dark:bg-red-950">
        <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
          <p className="text-xs font-medium text-neutral-500 dark:text-neutral-400">
            Total Monitors
          </p>
          <p className="mt-1 text-2xl font-bold text-neutral-900 dark:text-neutral-100">
            {totalMonitors}
          </p>
        </div>
        <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
          <p className="text-xs font-medium text-green-600 dark:text-green-400">
            Up
          </p>
          <p className="mt-1 text-2xl font-bold text-green-700 dark:text-green-300">
            {upMonitors}
          </p>
        </div>
        <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
          <p className="text-xs font-medium text-red-600 dark:text-red-400">
            Down
          </p>
          <p className="mt-1 text-2xl font-bold text-red-700 dark:text-red-300">
            {downMonitors}
          </p>
        </div>
        <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
          <p className="text-xs font-medium text-neutral-500 dark:text-neutral-400">
            Avg Uptime
          </p>
          <p className="mt-1 text-2xl font-bold text-neutral-900 dark:text-neutral-100">
            {avgUptime.toFixed(1)}%
          </p>
        </div>
        <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
          <p className="text-xs font-medium text-orange-600 dark:text-orange-400">
            Open Incidents
          </p>
          <p className="mt-1 text-2xl font-bold text-orange-700 dark:text-orange-300">
            {openIncidents}
          </p>
        </div>
      </div>

      {/* Actions Bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700"
          >
            {showCreateForm ? 'Cancel' : '+ Add Monitor'}
          </button>
          <label className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-400">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={e => setAutoRefresh(e.target.checked)}
              className="rounded border-neutral-300 text-primary-600 focus:ring-primary-500"
            />
            Auto-refresh (30s)
          </label>
        </div>
        <button
          onClick={() => {
            fetchMonitors();
            fetchIncidents();
            monitors.forEach(m => fetchStats(m.id));
          }}
          className="rounded-lg bg-neutral-100 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
        >
          Refresh Now
        </button>
      </div>

      {/* Create Monitor Form */}
      {showCreateForm && (
        <form
          onSubmit={handleCreateMonitor}
          className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900"
        >
          <h3 className="mb-4 text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            Create New Monitor
          </h3>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <div>
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                Name
              </label>
              <input
                type="text"
                value={formName}
                onChange={e => setFormName(e.target.value)}
                required
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
                placeholder="My API"
              />
            </div>
            <div className="sm:col-span-2">
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                Endpoint URL
              </label>
              <input
                type="url"
                value={formEndpoint}
                onChange={e => setFormEndpoint(e.target.value)}
                required
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
                placeholder="https://api.example.com/health"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                Method
              </label>
              <select
                value={formMethod}
                onChange={e => setFormMethod(e.target.value)}
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              >
                {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                Check Frequency
              </label>
              <select
                value={formFrequency}
                onChange={e => setFormFrequency(e.target.value)}
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              >
                {Object.entries(FREQUENCY_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                Expected Status Code
              </label>
              <input
                type="number"
                value={formExpectedStatus}
                onChange={e =>
                  setFormExpectedStatus(parseInt(e.target.value) || 200)
                }
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                Max Response Time (ms)
              </label>
              <input
                type="number"
                value={formExpectedResponseTime}
                onChange={e =>
                  setFormExpectedResponseTime(parseInt(e.target.value) || 5000)
                }
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                Alert Email (optional)
              </label>
              <input
                type="email"
                value={formAlertEmail}
                onChange={e => setFormAlertEmail(e.target.value)}
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-100"
                placeholder="alerts@example.com"
              />
            </div>
          </div>
          {createError && (
            <p className="mt-3 text-sm text-red-600 dark:text-red-400">
              {createError}
            </p>
          )}
          <div className="mt-4 flex justify-end">
            <button
              type="submit"
              disabled={creating}
              className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:opacity-50"
            >
              {creating ? 'Creating…' : 'Create Monitor'}
            </button>
          </div>
        </form>
      )}

      {/* Monitors List */}
      {monitors.length === 0 ? (
        <div className="rounded-xl border border-neutral-200 bg-white p-12 text-center dark:border-neutral-800 dark:bg-neutral-900">
          <svg
            className="mx-auto h-12 w-12 text-neutral-300 dark:text-neutral-600"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
            />
          </svg>
          <p className="mt-4 text-neutral-500 dark:text-neutral-400">
            No monitors configured yet. Click &quot;+ Add Monitor&quot; to start
            tracking your APIs.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {monitors.map(monitor => {
            const monitorStats = stats[monitor.id];
            const currentStatus = monitorStats?.currentStatus ?? 'DEGRADED';
            const statusClass =
              STATUS_COLORS[currentStatus] ?? STATUS_COLORS.DEGRADED;

            return (
              <div
                key={monitor.id}
                className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900"
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
                        {monitor.name}
                      </h3>
                      <span
                        className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${statusClass}`}
                      >
                        {currentStatus}
                      </span>
                    </div>
                    <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400 truncate">
                      <span className="font-mono text-xs font-medium text-neutral-600 dark:text-neutral-300">
                        {monitor.method}
                      </span>{' '}
                      {monitor.endpoint}
                    </p>
                    <p className="mt-1 text-xs text-neutral-400 dark:text-neutral-500">
                      Check every{' '}
                      {FREQUENCY_LABELS[monitor.frequency] ?? monitor.frequency}
                      {monitor.lastCheckAt &&
                        ` · Last checked: ${new Date(monitor.lastCheckAt).toLocaleString()}`}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => executeCheck(monitor.id)}
                      disabled={executing === monitor.id}
                      className="rounded-lg bg-neutral-100 px-3 py-1.5 text-xs font-medium text-neutral-700 hover:bg-neutral-200 disabled:opacity-50 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
                    >
                      {executing === monitor.id ? 'Checking…' : 'Check Now'}
                    </button>
                    <button
                      onClick={() => handleDeleteMonitor(monitor.id)}
                      className="rounded-lg bg-red-50 px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-100 dark:bg-red-950 dark:text-red-400 dark:hover:bg-red-900"
                    >
                      Remove
                    </button>
                  </div>
                </div>

                {/* Stats Row */}
                {monitorStats && (
                  <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
                    <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-800">
                      <p className="text-[10px] font-medium uppercase text-neutral-500 dark:text-neutral-400">
                        Uptime
                      </p>
                      <p className="text-sm font-bold text-neutral-900 dark:text-neutral-100">
                        {monitorStats.uptime.toFixed(1)}%
                      </p>
                    </div>
                    <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-800">
                      <p className="text-[10px] font-medium uppercase text-neutral-500 dark:text-neutral-400">
                        Avg Response
                      </p>
                      <p className="text-sm font-bold text-neutral-900 dark:text-neutral-100">
                        {monitorStats.avgResponseTime.toFixed(0)}ms
                      </p>
                    </div>
                    <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-800">
                      <p className="text-[10px] font-medium uppercase text-neutral-500 dark:text-neutral-400">
                        Total Checks
                      </p>
                      <p className="text-sm font-bold text-neutral-900 dark:text-neutral-100">
                        {monitorStats.totalChecks}
                      </p>
                    </div>
                    <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-800">
                      <p className="text-[10px] font-medium uppercase text-neutral-500 dark:text-neutral-400">
                        Successful
                      </p>
                      <p className="text-sm font-bold text-green-700 dark:text-green-300">
                        {monitorStats.successfulChecks}
                      </p>
                    </div>
                    <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-800">
                      <p className="text-[10px] font-medium uppercase text-neutral-500 dark:text-neutral-400">
                        Failed
                      </p>
                      <p className="text-sm font-bold text-red-700 dark:text-red-300">
                        {monitorStats.failedChecks}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Incidents Section */}
      {incidents.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
            Recent Incidents
          </h2>
          <div className="space-y-3">
            {incidents.map(incident => {
              const severityClass =
                SEVERITY_COLORS[incident.severity] ?? SEVERITY_COLORS.LOW;
              return (
                <div
                  key={incident.id}
                  className="flex items-start justify-between gap-4 rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${severityClass}`}
                      >
                        {incident.severity}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                          incident.status === 'OPEN'
                            ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'
                            : incident.status === 'ACKNOWLEDGED'
                              ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300'
                              : 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                        }`}
                      >
                        {incident.status}
                      </span>
                    </div>
                    <p className="mt-1 text-sm font-medium text-neutral-900 dark:text-neutral-100">
                      {incident.title}
                    </p>
                    <p className="text-xs text-neutral-500 dark:text-neutral-400">
                      {incident.description}
                    </p>
                    <p className="mt-1 text-[10px] text-neutral-400 dark:text-neutral-500">
                      Started: {new Date(incident.startedAt).toLocaleString()}
                      {incident.resolvedAt &&
                        ` · Resolved: ${new Date(incident.resolvedAt).toLocaleString()}`}
                    </p>
                  </div>
                  {incident.status === 'OPEN' && (
                    <button
                      onClick={() => acknowledgeIncident(incident.id)}
                      className="shrink-0 rounded-lg bg-neutral-100 px-3 py-1.5 text-xs font-medium text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
                    >
                      Acknowledge
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
