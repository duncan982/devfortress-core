/**
 * Collect Security Overview — Session Identifiers, Blocked IPs, Event Logs
 *
 * A unified view of all collected security intelligence from the SDK:
 * - Session Identifiers: Encrypted token inventory with revocation status
 * - Blocked IPs: IPs currently blocked across all modes (external + internal)
 * - Event Logs: Unified audit trail from all three CL modes
 *
 * @module app/dashboard/collect/overview
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';

// ── Types ───────────────────────────────────────────────────

const BREADCRUMB_PATHS = {
  dashboard: { label: 'Dashboard', href: '/dashboard' },
  collect: { label: 'Collect', href: '/dashboard/collect' },
} as const;
function BreadcrumbNav(_props: { items: { label: string; href: string }[]; currentPage: string }) { return null; }

type ActiveTab = 'tokens' | 'blocked-ips' | 'event-logs';

interface TokenAlias {
  aliasId: string;
  originalTokenPreview: string; // "sk-****1234"
  algorithm: string;
  createdAt: string;
  expiresAt: string | null;
  status: 'active' | 'revoked' | 'expired';
  revocationReason: string | null;
  lastAccessedAt: string | null;
  accessCount: number;
}

interface BlockedIPEntry {
  ip: string;
  source: 'external' | 'internal' | 'hybrid' | 'manual' | 'webhook';
  reason: string;
  blockedAt: string;
  expiresAt: string | null;
  score: number;
  matchedRules: string[];
  eventCount: number;
}

interface AuditLogEntry {
  eventId: string;
  timestamp: string;
  source: 'internal' | 'external' | 'hybrid';
  tier: 0 | 1 | 2 | 3;
  decision: string;
  score: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  latencyMs: number;
  ip: string;
  path: string;
  method: string;
  matchedRules: string[];
  userId: string | null;
  agentId: string | null;
}

interface OverviewStats {
  totalTokens: number;
  activeTokens: number;
  revokedTokens: number;
  totalBlockedIPs: number;
  autoBlockedIPs: number;
  manualBlockedIPs: number;
  totalEvents: number;
  blockedEvents: number;
  avgLatencyMs: number;
}

// ── Color Maps ──────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10',
  high: 'text-orange-400 bg-orange-500/10',
  medium: 'text-yellow-400 bg-yellow-500/10',
  low: 'text-green-400 bg-green-500/10',
};

const SOURCE_COLORS: Record<string, string> = {
  internal: 'text-purple-400 bg-purple-500/10',
  external: 'text-blue-400 bg-blue-500/10',
  hybrid: 'text-cyan-400 bg-cyan-500/10',
  manual: 'text-gray-400 bg-gray-500/10',
  webhook: 'text-yellow-400 bg-yellow-500/10',
};

const STATUS_COLORS: Record<string, string> = {
  active: 'text-green-400 bg-green-500/10',
  revoked: 'text-red-400 bg-red-500/10',
  expired: 'text-gray-400 bg-gray-500/10',
};

const DECISION_COLORS: Record<string, string> = {
  allow: 'text-green-400',
  block: 'text-red-400',
  rate_limit: 'text-yellow-400',
  quarantine: 'text-orange-400',
  webhook_response: 'text-blue-400',
};

// ── Component ───────────────────────────────────────────────

export default function CollectOverviewPage() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('event-logs');
  const [tokens, setTokens] = useState<TokenAlias[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<BlockedIPEntry[]>([]);
  const [eventLogs, setEventLogs] = useState<AuditLogEntry[]>([]);
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedProject, setSelectedProject] = useState<string>('');
  const [projects, setProjects] = useState<Array<{ id: string; name: string }>>(
    []
  );
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>(
    '24h'
  );
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams();
    if (selectedProject) params.set('projectId', selectedProject);
    params.set('timeRange', timeRange);
    if (sourceFilter !== 'all') params.set('source', sourceFilter);
    if (severityFilter !== 'all') params.set('severity', severityFilter);

    try {
      const [tokensRes, ipsRes, logsRes, statsRes, projectsRes] =
        await Promise.all([
          fetch(`/api/collect/tokens?${params}`),
          fetch(`/api/collect/blocked-ips?${params}`),
          fetch(`/api/collect/event-logs?${params}&limit=100`),
          fetch(`/api/collect/stats?${params}`),
          fetch('/api/projects'),
        ]);

      if (tokensRes.ok) {
        const data = await tokensRes.json();
        setTokens(data.tokens || []);
      }
      if (ipsRes.ok) {
        const data = await ipsRes.json();
        setBlockedIPs(data.blockedIPs || []);
      }
      if (logsRes.ok) {
        const data = await logsRes.json();
        setEventLogs(data.events || []);
      }
      if (statsRes.ok) {
        const data = await statsRes.json();
        setStats(data.stats || null);
      }
      if (projectsRes.ok) {
        const data = await projectsRes.json();
        setProjects(data.projects || []);
        if (!selectedProject && data.projects?.length > 0) {
          setSelectedProject(data.projects[0].id);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  }, [selectedProject, timeRange, sourceFilter, severityFilter]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchData();
  }, [fetchData]);

  const handleRevokeToken = async (aliasId: string) => {
    if (
      !confirm(
        'Revoke this session identifier? The underlying token will be blocked immediately.'
      )
    )
      return;
    try {
      const res = await fetch(`/api/collect/tokens/${aliasId}/revoke`, {
        method: 'POST',
      });
      if (res.ok) {
        await fetchData();
      } else {
        setError('Failed to revoke token');
      }
    } catch {
      setError('Failed to revoke token');
    }
  };

  const handleUnblockIP = async (ip: string) => {
    if (!confirm(`Unblock ${ip}?`)) return;
    try {
      const res = await fetch('/api/collect/blocked-ips/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, projectId: selectedProject }),
      });
      if (res.ok) {
        await fetchData();
      } else {
        setError('Failed to unblock IP');
      }
    } catch {
      setError('Failed to unblock IP');
    }
  };

  const tabs: Array<{
    key: ActiveTab;
    label: string;
    icon: string;
    count?: number;
  }> = [
    {
      key: 'event-logs',
      label: 'Event Logs',
      icon: '📋',
      count: stats?.totalEvents,
    },
    {
      key: 'blocked-ips',
      label: 'Blocked IPs',
      icon: '🛡️',
      count: stats?.totalBlockedIPs,
    },
    {
      key: 'tokens',
      label: 'Session Identifiers',
      icon: '🔐',
      count: stats?.totalTokens,
    },
  ];

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <BreadcrumbNav
        items={[BREADCRUMB_PATHS.collect]}
        currentPage="Security Intelligence"
      />

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold bg-gradient-to-r from-green-400 to-cyan-500 bg-clip-text text-transparent">
            Security Intelligence
          </h1>
          <p className="text-gray-400 mt-2">
            Unified view of aliased tokens, blocked IPs, and audit event logs
            from all three CL modes.
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 flex items-center justify-between">
            <span>{error}</span>
            <button
              onClick={() => setError(null)}
              className="text-red-400 hover:text-red-300"
            >
              ✕
            </button>
          </div>
        )}

        {/* Stats Summary */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
              <p className="text-2xl font-bold text-cyan-400">
                {stats.totalEvents.toLocaleString()}
              </p>
              <p className="text-xs text-gray-500 mt-1">Total Events</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
              <p className="text-2xl font-bold text-red-400">
                {stats.blockedEvents.toLocaleString()}
              </p>
              <p className="text-xs text-gray-500 mt-1">Blocked</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
              <p className="text-2xl font-bold text-orange-400">
                {stats.totalBlockedIPs.toLocaleString()}
              </p>
              <p className="text-xs text-gray-500 mt-1">Blocked IPs</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
              <p className="text-2xl font-bold text-green-400">
                {stats.avgLatencyMs.toFixed(1)}ms
              </p>
              <p className="text-xs text-gray-500 mt-1">Avg Latency</p>
            </div>
          </div>
        )}

        {/* Filters Bar */}
        <div className="flex flex-wrap gap-3 mb-6">
          <select
            value={selectedProject}
            onChange={e => setSelectedProject(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200"
          >
            {projects.map(p => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <select
            value={timeRange}
            onChange={e => setTimeRange(e.target.value as typeof timeRange)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200"
          >
            <option value="1h">Last 1 hour</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
          <select
            value={sourceFilter}
            onChange={e => setSourceFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200"
          >
            <option value="all">All Sources</option>
            <option value="internal">Internal CL</option>
            <option value="external">External CL</option>
            <option value="hybrid">Hybrid CL</option>
          </select>
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button
            onClick={fetchData}
            disabled={loading}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            {loading ? 'Loading...' : '🔄 Refresh'}
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-800 mb-6">
          {tabs.map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-5 py-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === tab.key
                  ? 'text-cyan-400 border-cyan-400'
                  : 'text-gray-400 border-transparent hover:text-gray-300'
              }`}
            >
              <span className="mr-1.5">{tab.icon}</span>
              {tab.label}
              {tab.count !== undefined && (
                <span className="ml-2 text-xs bg-gray-800 px-2 py-0.5 rounded-full">
                  {tab.count.toLocaleString()}
                </span>
              )}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-cyan-500" />
          </div>
        ) : (
          <>
            {/* ── Event Logs Tab ── */}
            {activeTab === 'event-logs' && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                {eventLogs.length === 0 ? (
                  <div className="text-center py-12 text-gray-500">
                    <p className="text-lg">No events in this time range</p>
                    <p className="text-sm mt-1">
                      Events from all three CL modes will appear here
                    </p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-gray-400 border-b border-gray-800 bg-gray-900/50">
                          <th className="text-left py-3 px-3">Time</th>
                          <th className="text-left py-3 px-3">Source</th>
                          <th className="text-left py-3 px-3">Tier</th>
                          <th className="text-left py-3 px-3">Decision</th>
                          <th className="text-left py-3 px-3">Score</th>
                          <th className="text-left py-3 px-3">Severity</th>
                          <th className="text-left py-3 px-3">IP</th>
                          <th className="text-left py-3 px-3">Endpoint</th>
                          <th className="text-left py-3 px-3">Latency</th>
                          <th className="text-left py-3 px-3">Rules</th>
                        </tr>
                      </thead>
                      <tbody>
                        {eventLogs.map(log => (
                          <tr
                            key={log.eventId}
                            className="border-b border-gray-800/50 hover:bg-gray-800/30"
                          >
                            <td className="py-2 px-3 text-gray-500 text-xs whitespace-nowrap">
                              {new Date(log.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="py-2 px-3">
                              <span
                                className={`text-xs px-2 py-0.5 rounded-full ${SOURCE_COLORS[log.source]}`}
                              >
                                {log.source}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-gray-400 text-xs font-mono">
                              T{log.tier}
                            </td>
                            <td className="py-2 px-3">
                              <span
                                className={`font-medium ${DECISION_COLORS[log.decision] || 'text-gray-400'}`}
                              >
                                {log.decision}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-gray-300 font-mono text-xs">
                              {log.score}
                            </td>
                            <td className="py-2 px-3">
                              <span
                                className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_COLORS[log.severity]}`}
                              >
                                {log.severity}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-gray-300 font-mono text-xs">
                              {log.ip}
                            </td>
                            <td className="py-2 px-3 text-gray-400 text-xs max-w-[150px] truncate">
                              <span className="text-gray-500 mr-1">
                                {log.method}
                              </span>
                              {log.path}
                            </td>
                            <td className="py-2 px-3 text-gray-400 text-xs">
                              {log.latencyMs < 1
                                ? `${(log.latencyMs * 1000).toFixed(0)}µs`
                                : `${log.latencyMs.toFixed(0)}ms`}
                            </td>
                            <td className="py-2 px-3 text-gray-500 text-xs max-w-[200px] truncate">
                              {log.matchedRules.join(', ') || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* ── Blocked IPs Tab ── */}
            {activeTab === 'blocked-ips' && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                {blockedIPs.length === 0 ? (
                  <div className="text-center py-12 text-gray-500">
                    <p className="text-lg">No blocked IPs</p>
                    <p className="text-sm mt-1">
                      IPs blocked by external, internal, or hybrid modes will
                      appear here
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-gray-800/50">
                    {blockedIPs.map(entry => (
                      <div key={entry.ip} className="p-4 hover:bg-gray-800/30">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-red-400 font-mono font-bold">
                              {entry.ip}
                            </span>
                            <span
                              className={`text-xs px-2 py-0.5 rounded-full ${SOURCE_COLORS[entry.source]}`}
                            >
                              {entry.source}
                            </span>
                            <span className="text-xs text-gray-500">
                              Score:{' '}
                              <span className="text-gray-300 font-mono">
                                {entry.score}
                              </span>
                            </span>
                          </div>
                          <button
                            onClick={() => handleUnblockIP(entry.ip)}
                            className="px-3 py-1.5 bg-green-600/20 text-green-400 hover:bg-green-600/30 rounded text-xs font-medium transition-colors"
                          >
                            Unblock
                          </button>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-3 text-xs text-gray-500">
                          <span>
                            Reason:{' '}
                            <span className="text-gray-400">
                              {entry.reason}
                            </span>
                          </span>
                          <span>
                            Blocked:{' '}
                            {new Date(entry.blockedAt).toLocaleString()}
                          </span>
                          {entry.expiresAt && (
                            <span>
                              Expires:{' '}
                              {new Date(entry.expiresAt).toLocaleString()}
                            </span>
                          )}
                          <span>{entry.eventCount} events</span>
                        </div>
                        {entry.matchedRules.length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {entry.matchedRules.map(rule => (
                              <span
                                key={rule}
                                className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded"
                              >
                                {rule}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── Credential Isolation Tab ── */}
            {activeTab === 'tokens' && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                {tokens.length === 0 ? (
                  <div className="text-center py-12 text-gray-500">
                    <p className="text-lg">No session identifiers</p>
                    <p className="text-sm mt-1">
                      Encrypted session identifiers managed by the SDK will
                      appear here
                    </p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-gray-400 border-b border-gray-800 bg-gray-900/50">
                          <th className="text-left py-3 px-3">Alias ID</th>
                          <th className="text-left py-3 px-3">Original</th>
                          <th className="text-left py-3 px-3">Algorithm</th>
                          <th className="text-left py-3 px-3">Status</th>
                          <th className="text-left py-3 px-3">Created</th>
                          <th className="text-left py-3 px-3">Expires</th>
                          <th className="text-left py-3 px-3">Accesses</th>
                          <th className="text-left py-3 px-3">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {tokens.map(token => (
                          <tr
                            key={token.aliasId}
                            className="border-b border-gray-800/50 hover:bg-gray-800/30"
                          >
                            <td className="py-2 px-3 text-cyan-400 font-mono text-xs">
                              {token.aliasId.slice(0, 16)}…
                            </td>
                            <td className="py-2 px-3 text-gray-300 font-mono text-xs">
                              {token.originalTokenPreview}
                            </td>
                            <td className="py-2 px-3 text-gray-400 text-xs">
                              {token.algorithm}
                            </td>
                            <td className="py-2 px-3">
                              <span
                                className={`text-xs px-2 py-0.5 rounded-full ${STATUS_COLORS[token.status]}`}
                              >
                                {token.status}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-gray-500 text-xs">
                              {new Date(token.createdAt).toLocaleDateString()}
                            </td>
                            <td className="py-2 px-3 text-gray-500 text-xs">
                              {token.expiresAt
                                ? new Date(token.expiresAt).toLocaleDateString()
                                : 'Never'}
                            </td>
                            <td className="py-2 px-3 text-gray-400 text-xs font-mono">
                              {token.accessCount}
                            </td>
                            <td className="py-2 px-3">
                              {token.status === 'active' && (
                                <button
                                  onClick={() =>
                                    handleRevokeToken(token.aliasId)
                                  }
                                  className="px-2 py-1 bg-red-600/20 text-red-400 hover:bg-red-600/30 rounded text-xs font-medium transition-colors"
                                >
                                  Revoke
                                </button>
                              )}
                              {token.revocationReason && (
                                <span className="text-xs text-gray-500 italic">
                                  {token.revocationReason}
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Back links */}
        <div className="pt-6 flex gap-4">
          <Link
            href="/dashboard/collect/surveillance"
            className="text-cyan-400 hover:text-cyan-300 text-sm transition-colors"
          >
            ← Surveillance Dashboard
          </Link>
          <Link
            href="/dashboard"
            className="text-cyan-400 hover:text-cyan-300 text-sm transition-colors"
          >
            → Back to Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
