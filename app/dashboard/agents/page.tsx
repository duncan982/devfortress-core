'use client';

import { useState, useEffect, useCallback } from 'react';

const BREADCRUMB_PATHS = { dashboard: { label: 'Dashboard', href: '/dashboard' } } as const;
function BreadcrumbNav(_props: { items: { label: string; href: string }[]; currentPage: string }) { return null; }

interface AgentSummary {
  agentId: string;
  totalEvents: number;
  eventTypes: Record<string, number>;
  severityDistribution: Record<string, number>;
  avgLatencyMs: number;
  lastSeenAt: string | null;
  actionsTriggered: number;
  topPaths: string[];
  // v4.0 Agentic A1-A4 Fields
  behavioralBaseline?: number[];
  baselineQuality?: number;
  clusterSimilarity?: number;
  activeCampaigns?: string[];
  rateLimitStage?: number;
  nonceStats?: { tracked: number; replaysBlocked: number };
}

interface AgentEvent {
  id: string;
  timestamp: string;
  eventType: string;
  severity: string;
  ip: string;
  path: string | null;
  method: string | null;
  actionTaken: string;
  latencyMs: number | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-blue-500',
  INFO: 'bg-neutral-400',
};

const SEVERITY_BADGES: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  MEDIUM:
    'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  INFO: 'bg-neutral-100 text-neutral-600 dark:bg-neutral-700 dark:text-neutral-300',
};

function formatTime(ts: string): string {
  return new Date(ts).toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatRelative(ts: string | null): string {
  if (!ts) return 'Never';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  const hours = Math.floor(mins / 60);
  const days = Math.floor(hours / 24);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return `${days}d ago`;
}

const pct = (val: number) => `${Math.round(val * 100)}%`;

export default function AgentsPage() {
  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [agentEvents, setAgentEvents] = useState<AgentEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAgents = useCallback(async () => {
    try {
      const url = selectedAgent
        ? `/api/events/agents?agentId=${encodeURIComponent(selectedAgent)}`
        : '/api/events/agents';
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setAgents(data.agents || []);
      if (data.agentDetail) {
        setAgentEvents(data.agentDetail.events || []);
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load agents');
    } finally {
      setIsLoading(false);
    }
  }, [selectedAgent]);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 30_000);
    return () => clearInterval(interval);
  }, [fetchAgents]);

  return (
    <main className="bg-neutral-50 px-4 py-6 font-sans text-neutral-900 transition-colors duration-200 sm:px-6 sm:py-12 dark:bg-neutral-950 dark:text-neutral-100">
      <section className="mx-auto w-full max-w-7xl rounded-2xl border border-neutral-200 bg-white px-4 py-6 shadow-xl sm:rounded-3xl sm:px-10 sm:py-14 dark:border-neutral-800 dark:bg-neutral-950">
        <div className="flex flex-col gap-8">
          <BreadcrumbNav
            items={[BREADCRUMB_PATHS.dashboard]}
            currentPage="Agents"
          />

          {/* Header */}
          <div>
            <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
              Agent Analytics
            </h1>
            <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
              Per-agent event filtering, behavioral baselines, and anomaly
              detection
            </p>
          </div>

          {isLoading ? (
            <div className="flex items-center gap-3 py-12">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary-600 border-t-transparent" />
              <span className="text-sm text-neutral-500 dark:text-neutral-400">
                Loading agent data...
              </span>
            </div>
          ) : error ? (
            <div className="py-6 text-sm text-red-600 dark:text-red-400">
              {error}
            </div>
          ) : agents.length === 0 ? (
            <div className="rounded-xl border border-neutral-200 px-8 py-16 text-center dark:border-neutral-700">
              <p className="text-lg font-medium text-neutral-600 dark:text-neutral-400">
                No agent traffic detected
              </p>
              <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-500">
                Agent events appear when the SDK detects AI agent traffic
                (userId starting with &quot;agent_&quot; or agent event types).
              </p>
            </div>
          ) : (
            <>
              {/* Agent grid */}
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {agents.map(agent => (
                  <AgentCard
                    key={agent.agentId}
                    agent={agent}
                    isSelected={selectedAgent === agent.agentId}
                    onClick={() =>
                      setSelectedAgent(
                        selectedAgent === agent.agentId ? null : agent.agentId
                      )
                    }
                  />
                ))}
              </div>

              {/* Agent detail panel */}
              {selectedAgent && (
                <AgentDetailPanel
                  agent={agents.find(a => a.agentId === selectedAgent)!}
                  events={agentEvents}
                />
              )}
            </>
          )}
        </div>
      </section>
    </main>
  );
}

function AgentCard({
  agent,
  isSelected,
  onClick,
}: {
  agent: AgentSummary;
  isSelected: boolean;
  onClick: () => void;
}) {
  const totalSeverity = Object.values(agent.severityDistribution).reduce(
    (a, b) => a + b,
    0
  );

  return (
    <button
      onClick={onClick}
      className={`rounded-xl border p-4 text-left transition-all ${
        isSelected
          ? 'border-primary-500 bg-primary-50 ring-2 ring-primary-200 dark:border-primary-400 dark:bg-primary-900/20 dark:ring-primary-800'
          : 'border-neutral-200 bg-white hover:border-neutral-300 dark:border-neutral-700 dark:bg-neutral-800 dark:hover:border-neutral-600'
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="min-w-0 flex-1">
          <h3 className="truncate font-mono text-sm font-bold text-neutral-900 dark:text-white">
            {agent.agentId}
          </h3>
          <p className="mt-0.5 text-xs text-neutral-500 dark:text-neutral-400">
            Last seen: {formatRelative(agent.lastSeenAt)}
          </p>
        </div>
        {agent.actionsTriggered > 0 && (
          <span className="rounded-full bg-red-100 px-2 py-0.5 text-[10px] font-bold text-red-700 dark:bg-red-900/30 dark:text-red-300">
            {agent.actionsTriggered} actions
          </span>
        )}
      </div>

      {/* Severity bar chart */}
      <div className="mt-3">
        <div className="flex h-2 overflow-hidden rounded-full bg-neutral-100 dark:bg-neutral-700">
          {Object.entries(agent.severityDistribution).map(([sev, count]) => (
            <div
              key={sev}
              className={`${SEVERITY_COLORS[sev] || 'bg-neutral-300'}`}
              style={{
                width:
                  totalSeverity > 0
                    ? `${(count / totalSeverity) * 100}%`
                    : '0%',
              }}
              title={`${sev}: ${count}`}
            />
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="mt-3 flex gap-4 text-xs text-neutral-500 dark:text-neutral-400">
        <span>{agent.totalEvents.toLocaleString()} events</span>
        <span>{agent.avgLatencyMs}ms avg</span>
        <span>{Object.keys(agent.eventTypes).length} types</span>
      </div>
    </button>
  );
}

function AgentDetailPanel({
  agent,
  events,
}: {
  agent: AgentSummary;
  events: AgentEvent[];
}) {
  const [activeTab, setActiveTab] = useState<'events' | 'activity'>('events');
  const activityEvents = events.filter(e =>
    [
      'tool_call_sequence_violation',
      'agent_loop_detected',
      'prompt_injection',
    ].includes(e.eventType)
  );
  const displayEvents = activeTab === 'events' ? events : activityEvents;

  return (
    <div className="rounded-xl border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-800">
      <div className="border-b border-neutral-200 px-5 py-4 dark:border-neutral-700">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-mono text-sm font-bold text-neutral-900 dark:text-white">
              {agent.agentId}
            </h3>
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              Detailed view &mdash; {agent.totalEvents.toLocaleString()} total
              events
            </p>
          </div>
          <div className="flex space-x-2 bg-neutral-100 p-1 rounded-lg dark:bg-neutral-800">
            <button
              className={`px-3 py-1 text-xs rounded-md ${activeTab === 'events' ? 'bg-white shadow-sm dark:bg-neutral-700 text-neutral-900 dark:text-white' : 'text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300'}`}
              onClick={() => setActiveTab('events')}
            >
              All Events
            </button>
            <button
              className={`px-3 py-1 text-xs rounded-md ${activeTab === 'activity' ? 'bg-white shadow-sm dark:bg-neutral-700 text-neutral-900 dark:text-white' : 'text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300'}`}
              onClick={() => setActiveTab('activity')}
            >
              Agent Activity (A7/A10/A16)
            </button>
          </div>
        </div>
      </div>

      {/* Behavioral baseline */}
      <div className="grid gap-4 border-b border-neutral-200 p-5 sm:grid-cols-4 dark:border-neutral-700">
        <div>
          <p className="text-[10px] uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Event Types
          </p>
          <div className="mt-1 flex flex-wrap gap-1">
            {Object.entries(agent.eventTypes)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5)
              .map(([type, count]) => (
                <span
                  key={type}
                  className="rounded bg-neutral-100 px-1.5 py-0.5 text-[10px] text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
                >
                  {type} ({count})
                </span>
              ))}
          </div>
        </div>

        <div>
          <p className="text-[10px] uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Top Paths
          </p>
          <div className="mt-1 flex flex-col gap-0.5">
            {agent.topPaths.slice(0, 3).map(path => (
              <span
                key={path}
                className="truncate font-mono text-[10px] text-neutral-600 dark:text-neutral-400"
              >
                {path}
              </span>
            ))}
          </div>
        </div>

        <div>
          <p className="text-[10px] uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Avg Latency
          </p>
          <p className="mt-1 text-lg font-bold text-neutral-900 dark:text-white">
            {agent.avgLatencyMs}
            <span className="text-xs font-normal text-neutral-500">ms</span>
          </p>
        </div>

        <div>
          <p className="text-[10px] uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
            Actions Triggered
          </p>
          <p
            className={`mt-1 text-lg font-bold ${
              agent.actionsTriggered > 0
                ? 'text-red-600 dark:text-red-400'
                : 'text-green-600 dark:text-green-400'
            }`}
          >
            {agent.actionsTriggered}
          </p>
        </div>
      </div>

      {/* A1-A4 Agentic Protections */}
      <div className="grid gap-6 border-b border-neutral-200 bg-neutral-50/50 p-5 lg:grid-cols-2 dark:border-neutral-700 dark:bg-neutral-900/20">
        {/* A1: Behavioral Vector */}
        <div>
          <div className="mb-2 flex items-center justify-between">
            <h4 className="text-[10px] font-bold uppercase tracking-widest text-neutral-500">
              A1 · Behavioral Baseline (8D)
            </h4>
            <span className="text-[9px] text-neutral-400">
              Quality: {pct(agent.baselineQuality || 0)}
            </span>
          </div>
          <div className="flex h-24 items-end gap-1 px-1">
            {['LAT', 'ENT', 'DEP', 'VEL', 'DIV', 'REC', 'NOV', 'STA'].map(
              (label, i) => {
                const val = agent.behavioralBaseline?.[i] || 0;
                return (
                  <div key={label} className="group relative flex-1">
                    <div
                      className="w-full rounded-t bg-cyan-500/40 transition-all group-hover:bg-cyan-500"
                      style={{ height: `${Math.max(10, val * 100)}%` }}
                    />
                    <div className="mt-1 text-center text-[7px] font-mono text-neutral-400">
                      {label}
                    </div>
                    {/* Tooltip */}
                    <div className="absolute -top-6 left-1/2 -translate-x-1/2 rounded bg-neutral-800 px-1 py-0.5 text-[8px] text-white opacity-0 transition-opacity group-hover:opacity-100">
                      {val.toFixed(3)}
                    </div>
                  </div>
                );
              }
            )}
          </div>
        </div>

        {/* A2, A3, A4 Stats */}
        <div className="grid grid-cols-2 gap-4">
          <div className="rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-700 dark:bg-neutral-800">
            <p className="text-[9px] font-bold uppercase text-neutral-500">
              A2 · Distributed Cluster
            </p>
            <div className="mt-2 space-y-1">
              <div className="flex justify-between text-[10px]">
                <span className="text-neutral-500">LSH Similarity</span>
                <span
                  className={
                    (agent.clusterSimilarity || 0) > 0.7
                      ? 'text-red-500'
                      : 'text-neutral-700 dark:text-neutral-300'
                  }
                >
                  {pct(agent.clusterSimilarity || 0)}
                </span>
              </div>
              <div className="flex justify-between text-[10px]">
                <span className="text-neutral-500">Active Campaigns</span>
                <span className="font-mono text-neutral-700 dark:text-neutral-300">
                  {agent.activeCampaigns?.length || 0}
                </span>
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-700 dark:bg-neutral-800">
            <p className="text-[9px] font-bold uppercase text-neutral-500">
              A3/A4 · Infrastructure
            </p>
            <div className="mt-2 space-y-1">
              <div className="flex justify-between text-[10px]">
                <span className="text-neutral-500">Rate Limit Stage</span>
                <span
                  className={`rounded px-1 text-[9px] font-bold ${
                    (agent.rateLimitStage || 0) > 0
                      ? 'bg-orange-100 text-orange-700'
                      : 'bg-green-100 text-green-700'
                  }`}
                >
                  T{agent.rateLimitStage || 0}
                </span>
              </div>
              <div className="flex justify-between text-[10px]">
                <span className="text-neutral-500">Nonce Replays</span>
                <span className="text-neutral-700 dark:text-neutral-300">
                  {agent.nonceStats?.replaysBlocked || 0}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Event table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-neutral-200 bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-800/50">
            <tr>
              <th className="px-4 py-2 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                Event
              </th>
              <th className="px-4 py-2 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                Severity
              </th>
              <th className="px-4 py-2 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                Path
              </th>
              <th className="px-4 py-2 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                Action
              </th>
              <th className="px-4 py-2 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                Latency
              </th>
              <th className="px-4 py-2 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                Time
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-100 dark:divide-neutral-700/50">
            {displayEvents.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-6 text-center text-xs text-neutral-500"
                >
                  Select an agent to see detailed events
                </td>
              </tr>
            ) : (
              displayEvents.map(e => (
                <tr
                  key={e.id}
                  className="transition-colors hover:bg-neutral-50 dark:hover:bg-neutral-800/50"
                >
                  <td className="px-4 py-2 text-xs text-neutral-700 dark:text-neutral-300">
                    {e.eventType}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                        SEVERITY_BADGES[e.severity] || SEVERITY_BADGES.LOW
                      }`}
                    >
                      {e.severity}
                    </span>
                  </td>
                  <td className="px-4 py-2 max-w-[200px] truncate font-mono text-[10px] text-neutral-600 dark:text-neutral-400">
                    {e.method} {e.path || '-'}
                  </td>
                  <td className="px-4 py-2 text-xs text-neutral-600 dark:text-neutral-400">
                    {e.actionTaken}
                  </td>
                  <td className="px-4 py-2 text-xs font-mono text-neutral-500">
                    {e.latencyMs !== null ? `${e.latencyMs}ms` : '-'}
                  </td>
                  <td className="px-4 py-2 text-[10px] text-neutral-400">
                    {formatTime(e.timestamp)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
