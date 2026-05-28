'use client';

import {
  useState,
  useEffect,
  useCallback,
  useRef,
  useTransition,
  useMemo,
  Fragment,
} from 'react';
import Link from 'next/link';
// ── Inline replacements for private-repo path-alias imports (open-core compatibility) ────────

/** Upgrade banner shown when a feature requires a higher tier. */
function UpgradeBanner({
  featureName,
  requiredTier,
}: {
  variant?: string;
  featureName: string;
  requiredTier: string;
  dismissible?: boolean;
}) {
  return (
    <div className="rounded-2xl border border-amber-200 bg-amber-50 p-8 text-center dark:border-amber-800 dark:bg-amber-900/20">
      <div className="mb-3 text-4xl">🔒</div>
      <h2 className="text-xl font-semibold text-neutral-900 dark:text-white">
        {featureName} requires {requiredTier}
      </h2>
      <p className="mt-2 text-neutral-600 dark:text-neutral-400">
        Upgrade your plan at{' '}
        <a href="/pricing" className="font-medium text-primary-600 underline">
          devfortress.net/pricing
        </a>{' '}
        to unlock this feature.
      </p>
    </div>
  );
}

/** Simple breadcrumb navigation component. */
function BreadcrumbNav({
  items,
  currentPage,
}: {
  items: Array<{ label: string; href?: string }>;
  currentPage: string;
}) {
  return (
    <nav className="flex items-center gap-1.5 text-sm text-neutral-500 dark:text-neutral-400">
      {items.map((item, idx) => (
        <span key={idx} className="flex items-center gap-1.5">
          {item.href ? (
            <a
              href={item.href}
              className="hover:text-neutral-700 dark:hover:text-neutral-200"
            >
              {item.label}
            </a>
          ) : (
            <span>{item.label}</span>
          )}
          <span>/</span>
        </span>
      ))}
      <span className="font-medium text-neutral-900 dark:text-white">
        {currentPage}
      </span>
    </nav>
  );
}

/** Breadcrumb path constants. */
const BREADCRUMB_PATHS = {
  dashboard: { label: 'Dashboard', href: '/dashboard' },
  collect: { label: 'Collect' },
};

/** Surveillance mode — filters between all events, agentic, and non-agentic. */
type SurveillanceMode = 'all' | 'agentic' | 'non-agentic';

/** Filter events by surveillance mode using clMode field. */
function filterEventsByMode<T extends { clMode?: string }>(
  events: T[],
  mode: SurveillanceMode
): T[] {
  if (mode === 'all') return events;
  if (mode === 'agentic')
    return events.filter(e => e.clMode === 'internal' || e.clMode === 'hybrid');
  return events.filter(e => !e.clMode || e.clMode === 'external');
}

/** Toggle between surveillance modes. */
function ModeToggle({
  defaultMode = 'all',
  onChange,
}: {
  defaultMode?: SurveillanceMode;
  onChange: (mode: SurveillanceMode) => void;
  persistKey?: string;
}) {
  const modes: SurveillanceMode[] = ['all', 'agentic', 'non-agentic'];
  const [active, setActive] = useState<SurveillanceMode>(defaultMode);
  function handle(m: SurveillanceMode) {
    setActive(m);
    onChange(m);
  }
  return (
    <div className="inline-flex gap-0.5 rounded-lg border border-neutral-200 bg-neutral-100 p-0.5 dark:border-neutral-700 dark:bg-neutral-800">
      {modes.map(m => (
        <button
          key={m}
          onClick={() => handle(m)}
          className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize transition-all ${
            active === m
              ? 'bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white'
              : 'text-neutral-500 hover:text-neutral-700 dark:text-neutral-400'
          }`}
        >
          {m}
        </button>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

interface CollectedEvent {
  id: string;
  eventType: string;
  ip: string;
  requestPath: string;
  method: string;
  severity: string;
  timestamp: string;
  statusCode?: number;
  userAgent?: string;
  headers?: Record<string, unknown>;
  body?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  // v3.1 observability fields
  clMode?: string;
  authPhase?: string;
  actionTaken?: string;
  responseLatencyMs?: number;
  sessionActiveAfterAction?: boolean;
  userId?: string;
  sessionId?: string;
}

interface SurveillanceStats {
  totalEvents: number;
  criticalEvents: number;
  warningEvents: number;
  infoEvents: number;
  uniqueIPs: number;
  topPaths: Array<{ path: string; count: number }>;
  retentionDays: number;
}

interface ConnectionDiagnostics {
  hasProjects: boolean;
  selectedProjectName: string;
  hasApiKey: boolean;
  lastEventAt: string | null;
  totalIngested: number;
  eventSources: string[];
  apiErrors: string[];
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  medium:
    'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  MEDIUM:
    'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
};

const methodColors: Record<string, string> = {
  GET: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
  POST: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  PUT: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  PATCH:
    'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
  DELETE: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
};

export default function CollectSurveillancePage() {
  const [events, setEvents] = useState<CollectedEvent[]>([]);
  const [stats, setStats] = useState<SurveillanceStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isPremium, setIsPremium] = useState(true);
  const [selectedProject, setSelectedProject] = useState<string>('');
  const [projects, setProjects] = useState<Array<{ id: string; name: string }>>(
    []
  );
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('7d');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshRate, setRefreshRate] = useState<number>(30_000); // 30s default
  const [surveillanceMode, setSurveillanceMode] =
    useState<SurveillanceMode>('all');
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [, startTransition] = useTransition();
  const [isGeneratingTest, setIsGeneratingTest] = useState(false);
  const [testGenMessage, setTestGenMessage] = useState<string | null>(null);
  const [diagnostics, setDiagnostics] = useState<ConnectionDiagnostics>({
    hasProjects: false,
    selectedProjectName: '',
    hasApiKey: false,
    lastEventAt: null,
    totalIngested: 0,
    eventSources: [],
    apiErrors: [],
  });
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [connectionCheck, setConnectionCheck] = useState<{
    loading: boolean;
    result: null | {
      connection: {
        hasApiKey: boolean;
        apiKeyPrefix: string | null;
        isReceivingEvents: boolean;
        isReceivingRecently: boolean;
      };
      stats: {
        totalEvents: number;
        recentEvents24h: number;
        latestEvent: {
          eventType: string;
          timestamp: string;
          ip: string;
          source: string;
        } | null;
        sources: Record<string, number>;
      };
      troubleshooting: {
        checks: Array<{ name: string; status: string; message: string }>;
        sdkEndpoint: string;
      };
    };
    error: string | null;
  }>({ loading: false, result: null, error: null });
  const [filter, setFilter] = useState<{
    severity?: string;
    eventType?: string;
  }>({});
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);

  // Filter events based on surveillance mode (Agents vs API vs All)
  const filteredEvents = useMemo(() => {
    return filterEventsByMode(events, surveillanceMode);
  }, [events, surveillanceMode]);

  // Fetch projects
  useEffect(() => {
    async function fetchProjects() {
      try {
        const response = await fetch('/api/projects');
        const data = await response.json();
        const projectList = Array.isArray(data) ? data : data.projects || [];
        if (response.ok && projectList.length > 0) {
          setProjects(projectList);
          setDiagnostics(prev => ({ ...prev, hasProjects: true }));
          if (!selectedProject) {
            setSelectedProject(projectList[0].id);
            setDiagnostics(prev => ({
              ...prev,
              selectedProjectName: projectList[0].name,
            }));
          }
        } else {
          setIsLoading(false);
          setDiagnostics(prev => ({
            ...prev,
            hasProjects: false,
            apiErrors: [
              ...prev.apiErrors,
              'No API projects found. Create a project first.',
            ],
          }));
        }
      } catch (err) {
        setIsLoading(false);
        setDiagnostics(prev => ({
          ...prev,
          apiErrors: [
            ...prev.apiErrors,
            `Failed to fetch projects: ${err instanceof Error ? err.message : 'Unknown error'}`,
          ],
        }));
      }
    }
    fetchProjects();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fetch collected events and stats
  const fetchData = useCallback(async () => {
    if (!selectedProject) {
      setIsLoading(false);
      return;
    }

    try {
      const params = new URLSearchParams();
      params.set('projectId', selectedProject);
      if (filter.severity) params.set('severity', filter.severity);
      if (filter.eventType) params.set('eventType', filter.eventType);

      // Fetch events and stats in parallel
      const [eventsResponse, statsResponse] = await Promise.all([
        fetch(`/api/events?${params.toString()}&limit=100`),
        fetch(`/api/events?projectId=${selectedProject}&statsOnly=true`),
      ]);

      const eventsData = await eventsResponse.json();
      const statsJson = statsResponse.ok ? await statsResponse.json() : null;

      if (!eventsResponse.ok) {
        if (eventsData.code === 'SUBSCRIPTION_REQUIRED') {
          setIsPremium(false);
        }
        setError(eventsData.error);
        setDiagnostics(prev => ({
          ...prev,
          apiErrors: [
            ...prev.apiErrors.slice(-4),
            `Events API: ${eventsData.error || 'Unknown error'}`,
          ],
        }));
        return;
      }

      const eventsList: CollectedEvent[] = eventsData.events || [];
      setEvents(eventsList);

      // Update diagnostics
      const sources = [
        ...new Set(
          eventsList.map(
            e => (e.metadata?.source as string) || e.eventType || 'unknown'
          )
        ),
      ];
      const latestEvent = eventsList.length > 0 ? eventsList[0] : null;

      startTransition(() => {
        setDiagnostics(prev => ({
          ...prev,
          lastEventAt: latestEvent?.timestamp ?? prev.lastEventAt,
          totalIngested: eventsData.total ?? eventsList.length,
          eventSources: sources.slice(0, 10),
          hasApiKey: true, // If we can fetch events, API key works
        }));
      });

      // Also fetch threat stats to include honeypot data
      const threatResponse = await fetch(
        `/api/threats?projectId=${selectedProject}`
      );
      const threatData = threatResponse.ok ? await threatResponse.json() : null;

      startTransition(() => {
        const liveTotal = eventsData.total ?? eventsList.length;
        const threats = threatData?.threats || [];
        const uniqueIPs = new Set([
          ...eventsList.map(e => e.ip),
          ...threats.map((t: { sourceIp?: string }) => t.sourceIp),
        ]).size;

        const pathCounts: Record<string, number> = {};
        [...eventsList, ...threats].forEach((t: { requestPath?: string }) => {
          if (t.requestPath) {
            pathCounts[t.requestPath] = (pathCounts[t.requestPath] || 0) + 1;
          }
        });

        if (statsJson) {
          setStats({
            totalEvents: (statsJson.total ?? liveTotal) + threats.length,
            criticalEvents:
              (statsJson.bySeverity?.CRITICAL ?? 0) +
              (statsJson.bySeverity?.critical ?? 0) +
              threats.filter(
                (t: { severity?: string }) =>
                  t.severity === 'CRITICAL' || t.severity === 'HIGH'
              ).length,
            warningEvents:
              (statsJson.bySeverity?.MEDIUM ?? 0) +
              (statsJson.bySeverity?.medium ?? 0) +
              threats.filter(
                (t: { severity?: string }) => t.severity === 'MEDIUM'
              ).length,
            infoEvents:
              (statsJson.bySeverity?.LOW ?? 0) +
              (statsJson.bySeverity?.low ?? 0) +
              threats.filter(
                (t: { severity?: string }) =>
                  t.severity === 'LOW' || t.severity === 'INFO'
              ).length,
            uniqueIPs,
            topPaths: Object.entries(pathCounts)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 5)
              .map(([path, count]) => ({ path, count })),
            retentionDays:
              timeRange === '24h' ? 1 : timeRange === '7d' ? 7 : 30,
          });
        } else {
          setStats({
            totalEvents: liveTotal + threats.length,
            criticalEvents: 0,
            warningEvents: 0,
            infoEvents: 0,
            uniqueIPs,
            topPaths: Object.entries(pathCounts)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 5)
              .map(([path, count]) => ({ path, count })),
            retentionDays:
              timeRange === '24h' ? 1 : timeRange === '7d' ? 7 : 30,
          });
        }
      });

      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch data');
      setDiagnostics(prev => ({
        ...prev,
        apiErrors: [
          ...prev.apiErrors.slice(-4),
          `Fetch error: ${err instanceof Error ? err.message : 'Unknown error'}`,
        ],
      }));
    } finally {
      setIsLoading(false);
    }
  }, [selectedProject, timeRange, filter]);

  useEffect(() => {
    if (selectedProject) {
      fetchData();
    }
  }, [selectedProject, fetchData]);

  // Handle case where no projects exist
  useEffect(() => {
    if (projects.length === 0 && !selectedProject) {
      const timeout = setTimeout(() => {
        setIsLoading(false);
      }, 3000);
      return () => clearTimeout(timeout);
    }
  }, [projects.length, selectedProject]);

  // Auto-refresh with configurable interval
  useEffect(() => {
    if (autoRefresh && selectedProject) {
      refreshIntervalRef.current = setInterval(fetchData, refreshRate);
    }
    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, [autoRefresh, selectedProject, fetchData, refreshRate]);

  const generateTestEvents = useCallback(async () => {
    if (!selectedProject) return;
    setIsGeneratingTest(true);
    setTestGenMessage(null);
    try {
      const response = await fetch('/api/events/test-generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId: selectedProject }),
      });
      const data = await response.json();
      if (response.ok) {
        setTestGenMessage(`✅ ${data.message}`);
        fetchData();
      } else {
        setTestGenMessage(`❌ ${data.error || 'Failed to generate events'}`);
      }
    } catch {
      setTestGenMessage('❌ Failed to generate test events');
    } finally {
      setIsGeneratingTest(false);
      setTimeout(() => setTestGenMessage(null), 5000);
    }
  }, [selectedProject, fetchData]);

  const verifyConnection = useCallback(async () => {
    if (!selectedProject) return;
    setConnectionCheck({ loading: true, result: null, error: null });
    try {
      const response = await fetch(
        `/api/events/verify-connection?projectId=${selectedProject}`
      );
      const data = await response.json();
      if (response.ok) {
        setConnectionCheck({ loading: false, result: data, error: null });
        // Update diagnostics with real connection data
        setDiagnostics(prev => ({
          ...prev,
          hasApiKey: data.connection.hasApiKey,
          totalIngested: data.stats.totalEvents,
          lastEventAt: data.stats.latestEvent?.timestamp ?? prev.lastEventAt,
        }));
      } else {
        setConnectionCheck({
          loading: false,
          result: null,
          error: data.error || 'Verification failed',
        });
      }
    } catch (err) {
      setConnectionCheck({
        loading: false,
        result: null,
        error: err instanceof Error ? err.message : 'Connection check failed',
      });
    }
  }, [selectedProject]);

  // ── S9: Export filtered events as CSV or JSON ──
  const exportEvents = useCallback(
    (format: 'csv' | 'json') => {
      const filtered = filterEventsByMode(events, surveillanceMode);
      if (filtered.length === 0) return;

      let blob: Blob;
      let filename: string;
      const ts = new Date().toISOString().slice(0, 10);

      if (format === 'json') {
        blob = new Blob([JSON.stringify(filtered, null, 2)], {
          type: 'application/json',
        });
        filename = `devfortress-events-${ts}.json`;
      } else {
        const headers = [
          'id',
          'eventType',
          'ip',
          'method',
          'requestPath',
          'severity',
          'timestamp',
          'statusCode',
          'actionTaken',
          'clMode',
          'authPhase',
          'responseLatencyMs',
        ];
        const rows = filtered.map(e =>
          headers
            .map(h => {
              const val = (e as unknown as Record<string, unknown>)[h];
              const str = val == null ? '' : String(val);
              return `"${str.replace(/"/g, '""')}"`;
            })
            .join(',')
        );
        blob = new Blob([headers.join(',') + '\n' + rows.join('\n')], {
          type: 'text/csv',
        });
        filename = `devfortress-events-${ts}.csv`;
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },
    [events, surveillanceMode]
  );

  const severityColor = (severity: string) =>
    severityColors[severity] ||
    severityColors[severity.toUpperCase()] ||
    'bg-neutral-100 text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300';

  if (!isPremium) {
    return (
      <main className="min-h-screen bg-neutral-50 px-6 py-12 dark:bg-neutral-950">
        <div className="mx-auto max-w-4xl">
          <UpgradeBanner
            variant="feature-gate"
            featureName="Live API Surveillance"
            requiredTier="PRO"
            dismissible={false}
          />
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-6 dark:bg-neutral-950 sm:px-6 sm:py-8">
      <div className="mx-auto max-w-7xl space-y-6">
        {/* Breadcrumb */}
        <BreadcrumbNav
          items={[BREADCRUMB_PATHS.dashboard, BREADCRUMB_PATHS.collect]}
          currentPage="Surveillance Data"
        />

        {/* Header */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold text-neutral-900 dark:text-white sm:text-3xl">
              Live Security Events
            </h1>
            <p className="mt-2 text-neutral-600 dark:text-neutral-400">
              Real-time feed of security events from your applications, APIs and
              AI agents via the DevFortress SDK
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={generateTestEvents}
              disabled={isGeneratingTest || !selectedProject}
              className="rounded-lg border border-green-300 bg-green-50 px-4 py-2 text-sm font-medium text-green-700 hover:bg-green-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-green-700 dark:bg-green-900/20 dark:text-green-300 dark:hover:bg-green-900/40"
              title="Generate sample security events to test your dashboard. Events are tagged as TEST data."
            >
              {isGeneratingTest ? 'Generating…' : '🧪 Generate Test Events'}
            </button>
            <label className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-400">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={e => setAutoRefresh(e.target.checked)}
                className="rounded border-neutral-300"
              />
              Auto-refresh
            </label>
            {autoRefresh && (
              <select
                value={refreshRate}
                onChange={e => setRefreshRate(Number(e.target.value))}
                className="rounded-md border border-neutral-300 bg-white px-2 py-1 text-xs dark:border-neutral-600 dark:bg-neutral-800"
                aria-label="Refresh interval"
              >
                <option value={5000}>5s</option>
                <option value={10000}>10s</option>
                <option value={30000}>30s</option>
                <option value={60000}>1m</option>
              </select>
            )}
            <button
              onClick={() => exportEvents('csv')}
              disabled={events.length === 0}
              className="rounded-lg border border-neutral-300 bg-white px-3 py-1.5 text-xs font-medium text-neutral-700 hover:bg-neutral-50 disabled:opacity-50 dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
              title="Export filtered events as CSV"
            >
              📥 CSV
            </button>
            <button
              onClick={() => exportEvents('json')}
              disabled={events.length === 0}
              className="rounded-lg border border-neutral-300 bg-white px-3 py-1.5 text-xs font-medium text-neutral-700 hover:bg-neutral-50 disabled:opacity-50 dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
              title="Export filtered events as JSON"
            >
              📥 JSON
            </button>
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
            {error}
          </div>
        )}

        {testGenMessage && (
          <div className="rounded-lg border border-green-200 bg-green-50 p-4 text-green-700 dark:border-green-800 dark:bg-green-900/20 dark:text-green-300">
            {testGenMessage}
          </div>
        )}

        {/* Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {projects.length > 0 && (
            <select
              value={selectedProject}
              onChange={e => {
                setSelectedProject(e.target.value);
                const proj = projects.find(p => p.id === e.target.value);
                if (proj)
                  setDiagnostics(prev => ({
                    ...prev,
                    selectedProjectName: proj.name,
                  }));
              }}
              className="rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-200"
            >
              {projects.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          )}

          <div className="flex items-center gap-1 rounded-lg bg-neutral-100 p-1 dark:bg-neutral-800">
            {(['24h', '7d', '30d'] as const).map(range => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${
                  timeRange === range
                    ? 'bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white'
                    : 'text-neutral-600 hover:text-neutral-900 dark:text-neutral-400'
                }`}
              >
                {range}
              </button>
            ))}
          </div>

          <select
            value={filter.severity || ''}
            onChange={e =>
              setFilter(prev => ({
                ...prev,
                severity: e.target.value || undefined,
              }))
            }
            className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={filter.eventType || ''}
            onChange={e =>
              setFilter(prev => ({
                ...prev,
                eventType: e.target.value || undefined,
              }))
            }
            className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800"
          >
            <option value="">All Event Types</option>
            <option value="auth_failure">Auth Failure</option>
            <option value="rate_limit">Rate Limit</option>
            <option value="injection_attempt">Injection</option>
            <option value="4xx_error">4xx Error</option>
            <option value="5xx_error">5xx Error</option>
            <option value="suspicious_pattern">Suspicious</option>
            <option value="bot_traffic">Bot Traffic</option>
          </select>

          {/* Mode Toggle - Agentic/Non-Agentic */}
          <ModeToggle
            defaultMode={surveillanceMode}
            onChange={setSurveillanceMode}
            persistKey="collect-surveillance-mode"
          />
        </div>

        {/* Connection Status Banner */}
        {!isLoading && (
          <div
            className={`flex items-center gap-4 rounded-lg border p-4 ${
              diagnostics.totalIngested > 0
                ? 'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-900/20'
                : 'border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-900/20'
            }`}
          >
            <div
              className={`h-3 w-3 rounded-full flex-shrink-0 ${
                diagnostics.totalIngested > 0
                  ? 'bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.5)]'
                  : 'bg-amber-500 animate-pulse'
              }`}
            />
            <div className="flex-1 min-w-0">
              <p
                className={`text-sm font-medium ${
                  diagnostics.totalIngested > 0
                    ? 'text-green-700 dark:text-green-300'
                    : 'text-amber-700 dark:text-amber-300'
                }`}
              >
                {diagnostics.totalIngested > 0
                  ? `Receiving events (${diagnostics.totalIngested} total)`
                  : 'Waiting for events...'}
              </p>
              {diagnostics.lastEventAt && (
                <p className="text-xs text-green-600 dark:text-green-400">
                  Last event:{' '}
                  {new Date(diagnostics.lastEventAt).toLocaleString()}
                  {diagnostics.eventSources.length > 0 && (
                    <> · Sources: {diagnostics.eventSources.join(', ')}</>
                  )}
                </p>
              )}
              {diagnostics.totalIngested === 0 && (
                <p className="text-xs text-amber-600 dark:text-amber-400">
                  If you have already installed the SDK, check that your API key
                  matches the project and that your application is receiving
                  traffic. Click &quot;Diagnostics&quot; for more details.
                </p>
              )}
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              {autoRefresh && (
                <span className="flex items-center gap-1 text-xs text-neutral-500">
                  <span className="h-2 w-2 animate-pulse rounded-full bg-blue-500" />
                  Live
                </span>
              )}
              <button
                onClick={() => setShowDiagnostics(!showDiagnostics)}
                className="rounded-lg border border-neutral-300 px-3 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-600 dark:text-neutral-300 dark:hover:bg-neutral-700"
              >
                {showDiagnostics ? 'Hide' : 'Diagnostics'}
              </button>
            </div>
          </div>
        )}

        {/* Diagnostics Panel */}
        {showDiagnostics && (
          <div className="rounded-lg border border-neutral-200 bg-white p-5 dark:border-neutral-700 dark:bg-neutral-800">
            <h3 className="mb-4 text-sm font-semibold text-neutral-900 dark:text-white">
              🔍 Connection Diagnostics
            </h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-900">
                <div className="text-xs font-medium text-neutral-500 dark:text-neutral-400">
                  Projects Found
                </div>
                <div
                  className={`mt-1 text-sm font-semibold ${diagnostics.hasProjects ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'}`}
                >
                  {diagnostics.hasProjects
                    ? `✅ ${projects.length} project(s)`
                    : '❌ No projects'}
                </div>
              </div>
              <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-900">
                <div className="text-xs font-medium text-neutral-500 dark:text-neutral-400">
                  Selected Project
                </div>
                <div className="mt-1 text-sm font-semibold text-neutral-900 dark:text-white truncate">
                  {diagnostics.selectedProjectName || 'None selected'}
                </div>
              </div>
              <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-900">
                <div className="text-xs font-medium text-neutral-500 dark:text-neutral-400">
                  Total Events Ingested
                </div>
                <div
                  className={`mt-1 text-sm font-semibold ${diagnostics.totalIngested > 0 ? 'text-green-700 dark:text-green-400' : 'text-amber-700 dark:text-amber-400'}`}
                >
                  {diagnostics.totalIngested > 0
                    ? `✅ ${diagnostics.totalIngested}`
                    : '⏳ 0 events'}
                </div>
              </div>
              <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-900">
                <div className="text-xs font-medium text-neutral-500 dark:text-neutral-400">
                  Last Event Received
                </div>
                <div className="mt-1 text-sm font-semibold text-neutral-900 dark:text-white">
                  {diagnostics.lastEventAt
                    ? new Date(diagnostics.lastEventAt).toLocaleString()
                    : 'Never'}
                </div>
              </div>
              <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-900">
                <div className="text-xs font-medium text-neutral-500 dark:text-neutral-400">
                  Event Sources
                </div>
                <div className="mt-1 text-sm font-semibold text-neutral-900 dark:text-white">
                  {diagnostics.eventSources.length > 0
                    ? diagnostics.eventSources.join(', ')
                    : 'None detected'}
                </div>
              </div>
              <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-900">
                <div className="text-xs font-medium text-neutral-500 dark:text-neutral-400">
                  Auto-Refresh
                </div>
                <div className="mt-1 text-sm font-semibold text-green-700 dark:text-green-400">
                  {autoRefresh
                    ? `✅ Active (every ${refreshRate < 60000 ? `${refreshRate / 1000}s` : `${refreshRate / 60000}m`})`
                    : '⏸️ Paused'}
                </div>
              </div>
            </div>
            {diagnostics.apiErrors.length > 0 && (
              <div className="mt-4">
                <div className="text-xs font-medium text-red-600 dark:text-red-400 mb-2">
                  Recent Errors:
                </div>
                <div className="space-y-1">
                  {diagnostics.apiErrors.map((err, idx) => (
                    <div
                      key={idx}
                      className="rounded bg-red-50 px-3 py-1 text-xs text-red-700 dark:bg-red-950/30 dark:text-red-300"
                    >
                      {err}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {/* Verify Connection Button & Results */}
            <div className="mt-4">
              <button
                onClick={verifyConnection}
                disabled={connectionCheck.loading || !selectedProject}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
              >
                {connectionCheck.loading
                  ? '🔄 Checking...'
                  : '🔌 Verify SDK Connection'}
              </button>
              {connectionCheck.error && (
                <div className="mt-2 rounded bg-red-50 p-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">
                  ❌ {connectionCheck.error}
                </div>
              )}
              {connectionCheck.result && (
                <div className="mt-3 space-y-2">
                  {connectionCheck.result.troubleshooting.checks.map(
                    (check, i) => (
                      <div
                        key={i}
                        className={`flex items-start gap-2 rounded-lg p-3 text-sm ${
                          check.status === 'pass'
                            ? 'bg-green-50 text-green-700 dark:bg-green-950/30 dark:text-green-300'
                            : check.status === 'warn'
                              ? 'bg-amber-50 text-amber-700 dark:bg-amber-950/30 dark:text-amber-300'
                              : 'bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-300'
                        }`}
                      >
                        <span className="shrink-0">
                          {check.status === 'pass'
                            ? '✅'
                            : check.status === 'warn'
                              ? '⚠️'
                              : '❌'}
                        </span>
                        <div>
                          <span className="font-medium">{check.name}:</span>{' '}
                          {check.message}
                        </div>
                      </div>
                    )
                  )}
                  {connectionCheck.result.stats.latestEvent && (
                    <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-900">
                      <div className="text-xs font-medium text-neutral-500 mb-1">
                        Latest Event
                      </div>
                      <div className="text-sm text-neutral-900 dark:text-white">
                        <span className="font-medium">
                          {connectionCheck.result.stats.latestEvent.eventType}
                        </span>
                        {' from '}
                        <span className="font-mono text-xs">
                          {connectionCheck.result.stats.latestEvent.ip}
                        </span>
                        {' at '}
                        {new Date(
                          connectionCheck.result.stats.latestEvent.timestamp
                        ).toLocaleString()}
                      </div>
                    </div>
                  )}
                  {Object.keys(connectionCheck.result.stats.sources).length >
                    0 && (
                    <div className="rounded-lg bg-neutral-50 p-3 dark:bg-neutral-900">
                      <div className="text-xs font-medium text-neutral-500 mb-1">
                        Event Sources (24h)
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(
                          connectionCheck.result.stats.sources
                        ).map(([source, count]) => (
                          <span
                            key={source}
                            className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800 dark:bg-blue-900/40 dark:text-blue-300"
                          >
                            {source}: {count}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="text-xs text-neutral-500 dark:text-neutral-400">
                    SDK Endpoint:{' '}
                    <code className="bg-neutral-100 px-1 rounded dark:bg-neutral-800">
                      {connectionCheck.result.troubleshooting.sdkEndpoint}
                    </code>
                  </div>
                </div>
              )}
            </div>
            <div className="mt-4 rounded-lg bg-blue-50 p-4 dark:bg-blue-950/30">
              <h4 className="text-xs font-semibold text-blue-700 dark:text-blue-400 mb-2">
                Troubleshooting Steps:
              </h4>
              <ol className="text-xs text-blue-600 dark:text-blue-300 space-y-1 list-decimal list-inside">
                <li>
                  Verify your{' '}
                  <code className="bg-blue-100 px-1 rounded dark:bg-blue-900/50">
                    DEVFORTRESS_API_KEY
                  </code>{' '}
                  environment variable matches a project&apos;s surveillance API
                  key
                </li>
                <li>
                  Confirm your application is deployed and receiving HTTP
                  traffic
                </li>
                <li>
                  Check that the SDK endpoint points to{' '}
                  <code className="bg-blue-100 px-1 rounded dark:bg-blue-900/50">
                    https://www.devfortress.net/api/events/ingest
                  </code>
                </li>
                <li>
                  Use the &quot;Generate Test Events&quot; button above to
                  verify the dashboard works
                </li>
                <li>Check your application logs for DevFortress SDK errors</li>
              </ol>
            </div>
          </div>
        )}

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-6">
            <div className="rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
              <div className="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                Total Events
              </div>
              <div className="mt-1 text-2xl font-bold text-neutral-900 dark:text-white">
                {stats.totalEvents}
              </div>
            </div>
            <div className="rounded-xl border border-red-200 bg-red-50 p-5 dark:border-red-800 dark:bg-red-950/30">
              <div className="text-sm font-medium text-red-600 dark:text-red-400">
                Critical / High
              </div>
              <div className="mt-1 text-2xl font-bold text-red-900 dark:text-red-200">
                {stats.criticalEvents}
              </div>
            </div>
            <div className="rounded-xl border border-yellow-200 bg-yellow-50 p-5 dark:border-yellow-800 dark:bg-yellow-950/30">
              <div className="text-sm font-medium text-yellow-600 dark:text-yellow-400">
                Warnings
              </div>
              <div className="mt-1 text-2xl font-bold text-yellow-900 dark:text-yellow-200">
                {stats.warningEvents}
              </div>
            </div>
            <div className="rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
              <div className="text-sm font-medium text-neutral-500 dark:text-neutral-400">
                Unique IPs
              </div>
              <div className="mt-1 text-2xl font-bold text-neutral-900 dark:text-white">
                {stats.uniqueIPs}
              </div>
            </div>
            {/* v3.1 proof-point cards */}
            <div className="rounded-xl border border-violet-200 bg-violet-50 p-5 dark:border-violet-800 dark:bg-violet-950/30">
              <div className="text-sm font-medium text-violet-600 dark:text-violet-400">
                Actions Taken
              </div>
              <div className="mt-1 text-2xl font-bold text-violet-900 dark:text-violet-200">
                {
                  events.filter(
                    e =>
                      e.actionTaken &&
                      !['allowed', 'monitored'].includes(e.actionTaken)
                  ).length
                }
              </div>
              <div className="mt-0.5 text-xs text-violet-500 dark:text-violet-400">
                {events.filter(e => e.actionTaken === 'session_revoked').length}{' '}
                sessions revoked
              </div>
            </div>
            <div className="rounded-xl border border-cyan-200 bg-cyan-50 p-5 dark:border-cyan-800 dark:bg-cyan-950/30">
              <div className="text-sm font-medium text-cyan-600 dark:text-cyan-400">
                Avg Latency
              </div>
              <div className="mt-1 text-2xl font-bold text-cyan-900 dark:text-cyan-200">
                {events.filter(e => e.responseLatencyMs).length > 0
                  ? `${Math.round(events.filter(e => e.responseLatencyMs).reduce((sum, e) => sum + (e.responseLatencyMs || 0), 0) / events.filter(e => e.responseLatencyMs).length)}ms`
                  : '—'}
              </div>
              <div className="mt-0.5 text-xs text-cyan-500 dark:text-cyan-400">
                {events.filter(e => e.clMode).length > 0 && (
                  <>
                    CL:{' '}
                    {events.filter(e => e.clMode === 'internal').length > 0
                      ? 'internal'
                      : events.filter(e => e.clMode === 'hybrid').length > 0
                        ? 'hybrid'
                        : 'external'}
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        {/* S7: Severity Distribution Chart */}
        {stats && stats.totalEvents > 0 && (
          <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
            <h3 className="mb-4 text-lg font-semibold text-neutral-900 dark:text-white">
              📊 Severity Distribution
            </h3>
            {(() => {
              const sevCounts = filteredEvents.reduce<Record<string, number>>(
                (acc, e) => {
                  const sev = (e.severity || 'UNKNOWN').toUpperCase();
                  acc[sev] = (acc[sev] || 0) + 1;
                  return acc;
                },
                {}
              );
              const total = filteredEvents.length || 1;
              const bars: Array<{
                label: string;
                count: number;
                color: string;
                bg: string;
              }> = [
                {
                  label: 'Critical',
                  count: sevCounts['CRITICAL'] || 0,
                  color: 'bg-red-600',
                  bg: 'text-red-700 dark:text-red-300',
                },
                {
                  label: 'High',
                  count: sevCounts['HIGH'] || 0,
                  color: 'bg-orange-500',
                  bg: 'text-orange-700 dark:text-orange-300',
                },
                {
                  label: 'Medium',
                  count: sevCounts['MEDIUM'] || 0,
                  color: 'bg-yellow-500',
                  bg: 'text-yellow-700 dark:text-yellow-300',
                },
                {
                  label: 'Low',
                  count: sevCounts['LOW'] || 0,
                  color: 'bg-green-500',
                  bg: 'text-green-700 dark:text-green-300',
                },
                {
                  label: 'Info',
                  count: sevCounts['INFO'] || 0,
                  color: 'bg-blue-500',
                  bg: 'text-blue-700 dark:text-blue-300',
                },
              ];
              return (
                <div className="space-y-3">
                  {bars
                    .filter(b => b.count > 0)
                    .map(b => (
                      <div key={b.label} className="flex items-center gap-3">
                        <span
                          className={`w-16 text-right text-sm font-medium ${b.bg}`}
                        >
                          {b.label}
                        </span>
                        <div className="h-5 flex-1 overflow-hidden rounded-full bg-neutral-100 dark:bg-neutral-700">
                          <div
                            className={`h-full rounded-full ${b.color} transition-all duration-500`}
                            style={{
                              width: `${Math.max(2, (b.count / total) * 100)}%`,
                            }}
                          />
                        </div>
                        <span className="w-16 text-sm font-medium text-neutral-600 dark:text-neutral-400">
                          {b.count}{' '}
                          <span className="text-xs text-neutral-400">
                            ({Math.round((b.count / total) * 100)}%)
                          </span>
                        </span>
                      </div>
                    ))}
                  {bars.every(b => b.count === 0) && (
                    <p className="text-sm text-neutral-500">
                      No severity data available
                    </p>
                  )}
                </div>
              );
            })()}
          </div>
        )}

        {/* Top Targeted Paths */}
        {stats && stats.topPaths.length > 0 && (
          <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
            <h3 className="mb-4 text-lg font-semibold text-neutral-900 dark:text-white">
              🎯 Most Targeted Endpoints
            </h3>
            <div className="space-y-3">
              {stats.topPaths.map((item, idx) => (
                <div key={idx} className="flex items-center gap-4">
                  <code className="min-w-0 flex-1 truncate text-sm font-mono text-neutral-700 dark:text-neutral-300">
                    {item.path}
                  </code>
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-24 overflow-hidden rounded-full bg-neutral-100 dark:bg-neutral-700">
                      <div
                        className="h-full rounded-full bg-amber-500"
                        style={{
                          width: `${Math.min(100, (item.count / (stats.topPaths[0]?.count || 1)) * 100)}%`,
                        }}
                      />
                    </div>
                    <span className="text-sm font-medium text-neutral-600 dark:text-neutral-400">
                      {item.count}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Events Table */}
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-amber-600 border-t-transparent" />
            <span className="ml-3 text-neutral-600 dark:text-neutral-400">
              Loading events...
            </span>
          </div>
        ) : events.length > 0 ? (
          <div className="rounded-xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
            <div className="p-4 border-b border-neutral-200 dark:border-neutral-800">
              <h3 className="text-lg font-semibold text-neutral-900 dark:text-white">
                📋 Security Events ({events.length})
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-neutral-200 bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-800">
                    <th className="w-8 px-2 py-3" />
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      Time
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      Type
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      Auth Phase
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      Method
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      Path
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      IP
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      Severity
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      Action Taken
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      Latency
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-neutral-600 dark:text-neutral-400">
                      CL Mode
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-100 dark:divide-neutral-800">
                  {filteredEvents.map(event => {
                    const isTest = !!(
                      event.metadata?.isTest ||
                      event.metadata?.testMetadata ||
                      event.metadata?.source === 'test-generate'
                    );
                    const isExpanded = expandedEventId === event.id;
                    // Resolve CL mode: prefer top-level column, fall back to metadata
                    const clModeRaw =
                      event.clMode ||
                      (event.metadata?.clMode as string) ||
                      (event.metadata?.closedLoopMode as string) ||
                      '';
                    const validClModes = ['internal', 'external', 'hybrid'];
                    const clMode = validClModes.includes(
                      clModeRaw.toLowerCase()
                    )
                      ? clModeRaw.toLowerCase()
                      : '—';
                    const clModeColor: Record<string, string> = {
                      internal:
                        'bg-violet-100 text-violet-800 dark:bg-violet-900/30 dark:text-violet-300',
                      external:
                        'bg-cyan-100 text-cyan-800 dark:bg-cyan-900/30 dark:text-cyan-300',
                      hybrid:
                        'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300',
                    };
                    // Resolve auth phase: prefer top-level, fall back to metadata
                    const authPhase =
                      event.authPhase ||
                      (event.metadata?.authPhase as string) ||
                      '';
                    const authPhaseColor: Record<string, string> = {
                      pre_auth:
                        'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
                      post_auth:
                        'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300',
                    };
                    // Resolve action taken
                    const actionTaken =
                      event.actionTaken ||
                      (event.metadata?.actionTaken as string) ||
                      '';
                    const actionColor: Record<string, string> = {
                      blocked:
                        'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
                      rate_limited:
                        'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
                      session_revoked:
                        'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
                      captcha_challenged:
                        'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
                      flagged:
                        'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
                      allowed:
                        'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
                      monitored:
                        'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
                      key_rotated:
                        'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
                      account_suspended:
                        'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
                      mfa_enforced:
                        'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
                      // Any unknown actionTaken falls back to grey via the || fallback below
                    };
                    // Resolve latency
                    const latencyMs =
                      event.responseLatencyMs ||
                      (event.metadata?.responseTime as number) ||
                      null;
                    return (
                      <Fragment key={event.id}>
                        <tr
                          onClick={() =>
                            setExpandedEventId(isExpanded ? null : event.id)
                          }
                          className={`cursor-pointer hover:bg-neutral-50 dark:hover:bg-neutral-800/50 ${isTest ? 'bg-blue-50/50 dark:bg-blue-950/20' : ''}`}
                        >
                          <td className="px-2 py-3 text-neutral-400">
                            <span className="text-xs">
                              {isExpanded ? '▼' : '▶'}
                            </span>
                          </td>
                          <td className="whitespace-nowrap px-4 py-3 text-neutral-600 dark:text-neutral-400">
                            <div className="flex items-center gap-2">
                              {isTest && (
                                <span
                                  className="px-1.5 py-0.5 text-[10px] font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded"
                                  title="Test event - not a real security event"
                                >
                                  TEST
                                </span>
                              )}
                              <span>
                                {new Date(event.timestamp).toLocaleString()}
                              </span>
                            </div>
                          </td>
                          <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-neutral-700 dark:text-neutral-300">
                            {event.eventType}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3">
                            {authPhase ? (
                              <span
                                className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${authPhaseColor[authPhase] || 'bg-neutral-100 text-neutral-600 dark:bg-neutral-700 dark:text-neutral-300'}`}
                              >
                                {authPhase === 'pre_auth'
                                  ? 'Pre-Auth'
                                  : authPhase === 'post_auth'
                                    ? 'Post-Auth'
                                    : authPhase}
                              </span>
                            ) : (
                              <span className="text-xs text-neutral-400">
                                —
                              </span>
                            )}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3">
                            {event.method && (
                              <span
                                className={`rounded px-2 py-0.5 text-xs font-bold ${methodColors[event.method] || 'bg-neutral-100 text-neutral-800 dark:bg-neutral-700 dark:text-neutral-300'}`}
                              >
                                {event.method}
                              </span>
                            )}
                          </td>
                          <td className="max-w-[200px] truncate px-4 py-3 font-mono text-xs text-neutral-700 dark:text-neutral-300">
                            {event.requestPath || '-'}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-neutral-600 dark:text-neutral-400">
                            {event.ip}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3">
                            <span
                              className={`rounded-full px-2 py-0.5 text-xs font-medium ${severityColor(event.severity)}`}
                            >
                              {event.severity}
                            </span>
                          </td>
                          <td className="whitespace-nowrap px-4 py-3">
                            {actionTaken ? (
                              <span
                                className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${actionColor[actionTaken] || 'bg-neutral-100 text-neutral-600 dark:bg-neutral-700 dark:text-neutral-300'}`}
                              >
                                {actionTaken.replace(/_/g, ' ')}
                              </span>
                            ) : (
                              <span className="text-xs text-neutral-400">
                                —
                              </span>
                            )}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-neutral-600 dark:text-neutral-400">
                            {latencyMs ? `${latencyMs}ms` : '—'}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3">
                            {clMode !== '—' ? (
                              <span
                                className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${clModeColor[clMode.toLowerCase()] || 'bg-neutral-100 text-neutral-600 dark:bg-neutral-700 dark:text-neutral-300'}`}
                              >
                                {clMode}
                              </span>
                            ) : (
                              <span className="text-xs text-neutral-400">
                                —
                              </span>
                            )}
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr key={`${event.id}-detail`}>
                            <td
                              colSpan={11}
                              className="bg-neutral-50 px-6 py-4 dark:bg-neutral-800/50"
                            >
                              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
                                {/* User Agent */}
                                <div>
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    User Agent
                                  </h5>
                                  <p className="break-all text-xs text-neutral-700 dark:text-neutral-300">
                                    {event.userAgent ||
                                      (event.metadata?.userAgent as string) ||
                                      'Not collected'}
                                  </p>
                                </div>

                                {/* Security Response Mode */}
                                <div>
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Security Response Mode
                                  </h5>
                                  <p className="text-xs text-neutral-700 dark:text-neutral-300">
                                    {clMode !== '—' ? clMode : 'Not specified'}
                                    {typeof event.metadata?.fallbackReason ===
                                      'string' && (
                                      <span className="ml-2 text-amber-600">
                                        (fallback:{' '}
                                        {event.metadata.fallbackReason})
                                      </span>
                                    )}
                                  </p>
                                </div>

                                {/* Auth Phase */}
                                <div>
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Auth Phase
                                  </h5>
                                  <p className="text-xs text-neutral-700 dark:text-neutral-300">
                                    {authPhase
                                      ? authPhase === 'pre_auth'
                                        ? 'Pre-Authentication'
                                        : 'Post-Authentication'
                                      : 'Not specified'}
                                    {event.userId && (
                                      <span className="ml-2 text-indigo-600 dark:text-indigo-400">
                                        (user: {event.userId.slice(0, 8)}…)
                                      </span>
                                    )}
                                  </p>
                                </div>

                                {/* Action Taken */}
                                <div>
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Action Taken
                                  </h5>
                                  <p className="text-xs text-neutral-700 dark:text-neutral-300">
                                    {actionTaken
                                      ? actionTaken.replace(/_/g, ' ')
                                      : 'Not specified'}
                                    {/* Only show session status when the action could affect the session
                                        (blocked, session_revoked, rate_limited, captcha_challenged).
                                        For allowed/monitored/flagged, session status is irrelevant. */}
                                    {event.sessionActiveAfterAction !==
                                      undefined &&
                                      event.sessionActiveAfterAction !== null &&
                                      actionTaken &&
                                      [
                                        'blocked',
                                        'session_revoked',
                                        'rate_limited',
                                        'captcha_challenged',
                                      ].includes(actionTaken) && (
                                        <span
                                          className={`ml-2 ${event.sessionActiveAfterAction ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}
                                        >
                                          (session{' '}
                                          {event.sessionActiveAfterAction
                                            ? 'active'
                                            : 'terminated'}
                                          )
                                        </span>
                                      )}
                                  </p>
                                </div>

                                {/* Response Latency */}
                                <div>
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Response Latency
                                  </h5>
                                  <p className="text-xs text-neutral-700 dark:text-neutral-300">
                                    {latencyMs
                                      ? `${latencyMs}ms`
                                      : 'Not measured'}
                                    {event.statusCode && (
                                      <span className="ml-2 text-neutral-500">
                                        (HTTP {event.statusCode})
                                      </span>
                                    )}
                                  </p>
                                </div>

                                {/* Metadata / Extra Context */}
                                <div>
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Event ID
                                  </h5>
                                  <code className="break-all text-xs text-neutral-600 dark:text-neutral-400">
                                    {event.id}
                                  </code>
                                </div>

                                {/* Request Headers */}
                                <div className="md:col-span-2 lg:col-span-3">
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Request Headers
                                  </h5>
                                  {event.headers || event.metadata?.headers ? (
                                    <pre className="max-h-40 overflow-auto rounded-lg bg-neutral-900 p-3 text-xs text-neutral-100">
                                      <code>
                                        {JSON.stringify(
                                          event.headers ||
                                            event.metadata?.headers,
                                          null,
                                          2
                                        )}
                                      </code>
                                    </pre>
                                  ) : (
                                    <p className="text-xs text-neutral-400">
                                      No headers collected
                                    </p>
                                  )}
                                </div>

                                {/* Request Body */}
                                <div className="md:col-span-1 lg:col-span-1">
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Request Body
                                  </h5>
                                  {event.body || event.metadata?.requestBody ? (
                                    <pre className="max-h-40 overflow-auto rounded-lg bg-neutral-900 p-3 text-xs text-neutral-100">
                                      <code>
                                        {JSON.stringify(
                                          event.body ||
                                            event.metadata?.requestBody,
                                          null,
                                          2
                                        )}
                                      </code>
                                    </pre>
                                  ) : (
                                    <p className="text-xs text-neutral-400">
                                      No body collected
                                    </p>
                                  )}
                                </div>

                                {/* Response Body */}
                                <div className="md:col-span-1 lg:col-span-1">
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Response Body
                                  </h5>
                                  {event.metadata?.responseBody ? (
                                    <pre className="max-h-40 overflow-auto rounded-lg bg-neutral-900 p-3 text-xs text-neutral-100">
                                      <code>
                                        {JSON.stringify(
                                          event.metadata.responseBody,
                                          null,
                                          2
                                        )}
                                      </code>
                                    </pre>
                                  ) : (
                                    <p className="text-xs text-neutral-400">
                                      No response body collected
                                    </p>
                                  )}
                                </div>

                                {/* Full Metadata */}
                                <div className="md:col-span-1 lg:col-span-1">
                                  <h5 className="mb-1 text-xs font-semibold uppercase text-neutral-500 dark:text-neutral-400">
                                    Additional Metadata
                                  </h5>
                                  {event.metadata ? (
                                    <pre className="max-h-40 overflow-auto rounded-lg bg-neutral-900 p-3 text-xs text-neutral-100">
                                      <code>
                                        {JSON.stringify(
                                          event.metadata,
                                          null,
                                          2
                                        )}
                                      </code>
                                    </pre>
                                  ) : (
                                    <p className="text-xs text-neutral-400">
                                      No metadata
                                    </p>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="rounded-xl border border-neutral-200 bg-white p-12 text-center dark:border-neutral-800 dark:bg-neutral-900">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/50">
              <span className="text-3xl">📥</span>
            </div>
            <h3 className="text-xl font-semibold text-neutral-900 dark:text-white">
              No Events Collected Yet
            </h3>
            <p className="mx-auto mt-2 max-w-md text-sm text-neutral-600 dark:text-neutral-400">
              {diagnostics.hasProjects
                ? 'Your project is set up but no events have been received yet. This could mean your SDK is not yet configured, your application is not receiving traffic, or there may be a configuration issue.'
                : 'Create an API project first, then install the DevFortress SDK in your production API to start collecting threat data.'}
            </p>
            <div className="mt-4 flex justify-center gap-4">
              <button
                onClick={generateTestEvents}
                disabled={isGeneratingTest || !selectedProject}
                className="rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
              >
                {isGeneratingTest ? 'Generating…' : '🧪 Generate Test Events'}
              </button>
              <button
                onClick={() => setShowDiagnostics(true)}
                className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300"
              >
                🔍 View Diagnostics
              </button>
            </div>

            {/* SDK Quick Start */}
            <div className="mx-auto mt-8 max-w-lg rounded-lg bg-neutral-50 p-6 text-left dark:bg-neutral-800">
              <h4 className="mb-3 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                Quick Start — Install the SDK
              </h4>
              <pre className="overflow-x-auto rounded-lg bg-neutral-900 p-4 text-xs text-green-400">
                <code>{`npm install devfortress-sdk

// In your middleware or Express app:
const DF_ENDPOINT = 'https://www.devfortress.net/api/events/ingest';
const DF_API_KEY = 'your-surveillance-api-key';

// Send events via POST with X-DevFortress-Key header
fetch(DF_ENDPOINT, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-DevFortress-Key': DF_API_KEY,
  },
  body: JSON.stringify({
    eventType: 'auth_failure',
    timestamp: new Date().toISOString(),
    ip: clientIp,
    method: 'POST',
    path: '/api/auth/login',
    statusCode: 401,
  }),
});`}</code>
              </pre>
              <p className="mt-3 text-xs text-neutral-500 dark:text-neutral-400">
                Get your surveillance API key from your{' '}
                <Link
                  href="/dashboard/credentials"
                  className="text-primary-600 hover:underline dark:text-primary-400"
                >
                  SDK Credentials
                </Link>{' '}
                page.
              </p>
            </div>
          </div>
        )}

        {/* Data Retention Info */}
        <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-lg">📊</span>
              <div>
                <h4 className="text-sm font-semibold text-neutral-900 dark:text-white">
                  Data Retention
                </h4>
                <p className="text-xs text-neutral-500 dark:text-neutral-400">
                  Your collected events are retained based on your subscription
                  tier
                </p>
              </div>
            </div>
            <Link
              href="/dashboard/insights"
              className="text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400"
            >
              Generate Insights →
            </Link>
          </div>
        </div>
      </div>
    </main>
  );
}
