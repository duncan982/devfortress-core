'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface SecurityEvent {
  id: string;
  type: 'threat' | 'insight' | 'test' | 'deployment' | 'action';
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  phase: 'BUILD' | 'DEFEND' | 'COLLECT' | 'LEARN';
  timestamp: string;
  link?: string;
}

const SEVERITY_STYLES = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  info: 'bg-neutral-100 text-neutral-800 dark:bg-neutral-700 dark:text-neutral-300',
};

const PHASE_ICONS: Record<string, string> = {
  BUILD: '🔨',
  DEFEND: '🛡️',
  COLLECT: '📥',
  LEARN: '📊',
};

const TYPE_ICONS: Record<string, string> = {
  threat: '⚠️',
  insight: '💡',
  test: '🧪',
  deployment: '🚀',
  action: '⚡',
};

function formatRelativeTime(timestamp: string): string {
  const diff = Date.now() - new Date(timestamp).getTime();
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

/**
 * SecurityEventsFeed displays recent important events across all four phases
 * of the DevFortress flywheel (BUILD → DEFEND → COLLECT → LEARN)
 */
export function SecurityEventsFeed() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'BUILD' | 'DEFEND' | 'COLLECT' | 'LEARN'>('all');

  useEffect(() => {
    fetchEvents();
    // Refresh every 60 seconds
    const interval = setInterval(fetchEvents, 60000);
    return () => clearInterval(interval);
  }, []);

  const fetchEvents = async () => {
    try {
      const response = await fetch('/api/events/recent');
      if (!response.ok) {
        throw new Error('Failed to fetch events');
      }
      const data = await response.json();
      setEvents(data.events || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load events');
    } finally {
      setIsLoading(false);
    }
  };

  const filteredEvents = filter === 'all'
    ? events
    : events.filter(e => e.phase === filter);

  if (isLoading) {
    return (
      <div className="rounded-xl border border-neutral-200 bg-white p-6 dark:border-neutral-700 dark:bg-neutral-800">
        <div className="flex items-center gap-3">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary-600 border-t-transparent" />
          <span className="text-sm text-neutral-500 dark:text-neutral-400">
            Loading security events...
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-800">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-neutral-200 px-5 py-4 dark:border-neutral-700">
        <div className="flex items-center gap-3">
          <span className="text-xl">🔔</span>
          <div>
            <h3 className="font-semibold text-neutral-900 dark:text-white">
              Security Events Feed
            </h3>
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              Recent activity across all phases
            </p>
          </div>
        </div>
        <div className="flex gap-1">
          {(['all', 'BUILD', 'DEFEND', 'COLLECT', 'LEARN'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded-md px-2 py-1 text-xs font-medium transition-colors ${
                filter === f
                  ? 'bg-primary-100 text-primary-700 dark:bg-primary-900/50 dark:text-primary-300'
                  : 'text-neutral-500 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-700'
              }`}
            >
              {f === 'all' ? 'All' : `${PHASE_ICONS[f]} ${f}`}
            </button>
          ))}
        </div>
      </div>

      {/* Events List */}
      <div className="max-h-[400px] overflow-y-auto">
        {error && (
          <div className="px-5 py-3 text-sm text-red-600 dark:text-red-400">
            {error}
          </div>
        )}

        {filteredEvents.length === 0 ? (
          <div className="px-5 py-8 text-center">
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              {events.length === 0
                ? 'No security events yet. Deploy honeypots or install the SDK to start collecting data.'
                : `No ${filter} events found.`}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-neutral-100 dark:divide-neutral-700">
            {filteredEvents.slice(0, 20).map(event => (
              <div
                key={event.id}
                className="flex items-start gap-3 px-5 py-3 transition-colors hover:bg-neutral-50 dark:hover:bg-neutral-750"
              >
                <span className="mt-0.5 text-base" title={event.type}>
                  {TYPE_ICONS[event.type] || '📌'}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    {event.link ? (
                      <Link
                        href={event.link}
                        className="text-sm font-medium text-neutral-900 hover:text-primary-600 dark:text-white dark:hover:text-primary-400"
                      >
                        {event.title}
                      </Link>
                    ) : (
                      <span className="text-sm font-medium text-neutral-900 dark:text-white">
                        {event.title}
                      </span>
                    )}
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${SEVERITY_STYLES[event.severity]}`}
                    >
                      {event.severity}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs text-neutral-500 dark:text-neutral-400 line-clamp-1">
                    {event.description}
                  </p>
                </div>
                <div className="shrink-0 text-right">
                  <span className="text-[10px] text-neutral-400 dark:text-neutral-500">
                    {formatRelativeTime(event.timestamp)}
                  </span>
                  <div className="mt-0.5 text-[10px] text-neutral-400 dark:text-neutral-500">
                    {PHASE_ICONS[event.phase]} {event.phase}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      {filteredEvents.length > 0 && (
        <div className="border-t border-neutral-200 px-5 py-3 dark:border-neutral-700">
          <Link
            href="/dashboard/insights"
            className="text-xs font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
          >
            View all insights →
          </Link>
        </div>
      )}
    </div>
  );
}
