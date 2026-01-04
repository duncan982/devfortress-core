'use client';

/**
 * Honeypot logs component
 * Displays threat event logs with filtering and pagination
 */

import { useState, useEffect, useCallback } from 'react';
import { ThreatSeverity } from '@prisma/client';

interface ThreatEvent {
  id: string;
  sourceIp: string;
  userAgent: string | null;
  severity: ThreatSeverity;
  tags: string[];
  payload: {
    isTest?: boolean;
    testMetadata?: {
      isTest: boolean;
      testUser?: {
        id: string;
        email: string;
        name: string;
        isAdmin: boolean;
      };
      testTarget?: {
        honeypotId: string;
        honeypotName?: string;
        testTimestamp: string;
        testId: string;
        testType?: string;
      };
    };
    path?: string;
    method?: string;
    [key: string]: unknown;
  } | null;
  detectedAt: Date;
  isFalsePositive: boolean;
}

interface LogsResponse {
  honeypotId: string;
  honeypotName: string;
  events: ThreatEvent[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

interface HoneypotLogsProps {
  honeypotId: string;
  honeypotName: string;
}

export default function HoneypotLogs({
  honeypotId,
  honeypotName,
}: HoneypotLogsProps) {
  const [logs, setLogs] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);

  // Filters
  const [severity, setSeverity] = useState<ThreatSeverity | ''>('');
  const [pattern, setPattern] = useState('');
  const [ip, setIp] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  const fetchLogs = useCallback(
    async (page = 1) => {
      setLoading(true);
      try {
        const params = new URLSearchParams({
          page: page.toString(),
          limit: '50',
        });

        if (severity) params.append('severity', severity);
        if (pattern) params.append('pattern', pattern);
        if (ip) params.append('ip', ip);
        if (startDate) params.append('startDate', startDate);
        if (endDate) params.append('endDate', endDate);

        const response = await fetch(
          `/api/honeypots/${honeypotId}/logs?${params}`
        );
        if (!response.ok) throw new Error('Failed to fetch logs');

        const data: LogsResponse = await response.json();
        setLogs(data.events);
        setTotal(data.pagination.total);
        setTotalPages(data.pagination.totalPages);
        setCurrentPage(data.pagination.page);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error('Failed to fetch honeypot logs:', error);
      } finally {
        setLoading(false);
      }
    },
    [honeypotId, severity, pattern, ip, startDate, endDate]
  );

  useEffect(() => {
    fetchLogs(1);
  }, [fetchLogs]);

  const handlePageChange = (page: number) => {
    fetchLogs(page);
  };

  const clearFilters = () => {
    setSeverity('');
    setPattern('');
    setIp('');
    setStartDate('');
    setEndDate('');
  };

  const severityColors: Record<ThreatSeverity, string> = {
    LOW: 'bg-neutral-100 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200',
    MEDIUM:
      'bg-warning-100 text-warning-800 dark:bg-warning-900 dark:text-warning-200',
    HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
    CRITICAL:
      'bg-error-100 text-error-800 dark:bg-error-900 dark:text-error-200',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold">Threat Logs</h2>
          <p className="text-neutral-600 dark:text-neutral-400">
            Monitor and analyze security threats detected by {honeypotName}
          </p>
        </div>
        <div className="text-sm text-neutral-500">{total} total events</div>
      </div>

      {/* Filters */}
      <div className="rounded-2xl border border-neutral-200 bg-neutral-50 p-6 dark:border-neutral-800 dark:bg-neutral-900">
        <h3 className="text-lg font-semibold mb-4">Filters</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
              Severity
            </label>
            <select
              value={severity}
              onChange={e => setSeverity(e.target.value as ThreatSeverity | '')}
              className="w-full px-3 py-2 border border-neutral-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:bg-neutral-800 dark:border-neutral-700 dark:text-white"
            >
              <option value="">All Severities</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
              Attack Pattern
            </label>
            <input
              type="text"
              value={pattern}
              onChange={e => setPattern(e.target.value)}
              placeholder="e.g., SQL_INJECTION"
              className="w-full px-3 py-2 border border-neutral-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:bg-neutral-800 dark:border-neutral-700 dark:text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
              Source IP
            </label>
            <input
              type="text"
              value={ip}
              onChange={e => setIp(e.target.value)}
              placeholder="e.g., 192.168.1.1"
              className="w-full px-3 py-2 border border-neutral-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:bg-neutral-800 dark:border-neutral-700 dark:text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
              Start Date
            </label>
            <input
              type="date"
              value={startDate}
              onChange={e => setStartDate(e.target.value)}
              className="w-full px-3 py-2 border border-neutral-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:bg-neutral-800 dark:border-neutral-700 dark:text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
              End Date
            </label>
            <input
              type="date"
              value={endDate}
              onChange={e => setEndDate(e.target.value)}
              className="w-full px-3 py-2 border border-neutral-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:bg-neutral-800 dark:border-neutral-700 dark:text-white"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={clearFilters}
              className="px-4 py-2 text-sm font-medium text-neutral-700 bg-white border border-neutral-300 rounded-lg hover:bg-neutral-50 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-700"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="rounded-2xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-950 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
            <p className="mt-4 text-sm text-neutral-600 dark:text-neutral-400">
              Loading threat logs...
            </p>
          </div>
        ) : logs.length === 0 ? (
          <div className="p-12 text-center">
            <div className="text-6xl mb-4">🛡️</div>
            <h3 className="text-xl font-semibold mb-2">
              No threat events found
            </h3>
            <p className="text-neutral-600 dark:text-neutral-400">
              {total === 0
                ? "This honeypot hasn't detected any threats yet."
                : 'No events match your current filters.'}
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-neutral-50 dark:bg-neutral-900 border-b border-neutral-200 dark:border-neutral-700">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                      Time
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                      IP Address
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                      Patterns
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                      Details
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-neutral-950 divide-y divide-neutral-200 dark:divide-neutral-800">
                  {logs.map(event => {
                    const isTest =
                      event.payload?.isTest ||
                      event.payload?.testMetadata?.isTest;
                    return (
                      <tr
                        key={event.id}
                        className={`hover:bg-neutral-50 dark:hover:bg-neutral-900 ${isTest ? 'bg-blue-50/50 dark:bg-blue-950/20' : ''}`}
                      >
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900 dark:text-neutral-100">
                          <div className="flex items-center gap-2">
                            {isTest && (
                              <span
                                className="px-1.5 py-0.5 text-[10px] font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded"
                                title="Test event - not a real attack"
                              >
                                TEST
                              </span>
                            )}
                            <span>
                              {new Date(event.detectedAt).toLocaleString()}
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-neutral-900 dark:text-neutral-100">
                          {event.sourceIp}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span
                            className={`px-2 py-1 text-xs font-medium rounded-full ${severityColors[event.severity]}`}
                          >
                            {event.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex flex-wrap gap-1">
                            {event.tags.slice(0, 3).map(tag => (
                              <span
                                key={tag}
                                className="px-2 py-1 text-xs bg-neutral-100 dark:bg-neutral-800 text-neutral-800 dark:text-neutral-200 rounded"
                              >
                                {tag}
                              </span>
                            ))}
                            {event.tags.length > 3 && (
                              <span className="px-2 py-1 text-xs bg-neutral-100 dark:bg-neutral-800 text-neutral-800 dark:text-neutral-200 rounded">
                                +{event.tags.length - 3}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 text-sm text-neutral-500 dark:text-neutral-400 max-w-xs truncate">
                          {event.payload?.path ||
                            event.payload?.method ||
                            'N/A'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="px-6 py-4 border-t border-neutral-200 dark:border-neutral-700 flex items-center justify-between">
                <div className="text-sm text-neutral-700 dark:text-neutral-300">
                  Showing {(currentPage - 1) * 50 + 1} to{' '}
                  {Math.min(currentPage * 50, total)} of {total} events
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="px-3 py-1 text-sm border border-neutral-300 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-800"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => handlePageChange(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className="px-3 py-1 text-sm border border-neutral-300 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-800"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
