'use client';

/**
 * Audit Logs Admin UI
 * Component for searching, viewing, and exporting audit logs
 */

import { useState, useEffect } from 'react';
import { Download, Search, Filter, Calendar, FileText } from 'lucide-react';
import { logError } from '@core/lib/logger/client';

interface AuditLog {
  id: string;
  userId?: string;
  apiProjectId?: string;
  level: string;
  message: string;
  createdAt: string;
  user?: {
    id: string;
    email: string;
    name?: string;
  };
  apiProject?: {
    id: string;
    name: string;
  };
}

interface AuditLogsResponse {
  logs: AuditLog[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
}

export function AuditLogsAdmin() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);

  // Filters
  const [search, setSearch] = useState('');
  const [level, setLevel] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [limit] = useState(50);
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    fetchLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offset, level, startDate, endDate]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (level) params.append('level', level);
      if (startDate) params.append('startDate', startDate);
      if (endDate) params.append('endDate', endDate);
      params.append('limit', limit.toString());
      params.append('offset', offset.toString());

      const response = await fetch(
        `/api/admin/audit-logs?${params.toString()}`
      );
      if (!response.ok) throw new Error('Failed to fetch logs');

      const data: AuditLogsResponse = await response.json();
      setLogs(data.logs);
      setTotal(data.total);
      setHasMore(data.hasMore);
    } catch (error) {
      logError('Error fetching audit logs', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    setOffset(0);
    fetchLogs();
  };

  const handleExport = async () => {
    try {
      const params = {
        search,
        level,
        startDate,
        endDate,
        limit: 10000,
      };

      const response = await fetch('/api/admin/audit-logs/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });

      if (!response.ok) throw new Error('Failed to export logs');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit-logs-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      logError('Error exporting logs', error);
    }
  };

  const handleGenerateReport = async (reportType: string) => {
    try {
      const end = new Date();
      const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);

      const response = await fetch('/api/admin/audit-logs/compliance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reportType,
          startDate: start.toISOString(),
          endDate: end.toISOString(),
        }),
      });

      if (!response.ok) throw new Error('Failed to generate report');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `compliance-${reportType}-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      logError('Error generating report', error);
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'ERROR':
        return 'text-error-600 bg-error-100 dark:text-error-400 dark:bg-error-900';
      case 'WARN':
        return 'text-warning-600 bg-warning-100 dark:text-warning-400 dark:bg-warning-900';
      case 'INFO':
        return 'text-primary-600 bg-primary-100 dark:text-primary-400 dark:bg-primary-900';
      case 'DEBUG':
        return 'text-neutral-600 bg-neutral-100 dark:text-neutral-400 dark:bg-neutral-800';
      default:
        return 'text-neutral-600 bg-neutral-100 dark:text-neutral-400 dark:bg-neutral-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-neutral-900 dark:text-neutral-100">
            Audit Logs
          </h1>
          <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
            View and manage system audit logs for compliance and security
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          <div className="relative group">
            <button className="flex items-center gap-2 px-4 py-2 bg-neutral-900 dark:bg-neutral-700 text-white rounded-lg hover:bg-neutral-800 dark:hover:bg-neutral-600 transition-colors">
              <FileText className="w-4 h-4" />
              Reports
            </button>
            <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-neutral-800 rounded-lg shadow-xl border border-neutral-200 dark:border-neutral-700 hidden group-hover:block z-10">
              <button
                onClick={() => handleGenerateReport('GDPR')}
                className="block w-full text-left px-4 py-2 hover:bg-neutral-100 dark:hover:bg-neutral-700 text-neutral-900 dark:text-neutral-100 first:rounded-t-lg"
              >
                GDPR Report
              </button>
              <button
                onClick={() => handleGenerateReport('SOC2')}
                className="block w-full text-left px-4 py-2 hover:bg-neutral-100 dark:hover:bg-neutral-700 text-neutral-900 dark:text-neutral-100"
              >
                SOC 2 Report
              </button>
              <button
                onClick={() => handleGenerateReport('GENERAL')}
                className="block w-full text-left px-4 py-2 hover:bg-neutral-100 dark:hover:bg-neutral-700 text-neutral-900 dark:text-neutral-100 last:rounded-b-lg"
              >
                General Report
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Filters Card */}
      <div className="rounded-2xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
              <Search className="w-4 h-4 inline mr-1" />
              Search
            </label>
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              onKeyPress={e => e.key === 'Enter' && handleSearch()}
              placeholder="Search logs..."
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
              <Filter className="w-4 h-4 inline mr-1" />
              Level
            </label>
            <select
              value={level}
              onChange={e => setLevel(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
            >
              <option value="">All Levels</option>
              <option value="ERROR">ERROR</option>
              <option value="WARN">WARN</option>
              <option value="INFO">INFO</option>
              <option value="DEBUG">DEBUG</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
              <Calendar className="w-4 h-4 inline mr-1" />
              Start Date
            </label>
            <input
              type="date"
              value={startDate}
              onChange={e => setStartDate(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
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
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white text-neutral-900 border-neutral-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
            />
          </div>
        </div>
        <button
          onClick={handleSearch}
          className="mt-4 px-6 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
        >
          Apply Filters
        </button>
      </div>

      {/* Results Info */}
      <div className="text-sm text-neutral-600 dark:text-neutral-400">
        Showing {logs.length} of {total} logs
      </div>

      {/* Logs Table Card */}
      <div className="rounded-2xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-neutral-500 dark:text-neutral-400">
            Loading...
          </div>
        ) : logs.length === 0 ? (
          <div className="p-8 text-center text-neutral-500 dark:text-neutral-400">
            No logs found
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-neutral-200 dark:divide-neutral-700">
              <thead className="bg-neutral-50 dark:bg-neutral-800">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                    Level
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                    Message
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                    Project
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-neutral-900 divide-y divide-neutral-200 dark:divide-neutral-700">
                {logs.map(log => (
                  <tr
                    key={log.id}
                    className="hover:bg-neutral-50 dark:hover:bg-neutral-800 transition-colors"
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900 dark:text-neutral-100">
                      {new Date(log.createdAt).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={`px-2 py-1 text-xs font-semibold rounded ${getLevelColor(log.level)}`}
                      >
                        {log.level}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900 dark:text-neutral-100">
                      {log.user?.email || log.userId || 'System'}
                    </td>
                    <td className="px-6 py-4 text-sm text-neutral-900 dark:text-neutral-100 max-w-md truncate">
                      {log.message}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900 dark:text-neutral-100">
                      {log.apiProject?.name || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {logs.length > 0 && (
          <div className="px-6 py-4 bg-neutral-50 dark:bg-neutral-800 flex justify-between items-center border-t border-neutral-200 dark:border-neutral-700">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="px-4 py-2 bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded-lg text-sm font-medium text-neutral-700 dark:text-neutral-200 hover:bg-neutral-50 dark:hover:bg-neutral-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Previous
            </button>
            <span className="text-sm text-neutral-700 dark:text-neutral-300">
              Page {Math.floor(offset / limit) + 1}
            </span>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={!hasMore}
              className="px-4 py-2 bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded-lg text-sm font-medium text-neutral-700 dark:text-neutral-200 hover:bg-neutral-50 dark:hover:bg-neutral-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
