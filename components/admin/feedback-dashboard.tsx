/**
 * Admin Feedback Dashboard Component
 * View and manage user feedback with filtering and status updates
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  ThumbsUp,
  ThumbsDown,
  Lightbulb,
  Bug,
  MessageSquare,
  Filter,
  CheckCircle,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';

type FeedbackType =
  | 'THUMBS_UP'
  | 'THUMBS_DOWN'
  | 'FEATURE_REQUEST'
  | 'BUG_REPORT'
  | 'GENERAL';
type FeedbackStatus =
  | 'NEW'
  | 'REVIEWED'
  | 'PLANNED'
  | 'IN_PROGRESS'
  | 'COMPLETED'
  | 'WONT_FIX'
  | 'DUPLICATE';

interface Feedback {
  id: string;
  type: FeedbackType;
  sentiment: number | null;
  category: string | null;
  page: string | null;
  title: string | null;
  description: string | null;
  status: FeedbackStatus;
  adminNotes: string | null;
  votes: number;
  createdAt: string;
  user: {
    id: string;
    name: string | null;
    email: string;
  } | null;
}

interface FeedbackStats {
  thumbsUp: number;
  thumbsDown: number;
  featureRequests: number;
  bugReports: number;
  newCount: number;
  satisfactionRate: number | null;
}

export function AdminFeedbackDashboard() {
  const [feedbacks, setFeedbacks] = useState<Feedback[]>([]);
  const [stats, setStats] = useState<FeedbackStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [typeFilter, setTypeFilter] = useState<FeedbackType | ''>('');
  const [statusFilter, setStatusFilter] = useState<FeedbackStatus | ''>('');
  const [selectedFeedback, setSelectedFeedback] = useState<Feedback | null>(
    null
  );
  const [adminNotes, setAdminNotes] = useState('');
  const [updating, setUpdating] = useState(false);

  const fetchFeedbacks = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        pageSize: '25',
      });
      if (typeFilter) params.append('type', typeFilter);
      if (statusFilter) params.append('status', statusFilter);

      const response = await fetch(`/api/feedback?${params.toString()}`);
      const data = await response.json();

      if (response.ok) {
        setFeedbacks(data.feedbacks);
        setTotalPages(data.totalPages);
        setStats(data.stats);
      }
    } catch {
      // Error handled silently - component will show loading state
    } finally {
      setLoading(false);
    }
  }, [page, typeFilter, statusFilter]);

  useEffect(() => {
    fetchFeedbacks();
  }, [fetchFeedbacks]);

  const updateFeedbackStatus = async (
    id: string,
    status: FeedbackStatus,
    notes?: string
  ) => {
    setUpdating(true);
    try {
      const response = await fetch(`/api/feedback/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status,
          ...(notes !== undefined && { adminNotes: notes }),
        }),
      });

      if (response.ok) {
        fetchFeedbacks();
        if (selectedFeedback?.id === id) {
          const data = await response.json();
          setSelectedFeedback(data.feedback);
        }
      }
    } catch {
      // Error handled silently - component will show loading state
    } finally {
      setUpdating(false);
    }
  };

  const getTypeIcon = (type: FeedbackType) => {
    switch (type) {
      case 'THUMBS_UP':
        return <ThumbsUp className="h-4 w-4 text-success-500" />;
      case 'THUMBS_DOWN':
        return <ThumbsDown className="h-4 w-4 text-error-500" />;
      case 'FEATURE_REQUEST':
        return <Lightbulb className="h-4 w-4 text-warning-500" />;
      case 'BUG_REPORT':
        return <Bug className="h-4 w-4 text-error-600" />;
      default:
        return <MessageSquare className="h-4 w-4 text-neutral-500" />;
    }
  };

  const getStatusBadge = (status: FeedbackStatus) => {
    const styles: Record<FeedbackStatus, string> = {
      NEW: 'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-400',
      REVIEWED:
        'bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300',
      PLANNED:
        'bg-warning-100 text-warning-700 dark:bg-warning-900/30 dark:text-warning-400',
      IN_PROGRESS:
        'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-400',
      COMPLETED:
        'bg-success-100 text-success-700 dark:bg-success-900/30 dark:text-success-400',
      WONT_FIX:
        'bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300',
      DUPLICATE:
        'bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300',
    };

    return (
      <span
        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${styles[status]}`}
      >
        {status.replace('_', ' ')}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
          <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900">
            <div className="flex items-center gap-2">
              <ThumbsUp className="h-5 w-5 text-success-500" />
              <span className="text-2xl font-bold">{stats.thumbsUp}</span>
            </div>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Positive
            </p>
          </div>
          <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900">
            <div className="flex items-center gap-2">
              <ThumbsDown className="h-5 w-5 text-error-500" />
              <span className="text-2xl font-bold">{stats.thumbsDown}</span>
            </div>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Negative
            </p>
          </div>
          <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900">
            <div className="flex items-center gap-2">
              <Lightbulb className="h-5 w-5 text-warning-500" />
              <span className="text-2xl font-bold">
                {stats.featureRequests}
              </span>
            </div>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Features
            </p>
          </div>
          <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900">
            <div className="flex items-center gap-2">
              <Bug className="h-5 w-5 text-error-600" />
              <span className="text-2xl font-bold">{stats.bugReports}</span>
            </div>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Bugs
            </p>
          </div>
          <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-primary-500" />
              <span className="text-2xl font-bold">{stats.newCount}</span>
            </div>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              New
            </p>
          </div>
          <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-success-500" />
              <span className="text-2xl font-bold">
                {stats.satisfactionRate !== null
                  ? `${stats.satisfactionRate}%`
                  : '-'}
              </span>
            </div>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Satisfaction
            </p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-neutral-500" />
          <select
            value={typeFilter}
            onChange={e => {
              setTypeFilter(e.target.value as FeedbackType | '');
              setPage(1);
            }}
            className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800"
          >
            <option value="">All Types</option>
            <option value="THUMBS_UP">Thumbs Up</option>
            <option value="THUMBS_DOWN">Thumbs Down</option>
            <option value="FEATURE_REQUEST">Feature Request</option>
            <option value="BUG_REPORT">Bug Report</option>
            <option value="GENERAL">General</option>
          </select>
        </div>
        <select
          value={statusFilter}
          onChange={e => {
            setStatusFilter(e.target.value as FeedbackStatus | '');
            setPage(1);
          }}
          className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800"
        >
          <option value="">All Status</option>
          <option value="NEW">New</option>
          <option value="REVIEWED">Reviewed</option>
          <option value="PLANNED">Planned</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="COMPLETED">Completed</option>
          <option value="WONT_FIX">Won&apos;t Fix</option>
          <option value="DUPLICATE">Duplicate</option>
        </select>
        <button
          onClick={() => fetchFeedbacks()}
          className="flex items-center gap-2 rounded-lg border border-neutral-300 px-3 py-2 text-sm hover:bg-neutral-50 dark:border-neutral-600 dark:hover:bg-neutral-800"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Feedback List */}
      <div className="overflow-hidden rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-6 w-6 animate-spin text-neutral-400" />
          </div>
        ) : feedbacks.length === 0 ? (
          <div className="py-12 text-center text-neutral-500">
            No feedback found
          </div>
        ) : (
          <table className="w-full">
            <thead className="border-b border-neutral-200 bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-800">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Content
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  User
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Page
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Date
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-700">
              {feedbacks.map(feedback => (
                <tr
                  key={feedback.id}
                  className="hover:bg-neutral-50 dark:hover:bg-neutral-800/50"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {getTypeIcon(feedback.type)}
                      <span className="text-sm">
                        {feedback.type.replace('_', ' ')}
                      </span>
                    </div>
                  </td>
                  <td className="max-w-xs px-4 py-3">
                    <div className="truncate text-sm">
                      {feedback.title || feedback.description || '-'}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {feedback.user?.email || 'Anonymous'}
                  </td>
                  <td className="px-4 py-3">
                    <code className="text-xs text-primary-600">
                      {feedback.page || '-'}
                    </code>
                  </td>
                  <td className="px-4 py-3">
                    {getStatusBadge(feedback.status)}
                  </td>
                  <td className="px-4 py-3 text-sm text-neutral-600 dark:text-neutral-400">
                    {new Date(feedback.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => {
                        setSelectedFeedback(feedback);
                        setAdminNotes(feedback.adminNotes || '');
                      }}
                      className="text-sm text-primary-600 hover:text-primary-700"
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-neutral-200 px-4 py-3 dark:border-neutral-700">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="rounded-lg px-3 py-1 text-sm hover:bg-neutral-100 disabled:opacity-50 dark:hover:bg-neutral-800"
            >
              Previous
            </button>
            <span className="text-sm text-neutral-600 dark:text-neutral-400">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="rounded-lg px-3 py-1 text-sm hover:bg-neutral-100 disabled:opacity-50 dark:hover:bg-neutral-800"
            >
              Next
            </button>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedFeedback && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl bg-white p-6 shadow-2xl dark:bg-neutral-900">
            <div className="mb-4 flex items-start justify-between">
              <div className="flex items-center gap-3">
                {getTypeIcon(selectedFeedback.type)}
                <h3 className="text-lg font-semibold">
                  {selectedFeedback.type.replace('_', ' ')}
                </h3>
                {getStatusBadge(selectedFeedback.status)}
              </div>
              <button
                onClick={() => setSelectedFeedback(null)}
                className="text-neutral-500 hover:text-neutral-700"
              >
                ×
              </button>
            </div>

            <div className="space-y-4">
              {selectedFeedback.title && (
                <div>
                  <label className="text-sm font-medium text-neutral-600 dark:text-neutral-400">
                    Title
                  </label>
                  <p className="mt-1">{selectedFeedback.title}</p>
                </div>
              )}

              {selectedFeedback.description && (
                <div>
                  <label className="text-sm font-medium text-neutral-600 dark:text-neutral-400">
                    Description
                  </label>
                  <p className="mt-1 whitespace-pre-wrap">
                    {selectedFeedback.description}
                  </p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <label className="font-medium text-neutral-600 dark:text-neutral-400">
                    User
                  </label>
                  <p>{selectedFeedback.user?.email || 'Anonymous'}</p>
                </div>
                <div>
                  <label className="font-medium text-neutral-600 dark:text-neutral-400">
                    Page
                  </label>
                  <code className="text-primary-600">
                    {selectedFeedback.page || '-'}
                  </code>
                </div>
                <div>
                  <label className="font-medium text-neutral-600 dark:text-neutral-400">
                    Date
                  </label>
                  <p>
                    {new Date(selectedFeedback.createdAt).toLocaleString()}
                  </p>
                </div>
                <div>
                  <label className="font-medium text-neutral-600 dark:text-neutral-400">
                    Category
                  </label>
                  <p>{selectedFeedback.category || '-'}</p>
                </div>
              </div>

              {/* Status Update */}
              <div>
                <label className="mb-2 block text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Update Status
                </label>
                <div className="flex flex-wrap gap-2">
                  {(
                    [
                      'REVIEWED',
                      'PLANNED',
                      'IN_PROGRESS',
                      'COMPLETED',
                      'WONT_FIX',
                      'DUPLICATE',
                    ] as FeedbackStatus[]
                  ).map(status => (
                    <button
                      key={status}
                      onClick={() =>
                        updateFeedbackStatus(selectedFeedback.id, status)
                      }
                      disabled={
                        updating || selectedFeedback.status === status
                      }
                      className={`rounded-lg px-3 py-1 text-sm transition-colors ${
                        selectedFeedback.status === status
                          ? 'bg-primary-600 text-white'
                          : 'border border-neutral-300 hover:bg-neutral-100 dark:border-neutral-600 dark:hover:bg-neutral-800'
                      } disabled:opacity-50`}
                    >
                      {status.replace('_', ' ')}
                    </button>
                  ))}
                </div>
              </div>

              {/* Admin Notes */}
              <div>
                <label className="mb-2 block text-sm font-medium text-neutral-600 dark:text-neutral-400">
                  Admin Notes
                </label>
                <textarea
                  value={adminNotes}
                  onChange={e => setAdminNotes(e.target.value)}
                  className="h-24 w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-600 dark:bg-neutral-800"
                  placeholder="Internal notes about this feedback..."
                />
                <button
                  onClick={() =>
                    updateFeedbackStatus(
                      selectedFeedback.id,
                      selectedFeedback.status,
                      adminNotes
                    )
                  }
                  disabled={updating}
                  className="mt-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
                >
                  {updating ? 'Saving...' : 'Save Notes'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AdminFeedbackDashboard;
