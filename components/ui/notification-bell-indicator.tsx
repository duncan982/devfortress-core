/**
 * Notification Bell Indicator — Header navigation icon
 * Shows unread notification count with a bell icon and dropdown panel.
 */

'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';

/** Format a date string as a relative time-ago label */
function formatTimeAgo(dateStr: string): string {
  const now = Date.now();
  const diff = now - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

interface NotificationSummary {
  unread: number;
  recent: Array<{
    id: string;
    title: string;
    message: string;
    type: string;
    createdAt: string;
  }>;
}

export function NotificationBellIndicator() {
  const [summary, setSummary] = useState<NotificationSummary>({
    unread: 0,
    recent: [],
  });
  const [showPanel, setShowPanel] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);

  // Fetch notifications and update state outside of the effect body
  // to satisfy the react-hooks/set-state-in-effect lint rule
  useEffect(() => {
    let cancelled = false;

    async function pollNotifications() {
      try {
        const res = await fetch('/api/notifications');
        if (!res.ok || cancelled) return;
        const data = await res.json();
        const notifications = data.notifications || [];
        const unread = notifications.filter(
          (n: { status: string }) => n.status === 'UNREAD'
        ).length;
        if (!cancelled) {
          setSummary({ unread, recent: notifications.slice(0, 5) });
        }
      } catch {
        // Silently fail — notification count is not critical
      }
    }

    // Initial fetch + polling
    pollNotifications();
    const interval = setInterval(pollNotifications, 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  // Close panel when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        panelRef.current &&
        !panelRef.current.contains(event.target as Node)
      ) {
        setShowPanel(false);
      }
    }

    if (showPanel) {
      document.addEventListener('mousedown', handleClickOutside);
      return () =>
        document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [showPanel]);

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'SECURITY':
        return 'text-red-500';
      case 'CHAT_ESCALATION':
        return 'text-orange-500';
      case 'BILLING':
        return 'text-green-500';
      default:
        return 'text-blue-500';
    }
  };

  return (
    <div ref={panelRef} className="relative">
      <button
        onClick={() => setShowPanel(!showPanel)}
        className="relative inline-flex items-center justify-center rounded-lg p-1.5 text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-100"
        aria-label={`Notifications${summary.unread > 0 ? ` (${summary.unread} unread)` : ''}`}
        title="Notifications"
      >
        <svg
          className="h-6 w-6"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
          />
        </svg>
        {summary.unread > 0 && (
          <span className="absolute top-0.5 right-0.5 h-2 w-2 rounded-full bg-red-500" />
        )}
      </button>

      {/* Dropdown Panel */}
      {showPanel && (
        <div className="absolute right-0 z-50 mt-2 w-[min(20rem,calc(100vw-1rem))] rounded-lg border border-neutral-200 bg-white shadow-lg dark:border-neutral-700 dark:bg-neutral-800">
          <div className="flex items-center justify-between border-b border-neutral-200 px-4 py-3 dark:border-neutral-700">
            <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              Notifications
            </h3>
            {summary.unread > 0 && (
              <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-700 dark:bg-red-900 dark:text-red-300">
                {summary.unread} unread
              </span>
            )}
          </div>

          <div className="max-h-80 overflow-y-auto">
            {summary.recent.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-neutral-500 dark:text-neutral-400">
                No notifications yet
              </div>
            ) : (
              summary.recent.map(notification => (
                <Link
                  key={notification.id}
                  href="/dashboard/notifications"
                  onClick={() => setShowPanel(false)}
                  className="block border-b border-neutral-100 px-4 py-3 last:border-b-0 hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-750 cursor-pointer"
                >
                  <div className="flex items-start gap-2">
                    <span
                      className={`mt-0.5 text-xs ${getTypeColor(notification.type)}`}
                    >
                      ●
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-neutral-900 dark:text-neutral-100 truncate">
                        {notification.title}
                      </p>
                      <p className="text-xs text-neutral-500 dark:text-neutral-400 line-clamp-2">
                        {notification.message}
                      </p>
                      <p className="mt-1 text-[10px] text-neutral-400 dark:text-neutral-500">
                        {formatTimeAgo(notification.createdAt)}
                      </p>
                    </div>
                  </div>
                </Link>
              ))
            )}
          </div>

          <div className="border-t border-neutral-200 px-4 py-2 dark:border-neutral-700">
            <Link
              href="/dashboard/notifications"
              onClick={() => setShowPanel(false)}
              className="block text-center text-xs font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
            >
              View all notifications
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
