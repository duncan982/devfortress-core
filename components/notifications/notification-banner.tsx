'use client';

import { useState } from 'react';
import { X, Bell, AlertTriangle, Info, CheckCircle, AlertCircle } from 'lucide-react';
import { logError } from '@core/lib/logger/client';

interface Notification {
  id: string;
  type: 'FEEDBACK' | 'CHAT_ESCALATION' | 'SYSTEM' | 'SECURITY' | 'BILLING' | 'UPDATE';
  title: string;
  message: string;
  status: 'UNREAD' | 'READ' | 'DISMISSED';
  createdAt: string;
}

interface NotificationBannerProps {
  notifications: Notification[];
  onMarkAsRead: (id: string) => void;
  onDismiss: (id: string) => void;
}

/**
 * Notification Banner Component
 * Displays non-intrusive notification banner for in-app messages
 */
export function NotificationBanner({
  notifications,
  onMarkAsRead,
  onDismiss,
}: NotificationBannerProps) {
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set());

  // Find the first unread notification that hasn't been dismissed
  const currentNotification = notifications.find(n =>
    n.status === 'UNREAD' && !dismissedIds.has(n.id)
  );

  if (!currentNotification) {
    return null;
  }

  const getIcon = (type: string) => {
    switch (type) {
      case 'FEEDBACK':
        return <Info className="w-5 h-5" />;
      case 'CHAT_ESCALATION':
        return <AlertTriangle className="w-5 h-5" />;
      case 'SECURITY':
        return <AlertCircle className="w-5 h-5" />;
      case 'BILLING':
        return <CheckCircle className="w-5 h-5" />;
      default:
        return <Bell className="w-5 h-5" />;
    }
  };

  const getVariantStyles = (type: string) => {
    switch (type) {
      case 'SECURITY':
        return 'bg-red-50 border-red-200 text-red-800 dark:bg-red-950 dark:border-red-800 dark:text-red-200';
      case 'CHAT_ESCALATION':
        return 'bg-orange-50 border-orange-200 text-orange-800 dark:bg-orange-950 dark:border-orange-800 dark:text-orange-200';
      case 'BILLING':
        return 'bg-green-50 border-green-200 text-green-800 dark:bg-green-950 dark:border-green-800 dark:text-green-200';
      default:
        return 'bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-950 dark:border-blue-800 dark:text-blue-200';
    }
  };

  const handleMarkAsRead = async () => {
    if (!currentNotification) return;
    try {
      await onMarkAsRead(currentNotification.id);
      setDismissedIds(prev => new Set(prev).add(currentNotification.id));
    } catch (error) {
      logError('Failed to mark notification as read', error);
    }
  };

  const handleDismiss = async () => {
    if (!currentNotification) return;
    try {
      await onDismiss(currentNotification.id);
      setDismissedIds(prev => new Set(prev).add(currentNotification.id));
    } catch (error) {
      logError('Failed to dismiss notification', error);
    }
  };

  return (
    <div className={`fixed top-4 right-4 z-50 max-w-sm ${getVariantStyles(currentNotification.type)} border rounded-lg shadow-lg p-4 transition-all duration-300`}>
      <div className="flex items-start gap-3">
        <div className="flex-shrink-0">
          {getIcon(currentNotification.type)}
        </div>
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-semibold mb-1">
            {currentNotification.title}
          </h4>
          <p className="text-sm opacity-90">
            {currentNotification.message}
          </p>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={handleMarkAsRead}
            className="text-xs opacity-70 hover:opacity-100 transition-opacity"
            title="Mark as read"
          >
            ✓
          </button>
          <button
            onClick={handleDismiss}
            className="text-xs opacity-70 hover:opacity-100 transition-opacity"
            title="Dismiss"
            aria-label="Dismiss notification"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}