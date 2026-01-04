/**
 * Client-side Notification Hook
 * Handles client-side notification management
 */

import { useState, useEffect } from 'react';
import { createSupabaseClientComponentClient } from '@core/lib/supabase/client';
import { logError, logInfo } from '@core/lib/logger/client';

export interface Notification {
  id: string;
  userId: string;
  type:
    | 'FEEDBACK'
    | 'CHAT_ESCALATION'
    | 'SYSTEM'
    | 'SECURITY'
    | 'BILLING'
    | 'UPDATE';
  title: string;
  message: string;
  metadata?: Record<string, unknown>;
  status: 'UNREAD' | 'READ' | 'DISMISSED';
  readAt?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * React hook for managing notifications
 */
export function useNotifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchNotifications = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/notifications');
      if (!response.ok) {
        throw new Error('Failed to fetch notifications');
      }

      const data = await response.json();
      setNotifications(data.notifications || []);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      logError('Failed to fetch notifications in hook', err);
    } finally {
      setLoading(false);
    }
  };

  const markAsRead = async (notificationId: string) => {
    try {
      const response = await fetch('/api/notifications', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notificationId, action: 'read' }),
      });

      if (!response.ok) {
        throw new Error('Failed to mark as read');
      }

      // Update local state
      setNotifications(prev =>
        prev.map(n =>
          n.id === notificationId
            ? { ...n, status: 'READ', readAt: new Date().toISOString() }
            : n
        )
      );
    } catch (err) {
      logError('Failed to mark notification as read', err);
      throw err;
    }
  };

  const dismiss = async (notificationId: string) => {
    try {
      const response = await fetch('/api/notifications', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notificationId, action: 'dismiss' }),
      });

      if (!response.ok) {
        throw new Error('Failed to dismiss');
      }

      // Update local state
      setNotifications(prev =>
        prev.map(n =>
          n.id === notificationId ? { ...n, status: 'DISMISSED' } : n
        )
      );
    } catch (err) {
      logError('Failed to dismiss notification', err);
      throw err;
    }
  };

  useEffect(() => {
    fetchNotifications();

    // Set up real-time subscription for new notifications
    const setupSubscription = async () => {
      try {
        const supabase = await createSupabaseClientComponentClient();
        const channel = supabase
          .channel('notifications')
          .on(
            'postgres_changes',
            {
              event: 'INSERT',
              schema: 'public',
              table: 'Notification',
            },
            payload => {
              logInfo('New notification received', payload);
              fetchNotifications(); // Refetch to get the new notification
            }
          )
          .subscribe();

        return () => {
          supabase.removeChannel(channel);
        };
      } catch (err) {
        logError('Failed to set up notification subscription', err);
        return () => {}; // Return empty cleanup function
      }
    };

    const cleanup = setupSubscription();

    return () => {
      cleanup.then(cleanupFn => cleanupFn());
    };
  }, []);

  return {
    notifications,
    loading,
    error,
    markAsRead,
    dismiss,
    refetch: fetchNotifications,
  };
}
