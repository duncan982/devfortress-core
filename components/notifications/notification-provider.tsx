'use client';

import { NotificationBanner } from '@core/components/notifications/notification-banner';
import { useNotifications } from '@core/lib/notifications';

/**
 * Notification Provider Component
 * Manages and displays in-app notifications
 */
export function NotificationProvider() {
  const { notifications, markAsRead, dismiss } = useNotifications();

  return (
    <NotificationBanner
      notifications={notifications}
      onMarkAsRead={markAsRead}
      onDismiss={dismiss}
    />
  );
}