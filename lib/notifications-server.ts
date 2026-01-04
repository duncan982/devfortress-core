/**
 * Server-side Notification Service
 * Handles server-side notification operations
 */

import { prisma } from '@core/lib/prisma';
import { logError, logInfo } from '@core/lib/logger';
import { Prisma } from '@prisma/client';

interface Notification {
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
  metadata?: Prisma.InputJsonValue;
  status: 'UNREAD' | 'READ' | 'DISMISSED';
  readAt?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * Fetch notifications for a user (server-side)
 */
export async function fetchNotificationsService(userId: string) {
  try {
    const notifications = await prisma.notification.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 10, // Limit to recent notifications
    });

    return notifications.map(n => ({
      id: n.id,
      userId: n.userId,
      type: n.type as Notification['type'],
      title: n.title,
      message: n.message,
      metadata: n.metadata as Record<string, unknown> | undefined,
      status: n.status as Notification['status'],
      readAt: n.readAt?.toISOString(),
      createdAt: n.createdAt.toISOString(),
      updatedAt: n.updatedAt.toISOString(),
    }));
  } catch (error) {
    logError('Failed to fetch notifications', error);
    throw error;
  }
}

/**
 * Mark a notification as read
 */
export async function markNotificationAsRead(
  notificationId: string
): Promise<void> {
  try {
    await prisma.notification.update({
      where: { id: notificationId },
      data: {
        status: 'READ',
        readAt: new Date(),
        updatedAt: new Date(),
      },
    });

    logInfo('Notification marked as read', { notificationId });
  } catch (error) {
    logError('Failed to mark notification as read', error);
    throw error;
  }
}

/**
 * Dismiss a notification
 */
export async function dismissNotification(
  notificationId: string
): Promise<void> {
  try {
    await prisma.notification.update({
      where: { id: notificationId },
      data: {
        status: 'DISMISSED',
        updatedAt: new Date(),
      },
    });

    logInfo('Notification dismissed', { notificationId });
  } catch (error) {
    logError('Failed to dismiss notification', error);
    throw error;
  }
}

/**
 * Create a new notification (for admin/system use)
 */
export async function createNotification(
  userId: string,
  type: Notification['type'],
  title: string,
  message: string,
  metadata?: Prisma.InputJsonValue
): Promise<void> {
  try {
    await prisma.notification.create({
      data: {
        userId,
        type,
        title,
        message,
        metadata: metadata, // JSON field can contain arbitrary data
        status: 'UNREAD',
      },
    });

    logInfo('Notification created', { userId, type, title });
  } catch (error) {
    logError('Failed to create notification', error);
    throw error;
  }
}
