/**
 * Notification service for credit-related alerts
 * Sends notifications via email and in-app messaging
 */

import { logInfo, logError } from '../logger';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export enum NotificationType {
  LOW_CREDITS = 'low_credits',
  CREDITS_EXHAUSTED = 'credits_exhausted',
  CREDITS_PURCHASED = 'credits_purchased',
  SUBSCRIPTION_RENEWED = 'subscription_renewed',
}

interface NotificationParams {
  userId?: string;
  organizationId?: string;
  type: NotificationType;
  data: Record<string, string | number>;
}

/**
 * Send a credit notification to user
 */
export async function sendCreditNotification(params: NotificationParams) {
  const { userId, organizationId, type, data } = params;

  try {
    logInfo('Sending credit notification', { userId, organizationId, type });

    // Get user information and preferences
    let user;
    let preferences;
    if (userId) {
      user = await prisma.user.findUnique({
        where: { id: userId },
      });

      preferences = await prisma.notificationPreference.findUnique({
        where: { userId },
      });
    }

    // Check if user has opted in to notifications
    if (preferences?.creditAlertsEnabled === false) {
      logInfo('User has disabled credit notifications', { userId });
      return;
    }

    // Send notification based on type
    if (user) {
      switch (type) {
        case NotificationType.LOW_CREDITS:
          await sendLowCreditsNotification(user, data);
          break;

        case NotificationType.CREDITS_EXHAUSTED:
          await sendCreditsExhaustedNotification(user, data);
          break;

        case NotificationType.CREDITS_PURCHASED:
          await sendCreditsPurchasedNotification(user, data);
          break;

        case NotificationType.SUBSCRIPTION_RENEWED:
          await sendSubscriptionRenewedNotification(user, data);
          break;

        default:
          logError('Unknown notification type', { type });
      }
    }

    logInfo('Credit notification sent successfully', { userId, type });
  } catch (error) {
    logError('Failed to send credit notification', { error, params });
  }
}

interface User {
  id: string;
  email: string;
  name?: string | null;
}

/**
 * Send low credits warning notification
 */
async function sendLowCreditsNotification(
  user: User | null,
  data: Record<string, string | number>
) {
  const { availableCredits, percentageRemaining } = data;

  // TODO: Integrate with email service (SendGrid/Resend)
  logInfo('Low credits notification', {
    userId: user?.id,
    email: user?.email,
    availableCredits,
    percentageRemaining,
  });

  // Email template:
  // Subject: Low Credit Balance Alert
  // Body: You have {availableCredits} credits remaining ({percentageRemaining}%)
  //       Purchase more credits to avoid service interruption.
}

/**
 * Send credits exhausted notification
 */
async function sendCreditsExhaustedNotification(
  user: User | null,
  _data: Record<string, string | number>
) {
  // TODO: Integrate with email service
  logInfo('Credits exhausted notification', {
    userId: user?.id,
    email: user?.email,
  });

  // Email template:
  // Subject: Action Required: Credits Exhausted
  // Body: Your API generation credits have been exhausted.
  //       Purchase more credits to continue using VortexSecure.
}

/**
 * Send credits purchased confirmation
 */
async function sendCreditsPurchasedNotification(
  user: User | null,
  data: Record<string, string | number>
) {
  const { creditsPurchased, newBalance } = data;

  // TODO: Integrate with email service
  logInfo('Credits purchased notification', {
    userId: user?.id,
    email: user?.email,
    creditsPurchased,
    newBalance,
  });

  // Email template:
  // Subject: Credit Purchase Confirmed
  // Body: You've successfully purchased {creditsPurchased} credits.
  //       Your new balance is {newBalance} credits.
}

/**
 * Send subscription renewed notification
 */
async function sendSubscriptionRenewedNotification(
  user: User | null,
  data: Record<string, string | number>
) {
  const { plan, creditsAllocated } = data;

  // TODO: Integrate with email service
  logInfo('Subscription renewed notification', {
    userId: user?.id,
    email: user?.email,
    plan,
    creditsAllocated,
  });

  // Email template:
  // Subject: Subscription Renewed
  // Body: Your {plan} subscription has been renewed.
  //       {creditsAllocated} credits have been added to your account.
}

/**
 * Get user notification preferences
 */
export async function getNotificationPreferences(userId: string) {
  try {
    let prefs = await prisma.notificationPreference.findUnique({
      where: { userId },
    });

    // Create default preferences if they don't exist
    if (!prefs) {
      prefs = await prisma.notificationPreference.create({
        data: {
          userId,
          creditAlertsEnabled: true,
          securityAlertsEnabled: true,
          marketingOptIn: false,
        },
      });
    }

    return prefs;
  } catch (error) {
    logError('Failed to get notification preferences', { error, userId });
    throw error;
  }
}

/**
 * Update user notification preferences
 */
export async function updateNotificationPreferences(
  userId: string,
  preferences: {
    creditAlertsEnabled?: boolean;
    securityAlertsEnabled?: boolean;
    marketingOptIn?: boolean;
  }
) {
  try {
    logInfo('Updating notification preferences', { userId, preferences });

    const prefs = await prisma.notificationPreference.upsert({
      where: { userId },
      update: preferences,
      create: {
        userId,
        creditAlertsEnabled: preferences.creditAlertsEnabled ?? true,
        securityAlertsEnabled: preferences.securityAlertsEnabled ?? true,
        marketingOptIn: preferences.marketingOptIn ?? false,
      },
    });

    logInfo('Notification preferences updated', { userId });

    return prefs;
  } catch (error) {
    logError('Failed to update notification preferences', { error, userId });
    throw error;
  }
}
