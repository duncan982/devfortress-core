/**
 * Credit enforcement middleware
 * Checks and enforces credit limits before allowing operations
 */

import { logWarn, logError, logInfo } from '../logger';
import {
  getCreditBalance,
  consumeCredits,
} from '../payments/subscription-service';
import { PrismaClient } from '@prisma/client';
import { hasPrivilegedRole } from '../auth/subscription-middleware';

const prisma = new PrismaClient();

interface CreditCheckParams {
  userId?: string;
  organizationId?: string;
  requiredCredits: number;
  operation: string;
  apiProjectId?: string;
}

interface CreditNotificationParams {
  userId?: string;
  organizationId?: string;
  availableCredits: number;
  totalCredits: number;
}

/**
 * Check if user/organization has sufficient credits
 */
export async function checkCredits(
  params: CreditCheckParams
): Promise<boolean> {
  const { userId, organizationId, requiredCredits } = params;

  try {
    const balance = await getCreditBalance({ userId, organizationId });

    if (!balance) {
      logWarn('No credit balance found', { userId, organizationId });
      return false;
    }

    if (balance.available < requiredCredits) {
      logWarn('Insufficient credits', {
        userId,
        organizationId,
        required: requiredCredits,
        available: balance.available,
      });
      return false;
    }

    return true;
  } catch (error) {
    logError('Failed to check credits', { error, params });
    return false;
  }
}

/**
 * Enforce credit limit and consume credits for an operation
 */
export async function enforceCreditsAndConsume(
  params: CreditCheckParams
): Promise<void> {
  const { userId, organizationId, requiredCredits, operation, apiProjectId } =
    params;

  // Check if user is privileged and has no subscription (unlimited)
  if (userId) {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (user && hasPrivilegedRole(user.role)) {
      const subscription = await prisma.subscription.findFirst({
        where: {
          userId,
          status: { in: ['ACTIVE', 'TRIALING'] },
        },
      });
      if (!subscription) {
        // Privileged user without subscription has unlimited credits
        logInfo('Skipping credit enforcement for privileged user without subscription', {
          userId,
          operation,
        });
        return;
      }
    }
  }

  try {
    // Check if credits are available
    const hasCredits = await checkCredits(params);

    if (!hasCredits) {
      throw new Error(
        'Insufficient credits. Please purchase more credits to continue using this feature.'
      );
    }

    // Consume credits
    await consumeCredits({
      userId,
      organizationId,
      amount: requiredCredits,
      reason: operation,
      apiProjectId,
    });

    // Check if notification threshold reached
    const balance = await getCreditBalance({ userId, organizationId });
    if (balance) {
      await checkAndNotifyLowCredits({
        userId,
        organizationId,
        availableCredits: balance.available,
        totalCredits: balance.available + balance.consumed,
      });
    }

    logInfo('Credits consumed successfully', {
      userId,
      organizationId,
      amount: requiredCredits,
      operation,
    });
  } catch (error) {
    logError('Failed to enforce and consume credits', { error, params });
    throw error;
  }
}

/**
 * Check credit level and send notification if below threshold
 */
async function checkAndNotifyLowCredits(params: CreditNotificationParams) {
  const { userId, organizationId, availableCredits, totalCredits } = params;

  try {
    // Calculate percentage remaining
    const percentageRemaining = (availableCredits / totalCredits) * 100;

    // Notify at 20% threshold (80% consumed)
    if (percentageRemaining <= 20 && percentageRemaining > 0) {
      const balance = await prisma.creditBalance.findFirst({
        where: userId ? { userId } : { organizationId },
      });

      if (!balance) return;

      // Check if we've already notified recently (within last 24 hours)
      const lastNotified = balance.lastNotifiedAt;
      const now = new Date();
      const hoursSinceNotification = lastNotified
        ? (now.getTime() - lastNotified.getTime()) / (1000 * 60 * 60)
        : 25; // More than 24 hours

      if (hoursSinceNotification > 24) {
        logWarn('Low credit warning', {
          userId,
          organizationId,
          availableCredits,
          percentageRemaining: percentageRemaining.toFixed(2),
        });

        // Update last notified timestamp
        await prisma.creditBalance.update({
          where: { id: balance.id },
          data: { lastNotifiedAt: now },
        });

        // TODO: Send email/in-app notification to user
        // This could integrate with a notification service
      }
    }

    // Notify if credits completely exhausted
    if (availableCredits === 0) {
      logWarn('Credits exhausted', { userId, organizationId });
      // TODO: Send urgent notification to user
    }
  } catch (error) {
    logError('Failed to check and notify low credits', { error, params });
  }
}

/**
 * Get credit usage statistics
 */
export async function getCreditUsageStats(params: {
  userId?: string;
  organizationId?: string;
}) {
  try {
    const balance = await getCreditBalance(params);

    if (!balance) {
      return {
        available: 0,
        consumed: 0,
        total: 0,
        percentageUsed: 0,
        percentageRemaining: 0,
      };
    }

    const total = balance.available + balance.consumed;
    const percentageUsed = total > 0 ? (balance.consumed / total) * 100 : 0;
    const percentageRemaining = 100 - percentageUsed;

    return {
      available: balance.available,
      consumed: balance.consumed,
      total,
      percentageUsed: Math.round(percentageUsed * 100) / 100,
      percentageRemaining: Math.round(percentageRemaining * 100) / 100,
    };
  } catch (error) {
    logError('Failed to get credit usage stats', { error, params });
    throw error;
  }
}

/**
 * Validate credit requirements for an operation
 */
export function validateCreditRequirement(operationType: string): number {
  // Define credit costs for different operations
  const creditCosts: Record<string, number> = {
    api_generation: 1,
    security_scan: 1,
    honeypot_deployment: 0, // Free to deploy, but counts against tier limits
    documentation_generation: 0, // Free
  };

  return creditCosts[operationType] || 1; // Default to 1 credit
}
