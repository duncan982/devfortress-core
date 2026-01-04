/**
 * Subscription service for managing user subscriptions
 * Handles subscription creation, updates, cancellations, and credit allocation
 */

import {
  PrismaClient,
  SubscriptionPlan,
  SubscriptionStatus,
} from '@prisma/client';
import { logInfo, logError, logWarn } from '../logger';
import {
  SubscriptionTier,
  SUBSCRIPTION_PRICING,
  PaymentProvider,
} from './types';

const prisma = new PrismaClient();

interface CreateSubscriptionParams {
  userId?: string;
  organizationId?: string;
  plan: SubscriptionPlan;
  provider: PaymentProvider;
  providerReference: string;
  seats?: number;
}

interface UpdateSubscriptionParams {
  subscriptionId: string;
  status?: SubscriptionStatus;
  plan?: SubscriptionPlan;
  seats?: number;
  renewsAt?: Date;
  canceledAt?: Date;
}

/**
 * Create a new subscription for a user or organization
 */
export async function createSubscription(params: CreateSubscriptionParams) {
  const { userId, organizationId, plan, provider, providerReference, seats } =
    params;

  try {
    logInfo('Creating subscription', {
      userId,
      organizationId,
      plan,
      provider,
    });

    // Validate that either userId or organizationId is provided
    if (!userId && !organizationId) {
      throw new Error('Either userId or organizationId must be provided');
    }

    // Get pricing info (STARTER tier commented out)
    if (plan === SubscriptionTier.STARTER) {
      throw new Error('STARTER tier is no longer available - free tier commented out');
    }
    const pricing = SUBSCRIPTION_PRICING[plan as keyof typeof SUBSCRIPTION_PRICING];
    if (!pricing) {
      throw new Error(`Invalid subscription plan: ${plan}`);
    }

    // Create subscription
    const subscription = await prisma.subscription.create({
      data: {
        plan,
        status: SubscriptionStatus.ACTIVE,
        provider,
        providerReference,
        seats: seats || pricing.seats,
        renewsAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
        userId,
        organizationId,
      },
    });

    // Allocate credits based on plan
    await allocateCredits({
      userId,
      organizationId,
      amount: pricing.apiGenerations,
      reason: `Initial allocation for ${plan} plan`,
      subscriptionId: subscription.id,
    });

    logInfo('Subscription created successfully', {
      subscriptionId: subscription.id,
      plan,
    });

    return subscription;
  } catch (error) {
    logError('Failed to create subscription', { error, params });
    throw error;
  }
}

/**
 * Update an existing subscription
 */
export async function updateSubscription(params: UpdateSubscriptionParams) {
  const { subscriptionId, ...updateData } = params;

  try {
    logInfo('Updating subscription', { subscriptionId, updateData });

    const subscription = await prisma.subscription.update({
      where: { id: subscriptionId },
      data: updateData,
    });

    logInfo('Subscription updated successfully', { subscriptionId });

    return subscription;
  } catch (error) {
    logError('Failed to update subscription', { error, subscriptionId });
    throw error;
  }
}

/**
 * Cancel a subscription
 */
export async function cancelSubscription(subscriptionId: string) {
  try {
    logInfo('Cancelling subscription', { subscriptionId });

    const subscription = await prisma.subscription.update({
      where: { id: subscriptionId },
      data: {
        status: SubscriptionStatus.CANCELED,
        canceledAt: new Date(),
      },
    });

    logInfo('Subscription cancelled successfully', { subscriptionId });

    return subscription;
  } catch (error) {
    logError('Failed to cancel subscription', { error, subscriptionId });
    throw error;
  }
}

/**
 * Get subscription by provider reference
 */
export async function getSubscriptionByProviderRef(providerReference: string) {
  try {
    const subscription = await prisma.subscription.findUnique({
      where: { providerReference },
      include: {
        user: true,
        organization: true,
      },
    });

    return subscription;
  } catch (error) {
    logError('Failed to get subscription', { error, providerReference });
    throw error;
  }
}

/**
 * Get user's active subscription
 */
export async function getUserSubscription(userId: string) {
  try {
    const subscription = await prisma.subscription.findFirst({
      where: {
        userId,
        status: {
          in: [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING],
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return subscription;
  } catch (error) {
    logError('Failed to get user subscription', { error, userId });
    throw error;
  }
}

/**
 * Get organization's active subscription
 */
export async function getOrganizationSubscription(organizationId: string) {
  try {
    const subscription = await prisma.subscription.findFirst({
      where: {
        organizationId,
        status: {
          in: [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING],
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return subscription;
  } catch (error) {
    logError('Failed to get organization subscription', {
      error,
      organizationId,
    });
    throw error;
  }
}

interface AllocateCreditsParams {
  userId?: string;
  organizationId?: string;
  amount: number;
  reason: string;
  subscriptionId?: string;
  apiProjectId?: string;
}

/**
 * Allocate credits to a user or organization
 */
export async function allocateCredits(params: AllocateCreditsParams) {
  const {
    userId,
    organizationId,
    amount,
    reason,
    subscriptionId,
    apiProjectId,
  } = params;

  try {
    logInfo('Allocating credits', { userId, organizationId, amount });

    // Get or create credit balance
    let balance = await prisma.creditBalance.findFirst({
      where: userId ? { userId } : { organizationId },
    });

    if (!balance) {
      balance = await prisma.creditBalance.create({
        data: {
          userId,
          organizationId,
          available: 0,
          consumed: 0,
        },
      });
    }

    // Update balance
    const updatedBalance = await prisma.creditBalance.update({
      where: { id: balance.id },
      data: {
        available: { increment: amount },
      },
    });

    // Create transaction record
    await prisma.creditTransaction.create({
      data: {
        userId: userId!,
        balanceId: balance.id,
        amount,
        type: 'ALLOCATION',
        reason,
        metadata: {
          subscriptionId,
          apiProjectId,
        },
        apiProjectId,
        organizationId,
      },
    });

    logInfo('Credits allocated successfully', {
      userId,
      organizationId,
      amount,
      newBalance: updatedBalance.available,
    });

    return updatedBalance;
  } catch (error) {
    logError('Failed to allocate credits', { error, params });
    throw error;
  }
}

/**
 * Consume credits for an action
 */
export async function consumeCredits(params: {
  userId?: string;
  organizationId?: string;
  amount: number;
  reason: string;
  apiProjectId?: string;
}) {
  const { userId, organizationId, amount, reason, apiProjectId } = params;

  try {
    logInfo('Consuming credits', { userId, organizationId, amount });

    // Get credit balance
    const balance = await prisma.creditBalance.findFirst({
      where: userId ? { userId } : { organizationId },
    });

    if (!balance) {
      throw new Error('Credit balance not found');
    }

    if (balance.available < amount) {
      logWarn('Insufficient credits', {
        userId,
        organizationId,
        required: amount,
        available: balance.available,
      });
      throw new Error('Insufficient credits');
    }

    // Update balance
    const updatedBalance = await prisma.creditBalance.update({
      where: { id: balance.id },
      data: {
        available: { decrement: amount },
        consumed: { increment: amount },
      },
    });

    // Create transaction record
    await prisma.creditTransaction.create({
      data: {
        userId: userId!,
        balanceId: balance.id,
        amount: -amount,
        type: 'CONSUMPTION',
        reason,
        apiProjectId,
        organizationId,
      },
    });

    logInfo('Credits consumed successfully', {
      userId,
      organizationId,
      amount,
      remainingBalance: updatedBalance.available,
    });

    return updatedBalance;
  } catch (error) {
    logError('Failed to consume credits', { error, params });
    throw error;
  }
}

/**
 * Get credit balance
 */
export async function getCreditBalance(params: {
  userId?: string;
  organizationId?: string;
}) {
  const { userId, organizationId } = params;

  try {
    const balance = await prisma.creditBalance.findFirst({
      where: userId ? { userId } : { organizationId },
    });

    return balance;
  } catch (error) {
    logError('Failed to get credit balance', { error, params });
    throw error;
  }
}

/**
 * Handle subscription renewal
 */
export async function handleSubscriptionRenewal(subscriptionId: string) {
  try {
    logInfo('Handling subscription renewal', { subscriptionId });

    const subscription = await prisma.subscription.findUnique({
      where: { id: subscriptionId },
    });

    if (!subscription) {
      throw new Error('Subscription not found');
    }

    // Get pricing info (handle STARTER tier gracefully for existing subscriptions)
    let pricing;
    if (subscription.plan === SubscriptionTier.STARTER) {
      // STARTER tier commented out - give minimal renewal
      pricing = {
        tier: SubscriptionTier.STARTER,
        monthlyPrice: 0,
        seats: 1,
        apiGenerations: 0,
        honeypots: 0,
        features: ['Free tier - upgrade required']
      };
    } else {
      pricing = SUBSCRIPTION_PRICING[subscription.plan as keyof typeof SUBSCRIPTION_PRICING];
    }

    // Allocate new credits for the month
    await allocateCredits({
      userId: subscription.userId || undefined,
      organizationId: subscription.organizationId || undefined,
      amount: pricing.apiGenerations,
      reason: `Monthly renewal for ${subscription.plan} plan`,
      subscriptionId: subscription.id,
    });

    // Update renewal date
    await prisma.subscription.update({
      where: { id: subscriptionId },
      data: {
        renewsAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      },
    });

    logInfo('Subscription renewed successfully', { subscriptionId });
  } catch (error) {
    logError('Failed to handle subscription renewal', {
      error,
      subscriptionId,
    });
    throw error;
  }
}
