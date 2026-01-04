/**
 * Data Retention Manager
 * Implements tier-based data retention policies and GDPR compliance
 * 
 * Retention Policies:
 * - FREE/STARTER: 7 days
 * - PRO: 30 days  
 * - ENTERPRISE: 90 days
 * 
 * GDPR Compliance:
 * - Data export
 * - Data deletion
 * - Anonymization
 */

import { prisma } from '@core/lib/prisma';
import { SubscriptionTier } from '@core/lib/payments/types';
import { logInfo, logError } from '@core/lib/logger';

/**
 * Retention policy configuration by tier
 */
const RETENTION_DAYS: Record<SubscriptionTier, number> = {
  // FREE: 7, // Commented out - FREE tier removed
  [SubscriptionTier.STARTER]: 7,
  [SubscriptionTier.PRO]: 30,
  [SubscriptionTier.ENTERPRISE]: 90,
};

/**
 * Data export format
 */
export interface UserDataExport {
  user: {
    id: string;
    email: string;
    name: string | null;
    createdAt: Date;
  };
  apiProjects: Array<{
    id: string;
    name: string;
    description: string | null;
    createdAt: Date;
  }>;
  threats: Array<{
    id: string;
    sourceIp: string;
    detectedAt: Date;
    severity: string;
  }>;
  insights: Array<{
    id: string;
    title: string;
    category: string;
    createdAt: Date;
  }>;
  honeypots: Array<{
    id: string;
    name: string;
    status: string;
    createdAt: Date;
  }>;
  exportedAt: Date;
}

/**
 * Get retention days for a user based on their subscription tier
 */
async function getRetentionDays(userId: string): Promise<number> {
  const subscription = await prisma.subscription.findFirst({
    where: {
      userId,
      status: 'ACTIVE',
    },
    orderBy: {
      createdAt: 'desc',
    },
  });

  const tier = subscription?.plan as SubscriptionTier || 'FREE';
  return RETENTION_DAYS[tier];
}

/**
 * Clean up old threat events based on retention policy
 */
export async function cleanupOldThreatEvents(userId?: string): Promise<number> {
  try {
    let deletedCount = 0;

    if (userId) {
      // Clean up for specific user
      const retentionDays = await getRetentionDays(userId);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      // Get user's honeypots
      const honeypots = await prisma.honeypot.findMany({
        where: { ownerId: userId },
        select: { id: true },
      });

      const honeypotIds = honeypots.map(h => h.id);

      // Delete old threat events
      const result = await prisma.threatEvent.deleteMany({
        where: {
          honeypotId: { in: honeypotIds },
          detectedAt: { lt: cutoffDate },
        },
      });

      deletedCount = result.count;

      logInfo('Cleaned up old threat events for user', {
        userId,
        retentionDays,
        deletedCount,
      });
    } else {
      // Clean up for all users (run in cron job)
      const users = await prisma.user.findMany({
        select: { id: true },
      });

      for (const user of users) {
        const count = await cleanupOldThreatEvents(user.id);
        deletedCount += count;
      }

      logInfo('Cleaned up old threat events for all users', {
        userCount: users.length,
        totalDeleted: deletedCount,
      });
    }

    return deletedCount;
  } catch (error) {
    logError('Failed to cleanup old threat events', { userId, error });
    throw error;
  }
}

/**
 * Clean up old live threat events
 */
export async function cleanupOldLiveEvents(userId?: string): Promise<number> {
  try {
    let deletedCount = 0;

    if (userId) {
      const retentionDays = await getRetentionDays(userId);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      // Get user's projects
      const projects = await prisma.apiProject.findMany({
        where: { createdById: userId },
        select: { id: true },
      });

      const projectIds = projects.map(p => p.id);

      // Delete old threat events
      const result = await prisma.threatEvent.deleteMany({
        where: {
          apiProjectId: { in: projectIds },
          detectedAt: { lt: cutoffDate },
        },
      });

      deletedCount = result.count;

      logInfo('Cleaned up old live events for user', {
        userId,
        retentionDays,
        deletedCount,
      });
    } else {
      const users = await prisma.user.findMany({
        select: { id: true },
      });

      for (const user of users) {
        const count = await cleanupOldLiveEvents(user.id);
        deletedCount += count;
      }

      logInfo('Cleaned up old live events for all users', {
        userCount: users.length,
        totalDeleted: deletedCount,
      });
    }

    return deletedCount;
  } catch (error) {
    logError('Failed to cleanup old live events', { userId, error });
    throw error;
  }
}

/**
 * Clean up old insights
 */
export async function cleanupOldInsights(userId?: string): Promise<number> {
  try {
    let deletedCount = 0;

    if (userId) {
      const retentionDays = await getRetentionDays(userId);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      // Get user's projects
      const projects = await prisma.apiProject.findMany({
        where: { createdById: userId },
        select: { id: true },
      });

      const projectIds = projects.map(p => p.id);

      // Delete old insights
      const result = await prisma.flywheelInsight.deleteMany({
        where: {
          apiProjectId: { in: projectIds },
          generatedAt: { lt: cutoffDate },
        },
      });

      deletedCount = result.count;

      logInfo('Cleaned up old insights for user', {
        userId,
        retentionDays,
        deletedCount,
      });
    } else {
      const users = await prisma.user.findMany({
        select: { id: true },
      });

      for (const user of users) {
        const count = await cleanupOldInsights(user.id);
        deletedCount += count;
      }
    }

    return deletedCount;
  } catch (error) {
    logError('Failed to cleanup old insights', { userId, error });
    throw error;
  }
}

/**
 * Run all cleanup tasks (called by cron job)
 */
export async function runRetentionCleanup(): Promise<void> {
  logInfo('Starting retention cleanup job');

  try {
    const threatEventsDeleted = await cleanupOldThreatEvents();
    const liveEventsDeleted = await cleanupOldLiveEvents();
    const insightsDeleted = await cleanupOldInsights();

    logInfo('Retention cleanup job completed', {
      threatEventsDeleted,
      liveEventsDeleted,
      insightsDeleted,
      totalDeleted: threatEventsDeleted + liveEventsDeleted + insightsDeleted,
    });
  } catch (error) {
    logError('Retention cleanup job failed', { error });
    throw error;
  }
}

/**
 * Export all user data (GDPR compliance)
 */
export async function exportUserData(userId: string): Promise<UserDataExport> {
  try {
    logInfo('Exporting user data', { userId });

    const [user, apiProjects, honeypots] = await Promise.all([
      prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          email: true,
          name: true,
          createdAt: true,
        },
      }),
      prisma.apiProject.findMany({
        where: { createdById: userId },
        select: {
          id: true,
          name: true,
          description: true,
          createdAt: true,
        },
      }),
      prisma.honeypot.findMany({
        where: { ownerId: userId },
        select: {
          id: true,
          name: true,
          status: true,
          createdAt: true,
        },
      }),
    ]);

    if (!user) {
      throw new Error('User not found');
    }

    // Get honeypot IDs
    const honeypotIds = honeypots.map(h => h.id);

    // Get threat events
    const threatEvents = await prisma.threatEvent.findMany({
      where: { honeypotId: { in: honeypotIds } },
      select: {
        id: true,
        sourceIp: true,
        detectedAt: true,
        severity: true,
      },
      orderBy: { detectedAt: 'desc' },
    });

    // Get project IDs
    const projectIds = apiProjects.map(p => p.id);

    // Get live events
    const liveEvents = await prisma.liveThreatEvent.findMany({
      where: { projectId: { in: projectIds } },
      select: {
        id: true,
        ip: true,
        timestamp: true,
        severity: true,
      },
      orderBy: { timestamp: 'desc' },
    });

    // Get insights
    const insights = await prisma.flywheelInsight.findMany({
      where: { apiProjectId: { in: projectIds } },
      select: {
        id: true,
        summary: true,
        type: true,
        generatedAt: true,
      },
      orderBy: { generatedAt: 'desc' },
    });

    // Combine threat events and live events
    const allThreats = [
      ...threatEvents.map(t => ({
        id: t.id,
        sourceIp: t.sourceIp,
        detectedAt: t.detectedAt,
        severity: t.severity,
      })),
      ...liveEvents.map(t => ({
        id: t.id,
        sourceIp: t.ip,
        detectedAt: t.timestamp,
        severity: t.severity,
      })),
    ].sort((a, b) => b.detectedAt.getTime() - a.detectedAt.getTime());

    const exportData: UserDataExport = {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
      },
      apiProjects: apiProjects.map(p => ({
        id: p.id,
        name: p.name,
        description: p.description,
        createdAt: p.createdAt,
      })),
      threats: allThreats,
      insights: insights.map(i => ({
        id: i.id,
        title: i.summary,
        category: i.type,
        createdAt: i.generatedAt,
      })),
      honeypots: honeypots.map(h => ({
        id: h.id,
        name: h.name,
        status: h.status,
        createdAt: h.createdAt,
      })),
      exportedAt: new Date(),
    };

    logInfo('User data exported successfully', {
      userId,
      apiProjectsCount: apiProjects.length,
      threatsCount: allThreats.length,
      insightsCount: insights.length,
    });

    return exportData;
  } catch (error) {
    logError('Failed to export user data', { userId, error });
    throw error;
  }
}

/**
 * Delete all user data (GDPR right to be forgotten)
 */
export async function deleteUserData(userId: string): Promise<void> {
  try {
    logInfo('Deleting user data', { userId });

    // Delete in correct order to respect foreign key constraints
    await prisma.$transaction(async (tx) => {
      // Get project and honeypot IDs
      const projects = await tx.apiProject.findMany({
        where: { createdById: userId },
        select: { id: true },
      });
      const projectIds = projects.map(p => p.id);

      const honeypots = await tx.honeypot.findMany({
        where: { ownerId: userId },
        select: { id: true },
      });
      const honeypotIds = honeypots.map(h => h.id);

      // Delete dependent records
      await tx.liveThreatEvent.deleteMany({
        where: { projectId: { in: projectIds } },
      });

      await tx.threatEvent.deleteMany({
        where: { honeypotId: { in: honeypotIds } },
      });

      await tx.honeypotAlert.deleteMany({
        where: { honeypotId: { in: honeypotIds } },
      });

      await tx.flywheelInsight.deleteMany({
        where: { apiProjectId: { in: projectIds } },
      });

      await tx.honeypot.deleteMany({
        where: { ownerId: userId },
      });

      await tx.apiProject.deleteMany({
        where: { createdById: userId },
      });

      await tx.userApiKey.deleteMany({
        where: { userId },
      });

      // Delete credit transactions first (FK constraint)
      const balances = await tx.creditBalance.findMany({
        where: { userId },
        select: { id: true },
      });
      const balanceIds = balances.map(b => b.id);
      
      await tx.creditTransaction.deleteMany({
        where: { balanceId: { in: balanceIds } },
      });

      await tx.creditBalance.deleteMany({
        where: { userId },
      });

      await tx.subscription.deleteMany({
        where: { userId },
      });

      // Finally delete the user
      await tx.user.delete({
        where: { id: userId },
      });
    });

    logInfo('User data deleted successfully', { userId });
  } catch (error) {
    logError('Failed to delete user data', { userId, error });
    throw error;
  }
}

/**
 * Anonymize user data (alternative to deletion)
 */
export async function anonymizeUserData(userId: string): Promise<void> {
  try {
    logInfo('Anonymizing user data', { userId });

    await prisma.user.update({
      where: { id: userId },
      data: {
        email: `deleted-${userId}@anonymized.local`,
        name: 'Deleted User',
        image: null,
      },
    });

    // Anonymize threat events
    const honeypots = await prisma.honeypot.findMany({
      where: { ownerId: userId },
      select: { id: true },
    });

    for (const honeypot of honeypots) {
      await prisma.threatEvent.updateMany({
        where: { honeypotId: honeypot.id },
        data: {
          sourceIp: '0.0.0.0',
          userAgent: null,
        },
      });
    }

    logInfo('User data anonymized successfully', { userId });
  } catch (error) {
    logError('Failed to anonymize user data', { userId, error });
    throw error;
  }
}
