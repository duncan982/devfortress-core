/**
 * Honeypot service
 * Manages honeypot deployment, monitoring, and lifecycle
 */

import { HoneypotStatus, SubscriptionPlan } from '@prisma/client';
import { prisma } from '../prisma';
import { logInfo, logError, logWarn } from '../logger';
import { SUBSCRIPTION_PRICING } from '../payments/types';
import { deleteVercelProject } from './deployment';

interface CreateHoneypotParams {
  name: string;
  slug: string;
  ownerId: string;
  teamId?: string;
  organizationId?: string;
  apiProjectId?: string;
  repositoryId?: string;
  tier: SubscriptionPlan;
  config?: Record<string, unknown>;
  isPrivileged?: boolean;
}

interface DeployHoneypotParams {
  honeypotId: string;
  targetUrl?: string;
}

/**
 * Get honeypot tier limits based on subscription plan
 */
export function getHoneypotLimits(plan: SubscriptionPlan): number {
  try {
    // Handle enum compatibility issues by using string keys
    const planKey = plan as string;
    const pricing = SUBSCRIPTION_PRICING[planKey as keyof typeof SUBSCRIPTION_PRICING];

    if (pricing?.honeypots !== undefined) {
      return pricing.honeypots;
    }

    // Fallback: try direct string lookup
    const directPricing =
      SUBSCRIPTION_PRICING[plan as keyof typeof SUBSCRIPTION_PRICING];
    if (directPricing?.honeypots !== undefined) {
      return directPricing.honeypots;
    }

    // Hardcoded fallback limits
    const fallbackLimits: Record<string, number> = {
      STARTER: 1,
      PRO: 3,
      ENTERPRISE: 10,
    };

    const fallbackLimit =
      fallbackLimits[planKey] || fallbackLimits[plan as string];
    if (fallbackLimit !== undefined) {
      logInfo('Using fallback limit for plan', {
        plan,
        planKey,
        fallbackLimit,
      });
      return fallbackLimit;
    }

    // Last resort: return 0
    logError('Could not find pricing for plan', { plan, planKey });
    return 0;
  } catch (error) {
    logError('Failed to get honeypot limits', { plan, error });
    return 0;
  }
}

/**
 * Check if user can create more honeypots based on their subscription
 */
export async function canCreateHoneypot(params: {
  userId?: string;
  organizationId?: string;
  tier: SubscriptionPlan;
  isPrivileged?: boolean;
}): Promise<{ allowed: boolean; limit: number; current: number }> {
  const { userId, organizationId, tier, isPrivileged } = params;

  // Privileged users have unlimited access
  if (isPrivileged) {
    return { allowed: true, limit: 999, current: 0 };
  }

  try {
    const limit = getHoneypotLimits(tier);

    // Count active honeypots
    const current = await prisma.honeypot.count({
      where: {
        ownerId: userId,
        organizationId,
        status: {
          in: [
            HoneypotStatus.ACTIVE,
            HoneypotStatus.DEPLOYING,
            HoneypotStatus.DEPLOYED,
          ],
        },
      },
    });

    return {
      allowed: current < limit,
      limit,
      current,
    };
  } catch (error) {
    logError('Failed to check honeypot creation limits', { error, params });
    return { allowed: false, limit: 0, current: 0 };
  }
}

/**
 * Create a new honeypot
 */
export async function createHoneypot(params: CreateHoneypotParams) {
  const {
    name,
    slug,
    ownerId,
    teamId,
    organizationId,
    apiProjectId,
    repositoryId,
    tier,
    config,
    isPrivileged = false,
  } = params;

  try {
    logInfo('Creating honeypot', { name, slug, ownerId, tier, isPrivileged });

    // Check if user can create more honeypots
    const { allowed, limit, current } = await canCreateHoneypot({
      userId: ownerId,
      organizationId,
      tier,
      isPrivileged,
    });

    if (!allowed) {
      throw new Error(
        `Honeypot limit reached. Your ${tier} plan allows ${limit} honeypots (currently using ${current})`
      );
    }

    // Check if slug is already taken
    const existingHoneypot = await prisma.honeypot.findUnique({
      where: { slug },
    });

    if (existingHoneypot) {
      throw new Error('Honeypot slug already exists');
    }

    // Create honeypot
    const honeypot = await prisma.honeypot.create({
      data: {
        name,
        slug,
        ownerId,
        teamId,
        organizationId,
        apiProjectId,
        repositoryId,
        tier,
        status: HoneypotStatus.INACTIVE,
        config: config as never,
      },
      include: {
        apiProject: {
          select: {
            id: true,
            name: true,
            framework: true,
            language: true,
          },
        },
        repository: {
          select: {
            id: true,
            name: true,
            provider: true,
          },
        },
      },
    });

    logInfo('Honeypot created successfully', {
      honeypotId: honeypot.id,
      name: honeypot.name,
    });

    return honeypot;
  } catch (error) {
    logError('Failed to create honeypot', { error, params });
    throw error;
  }
}

/**
 * Get honeypot by ID
 */
export async function getHoneypot(honeypotId: string) {
  try {
    const honeypot = await prisma.honeypot.findUnique({
      where: { id: honeypotId },
      include: {
        owner: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
        team: {
          select: {
            id: true,
            name: true,
            slug: true,
          },
        },
        organization: {
          select: {
            id: true,
            name: true,
            slug: true,
          },
        },
        apiProject: {
          select: {
            id: true,
            name: true,
            description: true,
            framework: true,
            language: true,
            specification: true,
          },
        },
        repository: {
          select: {
            id: true,
            name: true,
            provider: true,
            ownerLogin: true,
          },
        },
        threatEvents: {
          orderBy: {
            detectedAt: 'desc',
          },
          take: 10,
        },
      },
    });

    return honeypot;
  } catch (error) {
    logError('Failed to get honeypot', { error, honeypotId });
    throw error;
  }
}

/**
 * Get user's honeypots
 */
export async function getUserHoneypots(userId: string) {
  try {
    const honeypots = await prisma.honeypot.findMany({
      where: {
        ownerId: userId,
      },
      select: {
        id: true,
        name: true,
        slug: true,
        status: true,
        deploymentUrl: true,
        vercelProjectName: true,
        vercelProjectId: true,
        createdAt: true,
        updatedAt: true,
        apiProject: {
          select: {
            id: true,
            name: true,
          },
        },
        team: {
          select: {
            id: true,
            name: true,
          },
        },
        threatEvents: {
          select: {
            id: true,
            severity: true,
            detectedAt: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return honeypots;
  } catch (error) {
    // Log and return empty list so UI can render empty state instead of crashing
    logError('Failed to get user honeypots - returning empty list', {
      error,
      userId,
    });
    return [];
  }
}

/**
 * Update honeypot status
 */
export async function updateHoneypotStatus(
  honeypotId: string,
  status: HoneypotStatus
) {
  try {
    logInfo('Updating honeypot status', { honeypotId, status });

    const honeypot = await prisma.honeypot.update({
      where: { id: honeypotId },
      data: { status, updatedAt: new Date() },
    });

    logInfo('Honeypot status updated', { honeypotId, status });

    return honeypot;
  } catch (error) {
    logError('Failed to update honeypot status', { error, honeypotId, status });
    throw error;
  }
}

/**
 * Deploy a honeypot (mark as deploying, actual deployment handled separately)
 */
export async function deployHoneypot(params: DeployHoneypotParams) {
  const { honeypotId, targetUrl } = params;

  try {
    logInfo('Deploying honeypot', { honeypotId, targetUrl });

    // Update status to deploying
    const honeypot = await prisma.honeypot.update({
      where: { id: honeypotId },
      data: {
        status: HoneypotStatus.DEPLOYING,
        deploymentUrl: targetUrl,
        updatedAt: new Date(),
      },
    });

    logInfo('Honeypot marked as deploying', { honeypotId });

    return honeypot;
  } catch (error) {
    logError('Failed to deploy honeypot', { error, params });
    throw error;
  }
}

/**
 * Pause a honeypot
 */
export async function pauseHoneypot(honeypotId: string) {
  try {
    logInfo('Pausing honeypot', { honeypotId });

    const honeypot = await updateHoneypotStatus(
      honeypotId,
      HoneypotStatus.PAUSED
    );

    logInfo('Honeypot paused', { honeypotId });

    return honeypot;
  } catch (error) {
    logError('Failed to pause honeypot', { error, honeypotId });
    throw error;
  }
}

/**
 * Bulk pause honeypots
 */
export async function bulkPauseHoneypots(honeypotIds: string[]) {
  try {
    logInfo('Bulk pausing honeypots', { honeypotIds });

    await prisma.honeypot.updateMany({
      where: { id: { in: honeypotIds } },
      data: { status: HoneypotStatus.PAUSED, updatedAt: new Date() },
    });

    logInfo('Bulk honeypots paused', { honeypotIds });

    return { success: true, updatedCount: honeypotIds.length };
  } catch (error) {
    logError('Failed to bulk pause honeypots', { error, honeypotIds });
    throw error;
  }
}

/**
 * Resume a paused honeypot
 */
export async function resumeHoneypot(honeypotId: string) {
  try {
    logInfo('Resuming honeypot', { honeypotId });

    const honeypot = await updateHoneypotStatus(
      honeypotId,
      HoneypotStatus.ACTIVE
    );

    logInfo('Honeypot resumed', { honeypotId });

    return honeypot;
  } catch (error) {
    logError('Failed to resume honeypot', { error, honeypotId });
    throw error;
  }
}

/**
 * Decommission a honeypot
 * Marks honeypot as decommissioned and optionally deletes Vercel project
 */
export async function decommissionHoneypot(
  honeypotId: string,
  deleteVercelDeployment: boolean = false
) {
  try {
    logInfo('Decommissioning honeypot', { honeypotId, deleteVercelDeployment });

    // Get honeypot to retrieve Vercel project info
    const honeypot = await prisma.honeypot.findUnique({
      where: { id: honeypotId },
      select: {
        vercelProjectId: true,
        vercelProjectName: true,
      },
    });

    // Delete Vercel project if requested and project info exists
    if (deleteVercelDeployment && honeypot) {
      const projectIdOrName =
        honeypot.vercelProjectId || honeypot.vercelProjectName;
      if (projectIdOrName) {
        const deleted = await deleteVercelProject(projectIdOrName);
        if (deleted) {
          logInfo('Vercel project deleted during decommission', {
            honeypotId,
            projectIdOrName,
          });
        } else {
          logWarn(
            'Failed to delete Vercel project during decommission - continuing anyway',
            { honeypotId, projectIdOrName }
          );
        }
      }
    }

    const updatedHoneypot = await updateHoneypotStatus(
      honeypotId,
      HoneypotStatus.DECOMMISSIONED
    );

    logInfo('Honeypot decommissioned', { honeypotId, deleteVercelDeployment });

    return updatedHoneypot;
  } catch (error) {
    logError('Failed to decommission honeypot', { error, honeypotId });
    throw error;
  }
}

/**
 * Permanently delete a honeypot and all associated data
 * Also deletes the Vercel project deployment
 */
export async function hardDeleteHoneypot(honeypotId: string) {
  try {
    logInfo('Hard deleting honeypot', { honeypotId });

    // Get honeypot to retrieve Vercel project info before deletion
    const honeypot = await prisma.honeypot.findUnique({
      where: { id: honeypotId },
      select: {
        vercelProjectId: true,
        vercelProjectName: true,
      },
    });

    // Delete Vercel project if project info exists
    if (honeypot) {
      const projectIdOrName =
        honeypot.vercelProjectId || honeypot.vercelProjectName;
      if (projectIdOrName) {
        const deleted = await deleteVercelProject(projectIdOrName);
        if (deleted) {
          logInfo('Vercel project deleted during hard delete', {
            honeypotId,
            projectIdOrName,
          });
        } else {
          logWarn(
            'Failed to delete Vercel project during hard delete - continuing with database deletion',
            { honeypotId, projectIdOrName }
          );
        }
      } else {
        logInfo('No Vercel project info found - skipping Vercel deletion', {
          honeypotId,
        });
      }
    }

    // Delete associated threat events first
    await prisma.threatEvent.deleteMany({
      where: { honeypotId },
    });

    // Delete the honeypot
    await prisma.honeypot.delete({
      where: { id: honeypotId },
    });

    logInfo('Honeypot hard deleted', { honeypotId });

    return { success: true };
  } catch (error) {
    logError('Failed to hard delete honeypot', { error, honeypotId });
    throw error;
  }
}

/**
 * Bulk permanently delete honeypots and all associated data
 * Also deletes the Vercel project deployments
 */
export async function bulkHardDeleteHoneypots(honeypotIds: string[]) {
  try {
    logInfo('Bulk hard deleting honeypots', { honeypotIds });

    // Get all honeypots to retrieve Vercel project info before deletion
    const honeypots = await prisma.honeypot.findMany({
      where: { id: { in: honeypotIds } },
      select: {
        id: true,
        vercelProjectId: true,
        vercelProjectName: true,
      },
    });

    // Delete Vercel projects in parallel for efficiency
    const vercelDeletionPromises = honeypots.map(async honeypot => {
      const projectIdOrName =
        honeypot.vercelProjectId || honeypot.vercelProjectName;
      if (projectIdOrName) {
        const deleted = await deleteVercelProject(projectIdOrName);
        return {
          honeypotId: honeypot.id,
          projectIdOrName,
          deleted,
        };
      }
      return {
        honeypotId: honeypot.id,
        projectIdOrName: null,
        deleted: true, // No project to delete
      };
    });

    const vercelResults = await Promise.all(vercelDeletionPromises);

    // Log Vercel deletion results
    const successfulDeletions = vercelResults.filter(r => r.deleted);
    const failedDeletions = vercelResults.filter(
      r => !r.deleted && r.projectIdOrName
    );

    if (successfulDeletions.length > 0) {
      logInfo('Vercel projects deleted during bulk hard delete', {
        count: successfulDeletions.length,
        honeypotIds: successfulDeletions.map(r => r.honeypotId),
      });
    }

    if (failedDeletions.length > 0) {
      logWarn(
        'Some Vercel projects failed to delete during bulk hard delete - continuing with database deletion',
        {
          count: failedDeletions.length,
          failed: failedDeletions.map(r => ({
            honeypotId: r.honeypotId,
            projectIdOrName: r.projectIdOrName,
          })),
        }
      );
    }

    // Use transaction for atomicity of database operations
    await prisma.$transaction(async tx => {
      // Delete associated threat events first
      await tx.threatEvent.deleteMany({
        where: { honeypotId: { in: honeypotIds } },
      });

      // Delete the honeypots
      await tx.honeypot.deleteMany({
        where: { id: { in: honeypotIds } },
      });
    });

    logInfo('Bulk honeypots hard deleted', {
      honeypotIds,
      vercelProjectsDeleted: successfulDeletions.length,
      vercelProjectsFailed: failedDeletions.length,
    });

    return {
      success: true,
      deletedCount: honeypotIds.length,
      vercelProjectsDeleted: successfulDeletions.length,
      vercelProjectsFailed: failedDeletions.length,
    };
  } catch (error) {
    logError('Failed to bulk hard delete honeypots', { error, honeypotIds });
    throw error;
  }
}

/**
 * Get honeypot deployment statistics
 */
export async function getHoneypotStats(userId: string) {
  try {
    const stats = await prisma.honeypot.groupBy({
      by: ['status'],
      where: {
        ownerId: userId,
      },
      _count: {
        id: true,
      },
    });

    const totalThreats = await prisma.threatEvent.count({
      where: {
        honeypot: {
          ownerId: userId,
        },
      },
    });

    return {
      byStatus: stats.reduce(
        (acc, stat) => {
          acc[stat.status] = stat._count.id;
          return acc;
        },
        {} as Record<HoneypotStatus, number>
      ),
      totalThreats,
    };
  } catch (error) {
    // Return zeroed stats on error so dashboard can still render
    logError('Failed to get honeypot stats - returning zeros', {
      error,
      userId,
    });
    return {
      byStatus: {
        [HoneypotStatus.ACTIVE]: 0,
        [HoneypotStatus.INACTIVE]: 0,
        [HoneypotStatus.DEPLOYING]: 0,
        [HoneypotStatus.PAUSED]: 0,
        [HoneypotStatus.SUSPENDED]: 0,
        [HoneypotStatus.DECOMMISSIONED]: 0,
        [HoneypotStatus.ERROR]: 0,
      } as Record<HoneypotStatus, number>,
      totalThreats: 0,
    };
  }
}

/**
 * Update honeypot configuration
 */
export async function updateHoneypotConfig(
  honeypotId: string,
  config: Record<string, unknown>
) {
  try {
    logInfo('Updating honeypot config', { honeypotId });

    const honeypot = await prisma.honeypot.update({
      where: { id: honeypotId },
      data: {
        config: config as never,
        updatedAt: new Date(),
      },
    });

    logInfo('Honeypot config updated', { honeypotId });

    return honeypot;
  } catch (error) {
    logError('Failed to update honeypot config', { error, honeypotId });
    throw error;
  }
}
