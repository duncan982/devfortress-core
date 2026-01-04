/**
 * Honeypot Status Synchronization
 * Verifies honeypot deployment status with Vercel and syncs database state
 */

import { HoneypotStatus } from '@prisma/client';
import { prisma } from '../prisma';
import { logInfo, logError, logWarn } from '../logger';

interface VercelProjectStatus {
  exists: boolean;
  status?: 'READY' | 'ERROR' | 'BUILDING' | 'QUEUED' | 'CANCELED' | 'DELETED';
  deploymentUrl?: string;
  lastDeployment?: {
    id: string;
    createdAt: string;
    readyState: string;
  };
}

/**
 * Check the status of a Vercel project
 */
async function checkVercelProjectStatus(
  projectId: string
): Promise<VercelProjectStatus> {
  const vercelToken = process.env.VERCEL_TOKEN;

  if (!vercelToken) {
    logWarn('VERCEL_TOKEN not set - cannot verify deployment status');
    return { exists: false };
  }

  try {
    // First, try to get the project
    const projectResponse = await fetch(
      `https://api.vercel.com/v9/projects/${projectId}`,
      {
        headers: {
          Authorization: `Bearer ${vercelToken}`,
        },
      }
    );

    if (projectResponse.status === 404) {
      logInfo('Vercel project not found - may have been deleted', {
        projectId,
      });
      return { exists: false, status: 'DELETED' };
    }

    if (!projectResponse.ok) {
      logError('Failed to check Vercel project status', {
        projectId,
        status: projectResponse.status,
      });
      return { exists: false };
    }

    const projectData = await projectResponse.json();

    // Get the latest deployment
    const deploymentsResponse = await fetch(
      `https://api.vercel.com/v6/deployments?projectId=${projectId}&limit=1`,
      {
        headers: {
          Authorization: `Bearer ${vercelToken}`,
        },
      }
    );

    if (!deploymentsResponse.ok) {
      return {
        exists: true,
        status: 'READY',
        deploymentUrl: projectData.latestDeployments?.[0]?.url
          ? `https://${projectData.latestDeployments[0].url}`
          : undefined,
      };
    }

    const deploymentsData = await deploymentsResponse.json();
    const latestDeployment = deploymentsData.deployments?.[0];

    if (!latestDeployment) {
      return { exists: true, status: 'READY' };
    }

    return {
      exists: true,
      status: latestDeployment.readyState as VercelProjectStatus['status'],
      deploymentUrl: latestDeployment.url
        ? `https://${latestDeployment.url}`
        : undefined,
      lastDeployment: {
        id: latestDeployment.uid,
        createdAt: latestDeployment.created,
        readyState: latestDeployment.readyState,
      },
    };
  } catch (error) {
    logError('Error checking Vercel project status', { error, projectId });
    return { exists: false };
  }
}

/**
 * Check honeypot deployment status by URL
 */
async function checkDeploymentHealth(
  deploymentUrl: string
): Promise<{ healthy: boolean; statusCode?: number }> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(`${deploymentUrl}/health`, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'APIForge-StatusSync/1.0',
      },
    });

    clearTimeout(timeoutId);

    return {
      healthy: response.ok,
      statusCode: response.status,
    };
  } catch {
    // Try root URL if health endpoint fails
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(deploymentUrl, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'APIForge-StatusSync/1.0',
        },
      });

      clearTimeout(timeoutId);

      return {
        healthy: response.ok,
        statusCode: response.status,
      };
    } catch {
      return { healthy: false };
    }
  }
}

/**
 * Sync status for a single honeypot
 */
export async function syncHoneypotStatus(honeypotId: string): Promise<{
  success: boolean;
  previousStatus: HoneypotStatus;
  newStatus: HoneypotStatus;
  reason?: string;
}> {
  try {
    const honeypot = await prisma.honeypot.findUnique({
      where: { id: honeypotId },
      select: {
        id: true,
        status: true,
        deploymentUrl: true,
        vercelProjectId: true,
        vercelProjectName: true,
      },
    });

    if (!honeypot) {
      return {
        success: false,
        previousStatus: HoneypotStatus.INACTIVE,
        newStatus: HoneypotStatus.INACTIVE,
        reason: 'Honeypot not found',
      };
    }

    const previousStatus = honeypot.status;

    // Skip sync for certain statuses
    const skipStatuses = [
      HoneypotStatus.INACTIVE,
      HoneypotStatus.DECOMMISSIONED,
      HoneypotStatus.DEPLOYING,
    ] as const;
    
    if (skipStatuses.includes(honeypot.status as typeof skipStatuses[number])) {
      return {
        success: true,
        previousStatus,
        newStatus: previousStatus,
        reason: 'Status does not require sync',
      };
    }

    // Check if we have a Vercel project ID
    if (honeypot.vercelProjectId) {
      const vercelStatus = await checkVercelProjectStatus(
        honeypot.vercelProjectId
      );

      if (!vercelStatus.exists || vercelStatus.status === 'DELETED') {
        // Project was deleted from Vercel
        await prisma.honeypot.update({
          where: { id: honeypotId },
          data: {
            status: HoneypotStatus.DECOMMISSIONED,
            suspendedReason: 'Vercel deployment was deleted or not found',
            suspendedAt: new Date(),
            updatedAt: new Date(),
          },
        });

        logInfo('Honeypot marked as decommissioned - Vercel project deleted', {
          honeypotId,
          vercelProjectId: honeypot.vercelProjectId,
        });

        return {
          success: true,
          previousStatus,
          newStatus: HoneypotStatus.DECOMMISSIONED,
          reason: 'Vercel project was deleted',
        };
      }

      if (vercelStatus.status === 'ERROR') {
        await prisma.honeypot.update({
          where: { id: honeypotId },
          data: {
            status: HoneypotStatus.ERROR,
            updatedAt: new Date(),
          },
        });

        return {
          success: true,
          previousStatus,
          newStatus: HoneypotStatus.ERROR,
          reason: 'Vercel deployment in error state',
        };
      }
    }

    // Check deployment health if we have a URL
    if (honeypot.deploymentUrl) {
      const healthStatus = await checkDeploymentHealth(honeypot.deploymentUrl);

      if (!healthStatus.healthy) {
        // If 404, the deployment might have been deleted
        if (healthStatus.statusCode === 404) {
          await prisma.honeypot.update({
            where: { id: honeypotId },
            data: {
              status: HoneypotStatus.DECOMMISSIONED,
              suspendedReason: 'Deployment URL returns 404 - may have been deleted',
              suspendedAt: new Date(),
              updatedAt: new Date(),
            },
          });

          logInfo('Honeypot marked as decommissioned - deployment returns 404', {
            honeypotId,
            deploymentUrl: honeypot.deploymentUrl,
          });

          return {
            success: true,
            previousStatus,
            newStatus: HoneypotStatus.DECOMMISSIONED,
            reason: 'Deployment returns 404',
          };
        }

        // Other errors might be temporary
        logWarn('Honeypot health check failed', {
          honeypotId,
          deploymentUrl: honeypot.deploymentUrl,
          statusCode: healthStatus.statusCode,
        });
      } else if (previousStatus !== HoneypotStatus.ACTIVE) {
        // Deployment is healthy, ensure status is ACTIVE
        await prisma.honeypot.update({
          where: { id: honeypotId },
          data: {
            status: HoneypotStatus.ACTIVE,
            updatedAt: new Date(),
          },
        });

        return {
          success: true,
          previousStatus,
          newStatus: HoneypotStatus.ACTIVE,
          reason: 'Deployment is healthy',
        };
      }
    }

    return {
      success: true,
      previousStatus,
      newStatus: previousStatus,
      reason: 'No status change needed',
    };
  } catch (error) {
    logError('Failed to sync honeypot status', { error, honeypotId });
    return {
      success: false,
      previousStatus: HoneypotStatus.INACTIVE,
      newStatus: HoneypotStatus.INACTIVE,
      reason: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Sync status for all active honeypots
 */
export async function syncAllHoneypotStatuses(userId?: string): Promise<{
  synced: number;
  updated: number;
  errors: number;
  results: Array<{
    honeypotId: string;
    previousStatus: HoneypotStatus;
    newStatus: HoneypotStatus;
    changed: boolean;
  }>;
}> {
  try {
    // Get all honeypots that might need status sync
    const where = {
      status: {
        in: [
          HoneypotStatus.ACTIVE,
          HoneypotStatus.DEPLOYED,
          HoneypotStatus.PAUSED,
          HoneypotStatus.ERROR,
        ],
      },
      ...(userId ? { ownerId: userId } : {}),
    };

    const honeypots = await prisma.honeypot.findMany({
      where,
      select: { id: true },
    });

    logInfo('Starting honeypot status sync', {
      count: honeypots.length,
      userId,
    });

    const results: Array<{
      honeypotId: string;
      previousStatus: HoneypotStatus;
      newStatus: HoneypotStatus;
      changed: boolean;
    }> = [];

    let updated = 0;
    let errors = 0;

    for (const honeypot of honeypots) {
      const result = await syncHoneypotStatus(honeypot.id);

      results.push({
        honeypotId: honeypot.id,
        previousStatus: result.previousStatus,
        newStatus: result.newStatus,
        changed: result.previousStatus !== result.newStatus,
      });

      if (!result.success) {
        errors++;
      } else if (result.previousStatus !== result.newStatus) {
        updated++;
      }

      // Add small delay between checks to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    logInfo('Honeypot status sync completed', {
      synced: honeypots.length,
      updated,
      errors,
    });

    return {
      synced: honeypots.length,
      updated,
      errors,
      results,
    };
  } catch (error) {
    logError('Failed to sync all honeypot statuses', { error, userId });
    return {
      synced: 0,
      updated: 0,
      errors: 1,
      results: [],
    };
  }
}
