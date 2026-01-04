/**
 * Data Retention Service
 * Configurable data lifecycle management with compliance features
 */

import { PrismaClient } from '@prisma/client';
import { logInfo, logError } from '@core/lib/logger';

const prisma = new PrismaClient();

// Retention policies (in days)
const DEFAULT_RETENTION_POLICIES = {
  // Honeypot data - NEVER DELETE (as per user requirements)
  honeypotData: -1, // -1 means never delete

  // Threat events - configurable, default 1 year
  threatEvents: 365,

  // User sessions - configurable, default 90 days
  userSessions: 90,

  // Audit logs - configurable, default 2 years
  auditLogs: 730,

  // API generation logs - configurable, default 180 days
  apiGenerationLogs: 180,
};

export interface RetentionConfig {
  honeypotData: number; // Always -1 (never delete)
  threatEvents: number;
  userSessions: number;
  auditLogs: number;
  apiGenerationLogs: number;
}

/**
 * Get current retention configuration
 */
export async function getRetentionConfig(): Promise<RetentionConfig> {
  try {
    // In a real implementation, this would be stored in database
    // For now, return defaults
    return DEFAULT_RETENTION_POLICIES;
  } catch (error) {
    logError('Failed to get retention config', { error });
    return DEFAULT_RETENTION_POLICIES;
  }
}

/**
 * Update retention configuration
 * Note: honeypotData retention cannot be changed (always -1)
 */
export async function updateRetentionConfig(
  config: Partial<RetentionConfig>
): Promise<RetentionConfig> {
  try {
    // Ensure honeypot data is never deleted
    const updatedConfig = {
      ...DEFAULT_RETENTION_POLICIES,
      ...config,
      honeypotData: -1, // Always override to never delete
    };

    // Validate retention periods
    Object.entries(updatedConfig).forEach(([key, value]) => {
      if (key !== 'honeypotData' && value < 30 && value !== -1) {
        throw new Error(
          `${key} retention must be at least 30 days or -1 (never delete)`
        );
      }
    });

    logInfo('Retention configuration updated', { config: updatedConfig });

    // In a real implementation, save to database
    return updatedConfig;
  } catch (error) {
    logError('Failed to update retention config', { error, config });
    throw error;
  }
}

/**
 * Apply data retention policies
 * This should be run periodically (e.g., daily cron job)
 */
export async function applyRetentionPolicies(): Promise<{
  deleted: Record<string, number>;
  errors: string[];
}> {
  const result = {
    deleted: {} as Record<string, number>,
    errors: [] as string[],
  };

  try {
    const config = await getRetentionConfig();

    // Clean up user sessions
    if (config.userSessions > 0) {
      try {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - config.userSessions);

        const deletedSessions = await prisma.userSession.deleteMany({
          where: {
            createdAt: {
              lt: cutoffDate,
            },
          },
        });

        result.deleted.userSessions = deletedSessions.count;
        logInfo('Cleaned up old user sessions', {
          deleted: deletedSessions.count,
          cutoffDate,
        });
      } catch (error) {
        const errorMsg = `Failed to clean user sessions: ${error}`;
        result.errors.push(errorMsg);
        logError('User session cleanup failed', { error });
      }
    }

    // Clean up threat events (but preserve honeypot data)
    if (config.threatEvents > 0) {
      try {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - config.threatEvents);

        // Note: This would delete threat events but honeypot data itself is never deleted
        // The honeypot records themselves are preserved, only old threat events are cleaned
        const deletedThreats = await prisma.threatEvent.deleteMany({
          where: {
            detectedAt: {
              lt: cutoffDate,
            },
          },
        });

        result.deleted.threatEvents = deletedThreats.count;
        logInfo('Cleaned up old threat events', {
          deleted: deletedThreats.count,
          cutoffDate,
        });
      } catch (error) {
        const errorMsg = `Failed to clean threat events: ${error}`;
        result.errors.push(errorMsg);
        logError('Threat event cleanup failed', { error });
      }
    }

    // Note: Honeypot data is NEVER deleted as per user requirements
    logInfo('Honeypot data preservation confirmed - no deletion applied');

    // Additional cleanup could be added here for other data types
    // (audit logs, API generation logs, etc.)
  } catch (error) {
    const errorMsg = `Retention policy application failed: ${error}`;
    result.errors.push(errorMsg);
    logError('Retention policy application failed', { error });
  }

  return result;
}

/**
 * Get data retention statistics
 */
export async function getRetentionStats(): Promise<{
  currentCounts: Record<string, number>;
  nextCleanupDates: Record<string, Date | null>;
  config: RetentionConfig;
}> {
  try {
    const config = await getRetentionConfig();

    // Get current data counts
    const [userSessionCount, threatEventCount, honeypotCount] =
      await Promise.all([
        prisma.userSession.count(),
        prisma.threatEvent.count(),
        prisma.honeypot.count(),
      ]);

    // Calculate next cleanup dates
    const nextCleanupDates: Record<string, Date | null> = {};

    Object.entries(config).forEach(([key, retentionDays]) => {
      if (retentionDays > 0) {
        const nextCleanup = new Date();
        nextCleanup.setDate(nextCleanup.getDate() + retentionDays);
        nextCleanupDates[key] = nextCleanup;
      } else {
        nextCleanupDates[key] = null; // Never delete
      }
    });

    return {
      currentCounts: {
        userSessions: userSessionCount,
        threatEvents: threatEventCount,
        honeypots: honeypotCount,
      },
      nextCleanupDates,
      config,
    };
  } catch (error) {
    logError('Failed to get retention stats', { error });
    throw error;
  }
}

/**
 * Compliance check - ensure data retention meets requirements
 */
export async function checkCompliance(): Promise<{
  compliant: boolean;
  issues: string[];
  recommendations: string[];
}> {
  const result = {
    compliant: true,
    issues: [] as string[],
    recommendations: [] as string[],
  };

  try {
    const config = await getRetentionConfig();
    const stats = await getRetentionStats();

    // Check honeypot data preservation
    if (config.honeypotData !== -1) {
      result.compliant = false;
      result.issues.push('Honeypot data must never be deleted');
    }

    // Check minimum retention periods for compliance
    if (config.threatEvents < 365) {
      result.issues.push(
        'Threat events should be retained for at least 1 year for security analysis'
      );
      result.recommendations.push(
        'Consider increasing threat event retention to 365+ days'
      );
    }

    // Check for data that should be cleaned up
    if (stats.currentCounts.userSessions > 10000) {
      result.recommendations.push(
        'Consider running session cleanup - high session count detected'
      );
    }

    if (stats.currentCounts.threatEvents > 100000) {
      result.recommendations.push(
        'Consider running threat event cleanup - high event count detected'
      );
    }
  } catch (error) {
    result.compliant = false;
    result.issues.push(`Compliance check failed: ${error}`);
    logError('Compliance check failed', { error });
  }

  return result;
}
