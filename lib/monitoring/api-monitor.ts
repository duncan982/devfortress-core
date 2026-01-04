/**
 * API Monitoring Service
 * Tracks external API health, performance, and uptime
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError, logWarn } from '@core/lib/logger';
import { sendGatedEmail } from '@core/lib/email/gated-email-service';

// Enums matching Prisma schema
enum MonitorStatus {
  ACTIVE = 'ACTIVE',
  PAUSED = 'PAUSED',
  DISABLED = 'DISABLED',
}

enum MonitorFrequency {
  ONE_MINUTE = 'ONE_MINUTE',
  FIVE_MINUTES = 'FIVE_MINUTES',
  FIFTEEN_MINUTES = 'FIFTEEN_MINUTES',
  THIRTY_MINUTES = 'THIRTY_MINUTES',
  ONE_HOUR = 'ONE_HOUR',
}

enum IncidentSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

enum IncidentStatus {
  OPEN = 'OPEN',
  ACKNOWLEDGED = 'ACKNOWLEDGED',
  RESOLVED = 'RESOLVED',
}

interface MonitorConfig {
  userId: string;
  name: string;
  endpoint: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  body?: string;
  expectedStatusCode?: number;
  expectedResponseTime?: number; // in milliseconds
  frequency?: MonitorFrequency;
  alertEmail?: string;
  teamId?: string;
}

interface CheckResult {
  success: boolean;
  statusCode: number;
  responseTime: number;
  error?: string;
  timestamp: Date;
}

interface MonitorStatistics {
  uptime: number; // percentage
  avgResponseTime: number;
  totalChecks: number;
  successfulChecks: number;
  failedChecks: number;
  lastCheckTime?: Date;
  currentStatus: 'UP' | 'DOWN' | 'DEGRADED';
}

export class APIMonitorService {
  /**
   * Create a new API monitor
   */
  static async createMonitor(config: MonitorConfig) {
    try {
      logInfo('Creating new API monitor', { endpoint: config.endpoint });

      const monitor = await prisma.aPIMonitor.create({
        data: {
          userId: config.userId,
          name: config.name,
          endpoint: config.endpoint,
          method: config.method || 'GET',
          headers: config.headers || {},
          body: config.body,
          expectedStatusCode: config.expectedStatusCode || 200,
          expectedResponseTime: config.expectedResponseTime || 5000,
          frequency: config.frequency || MonitorFrequency.FIVE_MINUTES,
          status: MonitorStatus.ACTIVE,
          alertEmail: config.alertEmail,
          teamId: config.teamId,
          lastCheckedAt: new Date(),
        },
      });

      logInfo('API monitor created', { monitorId: monitor.id });
      return monitor;
    } catch (error) {
      logError('Failed to create API monitor', { error, config });
      throw error;
    }
  }

  /**
   * Execute a health check on a monitor
   */
  static async executeCheck(monitorId: string): Promise<CheckResult> {
    try {
      const monitor = await prisma.aPIMonitor.findUnique({
        where: { id: monitorId },
      });

      if (!monitor || monitor.status !== MonitorStatus.ACTIVE) {
        throw new Error('Monitor not found or not active');
      }

      const startTime = Date.now();
      let success = false;
      let statusCode = 0;
      let error: string | undefined;

      try {
        const response = await fetch(monitor.endpoint, {
          method: monitor.method,
          headers: monitor.headers as Record<string, string>,
          body: monitor.body || undefined,
          signal: AbortSignal.timeout(monitor.expectedResponseTime + 5000),
        });

        statusCode = response.status;
        success = statusCode === monitor.expectedStatusCode;
      } catch (err) {
        error = err instanceof Error ? err.message : 'Unknown error';
        logWarn('API check failed', {
          monitorId,
          endpoint: monitor.endpoint,
          error,
        });
      }

      const responseTime = Date.now() - startTime;

      // Record the check result
      await prisma.monitorCheck.create({
        data: {
          monitorId,
          statusCode,
          responseTime,
          success,
          error,
          checkedAt: new Date(),
        },
      });

      // Update monitor last checked timestamp
      await prisma.aPIMonitor.update({
        where: { id: monitorId },
        data: { lastCheckedAt: new Date() },
      });

      // Check if we need to create an incident
      if (!success) {
        await this.handleFailure(monitor, statusCode, responseTime, error);
      } else {
        await this.resolveActiveIncidents(monitorId);
      }

      return {
        success,
        statusCode,
        responseTime,
        error,
        timestamp: new Date(),
      };
    } catch (error) {
      logError('Failed to execute monitor check', { error, monitorId });
      throw error;
    }
  }

  /**
   * Handle a failed check and create incidents if necessary
   */
  private static async handleFailure(
    monitor: {
      id: string;
      name: string;
      endpoint: string;
      expectedStatusCode: number;
      expectedResponseTime: number;
      alertEmail?: string | null;
      userId: string;
    },
    statusCode: number,
    responseTime: number,
    error?: string
  ) {
    // Check if there's already an open incident
    const existingIncident = await prisma.monitorIncident.findFirst({
      where: {
        monitorId: monitor.id,
        status: { in: [IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED] },
      },
    });

    if (existingIncident) {
      // Update existing incident
      await prisma.monitorIncident.update({
        where: { id: existingIncident.id },
        data: { lastOccurredAt: new Date() },
      });
      return;
    }

    // Determine severity based on status code and response time
    let severity = IncidentSeverity.LOW;
    if (statusCode >= 500 || error?.includes('timeout')) {
      severity = IncidentSeverity.CRITICAL;
    } else if (
      statusCode >= 400 ||
      responseTime > monitor.expectedResponseTime * 2
    ) {
      severity = IncidentSeverity.HIGH;
    } else if (responseTime > monitor.expectedResponseTime) {
      severity = IncidentSeverity.MEDIUM;
    }

    // Create new incident
    const incident = await prisma.monitorIncident.create({
      data: {
        monitorId: monitor.id,
        severity,
        status: IncidentStatus.OPEN,
        message: error || `API returned status code ${statusCode}`,
        detectedAt: new Date(),
        lastOccurredAt: new Date(),
      },
    });

    logWarn('New API incident created', {
      incidentId: incident.id,
      monitorId: monitor.id,
      severity,
    });

    // Send alert email if configured (gated - requires subscription)
    if (monitor.alertEmail) {
      await this.sendAlert(
        {
          name: monitor.name,
          endpoint: monitor.endpoint,
          alertEmail: monitor.alertEmail,
          userId: monitor.userId,
        },
        incident
      );
    }
  }

  /**
   * Resolve any active incidents for a monitor
   */
  private static async resolveActiveIncidents(monitorId: string) {
    const activeIncidents = await prisma.monitorIncident.findMany({
      where: {
        monitorId,
        status: { in: [IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED] },
      },
    });

    for (const incident of activeIncidents) {
      await prisma.monitorIncident.update({
        where: { id: incident.id },
        data: { status: IncidentStatus.RESOLVED, resolvedAt: new Date() },
      });

      logInfo('Incident resolved', { incidentId: incident.id, monitorId });
    }
  }

  /**
   * Send alert email for an incident (gated - requires subscription)
   */
  private static async sendAlert(
    monitor: {
      name: string;
      endpoint: string;
      alertEmail: string;
      userId: string;
    },
    incident: {
      id: string;
      severity: string;
      message: string;
      detectedAt: Date;
    }
  ) {
    try {
      await sendGatedEmail({
        to: monitor.alertEmail,
        subject: `[${incident.severity}] API Monitor Alert: ${monitor.name}`,
        html: `
          <h2>API Monitor Alert</h2>
          <p><strong>Monitor:</strong> ${monitor.name}</p>
          <p><strong>Endpoint:</strong> ${monitor.endpoint}</p>
          <p><strong>Severity:</strong> ${incident.severity}</p>
          <p><strong>Message:</strong> ${incident.message}</p>
          <p><strong>Detected At:</strong> ${incident.detectedAt.toISOString()}</p>
          <p>Please investigate this issue as soon as possible.</p>
        `,
        userId: monitor.userId,
        silentFail: true, // Don't throw if user lacks subscription
      });

      logInfo('Alert email sent', {
        incidentId: incident.id,
        email: monitor.alertEmail,
      });
    } catch (error) {
      logError('Failed to send alert email', {
        error,
        incidentId: incident.id,
      });
    }
  }

  /**
   * Get monitor statistics
   */
  static async getStatistics(monitorId: string): Promise<MonitorStatistics> {
    try {
      const checks = await prisma.monitorCheck.findMany({
        where: { monitorId },
        orderBy: { checkedAt: 'desc' },
        take: 1000, // Last 1000 checks for stats
      });

      if (checks.length === 0) {
        return {
          uptime: 0,
          avgResponseTime: 0,
          totalChecks: 0,
          successfulChecks: 0,
          failedChecks: 0,
          currentStatus: 'DOWN',
        };
      }

      const totalChecks = checks.length;
      const successfulChecks = checks.filter(c => c.success).length;
      const failedChecks = totalChecks - successfulChecks;
      const uptime = (successfulChecks / totalChecks) * 100;
      const avgResponseTime =
        checks.reduce((sum, c) => sum + c.responseTime, 0) / totalChecks;

      // Determine current status based on recent checks
      const recentChecks = checks.slice(0, 5);
      const recentFailures = recentChecks.filter(c => !c.success).length;
      let currentStatus: 'UP' | 'DOWN' | 'DEGRADED' = 'UP';
      if (recentFailures >= 3) {
        currentStatus = 'DOWN';
      } else if (recentFailures > 0) {
        currentStatus = 'DEGRADED';
      }

      return {
        uptime: Math.round(uptime * 100) / 100,
        avgResponseTime: Math.round(avgResponseTime),
        totalChecks,
        successfulChecks,
        failedChecks,
        lastCheckTime: checks[0]?.checkedAt,
        currentStatus,
      };
    } catch (error) {
      logError('Failed to get monitor statistics', { error, monitorId });
      throw error;
    }
  }

  /**
   * Get all monitors for a user
   */
  static async getMonitors(userId: string, teamId?: string) {
    try {
      const monitors = await prisma.aPIMonitor.findMany({
        where: {
          OR: [{ userId }, { teamId: teamId || undefined }],
        },
        include: {
          _count: {
            select: {
              checks: true,
              incidents: { where: { status: IncidentStatus.OPEN } },
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });

      return monitors;
    } catch (error) {
      logError('Failed to get monitors', { error, userId });
      throw error;
    }
  }

  /**
   * Update monitor configuration
   */
  static async updateMonitor(
    monitorId: string,
    updates: Partial<MonitorConfig>
  ) {
    try {
      logInfo('Updating monitor', { monitorId });

      const monitor = await prisma.aPIMonitor.update({
        where: { id: monitorId },
        data: {
          name: updates.name,
          endpoint: updates.endpoint,
          method: updates.method,
          headers: updates.headers,
          body: updates.body,
          expectedStatusCode: updates.expectedStatusCode,
          expectedResponseTime: updates.expectedResponseTime,
          frequency: updates.frequency,
          alertEmail: updates.alertEmail,
        },
      });

      logInfo('Monitor updated', { monitorId });
      return monitor;
    } catch (error) {
      logError('Failed to update monitor', { error, monitorId });
      throw error;
    }
  }

  /**
   * Delete a monitor
   */
  static async deleteMonitor(monitorId: string) {
    try {
      logInfo('Deleting monitor', { monitorId });

      // Delete related checks and incidents (cascade should handle this, but being explicit)
      await prisma.monitorCheck.deleteMany({ where: { monitorId } });
      await prisma.monitorIncident.deleteMany({ where: { monitorId } });
      await prisma.aPIMonitor.delete({ where: { id: monitorId } });

      logInfo('Monitor deleted', { monitorId });
    } catch (error) {
      logError('Failed to delete monitor', { error, monitorId });
      throw error;
    }
  }

  /**
   * Pause/resume a monitor
   */
  static async updateMonitorStatus(monitorId: string, status: MonitorStatus) {
    try {
      const monitor = await prisma.aPIMonitor.update({
        where: { id: monitorId },
        data: { status },
      });

      logInfo('Monitor status updated', { monitorId, status });
      return monitor;
    } catch (error) {
      logError('Failed to update monitor status', { error, monitorId });
      throw error;
    }
  }

  /**
   * Get incidents for a monitor
   */
  static async getIncidents(monitorId: string, limit = 50) {
    try {
      const incidents = await prisma.monitorIncident.findMany({
        where: { monitorId },
        orderBy: { detectedAt: 'desc' },
        take: limit,
      });

      return incidents;
    } catch (error) {
      logError('Failed to get incidents', { error, monitorId });
      throw error;
    }
  }

  /**
   * Acknowledge an incident
   */
  static async acknowledgeIncident(incidentId: string) {
    try {
      const incident = await prisma.monitorIncident.update({
        where: { id: incidentId },
        data: { status: IncidentStatus.ACKNOWLEDGED },
      });

      logInfo('Incident acknowledged', { incidentId });
      return incident;
    } catch (error) {
      logError('Failed to acknowledge incident', { error, incidentId });
      throw error;
    }
  }
}

export { MonitorStatus, MonitorFrequency, IncidentSeverity, IncidentStatus };
export type { MonitorConfig, CheckResult, MonitorStatistics };
