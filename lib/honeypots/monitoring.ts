/**
 * Honeypot Monitoring Service
 * Real-time monitoring of honeypot traffic with threat intelligence integration
 */

import { PrismaClient, HoneypotStatus } from '@prisma/client';
import { logInfo, logError, logWarn } from '../logger';
import { threatFeedsService } from '../threats/threat-feeds';
import type { ThreatFeedEntry } from '../threats/threat-feeds';

const prisma = new PrismaClient();

export interface HoneypotTrafficEvent {
  honeypotId: string;
  timestamp: Date;
  ip: string;
  method: string;
  path: string;
  userAgent?: string;
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
  statusCode?: number;
}

export interface ThreatAlert {
  id: string;
  honeypotId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  description: string;
  threats: ThreatFeedEntry[];
  recommendation: string;
  ip: string;
  path: string;
  timestamp: Date;
  autoBlocked: boolean;
}

/**
 * Process incoming honeypot traffic and check against threat feeds
 */
export async function processHoneypotTraffic(
  event: HoneypotTrafficEvent
): Promise<ThreatAlert | null> {
  try {
    logInfo('Processing honeypot traffic', {
      honeypotId: event.honeypotId,
      ip: event.ip,
      path: event.path,
    });

    // Check against threat intelligence feeds
    const analysis = await threatFeedsService.autoFlagSuspiciousActivity({
      ip: event.ip,
      path: event.path,
      userAgent: event.userAgent,
    });

    // Log the traffic event
    await logTrafficEvent(event, analysis.threats);

    // Create alert if threats detected
    if (analysis.threats.length > 0) {
      const alert = await createThreatAlert({
        honeypotId: event.honeypotId,
        ip: event.ip,
        path: event.path,
        threats: analysis.threats,
        recommendation: analysis.recommendation,
        autoBlocked: analysis.shouldBlock,
      });

      // Auto-shutdown honeypot if critical threat detected
      if (analysis.shouldBlock) {
        logWarn('Critical threat detected, triggering auto-shutdown', {
          honeypotId: event.honeypotId,
          ip: event.ip,
          threats: analysis.threats.length,
        });

        await autoShutdownHoneypot(event.honeypotId, alert.id);
      }

      return alert;
    }

    return null;
  } catch (error) {
    logError('Error processing honeypot traffic', { error, event });
    return null;
  }
}

/**
 * Log traffic event to database
 */
async function logTrafficEvent(
  event: HoneypotTrafficEvent,
  threats: ThreatFeedEntry[]
): Promise<void> {
  try {
    await prisma.honeypotTraffic.create({
      data: {
        honeypotId: event.honeypotId,
        timestamp: event.timestamp,
        ip: event.ip,
        method: event.method,
        path: event.path,
        userAgent: event.userAgent,
        headers: event.headers as never,
        body: event.body as never,
        statusCode: event.statusCode,
        threatsDetected: threats.length,
        threatDetails: threats as never,
      },
    });
  } catch (error) {
    logError('Error logging traffic event', { error, event });
  }
}

/**
 * Create a threat alert
 */
async function createThreatAlert(params: {
  honeypotId: string;
  ip: string;
  path: string;
  threats: ThreatFeedEntry[];
  recommendation: string;
  autoBlocked: boolean;
}): Promise<ThreatAlert> {
  const { honeypotId, ip, path, threats, recommendation, autoBlocked } = params;

  // Determine overall severity
  const hasCritical = threats.some(t => t.severity === 'critical');
  const hasHigh = threats.some(t => t.severity === 'high');
  const severity = hasCritical ? 'critical' : hasHigh ? 'high' : 'medium';

  // Generate description
  const threatTypes = [...new Set(threats.flatMap(t => t.tags))].join(', ');
  const description = `Detected ${threats.length} threat(s) from IP ${ip}: ${threatTypes}`;

  const alert: ThreatAlert = {
    id: crypto.randomUUID(),
    honeypotId,
    severity,
    type: threats[0]?.type || 'unknown',
    description,
    threats,
    recommendation,
    ip,
    path,
    timestamp: new Date(),
    autoBlocked,
  };

  // Store alert in database
  try {
    await prisma.honeypotAlert.create({
      data: {
        id: alert.id,
        honeypotId: alert.honeypotId,
        severity: alert.severity.toUpperCase() as never,
        type: alert.type,
        description: alert.description,
        threats: alert.threats as never,
        recommendation: alert.recommendation,
        ip: alert.ip,
        path: alert.path,
        timestamp: alert.timestamp,
        autoBlocked: alert.autoBlocked,
        resolved: false,
      },
    });

    logInfo('Threat alert created', {
      alertId: alert.id,
      honeypotId: alert.honeypotId,
      severity: alert.severity,
    });
  } catch (error) {
    logError('Error creating threat alert', { error, alert });
  }

  return alert;
}

/**
 * Auto-shutdown honeypot due to critical threat
 */
async function autoShutdownHoneypot(
  honeypotId: string,
  alertId: string
): Promise<void> {
  try {
    await prisma.honeypot.update({
      where: { id: honeypotId },
      data: {
        status: HoneypotStatus.SUSPENDED,
        suspendedReason: `Auto-shutdown due to critical threat detection (Alert: ${alertId})`,
        suspendedAt: new Date(),
      },
    });

    logInfo('Honeypot auto-shutdown completed', { honeypotId, alertId });
  } catch (error) {
    logError('Error shutting down honeypot', { error, honeypotId, alertId });
  }
}

/**
 * Get alerts for a honeypot
 */
export async function getHoneypotAlerts(
  honeypotId: string,
  options: {
    limit?: number;
    resolved?: boolean;
    severity?: string[];
  } = {}
): Promise<ThreatAlert[]> {
  const { limit = 50, resolved, severity } = options;

  try {
    const alerts = await prisma.honeypotAlert.findMany({
      where: {
        honeypotId,
        ...(resolved !== undefined && { resolved }),
        ...(severity && {
          severity: {
            in: severity.map(s => s.toUpperCase()) as (
              | 'LOW'
              | 'MEDIUM'
              | 'HIGH'
              | 'CRITICAL'
            )[],
          },
        }),
      },
      orderBy: {
        timestamp: 'desc',
      },
      take: limit,
    });

    return alerts.map(
      (alert): ThreatAlert => ({
        id: alert.id,
        honeypotId: alert.honeypotId,
        severity: alert.severity.toLowerCase() as
          | 'low'
          | 'medium'
          | 'high'
          | 'critical',
        type: alert.type,
        description: alert.description,
        threats: alert.threats as never as ThreatFeedEntry[],
        recommendation: alert.recommendation,
        ip: alert.ip,
        path: alert.path,
        timestamp: alert.timestamp,
        autoBlocked: alert.autoBlocked,
      })
    );
  } catch (error) {
    logError('Error fetching honeypot alerts', { error, honeypotId });
    return [];
  }
}

/**
 * Resolve an alert
 */
export async function resolveAlert(
  alertId: string,
  resolution: string
): Promise<void> {
  try {
    await prisma.honeypotAlert.update({
      where: { id: alertId },
      data: {
        resolved: true,
        resolvedAt: new Date(),
        resolution,
      },
    });

    logInfo('Alert resolved', { alertId, resolution });
  } catch (error) {
    logError('Error resolving alert', { error, alertId });
  }
}

/**
 * Get honeypot traffic statistics
 */
export async function getHoneypotStats(
  honeypotId: string,
  timeRange: { start: Date; end: Date }
): Promise<{
  totalRequests: number;
  uniqueIps: number;
  threatsDetected: number;
  blockedIps: number;
  topPaths: Array<{ path: string; count: number }>;
  threatsByType: Record<string, number>;
}> {
  try {
    const traffic = await prisma.honeypotTraffic.findMany({
      where: {
        honeypotId,
        timestamp: {
          gte: timeRange.start,
          lte: timeRange.end,
        },
      },
    });

    const alerts = await prisma.honeypotAlert.findMany({
      where: {
        honeypotId,
        timestamp: {
          gte: timeRange.start,
          lte: timeRange.end,
        },
      },
    });

    // Calculate statistics
    const uniqueIps = new Set(traffic.map((t: { ip: string }) => t.ip)).size;
    const threatsDetected = alerts.length;
    const blockedIps = alerts.filter(
      (a: { autoBlocked: boolean }) => a.autoBlocked
    ).length;

    // Top paths
    const pathCounts = new Map<string, number>();
    traffic.forEach((t: { path: string }) => {
      pathCounts.set(t.path, (pathCounts.get(t.path) || 0) + 1);
    });
    const topPaths = Array.from(pathCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([path, count]) => ({ path, count }));

    // Threats by type
    const threatsByType: Record<string, number> = {};
    alerts.forEach((alert: { type: string }) => {
      threatsByType[alert.type] = (threatsByType[alert.type] || 0) + 1;
    });

    return {
      totalRequests: traffic.length,
      uniqueIps,
      threatsDetected,
      blockedIps,
      topPaths,
      threatsByType,
    };
  } catch (error) {
    logError('Error calculating honeypot stats', { error, honeypotId });
    return {
      totalRequests: 0,
      uniqueIps: 0,
      threatsDetected: 0,
      blockedIps: 0,
      topPaths: [],
      threatsByType: {},
    };
  }
}

/**
 * Redeploy honeypot after suspension
 */
export async function redeployHoneypot(honeypotId: string): Promise<void> {
  try {
    const honeypot = await prisma.honeypot.findUnique({
      where: { id: honeypotId },
    });

    if (!honeypot) {
      throw new Error('Honeypot not found');
    }

    if (honeypot.status !== HoneypotStatus.SUSPENDED) {
      throw new Error('Only suspended honeypots can be redeployed');
    }

    // Update status to deploying
    await prisma.honeypot.update({
      where: { id: honeypotId },
      data: {
        status: HoneypotStatus.DEPLOYING,
        suspendedReason: null,
        suspendedAt: null,
      },
    });

    logInfo('Honeypot redeployment initiated', { honeypotId });

    // Simulate deployment process (remove this in production)
    setTimeout(async () => {
      try {
        await prisma.honeypot.update({
          where: { id: honeypotId },
          data: { status: HoneypotStatus.ACTIVE },
        });
        logInfo('Honeypot redeployment completed', { honeypotId });
      } catch (error) {
        logError('Error completing honeypot redeployment', {
          error,
          honeypotId,
        });
        await prisma.honeypot.update({
          where: { id: honeypotId },
          data: { status: HoneypotStatus.ERROR },
        });
      }
    }, 5000); // 5 second delay to simulate deployment
  } catch (error) {
    logError('Error redeploying honeypot', { error, honeypotId });
    throw error;
  }
}
