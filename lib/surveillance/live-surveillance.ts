/**
 * Live Surveillance Service - Premium A3
 *
 * Monitors user's production APIs for security events
 * Available for PRO and ENTERPRISE tiers
 */

import { PrismaClient, ThreatSeverity, LiveThreatEvent } from '@prisma/client';
import { logInfo, logError } from '../logger';
import { broadcastAlert, type RealTimeAlert } from '../alerts/real-time-alerts';
import crypto from 'crypto';

const prisma = new PrismaClient();

/**
 * Event types that can be captured by surveillance
 */
export type LiveEventType =
  | 'auth_failure'
  | 'validation_error'
  | '5xx_error'
  | '4xx_error'
  | 'injection_attempt'
  | 'rate_limit'
  | 'suspicious_pattern'
  | 'anomaly'
  | 'brute_force'
  | 'credential_stuffing'
  | 'bot_traffic'
  | 'custom';

/**
 * Incoming event from SDK
 */
export interface IncomingLiveEvent {
  eventType: LiveEventType | string;
  timestamp?: string | Date;
  ip: string;
  userAgent?: string;
  requestPath?: string;
  statusCode?: number;
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  severity?: ThreatSeverity;
  metadata?: Record<string, unknown>;
}

/**
 * SDK configuration response
 */
export interface SurveillanceConfig {
  apiKey: string;
  projectId: string;
  projectName: string;
  endpoint: string;
  rateLimitPerMinute: number;
}

/**
 * Data retention periods by tier (in days)
 */
export const DATA_RETENTION_DAYS: Record<string, number> = {
  STARTER: 7,
  PRO: 30,
  ENTERPRISE: 90,
};

/**
 * Rate limits per minute by tier
 */
export const EVENT_RATE_LIMITS: Record<string, number> = {
  STARTER: 100,
  PRO: 500,
  ENTERPRISE: 2000,
};

/**
 * In-memory rate tracking for event ingestion
 * Key: projectId, Value: Array of timestamps
 */
const eventRateTracking = new Map<string, number[]>();

/**
 * Generate a new surveillance API key
 */
export function generateSurveillanceApiKey(): string {
  return `vx_live_${crypto.randomBytes(24).toString('hex')}`;
}

/**
 * Validate a surveillance API key and get associated project
 */
export async function validateSurveillanceApiKey(apiKey: string): Promise<{
  valid: boolean;
  project?: {
    id: string;
    name: string;
    ownerId: string;
    tier: string;
  };
  error?: string;
}> {
  if (!apiKey || !apiKey.startsWith('vx_live_')) {
    return { valid: false, error: 'Invalid API key format' };
  }

  try {
    const project = await prisma.apiProject.findUnique({
      where: { surveillanceApiKey: apiKey },
      select: {
        id: true,
        name: true,
        createdById: true,
        createdBy: {
          select: {
            subscriptions: {
              where: {
                status: { in: ['ACTIVE', 'TRIALING'] },
              },
              select: {
                plan: true,
              },
              take: 1,
            },
          },
        },
      },
    });

    if (!project) {
      return { valid: false, error: 'API key not found' };
    }

    const tier = project.createdBy.subscriptions[0]?.plan || 'STARTER';

    return {
      valid: true,
      project: {
        id: project.id,
        name: project.name,
        ownerId: project.createdById,
        tier,
      },
    };
  } catch (error) {
    logError('Failed to validate surveillance API key', { error });
    return { valid: false, error: 'Validation failed' };
  }
}

/**
 * Check rate limit for event ingestion
 */
function checkEventRateLimit(projectId: string, tier: string): boolean {
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const limit = EVENT_RATE_LIMITS[tier] || 100;

  const timestamps = eventRateTracking.get(projectId) || [];
  const windowStart = now - windowMs;
  const recentCount = timestamps.filter(t => t >= windowStart).length;

  if (recentCount >= limit) {
    return false;
  }

  // Add current timestamp and clean old ones
  timestamps.push(now);
  eventRateTracking.set(
    projectId,
    timestamps.filter(t => t >= windowStart)
  );

  return true;
}

/**
 * Determine severity based on event type if not provided
 */
function determineSeverity(
  eventType: string,
  statusCode?: number
): ThreatSeverity {
  // Critical events
  if (
    ['injection_attempt', 'brute_force', 'credential_stuffing'].includes(
      eventType
    )
  ) {
    return 'CRITICAL';
  }

  // High severity events
  if (['auth_failure', '5xx_error', 'suspicious_pattern'].includes(eventType)) {
    return 'HIGH';
  }

  // Medium severity events
  if (
    ['rate_limit', 'validation_error', 'anomaly', 'bot_traffic'].includes(
      eventType
    )
  ) {
    return 'MEDIUM';
  }

  // Check status code for 4xx errors
  if (eventType === '4xx_error' && statusCode) {
    if (statusCode === 401 || statusCode === 403) return 'HIGH';
    return 'MEDIUM';
  }

  return 'LOW';
}

/**
 * Ingest a live threat event from SDK
 */
export async function ingestLiveEvent(
  projectId: string,
  ownerId: string,
  tier: string,
  event: IncomingLiveEvent
): Promise<{ success: boolean; eventId?: string; error?: string }> {
  try {
    // Check rate limit
    if (!checkEventRateLimit(projectId, tier)) {
      return {
        success: false,
        error: 'Rate limit exceeded. Please upgrade for higher limits.',
      };
    }

    // Validate and normalize event
    const severity =
      event.severity || determineSeverity(event.eventType, event.statusCode);
    const timestamp = event.timestamp ? new Date(event.timestamp) : new Date();

    // Store event
    const storedEvent = await prisma.liveThreatEvent.create({
      data: {
        projectId,
        eventType: event.eventType,
        timestamp,
        ip: event.ip,
        userAgent: event.userAgent,
        requestPath: event.requestPath,
        statusCode: event.statusCode,
        method: event.method,
        headers: event.headers as object | undefined,
        body: event.body as object | undefined,
        severity,
        metadata: event.metadata as object | undefined,
      },
    });

    logInfo('Live event ingested', {
      eventId: storedEvent.id,
      projectId,
      eventType: event.eventType,
      severity,
    });

    // Broadcast real-time alert for high/critical severity
    if (severity === 'HIGH' || severity === 'CRITICAL') {
      const alert: RealTimeAlert = {
        id: storedEvent.id,
        type: 'threat_detected',
        severity,
        title: `Live API ${severity}: ${event.eventType}`,
        message: `${event.eventType} detected on ${event.requestPath || 'your API'}`,
        sourceIp: event.ip,
        path: event.requestPath,
        timestamp: new Date(),
        metadata: { eventType: event.eventType, statusCode: event.statusCode },
        autoBlocked: false,
        recommendation: getRecommendation(event.eventType),
      };

      broadcastAlert(ownerId, alert);
    }

    return { success: true, eventId: storedEvent.id };
  } catch (error) {
    logError('Failed to ingest live event', {
      error,
      projectId,
      eventType: event.eventType,
    });
    return { success: false, error: 'Failed to store event' };
  }
}

/**
 * Get recommendation for event type
 */
function getRecommendation(eventType: string): string {
  const recommendations: Record<string, string> = {
    auth_failure:
      'Consider implementing account lockout after multiple failures',
    validation_error: 'Review input validation rules for the affected endpoint',
    '5xx_error': 'Check server logs and error handling for the affected route',
    injection_attempt: 'Verify input sanitization and parameterized queries',
    rate_limit:
      'Adjust rate limiting thresholds if legitimate traffic is affected',
    brute_force: 'Enable CAPTCHA and consider IP blocking',
    credential_stuffing: 'Implement compromised password detection',
    bot_traffic: 'Consider implementing bot protection measures',
    anomaly: 'Review the anomalous traffic pattern in your dashboard',
  };

  return (
    recommendations[eventType] || 'Review the event details in your dashboard'
  );
}

/**
 * Get live events for a project
 */
export async function getLiveEvents(
  projectId: string,
  options: {
    eventType?: string;
    severity?: ThreatSeverity;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
  } = {}
): Promise<{
  events: LiveThreatEvent[];
  total: number;
}> {
  const {
    eventType,
    severity,
    startDate,
    endDate,
    limit = 100,
    offset = 0,
  } = options;

   
  const where: any = { projectId };

  if (eventType) where.eventType = eventType;
  if (severity) where.severity = severity;
  if (startDate || endDate) {
    where.timestamp = {};
    if (startDate) where.timestamp.gte = startDate;
    if (endDate) where.timestamp.lte = endDate;
  }

  const [events, total] = await Promise.all([
    prisma.liveThreatEvent.findMany({
      where,
      orderBy: { timestamp: 'desc' },
      take: limit,
      skip: offset,
    }),
    prisma.liveThreatEvent.count({ where }),
  ]);

  return { events, total };
}

/**
 * Get live event statistics for a project
 */
export async function getLiveEventStats(
  projectId: string,
  options: {
    startDate?: Date;
    endDate?: Date;
  } = {}
): Promise<{
  total: number;
  bySeverity: Record<ThreatSeverity, number>;
  byType: Record<string, number>;
  topIPs: Array<{ ip: string; count: number }>;
  topPaths: Array<{ path: string; count: number }>;
  hourlyDistribution: Array<{ hour: number; count: number }>;
}> {
  const { startDate, endDate } = options;

   
  const where: any = { projectId };

  if (startDate || endDate) {
    where.timestamp = {};
    if (startDate) where.timestamp.gte = startDate;
    if (endDate) where.timestamp.lte = endDate;
  }

  const events = await prisma.liveThreatEvent.findMany({
    where,
    select: {
      severity: true,
      eventType: true,
      ip: true,
      requestPath: true,
      timestamp: true,
    },
  });

  const bySeverity: Record<ThreatSeverity, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };

  const byType: Record<string, number> = {};
  const ipCounts: Record<string, number> = {};
  const pathCounts: Record<string, number> = {};
  const hourCounts: Record<number, number> = {};

  for (const event of events) {
    bySeverity[event.severity]++;
    byType[event.eventType] = (byType[event.eventType] || 0) + 1;
    ipCounts[event.ip] = (ipCounts[event.ip] || 0) + 1;
    if (event.requestPath) {
      pathCounts[event.requestPath] = (pathCounts[event.requestPath] || 0) + 1;
    }
    const hour = new Date(event.timestamp).getHours();
    hourCounts[hour] = (hourCounts[hour] || 0) + 1;
  }

  const topIPs = Object.entries(ipCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const topPaths = Object.entries(pathCounts)
    .map(([path, count]) => ({ path, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const hourlyDistribution = Array.from({ length: 24 }, (_, hour) => ({
    hour,
    count: hourCounts[hour] || 0,
  }));

  return {
    total: events.length,
    bySeverity,
    byType,
    topIPs,
    topPaths,
    hourlyDistribution,
  };
}

/**
 * Generate or regenerate surveillance API key for a project
 */
export async function generateProjectApiKey(
  projectId: string,
  userId: string
): Promise<{ success: boolean; apiKey?: string; error?: string }> {
  try {
    // Verify ownership
    const project = await prisma.apiProject.findFirst({
      where: {
        id: projectId,
        createdById: userId,
      },
    });

    if (!project) {
      return { success: false, error: 'Project not found or access denied' };
    }

    const apiKey = generateSurveillanceApiKey();

    await prisma.apiProject.update({
      where: { id: projectId },
      data: { surveillanceApiKey: apiKey },
    });

    logInfo('Surveillance API key generated', { projectId, userId });

    return { success: true, apiKey };
  } catch (error) {
    logError('Failed to generate surveillance API key', {
      error,
      projectId,
      userId,
    });
    return { success: false, error: 'Failed to generate API key' };
  }
}

/**
 * Revoke surveillance API key for a project
 */
export async function revokeProjectApiKey(
  projectId: string,
  userId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const project = await prisma.apiProject.findFirst({
      where: {
        id: projectId,
        createdById: userId,
      },
    });

    if (!project) {
      return { success: false, error: 'Project not found or access denied' };
    }

    await prisma.apiProject.update({
      where: { id: projectId },
      data: { surveillanceApiKey: null },
    });

    logInfo('Surveillance API key revoked', { projectId, userId });

    return { success: true };
  } catch (error) {
    logError('Failed to revoke surveillance API key', {
      error,
      projectId,
      userId,
    });
    return { success: false, error: 'Failed to revoke API key' };
  }
}

/**
 * Clean up old events based on retention policy
 */
export async function cleanupOldEvents(dryRun: boolean = false): Promise<{
  deleted: number;
  projects: number;
}> {
  try {
    // Get all projects with their owner's subscription tier
    const projects = await prisma.apiProject.findMany({
      where: {
        liveThreatEvents: { some: {} },
      },
      select: {
        id: true,
        createdBy: {
          select: {
            subscriptions: {
              where: { status: { in: ['ACTIVE', 'TRIALING'] } },
              select: { plan: true },
              take: 1,
            },
          },
        },
      },
    });

    let totalDeleted = 0;

    for (const project of projects) {
      const tier = project.createdBy.subscriptions[0]?.plan || 'STARTER';
      const retentionDays = DATA_RETENTION_DAYS[tier] || 7;
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      if (dryRun) {
        const count = await prisma.liveThreatEvent.count({
          where: {
            projectId: project.id,
            createdAt: { lt: cutoffDate },
          },
        });
        totalDeleted += count;
      } else {
        const result = await prisma.liveThreatEvent.deleteMany({
          where: {
            projectId: project.id,
            createdAt: { lt: cutoffDate },
          },
        });
        totalDeleted += result.count;
      }
    }

    logInfo('Live event cleanup completed', {
      dryRun,
      deleted: totalDeleted,
      projects: projects.length,
    });

    return { deleted: totalDeleted, projects: projects.length };
  } catch (error) {
    logError('Failed to cleanup old events', { error });
    throw error;
  }
}
