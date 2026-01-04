/**
 * Real-Time Alert Service - Premium A2
 *
 * Provides real-time alert streaming and notification management
 * Available for PRO and ENTERPRISE tiers
 */

import { PrismaClient, ThreatSeverity, HoneypotAlert } from '@prisma/client';
import { logInfo, logError, logWarn } from '../logger';
import { sendEmail } from '../email/email-service';

const prisma = new PrismaClient();

/**
 * Alert types for real-time notifications
 */
export type AlertType =
  | 'threat_detected'
  | 'honeypot_triggered'
  | 'brute_force'
  | 'injection_attempt'
  | 'rate_limit_exceeded'
  | 'anomaly_detected'
  | 'system_alert';

/**
 * Real-time alert structure
 */
export interface RealTimeAlert {
  id: string;
  type: AlertType;
  severity: ThreatSeverity;
  title: string;
  message: string;
  honeypotId?: string;
  honeypotName?: string;
  sourceIp?: string;
  path?: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
  autoBlocked: boolean;
  recommendation?: string;
}

/**
 * Alert threshold configuration
 */
export interface AlertThreshold {
  type: AlertType;
  count: number;
  windowMs: number;
  severity: ThreatSeverity;
}

/**
 * Default alert thresholds
 */
export const DEFAULT_THRESHOLDS: AlertThreshold[] = [
  { type: 'brute_force', count: 10, windowMs: 60000, severity: 'HIGH' }, // 10 in 1 min
  {
    type: 'injection_attempt',
    count: 5,
    windowMs: 300000,
    severity: 'CRITICAL',
  }, // 5 in 5 min
  {
    type: 'rate_limit_exceeded',
    count: 20,
    windowMs: 60000,
    severity: 'MEDIUM',
  }, // 20 in 1 min
  { type: 'anomaly_detected', count: 3, windowMs: 600000, severity: 'HIGH' }, // 3 in 10 min
];

/**
 * In-memory storage for alert subscribers (SSE connections)
 * Key: userId, Value: Array of response writers
 */
const subscribers = new Map<
  string,
  Array<{
    id: string;
    write: (data: string) => void;
    close: () => void;
  }>
>();

/**
 * In-memory rate tracking for threshold-based alerts
 * Key: `${userId}-${alertType}`, Value: Array of timestamps
 */
const alertRateTracking = new Map<string, number[]>();

/**
 * Subscribe a user to real-time alerts
 */
export function subscribeToAlerts(
  userId: string,
  writer: { id: string; write: (data: string) => void; close: () => void }
): () => void {
  const userSubscribers = subscribers.get(userId) || [];
  userSubscribers.push(writer);
  subscribers.set(userId, userSubscribers);

  logInfo('User subscribed to alerts', {
    userId,
    subscriberId: writer.id,
    totalSubscribers: userSubscribers.length,
  });

  // Return unsubscribe function
  return () => {
    const currentSubscribers = subscribers.get(userId) || [];
    const filtered = currentSubscribers.filter(s => s.id !== writer.id);
    if (filtered.length > 0) {
      subscribers.set(userId, filtered);
    } else {
      subscribers.delete(userId);
    }
    logInfo('User unsubscribed from alerts', {
      userId,
      subscriberId: writer.id,
    });
  };
}

/**
 * Broadcast an alert to all subscribers for a user
 */
export function broadcastAlert(userId: string, alert: RealTimeAlert): void {
  const userSubscribers = subscribers.get(userId);
  if (!userSubscribers || userSubscribers.length === 0) {
    return;
  }

  const eventData = `data: ${JSON.stringify(alert)}\n\n`;

  for (const subscriber of userSubscribers) {
    try {
      subscriber.write(eventData);
    } catch (error) {
      logWarn('Failed to send alert to subscriber', {
        userId,
        subscriberId: subscriber.id,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  logInfo('Alert broadcast to subscribers', {
    userId,
    alertType: alert.type,
    subscriberCount: userSubscribers.length,
  });
}

/**
 * Check if alert threshold is exceeded
 */
function checkThreshold(
  userId: string,
  alertType: AlertType,
  thresholds: AlertThreshold[]
): AlertThreshold | null {
  const key = `${userId}-${alertType}`;
  const now = Date.now();

  // Get or initialize tracking array
  const timestamps = alertRateTracking.get(key) || [];

  // Add current timestamp
  timestamps.push(now);
  alertRateTracking.set(key, timestamps);

  // Check each threshold
  for (const threshold of thresholds) {
    if (threshold.type !== alertType) continue;

    const windowStart = now - threshold.windowMs;
    const recentCount = timestamps.filter(t => t >= windowStart).length;

    if (recentCount >= threshold.count) {
      // Clean up old timestamps
      alertRateTracking.set(
        key,
        timestamps.filter(t => t >= windowStart)
      );
      return threshold;
    }
  }

  // Clean up old timestamps (keep last hour)
  const oneHourAgo = now - 3600000;
  alertRateTracking.set(
    key,
    timestamps.filter(t => t >= oneHourAgo)
  );

  return null;
}

/**
 * Create and store a honeypot alert
 */
export async function createHoneypotAlert(
  honeypotId: string,
  alert: {
    type: string;
    severity: ThreatSeverity;
    description: string;
    threats: unknown[];
    recommendation: string;
    ip: string;
    path: string;
    autoBlocked?: boolean;
  }
): Promise<HoneypotAlert> {
  try {
    const honeypotAlert = await prisma.honeypotAlert.create({
      data: {
        honeypotId,
        type: alert.type,
        severity: alert.severity,
        description: alert.description,
        threats: alert.threats as object,
        recommendation: alert.recommendation,
        ip: alert.ip,
        path: alert.path,
        autoBlocked: alert.autoBlocked || false,
      },
      include: {
        honeypot: {
          select: {
            id: true,
            name: true,
            ownerId: true,
          },
        },
      },
    });

    // Get the owner ID for broadcasting
    const ownerId = honeypotAlert.honeypot.ownerId;

    // Create real-time alert
    const realTimeAlert: RealTimeAlert = {
      id: honeypotAlert.id,
      type: mapAlertTypeFromString(alert.type),
      severity: alert.severity,
      title: `${alert.severity} Severity Alert`,
      message: alert.description,
      honeypotId,
      honeypotName: honeypotAlert.honeypot.name,
      sourceIp: alert.ip,
      path: alert.path,
      timestamp: new Date(),
      metadata: { threats: alert.threats },
      autoBlocked: alert.autoBlocked || false,
      recommendation: alert.recommendation,
    };

    // Broadcast to subscribers
    broadcastAlert(ownerId, realTimeAlert);

    // Check thresholds and potentially send email
    const alertType = mapAlertTypeFromString(alert.type);
    const threshold = checkThreshold(ownerId, alertType, DEFAULT_THRESHOLDS);

    if (threshold) {
      await sendThresholdAlert(ownerId, threshold, realTimeAlert);
    }

    logInfo('Honeypot alert created', {
      alertId: honeypotAlert.id,
      honeypotId,
      type: alert.type,
      severity: alert.severity,
    });

    return honeypotAlert;
  } catch (error) {
    logError('Failed to create honeypot alert', {
      error,
      honeypotId,
      type: alert.type,
    });
    throw error;
  }
}

/**
 * Map string alert type to AlertType enum
 */
function mapAlertTypeFromString(type: string): AlertType {
  const typeMap: Record<string, AlertType> = {
    threat: 'threat_detected',
    honeypot: 'honeypot_triggered',
    brute_force: 'brute_force',
    injection: 'injection_attempt',
    rate_limit: 'rate_limit_exceeded',
    anomaly: 'anomaly_detected',
    system: 'system_alert',
  };

  return typeMap[type.toLowerCase()] || 'threat_detected';
}

/**
 * Send email notification when threshold is exceeded
 */
async function sendThresholdAlert(
  userId: string,
  threshold: AlertThreshold,
  triggeringAlert: RealTimeAlert
): Promise<void> {
  try {
    // Check if user has premium access for email notifications
    const { canAccessPremiumFeatures } = await import(
      '@core/lib/auth/subscription-middleware'
    );
    const hasAccess = await canAccessPremiumFeatures(userId);

    if (!hasAccess) {
      logWarn('Skipping threshold email - no premium access', { userId });
      return;
    }

    // Get user email
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, name: true },
    });

    if (!user?.email) {
      logWarn('Cannot send threshold alert - no user email', { userId });
      return;
    }

    // Check notification preferences
    const prefs = await prisma.notificationPreference.findUnique({
      where: { userId },
    });

    if (prefs && !prefs.securityAlertsEnabled) {
      logInfo('Security alerts disabled for user', { userId });
      return;
    }

    await sendEmail({
      to: user.email,
      subject: `[VortexSecure] ${threshold.severity} Alert: ${threshold.type} threshold exceeded`,
      html: `
        <h2>Security Alert Threshold Exceeded</h2>
        <p>Hi ${user.name || 'there'},</p>
        <p>Your honeypot has detected an elevated level of suspicious activity:</p>
        <ul>
          <li><strong>Alert Type:</strong> ${threshold.type}</li>
          <li><strong>Severity:</strong> ${threshold.severity}</li>
          <li><strong>Count:</strong> ${threshold.count} events in ${Math.round(threshold.windowMs / 60000)} minutes</li>
          <li><strong>Latest Source IP:</strong> ${triggeringAlert.sourceIp || 'Unknown'}</li>
          <li><strong>Honeypot:</strong> ${triggeringAlert.honeypotName || 'Unknown'}</li>
        </ul>
        <p><strong>Recommendation:</strong> ${triggeringAlert.recommendation || 'Review your honeypot dashboard for details.'}</p>
        <p><a href="${process.env.NEXT_PUBLIC_APP_URL}/dashboard/honeypots">View Dashboard</a></p>
      `,
    });

    logInfo('Threshold alert email sent', {
      userId,
      alertType: threshold.type,
      threshold: threshold.count,
    });
  } catch (error) {
    logError('Failed to send threshold alert email', {
      error,
      userId,
      alertType: threshold.type,
    });
  }
}

/**
 * Get recent alerts for a user
 */
export async function getRecentAlerts(
  userId: string,
  options: {
    honeypotId?: string;
    severity?: ThreatSeverity;
    resolved?: boolean;
    limit?: number;
    offset?: number;
  } = {}
): Promise<{
  alerts: HoneypotAlert[];
  total: number;
}> {
  const { honeypotId, severity, resolved, limit = 50, offset = 0 } = options;

  // Build where clause
   
  const where: any = {
    honeypot: {
      ownerId: userId,
    },
  };

  if (honeypotId) {
    where.honeypotId = honeypotId;
  }

  if (severity) {
    where.severity = severity;
  }

  if (resolved !== undefined) {
    where.resolved = resolved;
  }

  const [alerts, total] = await Promise.all([
    prisma.honeypotAlert.findMany({
      where,
      include: {
        honeypot: {
          select: {
            id: true,
            name: true,
            slug: true,
          },
        },
      },
      orderBy: {
        timestamp: 'desc',
      },
      take: limit,
      skip: offset,
    }),
    prisma.honeypotAlert.count({ where }),
  ]);

  return { alerts, total };
}

/**
 * Resolve an alert
 */
export async function resolveAlert(
  alertId: string,
  userId: string,
  resolution: string
): Promise<HoneypotAlert> {
  // Verify ownership
  const alert = await prisma.honeypotAlert.findFirst({
    where: {
      id: alertId,
      honeypot: {
        ownerId: userId,
      },
    },
  });

  if (!alert) {
    throw new Error('Alert not found or access denied');
  }

  return prisma.honeypotAlert.update({
    where: { id: alertId },
    data: {
      resolved: true,
      resolvedAt: new Date(),
      resolution,
    },
  });
}

/**
 * Get alert statistics for a user
 */
export async function getAlertStats(
  userId: string,
  options: {
    startDate?: Date;
    endDate?: Date;
    honeypotId?: string;
  } = {}
): Promise<{
  total: number;
  bySeverity: Record<ThreatSeverity, number>;
  byType: Record<string, number>;
  resolved: number;
  unresolved: number;
  autoBlocked: number;
}> {
  const { startDate, endDate, honeypotId } = options;

  // Build where clause
   
  const where: any = {
    honeypot: {
      ownerId: userId,
    },
  };

  if (honeypotId) {
    where.honeypotId = honeypotId;
  }

  if (startDate || endDate) {
    where.timestamp = {};
    if (startDate) where.timestamp.gte = startDate;
    if (endDate) where.timestamp.lte = endDate;
  }

  const alerts = await prisma.honeypotAlert.findMany({
    where,
    select: {
      severity: true,
      type: true,
      resolved: true,
      autoBlocked: true,
    },
  });

  const bySeverity: Record<ThreatSeverity, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };

  const byType: Record<string, number> = {};
  let resolved = 0;
  let autoBlocked = 0;

  for (const alert of alerts) {
    bySeverity[alert.severity]++;
    byType[alert.type] = (byType[alert.type] || 0) + 1;
    if (alert.resolved) resolved++;
    if (alert.autoBlocked) autoBlocked++;
  }

  return {
    total: alerts.length,
    bySeverity,
    byType,
    resolved,
    unresolved: alerts.length - resolved,
    autoBlocked,
  };
}

/**
 * Get subscriber count for monitoring
 */
export function getSubscriberCount(): number {
  let count = 0;
  subscribers.forEach(subs => {
    count += subs.length;
  });
  return count;
}
