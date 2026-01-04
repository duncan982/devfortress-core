/**
 * Incident Response Service
 * Automates threat response workflows and escalation
 */

import { prisma } from '../prisma';
import { logInfo, logError, logWarn } from '../logger';
import { ThreatSeverity } from '@prisma/client';
import { dynamicRateLimiter } from './dynamic-rate-limiter';
import { sendGatedEmail } from '../email/gated-email-service';

export enum ResponseAction {
  BLOCK_IP = 'BLOCK_IP',
  RATE_LIMIT = 'RATE_LIMIT',
  SUSPEND_HONEYPOT = 'SUSPEND_HONEYPOT',
  NOTIFY_ADMIN = 'NOTIFY_ADMIN',
  NOTIFY_USER = 'NOTIFY_USER',
  LOG_ONLY = 'LOG_ONLY',
}

export interface IncidentResponseRule {
  severity: ThreatSeverity;
  actions: ResponseAction[];
  autoExecute: boolean;
  notificationThreshold: number; // Number of incidents before notification
}

export interface Incident {
  id: string;
  honeypotId: string;
  sourceIp: string;
  severity: ThreatSeverity;
  type: string;
  description: string;
  detectedAt: Date;
  responded: boolean;
  responseActions?: string[];
  resolvedAt?: Date;
}

// Default response rules
const DEFAULT_RULES: Record<ThreatSeverity, IncidentResponseRule> = {
  CRITICAL: {
    severity: 'CRITICAL',
    actions: [
      ResponseAction.BLOCK_IP,
      ResponseAction.SUSPEND_HONEYPOT,
      ResponseAction.NOTIFY_ADMIN,
      ResponseAction.NOTIFY_USER,
    ],
    autoExecute: true,
    notificationThreshold: 1,
  },
  HIGH: {
    severity: 'HIGH',
    actions: [
      ResponseAction.BLOCK_IP,
      ResponseAction.NOTIFY_ADMIN,
      ResponseAction.NOTIFY_USER,
    ],
    autoExecute: true,
    notificationThreshold: 1,
  },
  MEDIUM: {
    severity: 'MEDIUM',
    actions: [ResponseAction.RATE_LIMIT, ResponseAction.NOTIFY_ADMIN],
    autoExecute: true,
    notificationThreshold: 5,
  },
  LOW: {
    severity: 'LOW',
    actions: [ResponseAction.LOG_ONLY],
    autoExecute: true,
    notificationThreshold: 10,
  },
};

export class IncidentResponseService {
  private notificationCounts = new Map<string, number>();

  /**
   * Handle a threat incident
   */
  async handleIncident(
    incident: Omit<Incident, 'id' | 'responded' | 'responseActions'>
  ): Promise<{
    incidentId: string;
    actionsExecuted: ResponseAction[];
  }> {
    try {
      logInfo('Handling incident', {
        honeypotId: incident.honeypotId,
        severity: incident.severity,
        sourceIp: incident.sourceIp,
      });

      // Create incident record
       
      const prismaAny = prisma as any;
      const incidentRecord = await prismaAny.incident.create({
        data: {
          honeypotId: incident.honeypotId,
          sourceIp: incident.sourceIp,
          severity: incident.severity,
          type: incident.type,
          description: incident.description,
          detectedAt: incident.detectedAt,
          responded: false,
        },
      });

      // Get response rule for severity
      const rule = DEFAULT_RULES[incident.severity];

      // Check if we should execute actions
      if (!rule.autoExecute) {
        logInfo('Manual review required for incident', {
          incidentId: incidentRecord.id,
        });
        return {
          incidentId: incidentRecord.id,
          actionsExecuted: [],
        };
      }

      // Execute response actions
      const executedActions: ResponseAction[] = [];

      for (const action of rule.actions) {
        try {
          await this.executeAction(action, incident);
          executedActions.push(action);
        } catch (error) {
          logError('Error executing response action', {
            action,
            incident: incidentRecord.id,
            error,
          });
        }
      }

      // Update incident as responded
      await prismaAny.incident.update({
        where: { id: incidentRecord.id },
        data: {
          responded: true,
          responseActions: executedActions,
        },
      });

      logInfo('Incident response completed', {
        incidentId: incidentRecord.id,
        actionsExecuted: executedActions,
      });

      return {
        incidentId: incidentRecord.id,
        actionsExecuted: executedActions,
      };
    } catch (error) {
      logError('Error handling incident', { error, incident });
      throw error;
    }
  }

  /**
   * Execute a specific response action
   */
  private async executeAction(
    action: ResponseAction,
    incident: Omit<Incident, 'id' | 'responded' | 'responseActions'>
  ): Promise<void> {
    switch (action) {
      case ResponseAction.BLOCK_IP:
        await this.blockIP(incident.sourceIp, incident.severity);
        break;

      case ResponseAction.RATE_LIMIT:
        await this.applyRateLimit(incident.sourceIp, incident.severity);
        break;

      case ResponseAction.SUSPEND_HONEYPOT:
        await this.suspendHoneypot(incident.honeypotId, incident.description);
        break;

      case ResponseAction.NOTIFY_ADMIN:
        await this.notifyAdmins(incident);
        break;

      case ResponseAction.NOTIFY_USER:
        await this.notifyUser(incident);
        break;

      case ResponseAction.LOG_ONLY:
        logWarn('Incident logged - no automated action taken', { incident });
        break;

      default:
        logWarn('Unknown response action', { action });
    }
  }

  /**
   * Block an IP address
   */
  private async blockIP(ip: string, severity: ThreatSeverity): Promise<void> {
    try {
      await dynamicRateLimiter.applyAnomalyBasedRateLimit(
        ip,
        severity,
        'Blocked due to incident response'
      );

      logInfo('IP blocked', { ip, severity });
    } catch (error) {
      logError('Error blocking IP', { error, ip });
      throw error;
    }
  }

  /**
   * Apply rate limiting to an IP
   */
  private async applyRateLimit(
    ip: string,
    severity: ThreatSeverity
  ): Promise<void> {
    try {
      await dynamicRateLimiter.applyAnomalyBasedRateLimit(
        ip,
        severity,
        'Rate limited due to incident response'
      );

      logInfo('Rate limit applied', { ip, severity });
    } catch (error) {
      logError('Error applying rate limit', { error, ip });
      throw error;
    }
  }

  /**
   * Suspend a honeypot
   */
  private async suspendHoneypot(
    honeypotId: string,
    reason: string
  ): Promise<void> {
    try {
       
      const prismaAny = prisma as any;
      await prismaAny.honeypot.update({
        where: { id: honeypotId },
        data: {
          status: 'SUSPENDED',
          suspendedReason: reason,
          suspendedAt: new Date(),
        },
      });

      logInfo('Honeypot suspended', { honeypotId, reason });
    } catch (error) {
      logError('Error suspending honeypot', { error, honeypotId });
      throw error;
    }
  }

  /**
   * Notify administrators (gated - requires subscription)
   */
  private async notifyAdmins(
    incident: Omit<Incident, 'id' | 'responded' | 'responseActions'>
  ): Promise<void> {
    try {
      // Get honeypot owner details
      const honeypot = await prisma.honeypot.findUnique({
        where: { id: incident.honeypotId },
        include: {
          owner: {
            select: {
              id: true,
              email: true,
              name: true,
            },
          },
        },
      });

      if (!honeypot || !honeypot.owner.email) {
        logWarn('Cannot notify admin - no email found', {
          honeypotId: incident.honeypotId,
        });
        return;
      }

      // Check notification threshold
      const countKey = `${incident.honeypotId}:${incident.severity}`;
      const currentCount = (this.notificationCounts.get(countKey) || 0) + 1;
      this.notificationCounts.set(countKey, currentCount);

      const rule = DEFAULT_RULES[incident.severity];
      if (currentCount < rule.notificationThreshold) {
        logInfo('Notification threshold not met', {
          currentCount,
          threshold: rule.notificationThreshold,
        });
        return;
      }

      // Reset count after notification
      this.notificationCounts.set(countKey, 0);

      // Send email notification (gated - requires subscription)
      await sendGatedEmail({
        to: honeypot.owner.email,
        subject: `🚨 ${incident.severity} Security Incident - ${honeypot.name}`,
        html: `
          <h2>Security Incident Alert</h2>
          <p>A ${incident.severity.toLowerCase()} severity incident has been detected on your honeypot <strong>${honeypot.name}</strong>.</p>
          
          <h3>Incident Details:</h3>
          <ul>
            <li><strong>Type:</strong> ${incident.type}</li>
            <li><strong>Source IP:</strong> ${incident.sourceIp}</li>
            <li><strong>Description:</strong> ${incident.description}</li>
            <li><strong>Detected:</strong> ${incident.detectedAt.toISOString()}</li>
          </ul>

          <h3>Automated Actions Taken:</h3>
          <p>Our system has automatically responded to this incident based on its severity level.</p>

          <p><a href="${process.env.NEXT_PUBLIC_APP_URL}/dashboard/security">View Incident Details</a></p>
        `,
        userId: honeypot.owner.id,
        silentFail: true, // Don't throw if user lacks subscription
      });

      logInfo('Admin notification sent', {
        email: honeypot.owner.email,
        incidentType: incident.type,
      });
    } catch (error) {
      logError('Error notifying admins', { error, incident });
    }
  }

  /**
   * Notify affected user (gated - requires subscription)
   */
  private async notifyUser(
    incident: Omit<Incident, 'id' | 'responded' | 'responseActions'>
  ): Promise<void> {
    try {
      const honeypot = await prisma.honeypot.findUnique({
        where: { id: incident.honeypotId },
        include: {
          owner: {
            select: {
              id: true,
              email: true,
              name: true,
            },
          },
        },
      });

      if (!honeypot || !honeypot.owner.email) {
        return;
      }

      await sendGatedEmail({
        to: honeypot.owner.email,
        subject: `Security Notice - ${honeypot.name}`,
        html: `
          <h2>Security Notice</h2>
          <p>We wanted to inform you about a security incident involving your honeypot <strong>${honeypot.name}</strong>.</p>
          
          <p><strong>What happened:</strong> ${incident.description}</p>
          <p><strong>When:</strong> ${incident.detectedAt.toISOString()}</p>
          
          <p>Our security systems have automatically responded to protect your resources. No action is required from you at this time.</p>

          <p>If you have any questions or concerns, please contact our support team.</p>
        `,
        userId: honeypot.owner.id,
        silentFail: true, // Don't throw if user lacks subscription
      });

      logInfo('User notification sent', {
        email: honeypot.owner.email,
        incidentType: incident.type,
      });
    } catch (error) {
      logError('Error notifying user', { error, incident });
    }
  }

  /**
   * Get incident history
   */
  async getIncidents(filters: {
    honeypotId?: string;
    userId?: string;
    severity?: ThreatSeverity;
    responded?: boolean;
    limit?: number;
  }): Promise<Incident[]> {
    try {
       
      const where: any = {};

      if (filters.honeypotId) {
        where.honeypotId = filters.honeypotId;
      }

      if (filters.userId) {
        where.honeypot = {
          ownerId: filters.userId,
        };
      }

      if (filters.severity) {
        where.severity = filters.severity;
      }

      if (filters.responded !== undefined) {
        where.responded = filters.responded;
      }

       
      const prismaAny = prisma as any;
      const incidents = await prismaAny.incident.findMany({
        where,
        orderBy: { detectedAt: 'desc' },
        take: filters.limit || 50,
      });

      return incidents.map(
        (inc: {
          id: string;
          honeypotId: string;
          sourceIp: string;
          severity: ThreatSeverity;
          type: string;
          description: string;
          detectedAt: Date;
          responded: boolean;
          responseActions?: string[];
          resolvedAt: Date | null;
          resolution: string | null;
        }) => ({
          ...inc,
          resolvedAt: inc.resolvedAt || undefined,
          resolution: inc.resolution || undefined,
        })
      );
    } catch (error) {
      logError('Error fetching incidents', { error, filters });
      return [];
    }
  }

  /**
   * Resolve an incident manually
   */
  async resolveIncident(incidentId: string, resolution: string): Promise<void> {
    try {
       
      const prismaAny = prisma as any;
      await prismaAny.incident.update({
        where: { id: incidentId },
        data: {
          resolvedAt: new Date(),
          resolution,
        },
      });

      logInfo('Incident resolved', { incidentId, resolution });
    } catch (error) {
      logError('Error resolving incident', { error, incidentId });
      throw error;
    }
  }
}

// Singleton instance
export const incidentResponse = new IncidentResponseService();
