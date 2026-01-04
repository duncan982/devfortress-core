/**
 * Audit Logging Service
 * Comprehensive audit trail for security, compliance, and operational tracking
 */

// Only import client logger since this service is used in client components
import { logInfo, logError, logWarn } from '@core/lib/logger/client';
import { LogLevel } from '@prisma/client';
import type { PrismaClient } from '@prisma/client';

// Conditionally import prisma only on server side
let prisma: PrismaClient | null = null;
if (typeof window === 'undefined') {
  try {
     
    const { PrismaClient: PrismaClientClass } = require('@prisma/client');
    prisma = new PrismaClientClass();
  } catch {
    // Prisma not available in this environment
  }
}

export enum AuditAction {
  // Authentication
  USER_LOGIN = 'USER_LOGIN',
  USER_LOGOUT = 'USER_LOGOUT',
  USER_REGISTER = 'USER_REGISTER',
  PASSWORD_CHANGE = 'PASSWORD_CHANGE',
  MFA_ENABLED = 'MFA_ENABLED',
  MFA_DISABLED = 'MFA_DISABLED',

  // API Generation
  API_GENERATED = 'API_GENERATED',
  API_DELETED = 'API_DELETED',
  API_UPDATED = 'API_UPDATED',
  API_DEPLOYED = 'API_DEPLOYED',

  // Repository
  REPO_CONNECTED = 'REPO_CONNECTED',
  REPO_DISCONNECTED = 'REPO_DISCONNECTED',
  CODE_PUSHED = 'CODE_PUSHED',

  // Security
  SECURITY_SCAN_STARTED = 'SECURITY_SCAN_STARTED',
  SECURITY_SCAN_COMPLETED = 'SECURITY_SCAN_COMPLETED',
  VULNERABILITY_DETECTED = 'VULNERABILITY_DETECTED',
  HONEYPOT_CREATED = 'HONEYPOT_CREATED',
  HONEYPOT_TRIGGERED = 'HONEYPOT_TRIGGERED',
  THREAT_DETECTED = 'THREAT_DETECTED',

  // Payments & Billing
  PAYMENT_PROCESSED = 'PAYMENT_PROCESSED',
  PAYMENT_FAILED = 'PAYMENT_FAILED',
  SUBSCRIPTION_CREATED = 'SUBSCRIPTION_CREATED',
  SUBSCRIPTION_CANCELLED = 'SUBSCRIPTION_CANCELLED',
  CREDITS_PURCHASED = 'CREDITS_PURCHASED',
  CREDITS_USED = 'CREDITS_USED',

  // Data & Privacy
  DATA_EXPORTED = 'DATA_EXPORTED',
  DATA_DELETED = 'DATA_DELETED',
  CONSENT_GIVEN = 'CONSENT_GIVEN',
  CONSENT_WITHDRAWN = 'CONSENT_WITHDRAWN',

  // Admin Actions
  USER_ROLE_CHANGED = 'USER_ROLE_CHANGED',
  USER_SUSPENDED = 'USER_SUSPENDED',
  USER_REACTIVATED = 'USER_REACTIVATED',
  SYSTEM_SETTINGS_CHANGED = 'SYSTEM_SETTINGS_CHANGED',

  // Team & Organization
  TEAM_CREATED = 'TEAM_CREATED',
  TEAM_MEMBER_ADDED = 'TEAM_MEMBER_ADDED',
  TEAM_MEMBER_REMOVED = 'TEAM_MEMBER_REMOVED',
  ORG_CREATED = 'ORG_CREATED',
}

export interface AuditLogEntry {
  userId?: string;
  apiProjectId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  level: LogLevel;
  message: string;
  context?: {
    ipAddress?: string;
    userAgent?: string;
    location?: string;
    metadata?: Record<string, unknown>;
  };
}

export interface AuditLogDetails extends Record<string, unknown> {
  message?: string;
  level?: string;
  ipAddress?: string;
  userAgent?: string;
  location?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditLogQuery {
  userId?: string;
  apiProjectId?: string;
  action?: AuditAction | AuditAction[];
  level?: LogLevel | LogLevel[];
  startDate?: Date;
  endDate?: Date;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface ComplianceReport {
  reportType: 'GDPR' | 'SOC2' | 'HIPAA' | 'GENERAL';
  generatedAt: Date;
  period: {
    start: Date;
    end: Date;
  };
  summary: {
    totalEvents: number;
    securityEvents: number;
    dataAccessEvents: number;
    failedLogins: number;
    vulnerabilities: number;
  };
  events: Array<{
    id: string;
    timestamp: Date;
    action: string;
    userId?: string;
    message: string;
    level: string;
  }>;
  recommendations?: string[];
}

export class AuditLogService {
  /**
   * Log an audit event
   */
  static async log(entry: AuditLogEntry): Promise<void> {
    try {
      // Check if we're in browser environment
      if (typeof window !== 'undefined') {
        // Use API call for client-side logging
        await this.logViaAPI(entry);
      } else if (prisma) {
        // Use direct database access for server-side logging
        await this.logViaDatabase(entry);
      } else {
        // Fallback: just log to console if neither is available
        await logInfo('Audit event fallback logging', {
          action: entry.action,
          userId: entry.userId,
          level: entry.level,
        });
      }

      await logInfo('Audit event logged', {
        action: entry.action,
        userId: entry.userId,
        level: entry.level,
      });
    } catch (error) {
      await logError('Failed to log audit event', error);
      // Don't throw - audit logging should not break app functionality
    }
  }

  /**
   * Log via API call (client-side)
   */
  private static async logViaAPI(entry: AuditLogEntry): Promise<void> {
    try {
      const response = await fetch('/api/system/audit-log', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(entry),
      });

      if (!response.ok) {
        throw new Error(`API call failed: ${response.status}`);
      }
    } catch (error) {
      // If API call fails, fallback to console logging
      await logWarn('Failed to log audit event via API', { error: String(error) });
    }
  }

  /**
   * Log via direct database access (server-side)
   */
  private static async logViaDatabase(entry: AuditLogEntry): Promise<void> {
    if (!prisma) return;

    await prisma.auditLog.create({
      data: {
        userId: entry.userId || null,
        apiProjectId: entry.apiProjectId || null,
        action: entry.action,
        resource: entry.resource,
        resourceId: entry.resourceId || null,
        level: entry.level,
        message: entry.message,
         
        details: entry.context as any,
        ipAddress: entry.context?.ipAddress || null,
        userAgent: entry.context?.userAgent || null,
      },
    });
  }

  /**
   * Query audit logs with filtering
   */
  static async query(params: AuditLogQuery) {
    if (!prisma) {
      throw new Error('Audit log querying not available in client environment');
    }

    try {
      const {
        userId,
        apiProjectId,
        action,
        level,
        startDate,
        endDate,
        search,
        limit = 100,
        offset = 0,
      } = params;

      const where: Record<string, unknown> = {};

      if (userId) where.userId = userId;
      if (apiProjectId) where.apiProjectId = apiProjectId;

      if (action) {
        const actions = Array.isArray(action) ? action : [action];
        where.action = Array.isArray(action) ? { in: actions } : action;
      }

      if (level) {
        // Level is stored in details JSON, need to filter differently
        // For now, we'll skip level filtering in queries since it's in JSON
      }

      if (startDate || endDate) {
        where.createdAt = {};
        if (startDate)
          (where.createdAt as Record<string, unknown>).gte = startDate;
        if (endDate) (where.createdAt as Record<string, unknown>).lte = endDate;
      }

      if (search) {
        where.OR = [
          { action: { contains: search, mode: 'insensitive' } },
          { resource: { contains: search, mode: 'insensitive' } },
        ];
      }

      const [logs, total] = await Promise.all([
        prisma.auditLog.findMany({
          where,
          orderBy: { createdAt: 'desc' },
          take: limit,
          skip: offset,
          include: {
            user: {
              select: {
                id: true,
                email: true,
                name: true,
              },
            },
            apiProject: {
              select: {
                id: true,
                name: true,
              },
            },
          },
        }),
        prisma.auditLog.count({ where }),
      ]);

      return {
        logs,
        total,
        limit,
        offset,
        hasMore: offset + limit < total,
      };
    } catch (error) {
      await logError('Failed to query audit logs', error);
      throw new Error('Failed to retrieve audit logs');
    }
  }

  /**
   * Export audit logs as JSON
   */
  static async exportLogs(params: AuditLogQuery): Promise<string> {
    if (!prisma) {
      throw new Error('Audit log exporting not available in client environment');
    }

    try {
      const result = await this.query({ ...params, limit: 10000 });
      return JSON.stringify(result.logs, null, 2);
    } catch (error) {
      await logError('Failed to export audit logs', error);
      throw new Error('Failed to export logs');
    }
  }

  /**
   * Generate compliance report
   */
  static async generateComplianceReport(
    reportType: ComplianceReport['reportType'],
    startDate: Date,
    endDate: Date,
    userId?: string
  ): Promise<ComplianceReport> {
    if (!prisma) {
      throw new Error('Compliance report generation not available in client environment');
    }

    try {
      await logInfo('Generating compliance report', {
        reportType,
        startDate,
        endDate,
        userId,
      });

      const where: Record<string, unknown> = {
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      };

      if (userId) where.userId = userId;

      const [
        allEvents,
        securityEvents,
        dataAccessEvents,
        failedLogins,
        vulnerabilities,
      ] = await Promise.all([
        prisma.auditLog.count({ where }),
        prisma.auditLog.count({
          where: {
            ...where,
            resource: { contains: 'SECURITY', mode: 'insensitive' },
          },
        }),
        prisma.auditLog.count({
          where: {
            ...where,
            resource: { contains: 'DATA', mode: 'insensitive' },
          },
        }),
        prisma.auditLog.count({
          where: {
            ...where,
            action: { contains: 'LOGIN', mode: 'insensitive' },
            details: { path: ['level'], equals: 'ERROR' },
          },
        }),
        prisma.auditLog.count({
          where: {
            ...where,
            resource: { contains: 'VULNERABILITY', mode: 'insensitive' },
          },
        }),
      ]);

      const events = await prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: 1000,
        select: {
          id: true,
          createdAt: true,
          action: true,
          userId: true,
          details: true,
        },
      });

      const report: ComplianceReport = {
        reportType,
        generatedAt: new Date(),
        period: { start: startDate, end: endDate },
        summary: {
          totalEvents: allEvents,
          securityEvents,
          dataAccessEvents,
          failedLogins,
          vulnerabilities,
        },
        events: events.map(e => ({
          id: e.id,
          timestamp: e.createdAt,
          action: e.action,
          userId: e.userId || undefined,
          message: (e.details as AuditLogDetails)?.message || e.action,
          level: (e.details as AuditLogDetails)?.level || 'INFO',
        })),
        recommendations: this.getRecommendations(reportType, {
          failedLogins,
          vulnerabilities,
          securityEvents,
        }),
      };

      // Log report generation
      await this.log({
        userId,
        action: AuditAction.DATA_EXPORTED,
        resource: 'COMPLIANCE_REPORT',
        level: 'INFO',
        message: `Generated ${reportType} compliance report`,
        context: {
          metadata: {
            reportType,
            period: { start: startDate, end: endDate },
            eventCount: allEvents,
          },
        },
      });

      return report;
    } catch (error) {
      await logError('Failed to generate compliance report', error);
      throw new Error('Failed to generate compliance report');
    }
  }

  /**
   * Get compliance recommendations
   */
  private static getRecommendations(
    reportType: string,
    metrics: {
      failedLogins: number;
      vulnerabilities: number;
      securityEvents: number;
    }
  ): string[] {
    const recommendations: string[] = [];

    if (metrics.failedLogins > 10) {
      recommendations.push(
        'High number of failed logins detected. Consider implementing rate limiting and account lockout policies.'
      );
    }

    if (metrics.vulnerabilities > 0) {
      recommendations.push(
        'Vulnerabilities detected. Prioritize remediation based on severity levels.'
      );
    }

    if (metrics.securityEvents > 100) {
      recommendations.push(
        'Elevated security event activity. Review and investigate suspicious patterns.'
      );
    }

    if (reportType === 'GDPR') {
      recommendations.push(
        'Ensure all data processing activities have proper consent and legal basis.',
        'Verify data retention policies are being followed.',
        'Confirm data subject access requests are handled within 30 days.'
      );
    }

    if (reportType === 'SOC2') {
      recommendations.push(
        'Verify access controls are properly configured and reviewed regularly.',
        'Ensure audit logs are being retained for the required period.',
        'Validate that security incidents are being properly documented and responded to.'
      );
    }

    return recommendations;
  }

  /**
   * Prune old audit logs (for compliance with data retention policies)
   */
  static async pruneOldLogs(retentionDays: number): Promise<number> {
    if (!prisma) {
      throw new Error('Audit log pruning not available in client environment');
    }

    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const result = await prisma.auditLog.deleteMany({
        where: {
          createdAt: {
            lt: cutoffDate,
          },
        },
      });

      await logInfo('Pruned old audit logs', {
        deletedCount: result.count,
        retentionDays,
        cutoffDate,
      });

      return result.count;
    } catch (error) {
      await logError('Failed to prune audit logs', error);
      throw new Error('Failed to prune logs');
    }
  }

  /**
   * Get audit log statistics
   */
  static async getStatistics(startDate: Date, endDate: Date) {
    if (!prisma) {
      throw new Error('Audit log statistics not available in client environment');
    }

    try {
      const where = {
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      };

      const [totalLogs, logsByLevel, topUsers, topActions] = await Promise.all([
        prisma.auditLog.count({ where }),
        // For level stats, we need to extract from JSON - simplified for now
        prisma.auditLog.findMany({
          where,
          select: { details: true },
          take: 1000,
        }),
        prisma.auditLog.groupBy({
          by: ['userId'],
          where: { ...where, userId: { not: null } },
          _count: true,
          orderBy: { _count: { userId: 'desc' } },
          take: 10,
        }),
        // Get actions directly from action field
        prisma.auditLog.groupBy({
          by: ['action'],
          where,
          _count: true,
          orderBy: { _count: { action: 'desc' } },
          take: 10,
        }),
      ]);

      // Process levels from details JSON
      const levelCounts: Record<string, number> = {};
      logsByLevel.forEach((log) => {
        const details = log.details as AuditLogDetails;
        const level = details?.level || 'INFO';
        levelCounts[level] = (levelCounts[level] || 0) + 1;
      });

      const sortedLevels = Object.entries(levelCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10);

      return {
        totalLogs,
        logsByLevel: sortedLevels.map(([level, count]) => ({
          level,
          count,
        })),
        topUsers: topUsers.map((u) => ({ userId: u.userId, count: u._count })),
        topActions: topActions.map((a) => ({ action: a.action, count: a._count })),
      };
    } catch (error) {
      await logError('Failed to get audit log statistics', error);
      throw new Error('Failed to get statistics');
    }
  }
}
