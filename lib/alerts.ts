/**
 * Admin Alert System
 * Sends alerts to administrators for security events and abuse patterns
 */

import { sendEmail } from './email/email-service';
import { logInfo, logError, logWarn } from './logger';
import { prisma } from './prisma';

export interface AdminAlert {
  type: 'RATE_LIMIT_ABUSE' | 'SUSPICIOUS_ACTIVITY' | 'SECURITY_BREACH' | 'SYSTEM_ALERT';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  message: string;
  userId?: string;
  userEmail?: string;
  metadata?: Record<string, unknown>;
}

export class AdminAlertService {
  /**
   * Send alert to all admin users
   */
  async sendAdminAlert(alert: AdminAlert): Promise<void> {
    try {
      // Get all admin and owner users
      const adminUsers = await prisma.user.findMany({
        where: {
          role: {
            in: ['ADMIN', 'OWNER'],
          },
        },
        select: {
          id: true,
          email: true,
          name: true,
        },
      });

      if (adminUsers.length === 0) {
        logWarn('No admin users found to send alert to', { alert });
        return;
      }

      const emailPromises = adminUsers.map(admin =>
        this.sendAlertEmail(admin, alert)
      );

      await Promise.allSettled(emailPromises);

      // Log the alert
      await this.logAlert(alert);

      logInfo('Admin alert sent', {
        type: alert.type,
        severity: alert.severity,
        adminCount: adminUsers.length,
      });
    } catch (error) {
      logError('Failed to send admin alert', { error, alert });
    }
  }

  /**
   * Send rate limit abuse alert
   */
  async sendRateLimitAbuseAlert(
    userId: string,
    userEmail: string,
    role: string,
    path: string,
    requestCount: number,
    threshold: number
  ): Promise<void> {
    await this.sendAdminAlert({
      type: 'RATE_LIMIT_ABUSE',
      severity: 'MEDIUM',
      title: 'Rate Limit Abuse Detected',
      message: `User ${userEmail} (${role}) exceeded rate limit threshold on ${path}. ${requestCount} requests in window (threshold: ${threshold}).`,
      userId,
      userEmail,
      metadata: {
        path,
        requestCount,
        threshold,
        role,
      },
    });
  }

  /**
   * Send suspicious activity alert
   */
  async sendSuspiciousActivityAlert(
    userId: string,
    userEmail: string,
    activity: string,
    details: Record<string, unknown>
  ): Promise<void> {
    await this.sendAdminAlert({
      type: 'SUSPICIOUS_ACTIVITY',
      severity: 'HIGH',
      title: 'Suspicious Activity Detected',
      message: `Suspicious activity detected for user ${userEmail}: ${activity}`,
      userId,
      userEmail,
      metadata: details,
    });
  }

  private async sendAlertEmail(
    admin: { id: string; email: string; name: string | null },
    alert: AdminAlert
  ): Promise<void> {
    const subject = `[${alert.severity}] ${alert.title}`;

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: ${this.getSeverityColor(alert.severity)};">${alert.title}</h2>
        <p><strong>Type:</strong> ${alert.type}</p>
        <p><strong>Severity:</strong> ${alert.severity}</p>
        <p><strong>Message:</strong></p>
        <p>${alert.message}</p>
        ${alert.userId ? `<p><strong>User ID:</strong> ${alert.userId}</p>` : ''}
        ${alert.userEmail ? `<p><strong>User Email:</strong> ${alert.userEmail}</p>` : ''}
        ${alert.metadata ? `
          <h3>Details:</h3>
          <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px;">${JSON.stringify(alert.metadata, null, 2)}</pre>
        ` : ''}
        <hr>
        <p style="color: #666; font-size: 12px;">
          This alert was sent to all administrators. Please investigate immediately if severity is HIGH or CRITICAL.
        </p>
      </div>
    `;

    await sendEmail({
      to: admin.email,
      subject,
      html,
    });
  }

  private async logAlert(alert: AdminAlert): Promise<void> {
    try {
      await prisma.auditLog.create({
        data: {
          userId: alert.userId || 'system',
          action: 'ADMIN_ALERT',
          resource: 'SYSTEM',
          level: 'WARN',
          message: `Admin Alert: ${alert.title}`,
          details: {
            severity: alert.severity,
            title: alert.title,
            message: alert.message,
          },
        },
      });
    } catch (error) {
      logError('Failed to log admin alert', { error, alert });
    }
  }

  private getSeverityColor(severity: string): string {
    switch (severity) {
      case 'CRITICAL': return '#dc2626';
      case 'HIGH': return '#ea580c';
      case 'MEDIUM': return '#d97706';
      case 'LOW': return '#65a30d';
      default: return '#6b7280';
    }
  }
}

export const adminAlertService = new AdminAlertService();