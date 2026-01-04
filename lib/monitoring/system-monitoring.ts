/**
 * System Monitoring Service
 * Comprehensive monitoring for ML training, anomaly detection, and system-wide metrics
 */

import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';
import { sendEmail } from '@core/lib/email/email-service';

export interface MLTrainingMetrics {
  totalTrainingRuns: number;
  successfulRuns: number;
  failedRuns: number;
  averageAccuracy: number;
  averageTrainingTime: number; // in seconds
  lastTrainingDate?: Date;
  modelsDeployed: number;
  datasetSize: number;
}

export interface AnomalyDetectionMetrics {
  totalAnomaliesDetected: number;
  highSeverityAnomalies: number;
  mediumSeverityAnomalies: number;
  lowSeverityAnomalies: number;
  detectionRate: number; // percentage
  falsePositiveRate: number; // percentage
  lastDetectionDate?: Date;
}

export interface SystemMetrics {
  apiGeneration: {
    totalGenerations: number;
    last24Hours: number;
    averageGenerationTime: number;
    successRate: number;
  };
  security: {
    totalScans: number;
    vulnerabilitiesFound: number;
    honeypotsTrigger: number;
    threatsBlocked: number;
  };
  users: {
    totalUsers: number;
    activeUsers: number; // last 30 days
    newUsers: number; // last 7 days
    churnRate: number;
  };
  performance: {
    averageResponseTime: number;
    uptime: number; // percentage
    errorRate: number; // percentage
  };
}

export interface AlertConfig {
  userId: string;
  alertType: 'email' | 'in-app' | 'both';
  thresholds: {
    mlAccuracy?: number; // minimum accuracy threshold
    anomalyRate?: number; // maximum anomaly rate
    resourceUsage?: number; // percentage
    errorRate?: number; // percentage
  };
}

export class SystemMonitoringService {
  /**
   * Get ML training metrics
   */
  static async getMLTrainingMetrics(
    startDate?: Date,
    endDate?: Date
  ): Promise<MLTrainingMetrics> {
    try {
      const where =
        startDate && endDate
          ? {
              createdAt: {
                gte: startDate,
                lte: endDate,
              },
            }
          : {};

      // Since ML training data might be stored in audit logs or a dedicated table
      // For now, we'll return mock data structure - integrate with actual ML training logs
      const mlData: MLTrainingMetrics = {
        totalTrainingRuns: 0,
        successfulRuns: 0,
        failedRuns: 0,
        averageAccuracy: 0,
        averageTrainingTime: 0,
        modelsDeployed: 0,
        datasetSize: 0,
      };

      // Query audit logs for ML-related events
      const trainingLogs = await prisma.auditLog.findMany({
        where: {
          ...where,
          message: {
            contains: 'ML_TRAINING',
            mode: 'insensitive',
          },
        },
      });

      mlData.totalTrainingRuns = trainingLogs.length;
      mlData.successfulRuns = trainingLogs.filter(
        log => log.level === 'INFO' && log.message.includes('SUCCESS')
      ).length;
      mlData.failedRuns = trainingLogs.filter(
        log => log.level === 'ERROR'
      ).length;

      // Calculate average accuracy from context data
      const accuracyLogs = trainingLogs.filter(
        log =>
          log.details &&
          typeof log.details === 'object' &&
          'accuracy' in log.details
      );

      if (accuracyLogs.length > 0) {
        const totalAccuracy = accuracyLogs.reduce((sum, log) => {
          const context = log.details as { accuracy?: number };
          return sum + (context.accuracy || 0);
        }, 0);
        mlData.averageAccuracy = totalAccuracy / accuracyLogs.length;
      }

      // Get last training date
      if (trainingLogs.length > 0) {
        mlData.lastTrainingDate = trainingLogs[0].createdAt;
      }

      logInfo('ML training metrics retrieved', { mlData });
      return mlData;
    } catch (error) {
      logError('Failed to get ML training metrics', error);
      throw new Error('Failed to retrieve ML training metrics');
    }
  }

  /**
   * Get anomaly detection metrics
   */
  static async getAnomalyDetectionMetrics(
    startDate?: Date,
    endDate?: Date
  ): Promise<AnomalyDetectionMetrics> {
    try {
      const where =
        startDate && endDate
          ? {
              createdAt: {
                gte: startDate,
                lte: endDate,
              },
            }
          : {};

      // Query threat/anomaly detection logs
      const anomalyLogs = await prisma.auditLog.findMany({
        where: {
          ...where,
          message: {
            contains: 'ANOMALY',
            mode: 'insensitive',
          },
        },
      });

      const highSeverity = anomalyLogs.filter(
        log => log.message.includes('HIGH') || log.level === 'ERROR'
      ).length;

      const mediumSeverity = anomalyLogs.filter(
        log => log.message.includes('MEDIUM') || log.level === 'WARN'
      ).length;

      const lowSeverity = anomalyLogs.length - highSeverity - mediumSeverity;

      // Calculate detection and false positive rates (simplified)
      const detectionRate = anomalyLogs.length > 0 ? 95 : 0; // Mock value
      const falsePositiveRate = anomalyLogs.length > 0 ? 5 : 0; // Mock value

      const metrics: AnomalyDetectionMetrics = {
        totalAnomaliesDetected: anomalyLogs.length,
        highSeverityAnomalies: highSeverity,
        mediumSeverityAnomalies: mediumSeverity,
        lowSeverityAnomalies: lowSeverity,
        detectionRate,
        falsePositiveRate,
        lastDetectionDate: anomalyLogs[0]?.createdAt,
      };

      logInfo('Anomaly detection metrics retrieved', { metrics });
      return metrics;
    } catch (error) {
      logError('Failed to get anomaly detection metrics', error);
      throw new Error('Failed to retrieve anomaly detection metrics');
    }
  }

  /**
   * Get comprehensive system metrics
   */
  static async getSystemMetrics(): Promise<SystemMetrics> {
    try {
      const now = new Date();
      const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const last7Days = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const last30Days = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

      // API Generation metrics
      const totalGenerations = await prisma.auditLog.count({
        where: {
          message: { contains: 'API_GENERATED', mode: 'insensitive' },
        },
      });

      const generationsLast24h = await prisma.auditLog.count({
        where: {
          message: { contains: 'API_GENERATED', mode: 'insensitive' },
          createdAt: { gte: last24Hours },
        },
      });

      // Security metrics
      const totalScans = await prisma.auditLog.count({
        where: {
          message: { contains: 'SECURITY_SCAN', mode: 'insensitive' },
        },
      });

      const vulnerabilities = await prisma.auditLog.count({
        where: {
          message: { contains: 'VULNERABILITY', mode: 'insensitive' },
        },
      });

      const honeypotTriggers = await prisma.auditLog.count({
        where: {
          message: { contains: 'HONEYPOT_TRIGGERED', mode: 'insensitive' },
        },
      });

      const threatsBlocked = await prisma.auditLog.count({
        where: {
          message: { contains: 'THREAT_DETECTED', mode: 'insensitive' },
        },
      });

      // User metrics
      const totalUsers = await prisma.user.count();

      const activeUsers = await prisma.user.count({
        where: {
          lastLoginAt: { gte: last30Days },
        },
      });

      const newUsers = await prisma.user.count({
        where: {
          createdAt: { gte: last7Days },
        },
      });

      const churnRate =
        totalUsers > 0 ? ((totalUsers - activeUsers) / totalUsers) * 100 : 0;

      const metrics: SystemMetrics = {
        apiGeneration: {
          totalGenerations,
          last24Hours: generationsLast24h,
          averageGenerationTime: 2.5, // Mock value - would be calculated from actual data
          successRate: 98.5, // Mock value
        },
        security: {
          totalScans,
          vulnerabilitiesFound: vulnerabilities,
          honeypotsTrigger: honeypotTriggers,
          threatsBlocked,
        },
        users: {
          totalUsers,
          activeUsers,
          newUsers,
          churnRate: Math.round(churnRate * 10) / 10,
        },
        performance: {
          averageResponseTime: 150, // Mock value in ms
          uptime: 99.9, // Mock value
          errorRate: 0.1, // Mock value
        },
      };

      logInfo('System metrics retrieved', { metrics });
      return metrics;
    } catch (error) {
      logError('Failed to get system metrics', error);
      throw new Error('Failed to retrieve system metrics');
    }
  }

  /**
   * Check if any alerts should be triggered
   */
  static async checkAlerts(
    config: AlertConfig,
    metrics: {
      ml?: MLTrainingMetrics;
      anomaly?: AnomalyDetectionMetrics;
      system?: SystemMetrics;
    }
  ): Promise<string[]> {
    const alerts: string[] = [];

    try {
      // Check ML accuracy threshold
      if (config.thresholds.mlAccuracy && metrics.ml) {
        if (metrics.ml.averageAccuracy < config.thresholds.mlAccuracy) {
          alerts.push(
            `ML model accuracy (${metrics.ml.averageAccuracy.toFixed(1)}%) is below threshold (${config.thresholds.mlAccuracy}%)`
          );
        }
      }

      // Check anomaly rate threshold
      if (config.thresholds.anomalyRate && metrics.anomaly) {
        const anomalyRate =
          metrics.anomaly.totalAnomaliesDetected > 0
            ? (metrics.anomaly.highSeverityAnomalies /
                metrics.anomaly.totalAnomaliesDetected) *
              100
            : 0;

        if (anomalyRate > config.thresholds.anomalyRate) {
          alerts.push(
            `High anomaly rate detected (${anomalyRate.toFixed(1)}%) exceeds threshold (${config.thresholds.anomalyRate}%)`
          );
        }
      }

      // Check error rate threshold
      if (config.thresholds.errorRate && metrics.system) {
        if (
          metrics.system.performance.errorRate > config.thresholds.errorRate
        ) {
          alerts.push(
            `Error rate (${metrics.system.performance.errorRate.toFixed(1)}%) exceeds threshold (${config.thresholds.errorRate}%)`
          );
        }
      }

      if (alerts.length > 0) {
        logInfo('Alerts triggered', {
          userId: config.userId,
          alertCount: alerts.length,
          alerts,
        });
      }

      return alerts;
    } catch (error) {
      logError('Failed to check alerts', error);
      return [];
    }
  }

  /**
   * Send notification (email or in-app)
   */
  static async sendNotification(
    userId: string,
    alertType: 'email' | 'in-app' | 'both',
    message: string,
    severity: 'info' | 'warning' | 'error'
  ): Promise<void> {
    try {
      // Get user details
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { email: true, name: true },
      });

      if (!user) {
        logError('User not found for notification', { userId });
        return;
      }

      logInfo('Sending notification', {
        userId,
        alertType,
        message,
        severity,
      });

      if (alertType === 'in-app' || alertType === 'both') {
        // Store in-app notification
        await prisma.notification.create({
          data: {
            userId,
            type: 'SYSTEM',
            title: `System Alert - ${severity.toUpperCase()}`,
            message,
          },
        });
        logInfo('In-app notification stored', { userId, message });
      }

      if (alertType === 'email' || alertType === 'both') {
        // Send email notification
        const subject = `APIForge System Alert - ${severity.toUpperCase()}`;
        const html = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: ${SystemMonitoringService.getSeverityColor(severity)};">System Alert</h2>
            <p><strong>Severity:</strong> ${severity.toUpperCase()}</p>
            <p><strong>Message:</strong></p>
            <p>${message}</p>
            <hr>
            <p style="color: #666; font-size: 12px;">
              This is an automated notification from APIForge. Please check your dashboard for more details.
            </p>
          </div>
        `;

        const success = await sendEmail({
          to: user.email,
          subject,
          html,
        });

        if (success) {
          logInfo('Email notification sent', { userId, email: user.email });
        } else {
          logError('Failed to send email notification', { userId, email: user.email });
        }
      }
    } catch (error) {
      logError('Failed to send notification', error);
    }
  }

  private static getSeverityColor(severity: string): string {
    switch (severity) {
      case 'error': return '#dc2626';
      case 'warning': return '#d97706';
      case 'info': return '#2563eb';
      default: return '#6b7280';
    }
  }
}
