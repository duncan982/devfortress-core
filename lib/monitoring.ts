/**
 * ML Performance Monitoring System
 * Tracks ML vs NL performance and sends alerts for anomalies
 */

import { prisma } from './prisma';
import { logInfo, logError, logWarn } from './logger';
import { sendEmail } from './email/email-service';
import { AITaskType } from '@prisma/client';

interface PerformanceMetrics {
  taskType: AITaskType;
  mlMetrics: {
    avgAccuracy: number;
    avgLatency: number;
    totalCost: number;
    errorRate: number;
    sampleCount: number;
  };
  nlMetrics: {
    avgLatency: number;
    totalCost: number;
    errorRate: number;
    sampleCount: number;
  };
  costSavings: number;
  costSavingsPercent: number;
}

interface AlertConfig {
  maxErrorRate: number; // e.g., 0.05 (5%)
  maxCostPercent: number; // e.g., 0.20 (20% of revenue)
  minAccuracy: number; // e.g., 0.85 (85%)
}

const DEFAULT_ALERT_CONFIG: AlertConfig = {
  maxErrorRate: 0.05,
  maxCostPercent: 0.2,
  minAccuracy: 0.85,
};

/**
 * Calculate performance metrics for a specific task type
 */
async function calculateTaskMetrics(
  taskType: AITaskType,
  startDate: Date,
  endDate: Date
): Promise<PerformanceMetrics | null> {
  try {
    // Get ML logs
    const mlLogs = await prisma.aIPerformanceLog.findMany({
      where: {
        taskType,
        provider: 'ML_HF',
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      },
    });

    // Get NL logs
    const nlLogs = await prisma.aIPerformanceLog.findMany({
      where: {
        taskType,
        provider: 'NL_GPT4',
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      },
    });

    if (mlLogs.length === 0 && nlLogs.length === 0) {
      return null;
    }

    // Calculate ML metrics
    const mlMetrics = {
      avgAccuracy:
        mlLogs
          .filter(log => log.accuracy !== null)
          .reduce((sum, log) => sum + (log.accuracy ?? 0), 0) /
        (mlLogs.filter(log => log.accuracy !== null).length || 1),
      avgLatency:
        mlLogs.reduce((sum, log) => sum + log.latencyMs, 0) /
        (mlLogs.length || 1),
      totalCost: mlLogs.reduce((sum, log) => sum + log.costUsd, 0),
      errorRate:
        mlLogs.filter(log => log.errorOccurred).length / (mlLogs.length || 1),
      sampleCount: mlLogs.length,
    };

    // Calculate NL metrics
    const nlMetrics = {
      avgLatency:
        nlLogs.reduce((sum, log) => sum + log.latencyMs, 0) /
        (nlLogs.length || 1),
      totalCost: nlLogs.reduce((sum, log) => sum + log.costUsd, 0),
      errorRate:
        nlLogs.filter(log => log.errorOccurred).length / (nlLogs.length || 1),
      sampleCount: nlLogs.length,
    };

    // Calculate cost savings
    const estimatedMLCostIfNL =
      mlLogs.length > 0
        ? (mlMetrics.totalCost / mlLogs.length) * nlLogs.length
        : 0;
    const costSavings = estimatedMLCostIfNL - mlMetrics.totalCost;
    const costSavingsPercent =
      estimatedMLCostIfNL > 0 ? (costSavings / estimatedMLCostIfNL) * 100 : 0;

    return {
      taskType,
      mlMetrics,
      nlMetrics,
      costSavings,
      costSavingsPercent,
    };
  } catch (error) {
    logError('Failed to calculate task metrics', { error, taskType });
    return null;
  }
}

/**
 * Generate weekly performance report
 */
export async function generateWeeklyMLReport(): Promise<void> {
  try {
    logInfo('Generating weekly ML performance report');

    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 7);

    const taskTypes: AITaskType[] = [
      'SECURITY_SCAN',
      'THREAT_ANALYSIS',
      'VULNERABILITY_DETECTION',
      'CODE_REVIEW',
      'COMPLIANCE_CHECK',
      'API_GENERATION',
    ];

    const metrics: PerformanceMetrics[] = [];
    for (const taskType of taskTypes) {
      const taskMetrics = await calculateTaskMetrics(
        taskType,
        startDate,
        endDate
      );
      if (taskMetrics) {
        metrics.push(taskMetrics);
      }
    }

    if (metrics.length === 0) {
      logInfo('No ML performance data available for weekly report');
      return;
    }

    // Calculate totals
    const totalCostSavings = metrics.reduce((sum, m) => sum + m.costSavings, 0);
    const totalMLCost = metrics.reduce(
      (sum, m) => sum + m.mlMetrics.totalCost,
      0
    );
    const totalNLCost = metrics.reduce(
      (sum, m) => sum + m.nlMetrics.totalCost,
      0
    );
    const avgMLErrorRate =
      metrics.reduce((sum, m) => sum + m.mlMetrics.errorRate, 0) /
      metrics.length;

    // Check for alerts
    const alerts: string[] = [];
    const config = DEFAULT_ALERT_CONFIG;

    for (const metric of metrics) {
      if (metric.mlMetrics.errorRate > config.maxErrorRate) {
        alerts.push(
          `⚠️ Error rate for ${metric.taskType} is ${(metric.mlMetrics.errorRate * 100).toFixed(1)}% (threshold: ${(config.maxErrorRate * 100).toFixed(1)}%)`
        );
      }

      if (
        metric.mlMetrics.avgAccuracy > 0 &&
        metric.mlMetrics.avgAccuracy < config.minAccuracy
      ) {
        alerts.push(
          `⚠️ Accuracy for ${metric.taskType} is ${(metric.mlMetrics.avgAccuracy * 100).toFixed(1)}% (threshold: ${(config.minAccuracy * 100).toFixed(1)}%)`
        );
      }
    }

    // TODO: Get actual revenue from subscription system
    const estimatedRevenue = 10000; // Placeholder
    const mlCostPercent = (totalMLCost / estimatedRevenue) * 100;

    if (mlCostPercent > config.maxCostPercent * 100) {
      alerts.push(
        `🚨 ML costs are ${mlCostPercent.toFixed(1)}% of revenue (threshold: ${(config.maxCostPercent * 100).toFixed(1)}%)`
      );
    }

    // Generate report
    const report = generateReportHTML(
      metrics,
      {
        totalCostSavings,
        totalMLCost,
        totalNLCost,
        avgMLErrorRate,
        mlCostPercent,
      },
      alerts,
      startDate,
      endDate
    );

    // Send report to admin
    const admins = await prisma.user.findMany({
      where: { role: 'ADMIN' },
      select: { email: true },
    });

    for (const admin of admins) {
      await sendEmail({
        to: admin.email,
        subject: `Weekly ML Performance Report - ${startDate.toLocaleDateString()}`,
        html: report,
      });
    }

    logInfo('Weekly ML report sent successfully', {
      recipientCount: admins.length,
      alertCount: alerts.length,
    });
  } catch (error) {
    logError('Failed to generate weekly ML report', { error });
  }
}

/**
 * Generate HTML report
 */
function generateReportHTML(
  metrics: PerformanceMetrics[],
  totals: {
    totalCostSavings: number;
    totalMLCost: number;
    totalNLCost: number;
    avgMLErrorRate: number;
    mlCostPercent: number;
  },
  alerts: string[],
  startDate: Date,
  endDate: Date
): string {
  const alertsHTML =
    alerts.length > 0
      ? `
    <div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 16px; margin: 20px 0;">
      <h3 style="color: #991b1b; margin-top: 0;">⚠️ Alerts</h3>
      <ul style="color: #991b1b; margin: 0;">
        ${alerts.map(alert => `<li>${alert}</li>`).join('')}
      </ul>
    </div>
  `
      : '';

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Weekly ML Performance Report</title>
    </head>
    <body style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px;">
      <h1>Weekly ML Performance Report</h1>
      <p><strong>Period:</strong> ${startDate.toLocaleDateString()} - ${endDate.toLocaleDateString()}</p>
      
      ${alertsHTML}
      
      <div style="background: #f3f4f6; padding: 16px; border-radius: 8px; margin: 20px 0;">
        <h3 style="margin-top: 0;">📊 Summary</h3>
        <ul>
          <li><strong>Total ML Cost:</strong> $${totals.totalMLCost.toFixed(2)}</li>
          <li><strong>Total NL Cost:</strong> $${totals.totalNLCost.toFixed(2)}</li>
          <li><strong>Cost Savings:</strong> $${totals.totalCostSavings.toFixed(2)}</li>
          <li><strong>ML Cost % of Revenue:</strong> ${totals.mlCostPercent.toFixed(1)}%</li>
          <li><strong>Average ML Error Rate:</strong> ${(totals.avgMLErrorRate * 100).toFixed(1)}%</li>
        </ul>
      </div>
      
      <h3>📈 Task Performance</h3>
      <table style="width: 100%; border-collapse: collapse;">
        <thead>
          <tr style="background: #e5e7eb;">
            <th style="padding: 12px; text-align: left; border: 1px solid #d1d5db;">Task</th>
            <th style="padding: 12px; text-align: center; border: 1px solid #d1d5db;">ML Samples</th>
            <th style="padding: 12px; text-align: center; border: 1px solid #d1d5db;">Accuracy</th>
            <th style="padding: 12px; text-align: center; border: 1px solid #d1d5db;">Error Rate</th>
            <th style="padding: 12px; text-align: right; border: 1px solid #d1d5db;">Cost Savings</th>
          </tr>
        </thead>
        <tbody>
          ${metrics
            .map(
              m => `
            <tr>
              <td style="padding: 12px; border: 1px solid #d1d5db;">${m.taskType}</td>
              <td style="padding: 12px; text-align: center; border: 1px solid #d1d5db;">${m.mlMetrics.sampleCount}</td>
              <td style="padding: 12px; text-align: center; border: 1px solid #d1d5db;">${(m.mlMetrics.avgAccuracy * 100).toFixed(1)}%</td>
              <td style="padding: 12px; text-align: center; border: 1px solid #d1d5db;">${(m.mlMetrics.errorRate * 100).toFixed(1)}%</td>
              <td style="padding: 12px; text-align: right; border: 1px solid #d1d5db;">$${m.costSavings.toFixed(2)}</td>
            </tr>
          `
            )
            .join('')}
        </tbody>
      </table>
      
      <hr style="margin: 30px 0; border: 0; border-top: 1px solid #d1d5db;">
      
      <p style="color: #6b7280; font-size: 14px;">
        This is an automated report from the VortexSecure ML monitoring system.
        <br>
        To adjust alert thresholds or disable ML, visit the Admin Panel.
      </p>
    </body>
    </html>
  `;
}

/**
 * Check for immediate alerts (called more frequently than weekly report)
 */
export async function checkMLAlerts(): Promise<void> {
  try {
    const config = DEFAULT_ALERT_CONFIG;
    const last24Hours = new Date();
    last24Hours.setHours(last24Hours.getHours() - 24);

    const recentLogs = await prisma.aIPerformanceLog.findMany({
      where: {
        provider: 'ML_HF',
        createdAt: {
          gte: last24Hours,
        },
      },
    });

    if (recentLogs.length === 0) return;

    const errorRate =
      recentLogs.filter(log => log.errorOccurred).length / recentLogs.length;
    const avgAccuracy =
      recentLogs
        .filter(log => log.accuracy !== null)
        .reduce((sum, log) => sum + (log.accuracy ?? 0), 0) /
      (recentLogs.filter(log => log.accuracy !== null).length || 1);

    // Send immediate alert if thresholds breached
    if (errorRate > config.maxErrorRate) {
      logWarn('ML error rate exceeded threshold', {
        errorRate,
        threshold: config.maxErrorRate,
      });

      // Send urgent email to admins
      const admins = await prisma.user.findMany({
        where: { role: 'ADMIN' },
        select: { email: true },
      });

      for (const admin of admins) {
        await sendEmail({
          to: admin.email,
          subject: '🚨 ML Error Rate Alert',
          html: `
            <h2>ML Error Rate Alert</h2>
            <p>The ML system error rate has exceeded the threshold in the last 24 hours:</p>
            <ul>
              <li><strong>Current Error Rate:</strong> ${(errorRate * 100).toFixed(1)}%</li>
              <li><strong>Threshold:</strong> ${(config.maxErrorRate * 100).toFixed(1)}%</li>
              <li><strong>Recent Samples:</strong> ${recentLogs.length}</li>
            </ul>
            <p>Consider disabling ML for affected tasks or investigating the cause.</p>
          `,
        });
      }
    }

    if (avgAccuracy > 0 && avgAccuracy < config.minAccuracy) {
      logWarn('ML accuracy below threshold', {
        avgAccuracy,
        threshold: config.minAccuracy,
      });
    }
  } catch (error) {
    logError('Failed to check ML alerts', { error });
  }
}
