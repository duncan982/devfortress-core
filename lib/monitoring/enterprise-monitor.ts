/**
 * Enterprise Monitoring Service
 * Provides comprehensive monitoring for enterprise deployments
 * 
 * Features:
 * - Health checks
 * - Uptime monitoring
 * - Service dependency tracking
 * - Alert management
 * - SLA tracking
 */

import { logInfo, logWarn, logError } from '@core/lib/logger';

/**
 * Service health status
 */
export enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
  UNKNOWN = 'unknown',
}

/**
 * Service types
 */
export enum ServiceType {
  DATABASE = 'database',
  CACHE = 'cache',
  EXTERNAL_API = 'external_api',
  MESSAGE_QUEUE = 'message_queue',
  STORAGE = 'storage',
}

/**
 * Health check result
 */
export interface HealthCheckResult {
  service: string;
  type: ServiceType;
  status: HealthStatus;
  responseTime: number;
  lastCheck: Date;
  message?: string;
  details?: Record<string, unknown>;
}

/**
 * SLA metrics
 */
export interface SLAMetrics {
  uptime: number; // Percentage
  availability: number; // Percentage
  mttr: number; // Mean Time To Recovery (minutes)
  mtbf: number; // Mean Time Between Failures (hours)
  incidents: number;
  lastIncident?: Date;
}

/**
 * Alert configuration
 */
export interface AlertConfig {
  enabled: boolean;
  thresholds: {
    responseTime: number; // ms
    errorRate: number; // percentage
    uptimeTarget: number; // percentage
  };
  channels: AlertChannel[];
}

/**
 * Alert channels
 */
export enum AlertChannel {
  EMAIL = 'email',
  SLACK = 'slack',
  PAGERDUTY = 'pagerduty',
  WEBHOOK = 'webhook',
}

/**
 * Enterprise monitoring service
 */
class EnterpriseMonitor {
  private healthChecks: Map<string, HealthCheckResult> = new Map();
  private slaMetrics: Map<string, SLAMetrics> = new Map();
  private alertConfig: AlertConfig = {
    enabled: true,
    thresholds: {
      responseTime: 5000,
      errorRate: 5,
      uptimeTarget: 99.9,
    },
    channels: [AlertChannel.EMAIL],
  };

  /**
   * Register a service for monitoring
   */
  registerService(
    serviceName: string,
    type: ServiceType,
    healthCheckFn: () => Promise<{ status: HealthStatus; message?: string; details?: Record<string, unknown> }>
  ): void {
    logInfo('Registering service for monitoring', { serviceName, type });
    
    // Store health check function
    this.healthChecks.set(serviceName, {
      service: serviceName,
      type,
      status: HealthStatus.UNKNOWN,
      responseTime: 0,
      lastCheck: new Date(),
    });

    // Initialize SLA metrics
    this.slaMetrics.set(serviceName, {
      uptime: 100,
      availability: 100,
      mttr: 0,
      mtbf: 0,
      incidents: 0,
    });

    // Run initial health check
    this.runHealthCheck(serviceName, healthCheckFn);
  }

  /**
   * Run health check for a service
   */
  private async runHealthCheck(
    serviceName: string,
    healthCheckFn: () => Promise<{ status: HealthStatus; message?: string; details?: Record<string, unknown> }>
  ): Promise<void> {
    const start = Date.now();
    
    try {
      const result = await healthCheckFn();
      const responseTime = Date.now() - start;

      const currentCheck = this.healthChecks.get(serviceName);
      if (!currentCheck) return;

      const healthCheck: HealthCheckResult = {
        ...currentCheck,
        status: result.status,
        responseTime,
        lastCheck: new Date(),
        message: result.message,
        details: result.details,
      };

      this.healthChecks.set(serviceName, healthCheck);

      // Update SLA metrics
      this.updateSLAMetrics(serviceName, result.status, responseTime);

      // Check for alerts
      if (result.status === HealthStatus.UNHEALTHY) {
        this.triggerAlert(serviceName, 'Service unhealthy', result.message);
      } else if (responseTime > this.alertConfig.thresholds.responseTime) {
        this.triggerAlert(serviceName, 'High response time', `${responseTime}ms`);
      }
    } catch (error) {
      logError('Health check failed', { serviceName, error });
      
      const currentCheck = this.healthChecks.get(serviceName);
      if (currentCheck) {
        currentCheck.status = HealthStatus.UNHEALTHY;
        currentCheck.lastCheck = new Date();
        currentCheck.message = error instanceof Error ? error.message : 'Health check failed';
        this.healthChecks.set(serviceName, currentCheck);
      }
    }
  }

  /**
   * Update SLA metrics for a service
   */
  private updateSLAMetrics(
    serviceName: string,
    status: HealthStatus,
    _responseTime: number
  ): void {
    const metrics = this.slaMetrics.get(serviceName);
    if (!metrics) return;

    // Update availability
    if (status === HealthStatus.HEALTHY) {
      metrics.availability = Math.min(100, metrics.availability + 0.1);
    } else if (status === HealthStatus.UNHEALTHY) {
      metrics.availability = Math.max(0, metrics.availability - 1);
      metrics.incidents++;
      metrics.lastIncident = new Date();
    }

    // Update uptime (rolling average)
    metrics.uptime = metrics.availability;

    this.slaMetrics.set(serviceName, metrics);
  }

  /**
   * Trigger alert for a service
   */
  private triggerAlert(
    serviceName: string,
    issue: string,
    details?: string
  ): void {
    if (!this.alertConfig.enabled) return;

    logWarn('Triggering alert', { serviceName, issue, details });

    // Send alerts through configured channels
    this.alertConfig.channels.forEach(channel => {
      this.sendAlert(channel, {
        serviceName,
        issue,
        details,
        timestamp: new Date(),
      });
    });
  }

  /**
   * Send alert through specific channel
   */
  private sendAlert(
    channel: AlertChannel,
    alert: {
      serviceName: string;
      issue: string;
      details?: string;
      timestamp: Date;
    }
  ): void {
    // Implementation depends on channel
    switch (channel) {
      case AlertChannel.EMAIL:
        logInfo('Email alert would be sent', alert);
        // TODO: Implement email alerting
        break;
      case AlertChannel.SLACK:
        logInfo('Slack alert would be sent', alert);
        // TODO: Implement Slack webhook
        break;
      case AlertChannel.PAGERDUTY:
        logInfo('PagerDuty alert would be sent', alert);
        // TODO: Implement PagerDuty API
        break;
      case AlertChannel.WEBHOOK:
        logInfo('Webhook alert would be sent', alert);
        // TODO: Implement custom webhook
        break;
    }
  }

  /**
   * Get all health checks
   */
  getAllHealthChecks(): HealthCheckResult[] {
    return Array.from(this.healthChecks.values());
  }

  /**
   * Get health check for specific service
   */
  getHealthCheck(serviceName: string): HealthCheckResult | undefined {
    return this.healthChecks.get(serviceName);
  }

  /**
   * Get SLA metrics for specific service
   */
  getSLAMetrics(serviceName: string): SLAMetrics | undefined {
    return this.slaMetrics.get(serviceName);
  }

  /**
   * Get overall system health
   */
  getSystemHealth(): {
    status: HealthStatus;
    services: HealthCheckResult[];
    uptime: number;
  } {
    const services = this.getAllHealthChecks();
    
    // Determine overall status
    let status: HealthStatus;
    const unhealthyServices = services.filter(s => s.status === HealthStatus.UNHEALTHY);
    const degradedServices = services.filter(s => s.status === HealthStatus.DEGRADED);
    
    if (unhealthyServices.length > 0) {
      status = HealthStatus.UNHEALTHY;
    } else if (degradedServices.length > 0) {
      status = HealthStatus.DEGRADED;
    } else {
      status = HealthStatus.HEALTHY;
    }

    // Calculate overall uptime
    const uptimes = Array.from(this.slaMetrics.values()).map(m => m.uptime);
    const avgUptime = uptimes.length > 0
      ? uptimes.reduce((sum, uptime) => sum + uptime, 0) / uptimes.length
      : 100;

    return {
      status,
      services,
      uptime: avgUptime,
    };
  }

  /**
   * Configure alerts
   */
  configureAlerts(config: Partial<AlertConfig>): void {
    this.alertConfig = {
      ...this.alertConfig,
      ...config,
    };

    logInfo('Alert configuration updated', this.alertConfig);
  }
}

/**
 * Singleton enterprise monitor
 */
export const enterpriseMonitor = new EnterpriseMonitor();

/**
 * Initialize enterprise monitoring
 */
export function initializeEnterpriseMonitoring(): void {
  logInfo('Initializing enterprise monitoring');

  // Register database health check
  enterpriseMonitor.registerService('database', ServiceType.DATABASE, async () => {
    try {
      const { getDatabaseStatus } = await import('@core/lib/prisma');
      const status = await getDatabaseStatus();
      
      return {
        status: status.connected ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY,
        message: `Connected: ${status.connected}`,
        details: status as Record<string, unknown>,
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        message: error instanceof Error ? error.message : 'Database check failed',
      };
    }
  });

  // Register cache health check
  enterpriseMonitor.registerService('cache', ServiceType.CACHE, async () => {
    try {
      const { cache } = await import('@core/lib/cache/cache-service');
      const stats = await cache.getStats();
      
      return {
        status: HealthStatus.HEALTHY,
        message: `Hit rate: ${(stats.hitRate * 100).toFixed(2)}%`,
        details: stats as unknown as Record<string, unknown>,
      };
    } catch (error) {
      return {
        status: HealthStatus.DEGRADED,
        message: error instanceof Error ? error.message : 'Cache check failed',
      };
    }
  });

  logInfo('Enterprise monitoring initialized');
}
