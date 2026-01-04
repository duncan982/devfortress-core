/**
 * Performance Monitoring Service
 * Tracks application performance metrics
 * 
 * Metrics tracked:
 * - API response times
 * - Database query performance
 * - Cache hit rates
 * - External service latency
 * - Error rates
 */

import { logInfo, logWarn } from '@core/lib/logger';

/**
 * Performance metric types
 */
export enum MetricType {
  API_RESPONSE = 'api_response',
  DB_QUERY = 'db_query',
  CACHE_HIT = 'cache_hit',
  CACHE_MISS = 'cache_miss',
  EXTERNAL_SERVICE = 'external_service',
  ERROR = 'error',
}

/**
 * Performance metric
 */
interface PerformanceMetric {
  type: MetricType;
  name: string;
  duration: number;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

/**
 * Aggregated metrics
 */
export interface AggregatedMetrics {
  name: string;
  count: number;
  avg: number;
  min: number;
  max: number;
  p50: number;
  p95: number;
  p99: number;
}

/**
 * Performance monitoring service
 */
class PerformanceMonitor {
  private metrics: PerformanceMetric[] = [];
  private maxMetrics = 10000; // Keep last 10k metrics in memory

  /**
   * Record a performance metric
   */
  record(
    type: MetricType,
    _name: string,
    duration: number,
    metadata?: Record<string, unknown>
  ): void {
    const metric: PerformanceMetric = {
      type,
      name: _name,
      duration,
      timestamp: Date.now(),
      metadata,
    };

    this.metrics.push(metric);

    // Keep memory usage bounded
    if (this.metrics.length > this.maxMetrics) {
      this.metrics = this.metrics.slice(-this.maxMetrics);
    }

    // Log slow operations
    if (duration > 1000) {
      logWarn('Slow operation detected', {
        type,
        name,
        duration: `${duration}ms`,
      });
    }
  }

  /**
   * Start timing an operation
   */
  startTimer(_name: string): () => void {
    const start = Date.now();
    return () => Date.now() - start;
  }

  /**
   * Measure async operation
   */
  async measure<T>(
    type: MetricType,
    name: string,
    fn: () => Promise<T>,
    metadata?: Record<string, unknown>
  ): Promise<T> {
    const start = Date.now();
    try {
      const result = await fn();
      const duration = Date.now() - start;
      this.record(type, name, duration, metadata);
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      this.record(MetricType.ERROR, name, duration, {
        ...metadata,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Get aggregated metrics
   */
  getAggregated(type?: MetricType): AggregatedMetrics[] {
    let filtered = this.metrics;

    if (type) {
      filtered = this.metrics.filter(m => m.type === type);
    }

    // Group by name
    const grouped = new Map<string, number[]>();
    filtered.forEach(metric => {
      if (!grouped.has(metric.name)) {
        grouped.set(metric.name, []);
      }
      grouped.get(metric.name)!.push(metric.duration);
    });

    // Calculate statistics
    const results: AggregatedMetrics[] = [];
    grouped.forEach((durations, name) => {
      const sorted = [...durations].sort((a, b) => a - b);
      const count = sorted.length;
      const sum = sorted.reduce((acc, d) => acc + d, 0);

      results.push({
        name,
        count,
        avg: sum / count,
        min: sorted[0],
        max: sorted[count - 1],
        p50: sorted[Math.floor(count * 0.5)],
        p95: sorted[Math.floor(count * 0.95)],
        p99: sorted[Math.floor(count * 0.99)],
      });
    });

    return results;
  }

  /**
   * Get recent metrics
   */
  getRecent(limit = 100): PerformanceMetric[] {
    return this.metrics.slice(-limit);
  }

  /**
   * Get metrics summary
   */
  getSummary(): {
    totalMetrics: number;
    avgResponseTime: number;
    errorRate: number;
    cacheHitRate: number;
  } {
    const total = this.metrics.length;
    if (total === 0) {
      return {
        totalMetrics: 0,
        avgResponseTime: 0,
        errorRate: 0,
        cacheHitRate: 0,
      };
    }

    const apiMetrics = this.metrics.filter(
      m => m.type === MetricType.API_RESPONSE
    );
    const avgResponseTime =
      apiMetrics.reduce((sum, m) => sum + m.duration, 0) / (apiMetrics.length || 1);

    const errorMetrics = this.metrics.filter(m => m.type === MetricType.ERROR);
    const errorRate = errorMetrics.length / total;

    const cacheHits = this.metrics.filter(m => m.type === MetricType.CACHE_HIT).length;
    const cacheMisses = this.metrics.filter(
      m => m.type === MetricType.CACHE_MISS
    ).length;
    const cacheHitRate = cacheHits / (cacheHits + cacheMisses || 1);

    return {
      totalMetrics: total,
      avgResponseTime,
      errorRate,
      cacheHitRate,
    };
  }

  /**
   * Clear all metrics
   */
  clear(): void {
    this.metrics = [];
    logInfo('Performance metrics cleared');
  }

  /**
   * Export metrics (for external monitoring systems)
   */
  export(): PerformanceMetric[] {
    return [...this.metrics];
  }
}

/**
 * Singleton performance monitor
 */
export const performanceMonitor = new PerformanceMonitor();

/**
 * Decorator for measuring method performance
 */
export function Measure(type: MetricType = MetricType.API_RESPONSE) {
  return function (
    target: unknown,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: unknown[]) {
      const start = Date.now();
      try {
        const result = await originalMethod.apply(this, args);
        const duration = Date.now() - start;
        performanceMonitor.record(type, propertyKey, duration);
        return result;
      } catch (error) {
        const duration = Date.now() - start;
        performanceMonitor.record(MetricType.ERROR, propertyKey, duration);
        throw error;
      }
    };

    return descriptor;
  };
}
