/**
 * Performance monitoring utilities for VortexSecure
 * Tracks Core Web Vitals and custom metrics
 */

import { logInfo, logWarn, logError } from './logger';

export interface PerformanceMetric {
  name: string;
  value: number;
  rating: 'good' | 'needs-improvement' | 'poor';
  timestamp: number;
}

export interface WebVitals {
  FCP?: number; // First Contentful Paint
  LCP?: number; // Largest Contentful Paint
  FID?: number; // First Input Delay
  CLS?: number; // Cumulative Layout Shift
  TTFB?: number; // Time to First Byte
  INP?: number; // Interaction to Next Paint
}

/**
 * Core Web Vitals thresholds
 */
const THRESHOLDS = {
  FCP: { good: 1800, poor: 3000 },
  LCP: { good: 2500, poor: 4000 },
  FID: { good: 100, poor: 300 },
  CLS: { good: 0.1, poor: 0.25 },
  TTFB: { good: 800, poor: 1800 },
  INP: { good: 200, poor: 500 },
};

/**
 * Rate a metric based on thresholds
 */
export function rateMetric(
  name: keyof typeof THRESHOLDS,
  value: number
): 'good' | 'needs-improvement' | 'poor' {
  const threshold = THRESHOLDS[name];
  if (value <= threshold.good) return 'good';
  if (value <= threshold.poor) return 'needs-improvement';
  return 'poor';
}

/**
 * Report Web Vitals (client-side)
 */
export function reportWebVitals(metric: PerformanceMetric): void {
  // Log to logger in development
  if (process.env.NODE_ENV === 'development') {
    logInfo('Web Vitals', {
      metric: metric.name,
      value: metric.value,
      rating: metric.rating,
    });
  }

  // Send to analytics endpoint in production
  if (process.env.NODE_ENV === 'production') {
    fetch('/api/metrics/web-vitals', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(metric),
      keepalive: true,
    }).catch(() => {
      // Silently fail - don't disrupt user experience
    });
  }
}

/**
 * Measure server-side performance
 */
export class PerformanceMonitor {
  private startTime: number;
  private marks: Map<string, number>;

  constructor() {
    this.startTime = Date.now();
    this.marks = new Map();
  }

  /**
   * Mark a point in time
   */
  mark(name: string): void {
    this.marks.set(name, Date.now());
  }

  /**
   * Measure duration between marks
   */
  measure(name: string, startMark?: string, endMark?: string): number {
    const start = startMark
      ? this.marks.get(startMark) || this.startTime
      : this.startTime;
    const end = endMark ? this.marks.get(endMark) || Date.now() : Date.now();
    const duration = end - start;

    logInfo('Performance measurement', {
      name,
      duration,
      unit: 'ms',
    });

    return duration;
  }

  /**
   * Get elapsed time since start
   */
  getElapsed(): number {
    return Date.now() - this.startTime;
  }

  /**
   * Log final performance summary
   */
  summary(operationName: string): void {
    const elapsed = this.getElapsed();
    const marks = Array.from(this.marks.entries());

    logInfo('Performance summary', {
      operation: operationName,
      totalDuration: elapsed,
      marks: marks.map(([name, time]) => ({
        name,
        offset: time - this.startTime,
      })),
    });
  }
}

/**
 * Measure async function execution time
 */
export async function measureAsync<T>(
  name: string,
  fn: () => Promise<T>
): Promise<T> {
  const start = Date.now();
  try {
    const result = await fn();
    const duration = Date.now() - start;

    if (duration > 1000) {
      logWarn('Slow operation detected', { name, duration });
    } else {
      logInfo('Operation completed', { name, duration });
    }

    return result;
  } catch (error) {
    const duration = Date.now() - start;
    logError('Operation failed', { name, duration, error });
    throw error;
  }
}

/**
 * Database query performance tracker
 */
export class QueryPerformanceTracker {
  private queries: Array<{
    query: string;
    duration: number;
    timestamp: number;
  }> = [];

  track(query: string, duration: number): void {
    this.queries.push({
      query,
      duration,
      timestamp: Date.now(),
    });

    // Log slow queries
    if (duration > 1000) {
      logWarn('Slow database query', { query, duration });
    }

    // Keep only last 100 queries
    if (this.queries.length > 100) {
      this.queries.shift();
    }
  }

  getStats() {
    if (this.queries.length === 0) {
      return { count: 0, avgDuration: 0, maxDuration: 0 };
    }

    const durations = this.queries.map(q => q.duration);
    const sum = durations.reduce((a, b) => a + b, 0);
    const avg = sum / durations.length;
    const max = Math.max(...durations);

    return {
      count: this.queries.length,
      avgDuration: Math.round(avg),
      maxDuration: max,
      slowQueries: this.queries.filter(q => q.duration > 1000).length,
    };
  }

  reset(): void {
    this.queries = [];
  }
}

// Export singleton instance
export const queryTracker = new QueryPerformanceTracker();

/**
 * Memory usage tracker
 */
export function getMemoryUsage() {
  if (typeof process !== 'undefined' && process.memoryUsage) {
    const usage = process.memoryUsage();
    return {
      heapUsed: Math.round(usage.heapUsed / 1024 / 1024), // MB
      heapTotal: Math.round(usage.heapTotal / 1024 / 1024), // MB
      rss: Math.round(usage.rss / 1024 / 1024), // MB
      external: Math.round(usage.external / 1024 / 1024), // MB
    };
  }
  return null;
}

/**
 * Log memory usage
 */
export function logMemoryUsage(context?: string): void {
  const usage = getMemoryUsage();
  if (usage) {
    if (usage.heapUsed > 400) {
      logWarn('High memory usage', { context, ...usage });
    } else {
      logInfo('Memory usage', { context, ...usage });
    }
  }
}
