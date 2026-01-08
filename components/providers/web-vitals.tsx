'use client';

/**
 * Web Vitals tracking component
 * Monitors Core Web Vitals and sends metrics to analytics endpoint
 *
 * Version: v4.0.0 - 2026-01-07 15:50 UTC - FINAL cache invalidation
 * CRITICAL FIX (2026-01-07): Removed process.env.NODE_ENV client-side usage
 * Now uses runtime hostname detection for development environment checks
 * This prevents "process is not defined" errors in production builds
 */

import { useReportWebVitals } from 'next/web-vitals';

export function WebVitals() {
  useReportWebVitals(metric => {
    // Only track important metrics
    // Cache bust: v3.0.0 - Fix profiles table + CDN cache (2026-01-07 15:30 UTC)
    const vitals = ['FCP', 'LCP', 'CLS', 'FID', 'TTFB', 'INP'];
    if (vitals.includes(metric.name)) {
      // Rate the metric
      let rating: 'good' | 'needs-improvement' | 'poor' = 'good';

      // Define thresholds for each metric
      const thresholds: Record<string, { good: number; poor: number }> = {
        FCP: { good: 1800, poor: 3000 },
        LCP: { good: 2500, poor: 4000 },
        FID: { good: 100, poor: 300 },
        CLS: { good: 0.1, poor: 0.25 },
        TTFB: { good: 800, poor: 1800 },
        INP: { good: 200, poor: 500 },
      };

      const threshold = thresholds[metric.name];
      if (threshold) {
        if (metric.value <= threshold.good) {
          rating = 'good';
        } else if (metric.value <= threshold.poor) {
          rating = 'needs-improvement';
        } else {
          rating = 'poor';
        }
      }

      // Send to analytics endpoint
      const payload = {
        name: metric.name,
        value: metric.value,
        rating,
        timestamp: Date.now(),
        id: metric.id,
        navigationType: metric.navigationType,
      };

      // Use sendBeacon for reliability, fallback to fetch
      if (navigator.sendBeacon) {
        const blob = new Blob([JSON.stringify(payload)], {
          type: 'application/json',
        });
        navigator.sendBeacon('/api/metrics/web-vitals', blob);
      } else {
        fetch('/api/metrics/web-vitals', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          keepalive: true,
        }).catch(() => {
          // Silently fail - don't disrupt user experience
        });
      }

      // Log in development (check at runtime, not process.env)
      if (
        typeof window !== 'undefined' &&
        window.location.hostname === 'localhost'
      ) {
        // eslint-disable-next-line no-console
        console.log(`[Web Vitals] ${metric.name}:`, {
          value: metric.value,
          rating,
        });
      }
    }
  });

  return null;
}
