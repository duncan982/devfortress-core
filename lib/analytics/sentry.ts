/**
 * Sentry Error Tracking Configuration
 * Monitors errors and performance in production
 */

import * as Sentry from '@sentry/nextjs';
import { logError } from '@core/lib/logger';

// Only initialize in production or if explicitly enabled
const SENTRY_DSN = process.env.NEXT_PUBLIC_SENTRY_DSN;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const SENTRY_ENABLED = process.env.NEXT_PUBLIC_SENTRY_ENABLED === 'true';

if ((IS_PRODUCTION || SENTRY_ENABLED) && SENTRY_DSN) {
  Sentry.init({
    dsn: SENTRY_DSN,
    environment: process.env.NODE_ENV || 'development',

    // Set tracesSampleRate to 1.0 to capture 100% of transactions for performance monitoring.
    // We recommend adjusting this value in production
    tracesSampleRate: IS_PRODUCTION ? 0.1 : 1.0,

    // Capture 100% of errors
    sampleRate: 1.0,

    // Enable session replay
    replaysSessionSampleRate: IS_PRODUCTION ? 0.1 : 1.0,
    replaysOnErrorSampleRate: 1.0,

    // Filter out sensitive information
    beforeSend(event, hint) {
      // Don't send events in development unless explicitly enabled
      if (!IS_PRODUCTION && !SENTRY_ENABLED) {
        return null;
      }

      // Filter out sensitive data from breadcrumbs
      if (event.breadcrumbs) {
        event.breadcrumbs = event.breadcrumbs.map(breadcrumb => {
          if (breadcrumb.data) {
            // Remove sensitive keys
            const sensitiveKeys = ['password', 'token', 'apiKey', 'secret'];
            sensitiveKeys.forEach(key => {
              if (breadcrumb.data && key in breadcrumb.data) {
                breadcrumb.data[key] = '[REDACTED]';
              }
            });
          }
          return breadcrumb;
        });
      }

      // Also log to Winston
      if (hint.originalException) {
        logError('Sentry captured error', {
          error: hint.originalException,
          eventId: event.event_id,
        });
      }

      return event;
    },

    // Ignore certain errors
    ignoreErrors: [
      // Browser extensions
      /extensions\//i,
      /^chrome:\/\//i,
      /^chrome-extension:\/\//i,
      // Network errors
      'NetworkError',
      'Network request failed',
      // Common bot errors
      'Non-Error promise rejection captured',
    ],
  });
}

/**
 * Capture exception with context
 */
export function captureException(
  error: Error,
  context?: Record<string, unknown>
) {
  if ((IS_PRODUCTION || SENTRY_ENABLED) && SENTRY_DSN) {
    Sentry.captureException(error, {
      contexts: context ? { extra: context } : undefined,
    });
  }

  // Always log to Winston
  logError('Exception captured', { error, context });
}

/**
 * Capture message with severity
 */
export function captureMessage(
  message: string,
  level: 'fatal' | 'error' | 'warning' | 'info' | 'debug' = 'info'
) {
  if ((IS_PRODUCTION || SENTRY_ENABLED) && SENTRY_DSN) {
    Sentry.captureMessage(message, level);
  }
}

/**
 * Set user context for Sentry
 */
export function setUser(user: {
  id: string;
  email?: string;
  username?: string;
}) {
  if ((IS_PRODUCTION || SENTRY_ENABLED) && SENTRY_DSN) {
    Sentry.setUser(user);
  }
}

/**
 * Clear user context
 */
export function clearUser() {
  if ((IS_PRODUCTION || SENTRY_ENABLED) && SENTRY_DSN) {
    Sentry.setUser(null);
  }
}

/**
 * Add breadcrumb for debugging
 */
export function addBreadcrumb(
  message: string,
  category?: string,
  level?: 'fatal' | 'error' | 'warning' | 'info' | 'debug'
) {
  if ((IS_PRODUCTION || SENTRY_ENABLED) && SENTRY_DSN) {
    Sentry.addBreadcrumb({
      message,
      category,
      level: level || 'info',
      timestamp: Date.now() / 1000,
    });
  }
}

export { Sentry };
