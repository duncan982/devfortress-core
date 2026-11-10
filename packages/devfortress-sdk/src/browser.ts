/**
 * DevFortress SDK - Browser Entry Point
 *
 * Lightweight browser-compatible client for sending security events
 * from client-side applications. Uses fetch API instead of axios.
 *
 * @packageDocumentation
 */

export type {
  DevFortressClientOptions,
  LiveThreatEvent,
  EventType,
  SeverityLevel,
  ApiResponse,
} from './types';

import type { DevFortressClientOptions } from './types';

const DEFAULT_ENDPOINT = 'https://www.devfortress.net/api/events/ingest';
const DEFAULT_TIMEOUT = 5000;
const DEFAULT_RETRIES = 3;

/** @deprecated Use DevFortressClientOptions instead */
export type BrowserClientOptions = DevFortressClientOptions;

export class DevFortressBrowserClient {
  private apiKey: string;
  private endpoint: string;
  private timeout: number;
  private retries: number;
  private debug: boolean;

  constructor(options: DevFortressClientOptions) {
    if (!options.apiKey) {
      throw new Error('DevFortressBrowserClient: apiKey is required');
    }

    this.apiKey = options.apiKey;
    this.endpoint = options.endpoint || DEFAULT_ENDPOINT;
    this.timeout = options.timeout || DEFAULT_TIMEOUT;
    this.retries = options.retries || DEFAULT_RETRIES;
    this.debug = options.debug || false;

    // Warn if endpoint is not HTTPS
    if (
      this.endpoint.startsWith('http://') &&
      !this.endpoint.includes('localhost') &&
      !this.endpoint.includes('127.0.0.1')
    ) {
      console.warn(
        '[DevFortress] WARNING: Using non-HTTPS endpoint. API key will be transmitted in cleartext.'
      );
    }
  }

  /**
   * Track a security event from the browser
   */
  async trackEvent(event: {
    eventType: string;
    ip?: string;
    method?: string;
    path?: string;
    userAgent?: string;
    statusCode?: number;
    responseTime?: number;
    metadata?: Record<string, unknown>;
    severity?: string;
    reason?: string;
    timestamp?: string;
  }): Promise<{ success: boolean; eventId?: string; message?: string }> {
    const payload = {
      ...event,
      ip: event.ip || 'browser-client',
      userAgent:
        event.userAgent ||
        (typeof navigator !== 'undefined' ? navigator.userAgent : undefined),
      timestamp: event.timestamp || new Date().toISOString(),
    };

    return this.sendWithRetry(payload, 1);
  }

  /**
   * Track a page error as a security event
   */
  trackError(error: Error, context?: Record<string, unknown>): void {
    this.trackEvent({
      eventType: 'custom',
      reason: error.message,
      metadata: {
        stack: error.stack,
        ...context,
      },
      severity: 'MEDIUM',
    }).catch(() => {
      // Silently fail - don't crash the app for telemetry
    });
  }

  /**
   * Track a failed API response
   */
  trackApiFailure(url: string, status: number, method: string = 'GET'): void {
    let eventType: string = 'custom';
    let severity: string = 'LOW';

    if (status === 401 || status === 403) {
      eventType = 'auth_failure';
      severity = 'MEDIUM';
    } else if (status === 429) {
      eventType = 'rate_limit_exceeded';
      severity = 'MEDIUM';
    } else if (status >= 500) {
      eventType = '5xx_error';
      severity = 'HIGH';
    } else if (status >= 400) {
      eventType = '4xx_error';
      severity = 'LOW';
    }

    this.trackEvent({
      eventType,
      method,
      path: url,
      statusCode: status,
      severity,
      reason: `API ${method} ${url} returned ${status}`,
    }).catch(() => {
      // Silently fail
    });
  }

  /**
   * Install global error handler for automatic tracking
   */
  installGlobalErrorHandler(): () => void {
    if (typeof window === 'undefined') return () => {};

    const handler = (event: ErrorEvent) => {
      this.trackError(event.error || new Error(event.message), {
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
      });
    };

    const rejectionHandler = (event: PromiseRejectionEvent) => {
      const error =
        event.reason instanceof Error
          ? event.reason
          : new Error(String(event.reason));
      this.trackError(error, { type: 'unhandledRejection' });
    };

    window.addEventListener('error', handler);
    window.addEventListener('unhandledrejection', rejectionHandler);

    // Return cleanup function
    return () => {
      window.removeEventListener('error', handler);
      window.removeEventListener('unhandledrejection', rejectionHandler);
    };
  }

  /**
   * Test connection to the surveillance API
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.trackEvent({
        eventType: 'custom',
        ip: 'browser-test',
        metadata: { test: true },
      });
      return true;
    } catch {
      return false;
    }
  }

  private async sendWithRetry(
    payload: Record<string, unknown>,
    attempt: number
  ): Promise<{ success: boolean; eventId?: string; message?: string }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-DevFortress-Key': this.apiKey,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        // Don't retry on client errors
        if (response.status < 500) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.message || `HTTP ${response.status}`);
        }
        throw new Error(`Server error: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);

      if (attempt < this.retries) {
        const backoff = Math.pow(2, attempt) * 500;
        if (this.debug) {
          console.log(
            `[DevFortress] Retrying in ${backoff}ms (attempt ${attempt}/${this.retries})`
          );
        }
        await new Promise(resolve => setTimeout(resolve, backoff));
        return this.sendWithRetry(payload, attempt + 1);
      }

      throw error;
    }
  }
}

/**
 * Create a pre-configured browser client instance
 */
export function createBrowserClient(
  options: DevFortressClientOptions
): DevFortressBrowserClient {
  return new DevFortressBrowserClient(options);
}
