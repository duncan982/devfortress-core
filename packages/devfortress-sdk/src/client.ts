/**
 * DevFortress API Client
 * Core client for sending events to DevFortress surveillance API
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { SDK_VERSION } from './version';
import { attachPlatformSigning } from './ingest-signing';
import type {
  DevFortressClientOptions,
  LiveThreatEvent,
  ApiResponse,
} from './types';

const DEFAULT_ENDPOINT = 'https://www.devfortress.net/api/events/ingest';
const DEFAULT_TIMEOUT = 15000;
const DEFAULT_RETRIES = 3;

/** Default batch configuration */
const DEFAULT_BATCH_SIZE = 25;
const DEFAULT_FLUSH_INTERVAL_MS = 5000;

export class DevFortressClient {
  private apiKey: string;
  private endpoint: string;
  private timeout: number;
  private retries: number;
  private debug: boolean;
  private axios: AxiosInstance;

  // ── Batching state ────────────────────────────────────────────────────
  private batchBuffer: LiveThreatEvent[] = [];
  private batchSize: number;
  private flushIntervalMs: number;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private batchEnabled = false;

  constructor(options: DevFortressClientOptions) {
    if (!options.apiKey) {
      throw new Error('DevFortressClient: apiKey is required');
    }

    this.apiKey = options.apiKey;
    this.endpoint = options.endpoint || DEFAULT_ENDPOINT;
    this.timeout = options.timeout || DEFAULT_TIMEOUT;
    this.retries = options.retries || DEFAULT_RETRIES;
    this.debug = options.debug || false;
    this.batchSize = options.batchSize || DEFAULT_BATCH_SIZE;
    this.flushIntervalMs = options.flushIntervalMs || DEFAULT_FLUSH_INTERVAL_MS;

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

    this.axios = axios.create({
      baseURL: this.endpoint,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    attachPlatformSigning(this.axios, this.apiKey);
  }

  /**
   * Track a security event
   */
  async trackEvent(event: LiveThreatEvent): Promise<ApiResponse> {
    try {
      // Add timestamp if not provided
      const payload = {
        ...event,
        timestamp: event.timestamp || new Date().toISOString(),
      };

      const response = await this.sendWithRetry(payload);
      return response.data;
    } catch (error) {
      throw new Error(
        `Failed to track event: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Send event with automatic retry logic
   */
  private async sendWithRetry(
    payload: LiveThreatEvent,
    attempt: number = 1
  ): Promise<{ data: ApiResponse }> {
    try {
      const response = await this.axios.post('', payload);
      return response;
    } catch (error) {
      const axiosError = error as AxiosError;

      // Don't retry on client errors (4xx)
      if (axiosError.response?.status && axiosError.response.status < 500) {
        throw error;
      }

      // Retry on server errors (5xx) or network errors
      if (attempt < this.retries) {
        const backoff = Math.pow(2, attempt) * 1000; // Exponential backoff

        await new Promise(resolve => setTimeout(resolve, backoff));
        return this.sendWithRetry(payload, attempt + 1);
      }

      throw error;
    }
  }

  /**
   * Test connection to surveillance API.
   * Sends a fully-formed event with all mandatory fields so the
   * ingest route does not reject it.
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.trackEvent({
        eventType: 'custom',
        ip: '127.0.0.1',
        method: 'GET',
        path: '/__devfortress/test',
        severity: 'LOW',
        authPhase: 'pre_auth',
        actionTaken: 'monitored',
        responseLatencyMs: 0,
        clMode: 'external',
        metadata: { test: true, sdkVersion: SDK_VERSION },
      });
      return true;
    } catch {
      return false;
    }
  }

  // ── Batch API ─────────────────────────────────────────────────────────

  /**
   * Enable event batching.
   * Events queued via `queueEvent()` are buffered and sent in batches
   * of `batchSize` or when `flushIntervalMs` elapses, whichever comes first.
   * This reduces API invocations by up to 25× (the default batch size).
   */
  enableBatching(): void {
    if (this.batchEnabled) return;
    this.batchEnabled = true;
    this.flushTimer = setInterval(() => {
      void this.flush();
    }, this.flushIntervalMs);
  }

  /**
   * Disable batching and flush remaining events.
   */
  async disableBatching(): Promise<void> {
    this.batchEnabled = false;
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  /**
   * Queue an event for batch submission.
   * When the buffer reaches `batchSize`, a flush is triggered automatically.
   * Falls back to immediate `trackEvent()` if batching is not enabled.
   */
  async queueEvent(event: LiveThreatEvent): Promise<void> {
    if (!this.batchEnabled) {
      await this.trackEvent(event);
      return;
    }

    const payload = {
      ...event,
      timestamp: event.timestamp || new Date().toISOString(),
    };
    this.batchBuffer.push(payload);

    if (this.batchBuffer.length >= this.batchSize) {
      await this.flush();
    }
  }

  /**
   * Send multiple events in a single HTTP request.
   * The ingest endpoint accepts `{ events: [...] }` for batch mode.
   */
  async trackEvents(events: LiveThreatEvent[]): Promise<ApiResponse> {
    if (events.length === 0) {
      return { success: true, processed: 0, successful: 0, failed: 0 };
    }

    const payload = {
      events: events.map(e => ({
        ...e,
        timestamp: e.timestamp || new Date().toISOString(),
      })),
    };

    try {
      const response = await this.axios.post('', payload);
      return response.data;
    } catch (error) {
      throw new Error(
        `Failed to track batch: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Flush all buffered events to the API.
   * Called automatically by the flush interval or when buffer is full.
   */
  async flush(): Promise<void> {
    if (this.batchBuffer.length === 0) return;

    const events = this.batchBuffer.splice(0, this.batchBuffer.length);

    // Split into chunks of 100 (server max batch size)
    const maxChunk = 100;
    for (let i = 0; i < events.length; i += maxChunk) {
      const chunk = events.slice(i, i + maxChunk);
      try {
        await this.trackEvents(chunk);
      } catch {
        if (this.debug) {
          console.error(
            `[DevFortress] Batch flush failed for ${chunk.length} events`
          );
        }
      }
    }
  }

  /** Number of events currently buffered */
  get pendingEvents(): number {
    return this.batchBuffer.length;
  }
}
