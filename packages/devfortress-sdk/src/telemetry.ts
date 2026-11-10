/**
 * DevFortress SDK — Telemetry Heartbeat (CV-M2)
 *
 * Sends anonymised usage telemetry to the platform every 5 minutes.
 * No PII is transmitted — only aggregate counts and operational metadata.
 *
 * If heartbeat stops, the platform dashboard shows:
 *   "SDK offline — upgrade to Hybrid for guaranteed visibility."
 *
 * @packageDocumentation
 */

import { SDK_VERSION } from './version';
import { signedFetchHeaders } from './ingest-signing';

// ── Types ────────────────────────────────────────────────────

export interface TelemetrySnapshot {
  /** Total events observed since last heartbeat */
  eventCount: number;
  /** Total events blocked since last heartbeat */
  blockCount: number;
  /** Total events rate-limited since last heartbeat */
  rateLimitCount: number;
  /** Current closed-loop mode */
  clMode: 'external' | 'internal' | 'hybrid';
  /** Subscription tier */
  tier: 'starter' | 'pro' | 'team' | 'enterprise';
  /** SDK version */
  sdkVersion: string;
  /** Whether the ML model is expired */
  modelExpired: boolean;
  /** Whether the license is degraded */
  licenseDegraded: boolean;
  /** Integrity hash (anti-tampering) */
  integrityHash: string;
  /** Uptime in seconds since SDK init */
  uptimeSeconds: number;
  /** p99 observe latency in ms (sampled) */
  p99LatencyMs: number;
}

export interface TelemetryConfig {
  /** API key for authentication */
  apiKey: string;
  /** Platform base URL (no /api/events/ingest suffix) */
  endpoint: string;
  /** Heartbeat interval in ms. Default: 300000 (5 minutes) */
  heartbeatIntervalMs?: number;
  /** Enable debug logging */
  debug?: boolean;
  /** Custom fetch function (for testing) */
  fetchFn?: typeof fetch;
}

// ── Constants ────────────────────────────────────────────────

const DEFAULT_HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const HEARTBEAT_TIMEOUT_MS = 5_000; // 5s timeout

// ── Telemetry Manager ────────────────────────────────────────

export class TelemetryManager {
  private config: Required<
    Pick<
      TelemetryConfig,
      'apiKey' | 'endpoint' | 'heartbeatIntervalMs' | 'debug'
    >
  > & {
    fetchFn: typeof fetch;
  };

  // Counters (reset after each heartbeat)
  private eventCount = 0;
  private blockCount = 0;
  private rateLimitCount = 0;

  // Latency tracking (sampled)
  private latencies: number[] = [];
  private maxLatencySamples = 100;

  // State
  private startedAt = Date.now();
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private snapshotProvider: (() => Partial<TelemetrySnapshot>) | null = null;

  constructor(config: TelemetryConfig) {
    this.config = {
      apiKey: config.apiKey,
      endpoint: config.endpoint,
      heartbeatIntervalMs:
        config.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS,
      debug: config.debug ?? false,
      fetchFn: config.fetchFn ?? globalThis.fetch,
    };
  }

  /**
   * Start sending periodic heartbeats.
   * @param snapshotProvider Optional function to enrich telemetry with live state
   */
  start(snapshotProvider?: () => Partial<TelemetrySnapshot>): void {
    if (this.heartbeatTimer) return; // Already started

    this.snapshotProvider = snapshotProvider ?? null;
    this.startedAt = Date.now();

    // Send first heartbeat after a short delay (don't block init)
    setTimeout(() => this.sendHeartbeat(), 5000);

    // Schedule periodic heartbeats
    this.heartbeatTimer = setInterval(
      () => this.sendHeartbeat(),
      this.config.heartbeatIntervalMs
    );

    // Unref so it doesn't prevent process exit
    if (
      this.heartbeatTimer &&
      typeof this.heartbeatTimer === 'object' &&
      'unref' in this.heartbeatTimer
    ) {
      (this.heartbeatTimer as NodeJS.Timeout).unref();
    }

    this.log(
      'info',
      `Telemetry heartbeat started (interval: ${this.config.heartbeatIntervalMs / 1000}s)`
    );
  }

  /**
   * Record an observed event.
   */
  recordEvent(): void {
    this.eventCount++;
  }

  /**
   * Record a blocked event.
   */
  recordBlock(): void {
    this.blockCount++;
  }

  /**
   * Record a rate-limited event.
   */
  recordRateLimit(): void {
    this.rateLimitCount++;
  }

  /**
   * Record observe latency for p99 calculation.
   */
  recordLatency(ms: number): void {
    if (this.latencies.length >= this.maxLatencySamples) {
      // Reservoir sampling: replace random element
      const idx = Math.floor(Math.random() * this.latencies.length);
      this.latencies[idx] = ms;
    } else {
      this.latencies.push(ms);
    }
  }

  /**
   * Send a heartbeat to the platform.
   * Fire-and-forget — failures are silently logged.
   */
  private async sendHeartbeat(): Promise<void> {
    try {
      const enriched = this.snapshotProvider?.() ?? {};

      const snapshot: TelemetrySnapshot = {
        eventCount: this.eventCount,
        blockCount: this.blockCount,
        rateLimitCount: this.rateLimitCount,
        clMode: enriched.clMode ?? 'external',
        tier: enriched.tier ?? 'starter',
        sdkVersion: enriched.sdkVersion ?? SDK_VERSION,
        modelExpired: enriched.modelExpired ?? false,
        licenseDegraded: enriched.licenseDegraded ?? false,
        integrityHash: enriched.integrityHash ?? '',
        uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000),
        p99LatencyMs: this.computeP99(),
      };

      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        HEARTBEAT_TIMEOUT_MS
      );

      // Signed with a key ID and a fresh nonce per beat: the key is never sent.
      const url = `${this.config.endpoint}/api/sdk/heartbeat`;
      const body = JSON.stringify({
        timestamp: Date.now(),
        ...snapshot,
      });
      await this.config.fetchFn(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...signedFetchHeaders(this.config.apiKey, 'POST', url, body),
        },
        body,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      this.log(
        'debug',
        `Heartbeat sent: events=${snapshot.eventCount}, blocks=${snapshot.blockCount}, uptime=${snapshot.uptimeSeconds}s`
      );

      // Reset counters after successful send
      this.eventCount = 0;
      this.blockCount = 0;
      this.rateLimitCount = 0;
      this.latencies = [];
    } catch (error) {
      // Fire-and-forget: don't throw, just log
      this.log(
        'debug',
        `Heartbeat failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Compute p99 latency from sampled observations.
   */
  private computeP99(): number {
    if (this.latencies.length === 0) return 0;
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const idx = Math.floor(sorted.length * 0.99);
    return sorted[Math.min(idx, sorted.length - 1)];
  }

  /**
   * Get current telemetry state (for diagnostics).
   */
  getState(): {
    eventCount: number;
    blockCount: number;
    rateLimitCount: number;
    uptimeSeconds: number;
  } {
    return {
      eventCount: this.eventCount,
      blockCount: this.blockCount,
      rateLimitCount: this.rateLimitCount,
      uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000),
    };
  }

  /**
   * Stop sending heartbeats and clean up.
   */
  destroy(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private log(level: 'info' | 'warn' | 'debug', message: string): void {
    if (!this.config.debug && level === 'debug') return;
    const prefix = '[DevFortress:Telemetry]';
    switch (level) {
      case 'warn':
        console.warn(`${prefix} ${message}`);
        break;
      case 'debug':
        console.debug(`${prefix} ${message}`);
        break;
      default:
        console.log(`${prefix} ${message}`);
    }
  }
}
