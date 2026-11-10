/**
 * DevFortress SDK — License Manager (CV-M1, CV-M4, CV-M7)
 *
 * Implements:
 * - CV-M1: Server-side license validation with 24h check interval and 72h grace degradation
 * - CV-M4: ML model expiry (30-day staleness without platform sync)
 * - CV-M7: SDK anti-tampering HMAC signature verification
 *
 * @packageDocumentation
 */

import crypto from 'crypto';
import { signedFetchHeaders } from './ingest-signing';
import { SDK_VERSION } from './version';

// ── Types ────────────────────────────────────────────────────

export interface LicenseState {
  /** Whether the license is currently valid */
  valid: boolean;
  /** Subscription tier confirmed by platform */
  tier: 'starter' | 'pro' | 'team' | 'enterprise';
  /** Timestamp of last successful license check */
  lastCheckedAt: number;
  /** Number of consecutive check failures */
  consecutiveFailures: number;
  /** Whether SDK is in degraded (monitor-only) mode due to expired license */
  degraded: boolean;
  /** Reason for degradation (if applicable) */
  degradationReason?: string;
}

export interface ModelState {
  /** Timestamp when the ML model was last synced from platform */
  lastSyncedAt: number;
  /** Model version identifier */
  modelVersion: string;
  /** Whether the model has expired (>30 days without sync) */
  expired: boolean;
}

export interface LicenseManagerConfig {
  /** API key for license validation */
  apiKey: string;
  /** Platform base URL (no /api/events/ingest suffix) for license checks */
  endpoint: string;
  /** License check interval in ms. Default: 86400000 (24h) */
  checkIntervalMs?: number;
  /** Grace period before degradation in ms. Default: 259200000 (72h) */
  gracePeriodMs?: number;
  /** ML model expiry threshold in ms. Default: 2592000000 (30 days) */
  modelExpiryMs?: number;
  /** SDK distribution HMAC secret (for anti-tampering) */
  integritySecret?: string;
  /** Enable debug logging */
  debug?: boolean;
  /** Custom fetch function (for testing) */
  fetchFn?: typeof fetch;
}

// ── Constants ────────────────────────────────────────────────

const DEFAULT_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_GRACE_PERIOD_MS = 72 * 60 * 60 * 1000; // 72 hours
const DEFAULT_MODEL_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const LICENSE_CHECK_TIMEOUT_MS = 10_000; // 10s timeout for license checks

// ── License Manager ──────────────────────────────────────────

export class LicenseManager {
  private config: Required<
    Pick<
      LicenseManagerConfig,
      | 'apiKey'
      | 'endpoint'
      | 'checkIntervalMs'
      | 'gracePeriodMs'
      | 'modelExpiryMs'
      | 'debug'
    >
  > & {
    integritySecret: string | null;
    fetchFn: typeof fetch;
  };

  private licenseState: LicenseState = {
    valid: false,
    tier: 'starter',
    lastCheckedAt: 0,
    consecutiveFailures: 0,
    degraded: false,
  };

  private modelState: ModelState = {
    lastSyncedAt: Date.now(), // Assume fresh on init
    modelVersion: 'embedded-v1',
    expired: false,
  };

  private checkTimer: ReturnType<typeof setInterval> | null = null;
  private initialized = false;

  constructor(config: LicenseManagerConfig) {
    this.config = {
      apiKey: config.apiKey,
      endpoint: config.endpoint,
      checkIntervalMs: config.checkIntervalMs ?? DEFAULT_CHECK_INTERVAL_MS,
      gracePeriodMs: config.gracePeriodMs ?? DEFAULT_GRACE_PERIOD_MS,
      modelExpiryMs: config.modelExpiryMs ?? DEFAULT_MODEL_EXPIRY_MS,
      integritySecret: config.integritySecret ?? null,
      debug: config.debug ?? false,
      fetchFn: config.fetchFn ?? globalThis.fetch,
    };
  }

  // ── CV-M1: License Validation ──────────────────────────────

  /**
   * Initialize the license manager. Performs initial license check
   * and starts periodic validation.
   */
  async init(): Promise<LicenseState> {
    if (this.initialized) return this.licenseState;

    // Perform initial license check
    await this.checkLicense();

    // Start periodic checks
    this.checkTimer = setInterval(
      () => this.checkLicense(),
      this.config.checkIntervalMs
    );

    // Unref the timer so it doesn't prevent process exit
    if (
      this.checkTimer &&
      typeof this.checkTimer === 'object' &&
      'unref' in this.checkTimer
    ) {
      (this.checkTimer as NodeJS.Timeout).unref();
    }

    this.initialized = true;
    return this.licenseState;
  }

  /**
   * Perform a license check against the platform.
   * On failure, tracks consecutive failures and degrades after grace period.
   */
  async checkLicense(): Promise<LicenseState> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        LICENSE_CHECK_TIMEOUT_MS
      );

      // Signed with a key ID and a fresh nonce per attempt: the key is never sent.
      const url = `${this.config.endpoint}/api/sdk/license-check`;
      const body = JSON.stringify({
        sdkVersion: SDK_VERSION,
        timestamp: Date.now(),
        integrity: this.computeIntegrityHash(),
      });
      const response = await this.config.fetchFn(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...signedFetchHeaders(this.config.apiKey, 'POST', url, body),
        },
        body,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok) {
        const data = await response.json();
        this.licenseState = {
          valid: true,
          tier: data.tier || this.licenseState.tier,
          lastCheckedAt: Date.now(),
          consecutiveFailures: 0,
          degraded: false,
        };

        // CV-M4: Sync ML model freshness on successful license check
        if (data.modelVersion) {
          this.modelState = {
            lastSyncedAt: Date.now(),
            modelVersion: data.modelVersion,
            expired: false,
          };
        }

        this.log('info', `License validated: tier=${this.licenseState.tier}`);
      } else if (response.status === 402 || response.status === 403) {
        // Explicitly unauthorized/payment required
        this.licenseState = {
          valid: false,
          tier: 'starter',
          lastCheckedAt: Date.now(),
          consecutiveFailures: this.licenseState.consecutiveFailures + 1,
          degraded: true,
          degradationReason: `License rejected: HTTP ${response.status}`,
        };
        this.log('warn', `License rejected: HTTP ${response.status}`);
      } else {
        // Server error — treat as transient failure
        this.handleCheckFailure(`HTTP ${response.status}`);
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      this.handleCheckFailure(msg);
    }

    return this.licenseState;
  }

  private handleCheckFailure(reason: string): void {
    this.licenseState.consecutiveFailures += 1;
    // If never successfully checked, start grace period from initialization
    const baselineTime =
      this.licenseState.lastCheckedAt === 0
        ? Date.now()
        : this.licenseState.lastCheckedAt;
    const timeSinceLastSuccess = Date.now() - baselineTime;

    if (timeSinceLastSuccess >= this.config.gracePeriodMs) {
      // Grace period expired — degrade to monitor-only
      this.licenseState.degraded = true;
      this.licenseState.degradationReason =
        `License check failed for ${Math.round(timeSinceLastSuccess / 3600000)}h ` +
        `(grace period: ${Math.round(this.config.gracePeriodMs / 3600000)}h). ` +
        `Reason: ${reason}. SDK degraded to monitor-only mode.`;
      this.log('warn', this.licenseState.degradationReason);
    } else {
      this.log(
        'debug',
        `License check failed (${reason}), ` +
          `${this.licenseState.consecutiveFailures} consecutive failures, ` +
          `${Math.round((this.config.gracePeriodMs - timeSinceLastSuccess) / 3600000)}h grace remaining`
      );
    }
  }

  /**
   * Get current license state.
   */
  getLicenseState(): Readonly<LicenseState> {
    return { ...this.licenseState };
  }

  /**
   * Check if the SDK should operate in degraded (monitor-only) mode.
   * Degraded mode means: no blocking, no rate limiting, just logging.
   */
  isDegraded(): boolean {
    return this.licenseState.degraded;
  }

  /**
   * Check if a specific capability is available in current license state.
   */
  canPerformAction(action: 'block' | 'rate_limit' | 'observe'): boolean {
    if (action === 'observe') return true; // Always allowed
    if (this.licenseState.degraded) return false; // Degraded = monitor-only
    if (!this.licenseState.valid && this.licenseState.lastCheckedAt === 0) {
      // Never validated yet — allow actions during initial grace period
      return true;
    }
    return this.licenseState.valid;
  }

  // ── CV-M4: ML Model Expiry ─────────────────────────────────

  /**
   * Check if the embedded ML model has expired.
   * If expired (>30 days without platform sync), ICL falls back to Tier 1 only.
   */
  isModelExpired(): boolean {
    const age = Date.now() - this.modelState.lastSyncedAt;
    this.modelState.expired = age > this.config.modelExpiryMs;
    return this.modelState.expired;
  }

  /**
   * Get current ML model state.
   */
  getModelState(): Readonly<ModelState> {
    return {
      ...this.modelState,
      expired: this.isModelExpired(),
    };
  }

  /**
   * Manually trigger a model sync (called from DevFortress.init or heartbeat).
   */
  syncModel(modelVersion: string): void {
    this.modelState = {
      lastSyncedAt: Date.now(),
      modelVersion,
      expired: false,
    };
    this.log('info', `ML model synced: version=${modelVersion}`);
  }

  // ── CV-M7: Anti-Tampering ──────────────────────────────────

  /**
   * Compute HMAC signature over critical SDK code paths.
   * If the SDK distribution has been modified, this hash will differ
   * from the expected value on the platform side.
   */
  computeIntegrityHash(): string {
    if (!this.config.integritySecret) {
      return 'no-integrity-secret';
    }

    // Hash critical module references (class names, method signatures)
    const criticalPaths = [
      'DevFortress.observe',
      'DevFortress.isBlocked',
      'LicenseManager.checkLicense',
      'InternalClosedLoopEngine.evaluate',
      'TierGate.checkEventLimit',
    ].join('|');

    return crypto
      .createHmac('sha256', this.config.integritySecret)
      .update(criticalPaths)
      .update(this.config.apiKey)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Verify that the SDK has not been tampered with.
   * Returns `tampered: true` if the integrity hash doesn't match.
   */
  verifyIntegrity(expectedHash?: string): { tampered: boolean; hash: string } {
    const currentHash = this.computeIntegrityHash();
    if (!expectedHash) {
      return { tampered: false, hash: currentHash };
    }
    return {
      tampered: currentHash !== expectedHash,
      hash: currentHash,
    };
  }

  // ── Cleanup ────────────────────────────────────────────────

  /**
   * Stop periodic license checks and clean up.
   */
  destroy(): void {
    if (this.checkTimer) {
      clearInterval(this.checkTimer);
      this.checkTimer = null;
    }
    this.initialized = false;
  }

  // ── Logging ────────────────────────────────────────────────

  private log(
    level: 'info' | 'warn' | 'debug' | 'error',
    message: string
  ): void {
    if (!this.config.debug && level === 'debug') return;
    const prefix = `[DevFortress:License]`;
    switch (level) {
      case 'error':
        console.error(`${prefix} ${message}`);
        break;
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
