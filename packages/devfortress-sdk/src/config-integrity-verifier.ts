/**
 * DevFortress SDK — A9: Config Integrity Verifier
 *
 * Generates HMAC-SHA256 of SDK configuration at initialization and
 * periodically verifies integrity during runtime. Detects tampered
 * thresholds, disabled features, or injected configuration.
 *
 * Patent Pending.
 * @packageDocumentation
 */

import crypto from 'crypto';

export interface ConfigIntegrityConfig {
  /** Verification interval in ms. Default: 60_000 (1 min) */
  verifyIntervalMs?: number;
  /** HMAC secret (derived from API key if not provided) */
  hmacSecret?: string;
  /** Callback on integrity violation */
  onViolation?: (violation: ConfigViolation) => void;
  debug?: boolean;
}

export interface ConfigViolation {
  field: string;
  expected: string;
  actual: string;
  severity: 'HIGH' | 'CRITICAL';
  timestamp: number;
  reason: string;
}

export interface ConfigIntegrityResult {
  valid: boolean;
  violations: ConfigViolation[];
  lastVerified: number;
  checkCount: number;
}

export class ConfigIntegrityVerifier {
  private readonly hmacSecret: string;
  private readonly config: Required<ConfigIntegrityConfig>;
  private originalHash: string = '';
  private originalSnapshot: Record<string, unknown> = {};
  private verifyTimer: ReturnType<typeof setInterval> | null = null;
  private checkCount = 0;
  private lastVerified = 0;
  private violations: ConfigViolation[] = [];

  constructor(config: ConfigIntegrityConfig = {}) {
    this.hmacSecret =
      config.hmacSecret ?? crypto.randomBytes(32).toString('hex');
    this.config = {
      verifyIntervalMs: config.verifyIntervalMs ?? 60_000,
      hmacSecret: this.hmacSecret,
      onViolation: config.onViolation ?? (() => {}),
      debug: config.debug ?? false,
    };
  }

  /**
   * Seal the SDK configuration. Call once at initialization.
   * Returns the HMAC digest of the sealed config.
   */
  seal(sdkConfig: Record<string, unknown>): string {
    // Create deterministic snapshot
    this.originalSnapshot = this.deepClone(sdkConfig);
    this.originalHash = this.computeHMAC(this.originalSnapshot);
    this.lastVerified = Date.now();
    this.checkCount = 0;
    this.violations = [];

    // Start periodic verification
    if (this.verifyTimer) clearInterval(this.verifyTimer);
    this.verifyTimer = setInterval(
      () => this.verify(sdkConfig),
      this.config.verifyIntervalMs
    );
    if (this.verifyTimer.unref) this.verifyTimer.unref();

    if (this.config.debug) {
      console.log(
        `[ConfigIntegrity] Sealed config: ${this.originalHash.substring(0, 16)}...`
      );
    }

    return this.originalHash;
  }

  /**
   * Manually verify configuration integrity.
   */
  verify(currentConfig: Record<string, unknown>): ConfigIntegrityResult {
    this.checkCount++;
    this.lastVerified = Date.now();

    const currentHash = this.computeHMAC(currentConfig);
    const valid = currentHash === this.originalHash;

    if (!valid) {
      // Find specific violations
      const newViolations = this.findViolations(
        this.originalSnapshot,
        currentConfig
      );
      this.violations.push(...newViolations);

      newViolations.forEach(v => this.config.onViolation(v));

      if (this.config.debug) {
        console.log(
          `[ConfigIntegrity] VIOLATION: ${newViolations.length} changes detected`
        );
      }
    }

    return {
      valid,
      violations: this.violations,
      lastVerified: this.lastVerified,
      checkCount: this.checkCount,
    };
  }

  /**
   * Get current integrity status without re-checking.
   */
  getStatus(): ConfigIntegrityResult {
    return {
      valid: this.violations.length === 0,
      violations: [...this.violations],
      lastVerified: this.lastVerified,
      checkCount: this.checkCount,
    };
  }

  private computeHMAC(obj: Record<string, unknown>): string {
    const serialized = JSON.stringify(obj, Object.keys(obj).sort());
    return crypto
      .createHmac('sha256', this.hmacSecret)
      .update(serialized)
      .digest('hex');
  }

  private findViolations(
    original: Record<string, unknown>,
    current: Record<string, unknown>,
    prefix = ''
  ): ConfigViolation[] {
    const violations: ConfigViolation[] = [];
    const now = Date.now();

    const allKeys = new Set([
      ...Object.keys(original),
      ...Object.keys(current),
    ]);

    for (const key of allKeys) {
      const field = prefix ? `${prefix}.${key}` : key;
      const origVal = original[key];
      const currVal = current[key];

      if (origVal === currVal) continue;

      // Critical fields that affect security posture
      const criticalFields = [
        'mode',
        'failClosed',
        'tier',
        'apiKey',
        'blockThreshold',
        'rateLimitMax',
        'rateLimitWindowMs',
      ];
      const severity = criticalFields.some(f => field.includes(f))
        ? 'CRITICAL'
        : 'HIGH';

      if (
        typeof origVal === 'object' &&
        origVal !== null &&
        typeof currVal === 'object' &&
        currVal !== null &&
        !Array.isArray(origVal)
      ) {
        // Recurse into nested objects
        violations.push(
          ...this.findViolations(
            origVal as Record<string, unknown>,
            currVal as Record<string, unknown>,
            field
          )
        );
      } else if (JSON.stringify(origVal) !== JSON.stringify(currVal)) {
        violations.push({
          field,
          expected: String(origVal),
          actual: String(currVal),
          severity,
          timestamp: now,
          reason: `Config field '${field}' changed from '${origVal}' to '${currVal}'`,
        });
      }
    }

    return violations;
  }

  private deepClone(obj: Record<string, unknown>): Record<string, unknown> {
    return JSON.parse(JSON.stringify(obj));
  }

  destroy(): void {
    if (this.verifyTimer) {
      clearInterval(this.verifyTimer);
      this.verifyTimer = null;
    }
  }
}
