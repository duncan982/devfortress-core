/**
 * DevFortress SDK — Webhook Nonce Registry
 *
 * Prevents webhook replay attacks by maintaining a time-bounded registry
 * of recently processed nonces:
 *
 *   Registry size cap with LRU eviction (100K entries max)
 *   Clock skew tolerance (configurable, default 30s)
 *   Nonce format validation (/^[0-9a-f]{32}$/)
 *   Registry monitoring/metrics
 *
 * The nonce registry TTL is 2× the timestamp validation window (10 minutes),
 * creating overlapping protection with no gap:
 *   - Nonce registry protects the 0–10 minute window
 *   - Timestamp validation protects the 5+ minute window
 *
 * @packageDocumentation
 */

// ── Configuration ───────────────────────────────────────────

export interface NonceRegistryConfig {
  /** Maximum nonces to store. Default: 100_000 */
  maxEntries?: number;
  /** Nonce TTL in milliseconds. Default: 600_000 (10 minutes = 2× timestamp window) */
  ttlMs?: number;
  /** Clock skew tolerance in milliseconds. Default: 30_000 (30 seconds) */
  clockSkewToleranceMs?: number;
  /** Enable metrics collection. Default: true */
  enableMetrics?: boolean;
}

// ── Metrics ─────────────────────────────────────────────────

export interface NonceRegistryMetrics {
  /** Current number of nonces in registry */
  registrySize: number;
  /** Total replay attempts detected (nonce already seen) */
  replayDetections: number;
  /** Total nonces successfully registered */
  totalRegistered: number;
  /** Total nonces rejected for format violations */
  formatRejections: number;
  /** Total nonces evicted due to TTL expiry */
  ttlEvictions: number;
  /** Total nonces evicted due to size cap */
  capEvictions: number;
  /** Registry utilisation (size / maxEntries) */
  utilisation: number;
}

// ── Nonce Validation Result ─────────────────────────────────

export type NonceValidationResult =
  | { valid: true }
  | { valid: false; reason: 'replay_detected' | 'format_invalid' | 'missing' };

// ── Nonce Registry Entry ────────────────────────────────────

interface NonceEntry {
  /** When the nonce was first seen */
  registeredAt: number;
}

// ── Valid nonce pattern: exactly 32 lowercase hex characters ─

const NONCE_PATTERN = /^[0-9a-f]{32}$/;

// ── Nonce Registry Implementation ───────────────────────────

export class WebhookNonceRegistry {
  private readonly registry = new Map<string, NonceEntry>();
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly clockSkewToleranceMs: number;
  private readonly enableMetrics: boolean;

  // Metrics counters
  private _replayDetections = 0;
  private _totalRegistered = 0;
  private _formatRejections = 0;
  private _ttlEvictions = 0;
  private _capEvictions = 0;

  // Cleanup interval
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: NonceRegistryConfig = {}) {
    this.maxEntries = config.maxEntries ?? 100_000;
    this.ttlMs = config.ttlMs ?? 10 * 60 * 1000; // 10 minutes
    this.clockSkewToleranceMs = config.clockSkewToleranceMs ?? 30_000; // 30 seconds
    this.enableMetrics = config.enableMetrics ?? true;

    // Schedule periodic cleanup every 60 seconds
    this.cleanupTimer = setInterval(() => this.evictExpired(), 60_000);
    // Allow Node.js to exit even if timer is running
    if (this.cleanupTimer && typeof this.cleanupTimer.unref === 'function') {
      this.cleanupTimer.unref();
    }
  }

  // ── Core API ────────────────────────────────────────────

  /**
   * Validate a nonce format without registering it.
   * Returns true if the nonce matches the expected 32-char hex format.
   */
  isValidFormat(nonce: string | undefined | null): boolean {
    if (!nonce) return false;
    return NONCE_PATTERN.test(nonce);
  }

  /**
   * Check and register a nonce atomically.
   *
   * Flow:
   * 1. Validate format
   * 2. Check if nonce already exists (replay detection)
   * 3. Register nonce with TTL
   * 4. Enforce size cap with eviction
   *
   * @returns NonceValidationResult indicating validity and rejection reason
   */
  validateAndRegister(nonce: string | undefined | null): NonceValidationResult {
    // Format validation
    if (!nonce) {
      if (this.enableMetrics) this._formatRejections++;
      return { valid: false, reason: 'missing' };
    }

    if (!NONCE_PATTERN.test(nonce)) {
      if (this.enableMetrics) this._formatRejections++;
      return { valid: false, reason: 'format_invalid' };
    }

    const now = Date.now();

    // Check if nonce already exists and is not expired
    const existing = this.registry.get(nonce);
    if (existing) {
      if (now - existing.registeredAt < this.ttlMs) {
        // Nonce is still within TTL — this is a replay
        if (this.enableMetrics) this._replayDetections++;
        return { valid: false, reason: 'replay_detected' };
      }
      // Nonce exists but expired — remove and allow re-registration
      this.registry.delete(nonce);
      if (this.enableMetrics) this._ttlEvictions++;
    }

    // Enforce size cap before registering
    if (this.registry.size >= this.maxEntries) {
      this.evictOldest();
    }

    // Register the nonce
    this.registry.set(nonce, { registeredAt: now });
    if (this.enableMetrics) this._totalRegistered++;

    return { valid: true };
  }

  /**
   * Get the effective timestamp validation window accounting for clock skew.
   * Returns the max age + clock skew tolerance.
   */
  getEffectiveMaxAge(baseMaxAgeMs: number): number {
    return baseMaxAgeMs + this.clockSkewToleranceMs;
  }

  // ── Metrics ─────────────────────────────────

  /**
   * Get current registry metrics for monitoring and dashboard display.
   */
  getMetrics(): NonceRegistryMetrics {
    return {
      registrySize: this.registry.size,
      replayDetections: this._replayDetections,
      totalRegistered: this._totalRegistered,
      formatRejections: this._formatRejections,
      ttlEvictions: this._ttlEvictions,
      capEvictions: this._capEvictions,
      utilisation:
        this.maxEntries > 0 ? this.registry.size / this.maxEntries : 0,
    };
  }

  /**
   * Reset metrics counters (useful for periodic reporting).
   */
  resetMetrics(): void {
    this._replayDetections = 0;
    this._totalRegistered = 0;
    this._formatRejections = 0;
    this._ttlEvictions = 0;
    this._capEvictions = 0;
  }

  // ── Internal ────────────────────────────────────────────

  /**
   * Evict all nonces that have exceeded their TTL.
   */
  private evictExpired(): void {
    const now = Date.now();
    const cutoff = now - this.ttlMs;

    for (const [nonce, entry] of this.registry) {
      if (entry.registeredAt < cutoff) {
        this.registry.delete(nonce);
        if (this.enableMetrics) this._ttlEvictions++;
      }
    }
  }

  /**
   * Evict the oldest entry when the registry hits the size cap.
   * Uses FIFO eviction (Map maintains insertion order).
   */
  private evictOldest(): void {
    const first = this.registry.keys().next().value;
    if (first !== undefined) {
      this.registry.delete(first);
      if (this.enableMetrics) this._capEvictions++;
    }
  }

  /**
   * Clear the entire registry and stop cleanup timer.
   * Call this when shutting down the SDK.
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.registry.clear();
  }

  /**
   * Get the current size of the registry (for testing).
   */
  get size(): number {
    return this.registry.size;
  }
}
