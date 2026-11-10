/**
 * DevFortress SDK — Graduated Rate Limiter
 *
 * Implements alias-scoped graduated rate limiting with multi-stage
 * response escalation:
 *
 *   Latency jitter (±20%) in soft-limit injection
 *   Per-endpoint hierarchical rate limits (configurable)
 *   Burst detection (1-second micro-window)
 *   Escalating cooldowns (60s→120s→240s, revoke after 3)
 *
 * Four-stage graduated response:
 *   Stage 1: Observation (< 50% of limit)
 *   Stage 2: Warning (50%-75% of limit)
 *   Stage 3: Soft-limit with latency injection (75%-100% of limit)
 *   Stage 4: Hard-block with escalating cooldowns (≥ 100% of limit)
 *   Stage 5: Alias revocation (≥ 120% of limit or 3 consecutive blocks)
 *
 * @packageDocumentation
 */

// ── Configuration ───────────────────────────────────────────

export interface GraduatedRateLimiterConfig {
  /** Default rate limit (requests per window). Default: 100 */
  defaultLimit?: number;
  /** Sliding window size in ms. Default: 60_000 (1 minute) */
  windowMs?: number;
  /** Base latency for soft-limit injection in ms. Default: 2000 */
  softLimitBaseLatencyMs?: number;
  /** Maximum entries in the limiter. Default: 50_000 */
  maxEntries?: number;
  /** Per-endpoint rate limits. Key: endpoint path pattern, Value: max requests/window */
  endpointLimits?: Record<string, number>;
  /** Burst detection: max requests per 1-second micro-window. Default: 20 */
  burstLimit?: number;
  /** Initial cooldown duration in seconds. Default: 60 */
  initialCooldownSeconds?: number;
  /** Max consecutive hard-blocks before revocation. Default: 3 */
  maxConsecutiveBlocks?: number;
}

// ── Rate Limit Stage ────────────────────────────────────────

export type RateLimitStage =
  | 'observation'
  | 'warning'
  | 'soft_limit'
  | 'hard_block'
  | 'revocation';

// ── Rate Limit Result ───────────────────────────────────────

export interface RateLimitResult {
  /** Which stage was triggered */
  stage: RateLimitStage;
  /** Current request rate (requests in current window) */
  currentRate: number;
  /** Effective limit for this alias */
  limit: number;
  /** Ratio of current rate to limit (0.0 - 1.5+) */
  ratio: number;
  /** Injected latency in ms (0 for observation/warning, >0 for soft_limit) */
  injectedLatencyMs: number;
  /** Whether the request should be blocked */
  blocked: boolean;
  /** Whether the alias should be revoked */
  revoke: boolean;
  /** Cooldown duration in seconds (0 if not in cooldown) */
  cooldownSeconds: number;
  /** Remaining requests before next stage */
  remaining: number;
  /** Whether a burst was detected in the micro-window */
  burstDetected: boolean;
}

// ── Internal Entry ──────────────────────────────────────────

interface RateLimitEntry {
  /** Request timestamps within the window */
  timestamps: number[];
  /** Current cooldown state */
  cooldownUntil: number;
  /** Consecutive hard-block count */
  consecutiveBlocks: number;
  /** Whether this alias has been revoked */
  revoked: boolean;
  /** Burst micro-window timestamps (last 1 second) */
  burstTimestamps: number[];
}

// ── Graduated Rate Limiter Implementation ───────────────────

export class GraduatedRateLimiter {
  private readonly entries = new Map<string, RateLimitEntry>();
  private readonly config: Required<
    Omit<GraduatedRateLimiterConfig, 'endpointLimits'>
  > & { endpointLimits: Record<string, number> };

  // Cleanup interval
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: GraduatedRateLimiterConfig = {}) {
    this.config = {
      defaultLimit: config.defaultLimit ?? 100,
      windowMs: config.windowMs ?? 60_000,
      softLimitBaseLatencyMs: config.softLimitBaseLatencyMs ?? 2000,
      maxEntries: config.maxEntries ?? 50_000,
      endpointLimits: config.endpointLimits ?? {},
      burstLimit: config.burstLimit ?? 20,
      initialCooldownSeconds: config.initialCooldownSeconds ?? 60,
      maxConsecutiveBlocks: config.maxConsecutiveBlocks ?? 3,
    };

    // Periodic cleanup every 30 seconds
    this.cleanupTimer = setInterval(() => this.cleanup(), 30_000);
    if (this.cleanupTimer && typeof this.cleanupTimer.unref === 'function') {
      this.cleanupTimer.unref();
    }
  }

  // ── Core API ────────────────────────────────────────────

  /**
   * Check rate limit for an alias (identified by key, typically IP or session ID).
   * Records the request and returns the graduated response.
   *
   * @param key - Alias identifier (IP, session ID, or alias token)
   * @param endpoint - Optional endpoint path for per-endpoint limits
   */
  check(key: string, endpoint?: string): RateLimitResult {
    const now = Date.now();
    let entry = this.entries.get(key);

    if (!entry) {
      entry = {
        timestamps: [],
        cooldownUntil: 0,
        consecutiveBlocks: 0,
        revoked: false,
        burstTimestamps: [],
      };
    }

    // Check if alias has been permanently revoked
    if (entry.revoked) {
      return {
        stage: 'revocation',
        currentRate: 0,
        limit: 0,
        ratio: Infinity,
        injectedLatencyMs: 0,
        blocked: true,
        revoke: false, // already revoked
        cooldownSeconds: 0,
        remaining: 0,
        burstDetected: false,
      };
    }

    // Check if currently in cooldown
    if (entry.cooldownUntil > now) {
      const cooldownRemaining = Math.ceil((entry.cooldownUntil - now) / 1000);
      return {
        stage: 'hard_block',
        currentRate: entry.timestamps.length,
        limit: this.getLimit(endpoint),
        ratio: 1.0,
        injectedLatencyMs: 0,
        blocked: true,
        revoke: false,
        cooldownSeconds: cooldownRemaining,
        remaining: 0,
        burstDetected: false,
      };
    }

    // Clean old timestamps outside window
    const windowStart = now - this.config.windowMs;
    entry.timestamps = entry.timestamps.filter(t => t > windowStart);

    // Clean burst micro-window (1 second)
    const burstWindowStart = now - 1000;
    entry.burstTimestamps = entry.burstTimestamps.filter(
      t => t > burstWindowStart
    );

    // Record this request
    entry.timestamps.push(now);
    entry.burstTimestamps.push(now);

    // Enforce max entries
    if (!this.entries.has(key) && this.entries.size >= this.config.maxEntries) {
      this.evictOldest();
    }
    this.entries.set(key, entry);

    // Calculate rate and limit
    const limit = this.getLimit(endpoint);
    const currentRate = entry.timestamps.length;
    const ratio = currentRate / limit;

    // Burst detection
    const burstDetected = entry.burstTimestamps.length > this.config.burstLimit;

    // Determine stage
    if (
      ratio >= 1.2 ||
      entry.consecutiveBlocks >= this.config.maxConsecutiveBlocks
    ) {
      // Stage 5: Revocation
      entry.revoked = true;
      this.entries.set(key, entry);
      return {
        stage: 'revocation',
        currentRate,
        limit,
        ratio,
        injectedLatencyMs: 0,
        blocked: true,
        revoke: true,
        cooldownSeconds: 0,
        remaining: 0,
        burstDetected,
      };
    }

    if (ratio >= 1.0 || burstDetected) {
      // Stage 4: Hard-block with escalating cooldown
      entry.consecutiveBlocks++;
      const cooldownMultiplier = Math.pow(2, entry.consecutiveBlocks - 1);
      const cooldownSeconds =
        this.config.initialCooldownSeconds * cooldownMultiplier;
      entry.cooldownUntil = now + cooldownSeconds * 1000;
      this.entries.set(key, entry);

      return {
        stage: 'hard_block',
        currentRate,
        limit,
        ratio,
        injectedLatencyMs: 0,
        blocked: true,
        revoke: false,
        cooldownSeconds,
        remaining: 0,
        burstDetected,
      };
    }

    if (ratio >= 0.75) {
      // Stage 3: Soft-limit with latency injection + jitter
      // Reset consecutive blocks when in soft-limit (not hitting hard block)
      entry.consecutiveBlocks = 0;

      const progress = (ratio - 0.75) / 0.25; // 0.0 at 75%, 1.0 at 100%
      const baseLatency =
        this.config.softLimitBaseLatencyMs * Math.pow(progress, 2);
      // Add ±20% random jitter
      const jitter = 0.8 + 0.4 * Math.random();
      const injectedLatencyMs = Math.round(baseLatency * jitter);

      return {
        stage: 'soft_limit',
        currentRate,
        limit,
        ratio,
        injectedLatencyMs,
        blocked: false,
        revoke: false,
        cooldownSeconds: 0,
        remaining: Math.max(0, limit - currentRate),
        burstDetected,
      };
    }

    if (ratio >= 0.5) {
      // Stage 2: Warning
      entry.consecutiveBlocks = 0;
      return {
        stage: 'warning',
        currentRate,
        limit,
        ratio,
        injectedLatencyMs: 0,
        blocked: false,
        revoke: false,
        cooldownSeconds: 0,
        remaining: Math.max(0, limit - currentRate),
        burstDetected: false,
      };
    }

    // Stage 1: Observation
    entry.consecutiveBlocks = 0;
    return {
      stage: 'observation',
      currentRate,
      limit,
      ratio,
      injectedLatencyMs: 0,
      blocked: false,
      revoke: false,
      cooldownSeconds: 0,
      remaining: Math.max(0, limit - currentRate),
      burstDetected: false,
    };
  }

  /**
   * Manually revoke an alias (e.g., from external security decision).
   */
  revokeAlias(key: string): void {
    let entry = this.entries.get(key);
    if (!entry) {
      entry = {
        timestamps: [],
        cooldownUntil: 0,
        consecutiveBlocks: 0,
        revoked: true,
        burstTimestamps: [],
      };
    } else {
      entry.revoked = true;
    }
    this.entries.set(key, entry);
  }

  /**
   * Reset an alias's rate limit state (e.g., after admin override).
   */
  resetAlias(key: string): void {
    this.entries.delete(key);
  }

  /**
   * Check if an alias has been revoked.
   */
  isRevoked(key: string): boolean {
    return this.entries.get(key)?.revoked ?? false;
  }

  // ── Per-Endpoint Limits ─────────────────────

  /**
   * Set per-endpoint rate limits.
   * @param limits - Map of endpoint path patterns to max requests/window
   */
  setEndpointLimits(limits: Record<string, number>): void {
    Object.assign(this.config.endpointLimits, limits);
  }

  /**
   * Get the effective limit for an endpoint.
   * Returns the most specific matching endpoint limit, or the default.
   */
  private getLimit(endpoint?: string): number {
    if (!endpoint || Object.keys(this.config.endpointLimits).length === 0) {
      return this.config.defaultLimit;
    }

    // Check exact match first
    if (this.config.endpointLimits[endpoint] !== undefined) {
      return this.config.endpointLimits[endpoint];
    }

    // Check prefix match (e.g., /api/auth/* matches /api/auth/login)
    for (const [pattern, limit] of Object.entries(this.config.endpointLimits)) {
      if (pattern.endsWith('*') && endpoint.startsWith(pattern.slice(0, -1))) {
        return limit;
      }
    }

    return this.config.defaultLimit;
  }

  // ── Internal ────────────────────────────────────────────

  private evictOldest(): void {
    const first = this.entries.keys().next().value;
    if (first !== undefined) {
      this.entries.delete(first);
    }
  }

  private cleanup(): void {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    for (const [key, entry] of this.entries) {
      // Remove entries with no recent activity and not in cooldown
      const hasRecentActivity = entry.timestamps.some(t => t > windowStart);
      const inCooldown = entry.cooldownUntil > now;
      const isRevoked = entry.revoked;

      if (!hasRecentActivity && !inCooldown && !isRevoked) {
        this.entries.delete(key);
      }
    }
  }

  /**
   * Destroy the limiter and stop cleanup timer.
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.entries.clear();
  }

  /**
   * Get the current number of tracked aliases.
   */
  get size(): number {
    return this.entries.size;
  }
}
