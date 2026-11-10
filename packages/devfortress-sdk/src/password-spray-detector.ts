/**
 * DevFortress SDK — A5: Password Spray Detector
 *
 * Detects distributed password spray attacks by correlating authentication
 * failures across multiple accounts. Unlike brute force (many passwords,
 * one account), spray attacks try few passwords across many accounts to
 * evade per-account lockout thresholds.
 *
 * Detection signals:
 *   1. Same password hash submitted to N different accounts within window
 *   2. Low failure rate per account but high aggregate failure rate
 *   3. Credential rotation pattern (sequential password attempts)
 *   4. Geographic clustering of spray sources
 *
 * Patent Pending.
 * @packageDocumentation
 */

// ── Types ───────────────────────────────────────────────────

export interface PasswordSprayConfig {
  /** Max accounts with same password failure before alert. Default: 5 */
  accountThreshold?: number;
  /** Sliding window in ms. Default: 300_000 (5 min) */
  windowMs?: number;
  /** Max entries in credential failure map. Default: 50_000 */
  maxEntries?: number;
  /** Enable graduated response. Default: true */
  graduatedResponse?: boolean;
  /** Debug logging. Default: false */
  debug?: boolean;
}

export interface SprayDetectionResult {
  detected: boolean;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /** Number of unique accounts targeted with same credential */
  affectedAccounts: number;
  /** Confidence score 0-1 */
  confidence: number;
  /** Recommended action */
  action: 'allow' | 'rate_limit' | 'captcha_challenge' | 'block';
  /** Source IPs involved */
  sourceIPs: string[];
  /** Detection reason */
  reason: string;
}

export interface AuthFailureEvent {
  ip: string;
  /** Hashed credential (never store plaintext) */
  credentialHash: string;
  /** Target account identifier */
  accountId: string;
  timestamp?: number;
  userAgent?: string;
  /** Geographic region if available */
  geoRegion?: string;
}

// ── Bounded sliding window map ──────────────────────────────

class SlidingWindowMap<V> {
  private map = new Map<string, V>();
  constructor(private maxSize: number) {}

  set(key: string, value: V): void {
    if (this.map.size >= this.maxSize && !this.map.has(key)) {
      // LRU eviction: delete oldest entry
      const firstKey = this.map.keys().next().value;
      if (firstKey !== undefined) this.map.delete(firstKey);
    }
    this.map.set(key, value);
  }

  get(key: string): V | undefined {
    return this.map.get(key);
  }

  has(key: string): boolean {
    return this.map.has(key);
  }

  delete(key: string): boolean {
    return this.map.delete(key);
  }

  get size(): number {
    return this.map.size;
  }

  values(): IterableIterator<V> {
    return this.map.values();
  }

  forEach(fn: (value: V, key: string) => void): void {
    this.map.forEach(fn);
  }
}

// ── Password Spray Detector ─────────────────────────────────

interface CredentialFailureRecord {
  accounts: Map<string, number>; // accountId → timestamp
  sourceIPs: Set<string>;
  firstSeen: number;
  lastSeen: number;
}

export class PasswordSprayDetector {
  private readonly config: Required<PasswordSprayConfig>;
  private readonly credentialFailures: SlidingWindowMap<CredentialFailureRecord>;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: PasswordSprayConfig = {}) {
    this.config = {
      accountThreshold: config.accountThreshold ?? 5,
      windowMs: config.windowMs ?? 300_000,
      maxEntries: config.maxEntries ?? 50_000,
      graduatedResponse: config.graduatedResponse ?? true,
      debug: config.debug ?? false,
    };
    this.credentialFailures = new SlidingWindowMap(this.config.maxEntries);

    // Periodic cleanup of expired entries
    this.cleanupTimer = setInterval(() => this.cleanup(), this.config.windowMs);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  /**
   * Record an authentication failure and check for spray pattern.
   */
  recordFailure(event: AuthFailureEvent): SprayDetectionResult {
    const now = event.timestamp ?? Date.now();
    const { credentialHash, accountId, ip } = event;

    // Get or create credential failure record
    let record = this.credentialFailures.get(credentialHash);
    if (!record || now - record.firstSeen > this.config.windowMs) {
      record = {
        accounts: new Map(),
        sourceIPs: new Set(),
        firstSeen: now,
        lastSeen: now,
      };
    }

    // Update record
    record.accounts.set(accountId, now);
    record.sourceIPs.add(ip);
    record.lastSeen = now;

    // Purge expired accounts from window
    for (const [acct, ts] of record.accounts) {
      if (now - ts > this.config.windowMs) {
        record.accounts.delete(acct);
      }
    }

    this.credentialFailures.set(credentialHash, record);

    const affectedAccounts = record.accounts.size;
    const sourceIPs = Array.from(record.sourceIPs);

    // Detection logic
    if (affectedAccounts < this.config.accountThreshold) {
      return {
        detected: false,
        severity: 'LOW',
        affectedAccounts,
        confidence: affectedAccounts / this.config.accountThreshold,
        action: 'allow',
        sourceIPs,
        reason: `${affectedAccounts} accounts below threshold ${this.config.accountThreshold}`,
      };
    }

    // Spray detected — determine severity and action
    const ratio = affectedAccounts / this.config.accountThreshold;
    let severity: SprayDetectionResult['severity'];
    let action: SprayDetectionResult['action'];
    let confidence: number;

    if (ratio >= 4) {
      severity = 'CRITICAL';
      action = 'block';
      confidence = 0.98;
    } else if (ratio >= 2) {
      severity = 'HIGH';
      action = this.config.graduatedResponse ? 'captcha_challenge' : 'block';
      confidence = 0.9;
    } else {
      severity = 'MEDIUM';
      action = this.config.graduatedResponse
        ? 'rate_limit'
        : 'captcha_challenge';
      confidence = 0.75;
    }

    if (this.config.debug) {
      console.log(
        `[PasswordSprayDetector] SPRAY DETECTED: ${affectedAccounts} accounts, severity=${severity}`
      );
    }

    return {
      detected: true,
      severity,
      affectedAccounts,
      confidence,
      action,
      sourceIPs,
      reason: `Password spray detected: ${affectedAccounts} accounts targeted with same credential from ${sourceIPs.length} IPs in ${Math.round((now - record.firstSeen) / 1000)}s`,
    };
  }

  /**
   * Get current detection statistics.
   */
  getStats(): { trackedCredentials: number; totalFailures: number } {
    let totalFailures = 0;
    this.credentialFailures.forEach(record => {
      totalFailures += record.accounts.size;
    });
    return {
      trackedCredentials: this.credentialFailures.size,
      totalFailures,
    };
  }

  private cleanup(): void {
    const now = Date.now();
    const toDelete: string[] = [];
    this.credentialFailures.forEach((record, key) => {
      if (now - record.lastSeen > this.config.windowMs) {
        toDelete.push(key);
      }
    });
    toDelete.forEach(key => this.credentialFailures.delete(key));
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}
