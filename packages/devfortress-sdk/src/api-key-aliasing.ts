/**
 *
 * Provides alias lifecycle management for API keys: create, rotate,
 * revoke, inspect, and audit. Each alias is scoped to a workload
 * (CI, agent, browser, server) with fingerprint and scope binding.
 *
 * Key features:
 *   - Per-integration alias families (CI, agents, plugins, browser, server)
 *   - Fingerprint-bound alias enforcement
 *   - Selective alias revocation without primary key rotation
 *   - Zero-downtime rotation with overlap window
 *   - Anomaly detection for alias misuse patterns
 *
 * Forward-map storage uses the shared credential-vault primitive
 * (../credential-vault.ts) — real AES-256-GCM, not the HMAC-SHA256
 * placeholder this file used to carry. HMAC is one-way and cannot be
 * decrypted back to a credential; AES-256-GCM is required for resolve()
 * (below) to work at all.
 *
 *
 * @packageDocumentation
 */

import crypto from 'crypto';
import {
  encrypt,
  decrypt,
  deriveVaultKey,
  type VaultEncryptedRecord,
} from './credential-vault';

// ── Types ───────────────────────────────────────────────────

export type AliasWorkload =
  | 'ci'
  | 'agent'
  | 'plugin'
  | 'browser'
  | 'server'
  | 'custom';
export type AliasState = 'active' | 'rotating' | 'revoked' | 'expired';

export interface AliasConfig {
  /** Max aliases per primary key. Default: 50 */
  maxAliasesPerKey?: number;
  /** Alias rotation overlap window in ms. Default: 300_000 (5 min) */
  rotationOverlapMs?: number;
  /** Max tracked primary keys. Default: 10_000 */
  maxPrimaryKeys?: number;
  /** Enable anomaly detection. Default: true */
  anomalyDetection?: boolean;
  /** Alias creation burst threshold per hour. Default: 10 */
  creationBurstThreshold?: number;
  /**
   * Application secret used to derive the forward-map's AES-256-GCM vault
   * key (HKDF, see credential-vault.ts). If omitted, a random per-instance
   * key is generated at construction time — alias keys remain resolvable
   * for the lifetime of this service instance, but not across process
   * restarts. Provide this for resolve() to keep working across restarts.
   */
  vaultSecret?: string;
  debug?: boolean;
}

export interface AliasRecord {
  aliasId: string;
  aliasKey: string; // The alias API key (encrypted in storage)
  primaryKeyHash: string;
  workload: AliasWorkload;
  label: string;
  state: AliasState;
  fingerprint?: string;
  scope?: string[];
  createdAt: number;
  expiresAt?: number;
  lastUsedAt: number;
  rotatedFromId?: string;
  rotatedToId?: string;
  usageCount: number;
}

export interface AliasAuditEvent {
  type:
    | 'alias_created'
    | 'alias_rotated'
    | 'alias_revoked'
    | 'alias_misuse_detected'
    | 'alias_expired'
    | 'alias_used';
  aliasId: string;
  primaryKeyHash: string;
  workload: AliasWorkload;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface AliasCreationResult {
  success: boolean;
  alias?: AliasRecord;
  aliasKey?: string; // Only returned on creation
  error?: string;
}

export interface AliasRotationResult {
  success: boolean;
  oldAliasId?: string;
  newAlias?: AliasRecord;
  newAliasKey?: string;
  overlapExpiresAt?: number;
  error?: string;
}

export interface AliasValidationResult {
  valid: boolean;
  aliasId?: string;
  workload?: AliasWorkload;
  primaryKeyHash?: string;
  reason: string;
  anomalyDetected?: boolean;
}

export interface AliasStats {
  totalAliases: number;
  activeAliases: number;
  rotatingAliases: number;
  revokedAliases: number;
  byWorkload: Record<AliasWorkload, number>;
  recentAnomalies: number;
}

/**
 * Patent Pending — KIPI KE/P/2026/005972
 * Prior art: https://www.tdcommons.org/dpubs_series/9907/
 */
export class APIKeyAliasingService {
  private readonly config: Required<AliasConfig>;
  private readonly aliases = new Map<string, AliasRecord>(); // aliasId → record
  private readonly aliasKeyIndex = new Map<string, string>(); // aliasKeyHash → aliasId
  private readonly primaryKeyAliases = new Map<string, Set<string>>(); // primaryKeyHash → Set<aliasId>
  private readonly auditLog: AliasAuditEvent[] = [];
  private readonly creationTimestamps: number[] = [];
  private readonly vaultKey: Buffer;

  constructor(config: AliasConfig = {}) {
    this.config = {
      maxAliasesPerKey: config.maxAliasesPerKey ?? 50,
      rotationOverlapMs: config.rotationOverlapMs ?? 300_000,
      maxPrimaryKeys: config.maxPrimaryKeys ?? 10_000,
      anomalyDetection: config.anomalyDetection ?? true,
      creationBurstThreshold: config.creationBurstThreshold ?? 10,
      vaultSecret: config.vaultSecret ?? '',
      debug: config.debug ?? false,
    };
    this.vaultKey = config.vaultSecret
      ? deriveVaultKey(config.vaultSecret, 'api-key-aliasing')
      : crypto.randomBytes(32);
  }

  /**
   * Create a new alias for a primary API key.
   */
  createAlias(
    primaryKeyHash: string,
    workload: AliasWorkload,
    label: string,
    options?: { fingerprint?: string; scope?: string[]; expiresInMs?: number }
  ): AliasCreationResult {
    const now = Date.now();

    // Check max aliases per key
    const existing = this.primaryKeyAliases.get(primaryKeyHash);
    if (existing && existing.size >= this.config.maxAliasesPerKey) {
      return {
        success: false,
        error: `Maximum aliases (${this.config.maxAliasesPerKey}) reached for this key`,
      };
    }

    // Anomaly: creation burst detection
    if (this.config.anomalyDetection) {
      this.creationTimestamps.push(now);
      const recentCreations = this.creationTimestamps.filter(
        t => now - t <= 3_600_000
      );
      if (recentCreations.length > this.config.creationBurstThreshold) {
        this.emitAudit({
          type: 'alias_misuse_detected',
          aliasId: 'N/A',
          primaryKeyHash,
          workload,
          timestamp: now,
          metadata: { reason: 'creation_burst', count: recentCreations.length },
        });
        return {
          success: false,
          error: `Alias creation burst detected: ${recentCreations.length} in 1 hour`,
        };
      }
    }

    // Generate alias
    const aliasId = `alias_${crypto.randomBytes(16).toString('hex')}`;
    const aliasKey = `vx_alias_${crypto.randomBytes(24).toString('hex')}`;
    const aliasKeyHash = crypto
      .createHash('sha256')
      .update(aliasKey)
      .digest('hex');

    const record: AliasRecord = {
      aliasId,
      aliasKey: this.encryptAliasKey(aliasKey, primaryKeyHash),
      primaryKeyHash,
      workload,
      label,
      state: 'active',
      fingerprint: options?.fingerprint,
      scope: options?.scope,
      createdAt: now,
      expiresAt: options?.expiresInMs ? now + options.expiresInMs : undefined,
      lastUsedAt: now,
      usageCount: 0,
    };

    // Store
    this.aliases.set(aliasId, record);
    this.aliasKeyIndex.set(aliasKeyHash, aliasId);
    if (!this.primaryKeyAliases.has(primaryKeyHash)) {
      this.primaryKeyAliases.set(primaryKeyHash, new Set());
    }
    this.primaryKeyAliases.get(primaryKeyHash)!.add(aliasId);

    this.emitAudit({
      type: 'alias_created',
      aliasId,
      primaryKeyHash,
      workload,
      timestamp: now,
      metadata: {
        label,
        hasFingerprint: !!options?.fingerprint,
        scope: options?.scope,
      },
    });

    return {
      success: true,
      alias: { ...record, aliasKey: '[REDACTED]' },
      aliasKey,
    };
  }

  /**
   * Rotate an alias with zero-downtime overlap window.
   */
  rotateAlias(aliasId: string): AliasRotationResult {
    const now = Date.now();
    const oldAlias = this.aliases.get(aliasId);
    if (!oldAlias || oldAlias.state !== 'active') {
      return {
        success: false,
        error: `Alias ${aliasId} not found or not active`,
      };
    }

    // Mark old alias as rotating (grace period)
    oldAlias.state = 'rotating';
    oldAlias.expiresAt = now + this.config.rotationOverlapMs;

    // Create new alias with same properties
    const result = this.createAlias(
      oldAlias.primaryKeyHash,
      oldAlias.workload,
      `${oldAlias.label} (rotated)`,
      { fingerprint: oldAlias.fingerprint, scope: oldAlias.scope }
    );

    if (!result.success || !result.alias) {
      oldAlias.state = 'active'; // Rollback
      return { success: false, error: result.error };
    }

    // Link lineage
    oldAlias.rotatedToId = result.alias.aliasId;
    result.alias.rotatedFromId = aliasId;

    this.emitAudit({
      type: 'alias_rotated',
      aliasId,
      primaryKeyHash: oldAlias.primaryKeyHash,
      workload: oldAlias.workload,
      timestamp: now,
      metadata: {
        newAliasId: result.alias.aliasId,
        overlapMs: this.config.rotationOverlapMs,
      },
    });

    return {
      success: true,
      oldAliasId: aliasId,
      newAlias: result.alias,
      newAliasKey: result.aliasKey,
      overlapExpiresAt: oldAlias.expiresAt,
    };
  }

  /**
   * Revoke a specific alias without affecting other aliases.
   */
  revokeAlias(aliasId: string, reason?: string): boolean {
    const alias = this.aliases.get(aliasId);
    if (!alias) return false;

    alias.state = 'revoked';

    this.emitAudit({
      type: 'alias_revoked',
      aliasId,
      primaryKeyHash: alias.primaryKeyHash,
      workload: alias.workload,
      timestamp: Date.now(),
      metadata: { reason: reason ?? 'manual_revocation' },
    });

    return true;
  }

  /**
   * Validate an alias key for incoming requests.
   */
  validateAliasKey(
    aliasKey: string,
    fingerprint?: string
  ): AliasValidationResult {
    const aliasKeyHash = crypto
      .createHash('sha256')
      .update(aliasKey)
      .digest('hex');
    const aliasId = this.aliasKeyIndex.get(aliasKeyHash);

    if (!aliasId) {
      return { valid: false, reason: 'Unknown alias key' };
    }

    const alias = this.aliases.get(aliasId);
    if (!alias) {
      return { valid: false, reason: 'Alias record not found' };
    }

    const now = Date.now();

    // Check state
    if (alias.state === 'revoked') {
      return {
        valid: false,
        aliasId,
        workload: alias.workload,
        reason: 'Alias has been revoked',
      };
    }

    // Check expiry (for rotating aliases)
    if (alias.expiresAt && now > alias.expiresAt) {
      alias.state = 'expired';
      this.emitAudit({
        type: 'alias_expired',
        aliasId,
        primaryKeyHash: alias.primaryKeyHash,
        workload: alias.workload,
        timestamp: now,
      });
      return {
        valid: false,
        aliasId,
        workload: alias.workload,
        reason: 'Alias has expired',
      };
    }

    // Fingerprint check
    let anomalyDetected = false;
    if (alias.fingerprint && fingerprint && alias.fingerprint !== fingerprint) {
      anomalyDetected = true;
      this.emitAudit({
        type: 'alias_misuse_detected',
        aliasId,
        primaryKeyHash: alias.primaryKeyHash,
        workload: alias.workload,
        timestamp: now,
        metadata: {
          reason: 'fingerprint_mismatch',
          expectedFingerprint: alias.fingerprint.substring(0, 8),
        },
      });
    }

    // Update usage
    alias.lastUsedAt = now;
    alias.usageCount++;

    this.emitAudit({
      type: 'alias_used',
      aliasId,
      primaryKeyHash: alias.primaryKeyHash,
      workload: alias.workload,
      timestamp: now,
    });

    return {
      valid: !anomalyDetected,
      aliasId,
      workload: alias.workload,
      primaryKeyHash: alias.primaryKeyHash,
      reason: anomalyDetected ? 'Fingerprint mismatch detected' : 'Valid alias',
      anomalyDetected,
    };
  }

  /**
   * List all aliases for a primary key.
   */
  listAliases(primaryKeyHash: string): AliasRecord[] {
    const aliasIds = this.primaryKeyAliases.get(primaryKeyHash);
    if (!aliasIds) return [];

    return Array.from(aliasIds)
      .map(id => this.aliases.get(id))
      .filter((a): a is AliasRecord => !!a)
      .map(a => ({ ...a, aliasKey: '[REDACTED]' }));
  }

  /**
   * Get alias statistics.
   */
  getStats(): AliasStats {
    const stats: AliasStats = {
      totalAliases: this.aliases.size,
      activeAliases: 0,
      rotatingAliases: 0,
      revokedAliases: 0,
      byWorkload: {
        ci: 0,
        agent: 0,
        plugin: 0,
        browser: 0,
        server: 0,
        custom: 0,
      },
      recentAnomalies: 0,
    };

    for (const alias of this.aliases.values()) {
      if (alias.state === 'active') stats.activeAliases++;
      else if (alias.state === 'rotating') stats.rotatingAliases++;
      else if (alias.state === 'revoked') stats.revokedAliases++;
      stats.byWorkload[alias.workload]++;
    }

    const oneHourAgo = Date.now() - 3_600_000;
    stats.recentAnomalies = this.auditLog.filter(
      e => e.type === 'alias_misuse_detected' && e.timestamp > oneHourAgo
    ).length;

    return stats;
  }

  /**
   * Get audit log entries.
   */
  getAuditLog(limit = 100): AliasAuditEvent[] {
    return this.auditLog.slice(-limit);
  }

  /**
   * AES-256-GCM encrypt the alias key for forward-map storage.
   * Returns a JSON-serialized {ciphertext, iv, authTag} bundle — genuinely
   * reversible via resolve(), unlike the HMAC-SHA256 digest this used to
   * store (HMAC is one-way and can never be decrypted back to a credential).
   */
  private encryptAliasKey(aliasKey: string, primaryKeyHash: string): string {
    const record: VaultEncryptedRecord = encrypt(
      `${primaryKeyHash}:${aliasKey}`,
      this.vaultKey
    );
    return JSON.stringify(record);
  }

  /**
   * Resolve a stored alias back to its real alias key (the core gap —
   * no function anywhere previously resolved an alias back to a credential;
   * validateAliasKey only ever checked validity). Returns null for an
   * unknown/revoked/expired alias, or if the stored ciphertext fails
   * auth-tag verification (tampered/corrupted).
   */
  resolve(aliasId: string): string | null {
    const alias = this.aliases.get(aliasId);
    if (!alias) return null;
    if (alias.state === 'revoked' || alias.state === 'expired') return null;

    let record: VaultEncryptedRecord;
    try {
      record = JSON.parse(alias.aliasKey) as VaultEncryptedRecord;
    } catch {
      return null;
    }

    try {
      const decrypted = decrypt(record, this.vaultKey);
      const separatorIndex = decrypted.indexOf(':');
      return separatorIndex === -1
        ? decrypted
        : decrypted.slice(separatorIndex + 1);
    } catch {
      // Auth-tag verification failed — do not return garbage plaintext.
      return null;
    }
  }

  private emitAudit(event: AliasAuditEvent): void {
    this.auditLog.push(event);
    // Cap audit log at 10K entries
    if (this.auditLog.length > 10_000) {
      this.auditLog.splice(0, this.auditLog.length - 10_000);
    }
    if (this.config.debug) {
      console.log(
        `[REDACTED-Alias] ${event.type}: ${event.aliasId} (${event.workload})`
      );
    }
  }
}
