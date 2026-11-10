/**
 * Credential Isolation Security — Session Indirection (Hardened)
 *
 * Replaces real session tokens with opaque, random aliases before
 * they leave the client app's trust boundary. DevFortress only ever
 * sees the alias — never the real token.
 *
 * Uses CSPRNG — the alias has no mathematical relationship to the real token.
 *
 * Security hardening (IP-M3 through IP-M7, IP-S5):
 * - AES-256-GCM encryption of forward mapping values (IP-M3)
 * - SHA-256 hashed reverse mapping keys (IP-M4)
 * - SubjectId-level fallback revocation on cache failure (IP-M5)
 * - Local emergency blocklist (IP-M6) — synchronous, pre-webhook
 * - Alias rotation grace period (IP-M7) — old aliases remain resolvable
 * - In-memory LRU fallback cache (IP-S5) — survives Redis outages
 *
 * For production use with Redis, implement the CacheAdapter interface.
 * Falls back to in-memory storage for development/testing.
 */

import crypto from 'crypto';
import type { IsolatedCredentialData } from './types';

// ── Cache Adapter Interface ─────────────────────────────────

export interface CacheAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  del(key: string): Promise<void>;
}

// ── Credential Isolation Manager Configuration ─────────────

export interface CredentialIsolationManagerConfig {
  /** AES-256-GCM encryption key for forward mapping values (32-byte hex string).
   *  Set via DEVFORTRESS_REDIS_ENCRYPTION_KEY env var. */
  encryptionKey?: string;
  /** Maximum number of recent aliases to hold in the LRU fallback cache. Default: 1000 */
  lruMaxEntries?: number;
  /** TTL in seconds for LRU cache entries. Default: 60 */
  lruTtlSeconds?: number;
  /** Grace period (seconds) for old aliases during rotation. Default: 1200 (20 min) */
  rotationGracePeriodSeconds?: number;
  /** Callback invoked on fallback revocation (IP-M5).
   *  Receives the subjectId so the app can do broad session deletion. */
  onFallbackRevocation?: (
    subjectId: string,
    reason: string
  ) => Promise<void> | void;
}

// ── AES-256-GCM Encryption Helpers (IP-M3) ──────────────────

const ENCRYPTED_PREFIX = 'enc:v1:';

function encrypt(plaintext: string, keyHex: string): string {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return (
    ENCRYPTED_PREFIX +
    iv.toString('hex') +
    ':' +
    encrypted.toString('hex') +
    ':' +
    authTag.toString('hex')
  );
}

function decrypt(ciphertext: string, keyHex: string): string {
  if (!ciphertext.startsWith(ENCRYPTED_PREFIX)) {
    // Legacy unencrypted format — return as-is (rolling migration)
    return ciphertext;
  }
  const parts = ciphertext.slice(ENCRYPTED_PREFIX.length).split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted format');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = Buffer.from(parts[1], 'hex');
  const authTag = Buffer.from(parts[2], 'hex');
  const key = Buffer.from(keyHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString(
    'utf8'
  );
}

// ── SHA-256 Hashing for Reverse Mapping Key (IP-M4) ─────────

function hashToken(realToken: string): string {
  return crypto.createHash('sha256').update(realToken).digest('hex');
}

// ── In-Memory LRU Cache (IP-S5) — Fallback for Redis ───────

class LRUCache {
  private maxEntries: number;
  private defaultTtl: number;
  private cache = new Map<string, { value: string; expiresAt: number }>();

  constructor(maxEntries: number = 1000, defaultTtlSeconds: number = 60) {
    this.maxEntries = maxEntries;
    this.defaultTtl = defaultTtlSeconds;
  }

  get(key: string): string | null {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    // Move to end (most recently used)
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.value;
  }

  set(key: string, value: string, ttlSeconds?: number): void {
    // Evict oldest entry if at capacity
    if (this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) this.cache.delete(oldestKey);
    }
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + (ttlSeconds ?? this.defaultTtl) * 1000,
    });
  }

  del(key: string): void {
    this.cache.delete(key);
  }

  has(key: string): boolean {
    return this.get(key) !== null;
  }
}

// ── In-Memory Cache (development fallback) ──────────────────

const memStore = new Map<string, { value: string; expiresAt: number }>();

const memoryAdapter: CacheAdapter = {
  async get(key: string) {
    const entry = memStore.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      memStore.delete(key);
      return null;
    }
    return entry.value;
  },
  async set(key: string, value: string, ttlSeconds: number) {
    memStore.set(key, {
      value,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  },
  async del(key: string) {
    memStore.delete(key);
  },
};

// ── Emergency Blocklist (IP-M6) ─────────────────────────────

/**
 * Local emergency blocklist — synchronous, pre-webhook IP blocking.
 * When a critical event fires, the IP is written here BEFORE the webhook
 * is sent, ensuring the IP is blocked even if the webhook receiver is down.
 */
export class ThreatInterceptor {
  private cache: CacheAdapter;
  private lru: LRUCache;
  /** Default TTL: 15 minutes (10 min webhook retry window + 5 min safety) */
  private defaultTtlSeconds: number;

  constructor(cache?: CacheAdapter, ttlSeconds: number = 900) {
    this.cache = cache || memoryAdapter;
    this.lru = new LRUCache(5000, ttlSeconds);
    this.defaultTtlSeconds = ttlSeconds;
  }

  /** Block an IP immediately on critical event classification. */
  async blockIP(ip: string, reason: string = 'critical_event'): Promise<void> {
    const value = JSON.stringify({ reason, blockedAt: Date.now() });
    this.lru.set(`emergency:block:${ip}`, value, this.defaultTtlSeconds);
    try {
      await this.cache.set(
        `emergency:block:${ip}`,
        value,
        this.defaultTtlSeconds
      );
    } catch {
      // LRU cache is already set — Redis failure doesn't prevent blocking
    }
  }

  /** Check if an IP is emergency-blocked. O(1) — safe for every request. */
  async isBlocked(ip: string): Promise<boolean> {
    // Check LRU first (fastest path)
    if (this.lru.has(`emergency:block:${ip}`)) return true;
    try {
      const val = await this.cache.get(`emergency:block:${ip}`);
      return val !== null;
    } catch {
      return false; // On Redis failure, LRU was already checked
    }
  }

  /** Unblock an IP (manual override). */
  async unblockIP(ip: string): Promise<void> {
    this.lru.del(`emergency:block:${ip}`);
    try {
      await this.cache.del(`emergency:block:${ip}`);
    } catch {
      // Best-effort
    }
  }
}

// ── Revocation Reason Types (IP-M7) ─────────────────────────

export type RevocationReason = 'active_threat' | 'rotation_expired' | 'logout';

// ── Credential Isolation Manager (Hardened) ────────────────

export class CredentialIsolationManager {
  private cache: CacheAdapter;
  private encryptionKey: string;
  private lru: LRUCache;
  private rotationGracePeriod: number;
  private onFallbackRevocation?: (
    subjectId: string,
    reason: string
  ) => Promise<void> | void;

  constructor(
    cacheAdapter?: CacheAdapter,
    config?: CredentialIsolationManagerConfig
  ) {
    this.cache = cacheAdapter || memoryAdapter;
    this.lru = new LRUCache(
      config?.lruMaxEntries ?? 1000,
      config?.lruTtlSeconds ?? 60
    );
    this.rotationGracePeriod = config?.rotationGracePeriodSeconds ?? 1200;
    this.onFallbackRevocation = config?.onFallbackRevocation;

    // Encryption is mandatory: credentials must never be cached in plaintext.
    // Fail loudly at construction time rather than silently no-op'ing in
    // encryptValue/decryptValue (see credential-isolation audit finding #1).
    const key =
      config?.encryptionKey ||
      process.env.DEVFORTRESS_REDIS_ENCRYPTION_KEY ||
      null;
    if (!key) {
      throw new Error(
        'DEVFORTRESS_REDIS_ENCRYPTION_KEY is required — CredentialIsolationManager ' +
          'refuses to store credentials without encryption. Set this env var to a ' +
          '32-byte hex string (64 hex characters), e.g. `openssl rand -hex 32`, or ' +
          'pass config.encryptionKey explicitly.'
      );
    }
    if (key.length !== 64) {
      throw new Error(
        'DEVFORTRESS_REDIS_ENCRYPTION_KEY must be a 32-byte hex string (64 hex characters)'
      );
    }
    this.encryptionKey = key;
  }

  // ── Internal: Encrypt/Decrypt Wrappers ──────────────────────

  private encryptValue(plaintext: string): string {
    return encrypt(plaintext, this.encryptionKey);
  }

  private decryptValue(ciphertext: string): string {
    return decrypt(ciphertext, this.encryptionKey);
  }

  // ── Internal: Cache with LRU Fallback ───────────────────────

  private async cacheGet(key: string): Promise<string | null> {
    try {
      const value = await this.cache.get(key);
      if (value !== null) {
        // Backfill LRU on successful Redis read
        this.lru.set(key, value);
        return value;
      }
    } catch {
      // Redis failure — fall back to LRU (IP-S5)
    }
    // Check LRU fallback
    return this.lru.get(key);
  }

  private async cacheSet(
    key: string,
    value: string,
    ttlSeconds: number
  ): Promise<void> {
    // Always write to LRU first (synchronous, can't fail)
    this.lru.set(key, value, ttlSeconds);
    try {
      await this.cache.set(key, value, ttlSeconds);
    } catch {
      // LRU is set — Redis failure is survivable
    }
  }

  private async cacheDel(key: string): Promise<void> {
    this.lru.del(key);
    try {
      await this.cache.del(key);
    } catch {
      // Best-effort
    }
  }

  /**
   * Generate a cryptographically random alias for a real session token.
   * The alias has NO mathematical relationship to the real token.
   *
   * IP-M3: Forward mapping value is AES-256-GCM encrypted.
   * IP-M4: Reverse mapping key uses SHA-256(realToken) instead of plaintext.
   * IP-S5: Writes to both Redis and LRU cache for fallback resilience.
   */
  async createAlias(
    realToken: string,
    userId: string,
    ttlSeconds: number = 3600
  ): Promise<string> {
    // IP-M4: Use hashed token for reverse lookup key
    const tokenHash = hashToken(realToken);

    // Check if we already have an alias for this token
    const existingAlias = await this.cacheGet(`cred:alias:${tokenHash}`);
    if (existingAlias) return existingAlias;

    // Generate random alias — NOT a hash, not derived from the token
    const alias = 'df_sid_' + crypto.randomBytes(16).toString('hex');

    const data: IsolatedCredentialData = {
      realToken,
      userId,
      createdAt: Date.now(),
    };

    // IP-M3: Encrypt the forward mapping value before storage
    const encryptedData = this.encryptValue(JSON.stringify(data));

    // Store alias → encrypted real token mapping (client-side only)
    await this.cacheSet(`alias:${alias}`, encryptedData, ttlSeconds);

    // IP-M4: Store hashed reverse lookup — SHA-256(realToken) → alias
    await this.cacheSet(`cred:alias:${tokenHash}`, alias, ttlSeconds);

    return alias;
  }

  /**
   * Resolve an alias back to the real token and user.
   * Called ONLY when a revocation webhook arrives from DevFortress.
   *
   * IP-M3: Decrypts AES-256-GCM encrypted values.
   * IP-M7: Returns data even for aliases in "rotating" status.
   * IP-S5: Falls back to LRU cache on Redis failure.
   */
  async resolveAlias(alias: string): Promise<IsolatedCredentialData | null> {
    const raw = await this.cacheGet(`alias:${alias}`);
    if (!raw) return null;
    try {
      // IP-M3: Decrypt if encrypted
      const decrypted = this.decryptValue(raw);
      const data = JSON.parse(decrypted) as IsolatedCredentialData & {
        status?: string;
        canCreateNewEvents?: boolean;
      };

      // IP-M7: Alias is valid for revocation even if rotating
      // (canCreateNewEvents may be false, but resolution still works)
      return {
        realToken: data.realToken,
        userId: data.userId,
        createdAt: data.createdAt,
      };
    } catch {
      return null;
    }
  }

  /**
   * Revoke a session by alias.
   * The real token is resolved within the client app — DevFortress
   * never touches the real token.
   *
   * IP-M5: On cache failure, falls back to subjectId-level revocation.
   * IP-M7: Records revocation_reason in audit marker.
   *
   * Returns the resolved token data so the caller can perform
   * the actual session revocation.
   */
  async revokeByAlias(
    alias: string,
    reason: RevocationReason = 'active_threat',
    subjectId?: string
  ): Promise<IsolatedCredentialData | null> {
    try {
      const resolved = await this.resolveAlias(alias);
      if (!resolved) {
        // IP-M5: If alias resolution fails and we have a subjectId, trigger fallback
        if (subjectId && this.onFallbackRevocation) {
          await this.onFallbackRevocation(
            subjectId,
            `[DF] alias resolution failed for ${alias} — falling back to subjectId revocation`
          );
        }
        return null;
      }

      // Clean up alias mappings
      const tokenHash = hashToken(resolved.realToken);
      await this.cacheDel(`alias:${alias}`);
      await this.cacheDel(`cred:alias:${tokenHash}`);

      // Mark as revoked with reason (IP-M7) so repeated webhook delivery doesn't re-process
      const revocationMarker = JSON.stringify({
        revoked: true,
        reason,
        revokedAt: Date.now(),
        revocation_scope: 'precise',
      });
      await this.cacheSet(`revoked:alias:${alias}`, revocationMarker, 86400);

      return resolved;
    } catch (error) {
      // IP-M5: Cache failure — fall back to broad subjectId revocation
      const fallbackSubject = subjectId || 'unknown';
      if (this.onFallbackRevocation) {
        await this.onFallbackRevocation(
          fallbackSubject,
          `[DF] cache error during revokeByAlias(${alias}) — falling back to subjectId revocation. Error: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      // Record broad revocation scope
      try {
        const revocationMarker = JSON.stringify({
          revoked: true,
          reason,
          revokedAt: Date.now(),
          revocation_scope: 'broad',
        });
        await this.cacheSet(`revoked:alias:${alias}`, revocationMarker, 86400);
      } catch {
        // Best-effort
      }
      return null;
    }
  }

  /**
   * Rotate alias — replaces the alias for a live session.
   * Limits the window of exposure if an alias is somehow observed in transit.
   *
   * IP-M7: Old alias is NOT deleted immediately. Instead, it gets a grace
   * period TTL and is marked with status: "rotating". The old alias remains
   * resolvable for revocation purposes, but canCreateNewEvents is set to false.
   */
  async rotateAlias(
    oldAlias: string,
    ttlSeconds: number = 3600
  ): Promise<string | null> {
    const resolved = await this.resolveAlias(oldAlias);
    if (!resolved) return null;

    // IP-M7: Mark old alias as rotating instead of deleting
    const rotatingData: IsolatedCredentialData & {
      status: string;
      canCreateNewEvents: boolean;
    } = {
      ...resolved,
      status: 'rotating',
      canCreateNewEvents: false,
    };
    const encryptedRotating = this.encryptValue(JSON.stringify(rotatingData));
    // Set TTL to grace period (default 20 min) — old alias stays resolvable
    await this.cacheSet(
      `alias:${oldAlias}`,
      encryptedRotating,
      this.rotationGracePeriod
    );

    // Clean up old reverse mapping
    const tokenHash = hashToken(resolved.realToken);
    await this.cacheDel(`cred:alias:${tokenHash}`);

    // Issue fresh alias for the same session
    return this.createAlias(resolved.realToken, resolved.userId, ttlSeconds);
  }

  /**
   * Clean up alias when user logs out normally.
   * Always call this on logout — don't wait for TTL expiry.
   *
   * IP-M4: Uses SHA-256(realToken) for reverse key lookup.
   * IP-M7: Records revocation_reason: "logout".
   */
  async revokeOnLogout(realToken: string): Promise<void> {
    // IP-M4: Hash the token for reverse lookup
    const tokenHash = hashToken(realToken);
    const alias = await this.cacheGet(`cred:alias:${tokenHash}`);
    if (!alias) return;

    // Record logout revocation marker
    const revocationMarker = JSON.stringify({
      revoked: true,
      reason: 'logout' as RevocationReason,
      revokedAt: Date.now(),
      revocation_scope: 'precise',
    });
    await this.cacheSet(`revoked:alias:${alias}`, revocationMarker, 86400);

    await this.cacheDel(`alias:${alias}`);
    await this.cacheDel(`cred:alias:${tokenHash}`);
  }

  /**
   * Check if an alias was already revoked (idempotency for webhook retries).
   */
  async isRevoked(alias: string): Promise<boolean> {
    const revoked = await this.cacheGet(`revoked:alias:${alias}`);
    return revoked !== null;
  }

  /**
   * Get revocation details for an alias (IP-M7 audit support).
   */
  async getRevocationDetails(alias: string): Promise<{
    reason: RevocationReason;
    revokedAt: number;
    revocation_scope: 'precise' | 'broad';
  } | null> {
    const raw = await this.cacheGet(`revoked:alias:${alias}`);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      // Legacy format (just '1')
      return {
        reason: 'active_threat',
        revokedAt: Date.now(),
        revocation_scope: 'precise',
      };
    }
  }
}
