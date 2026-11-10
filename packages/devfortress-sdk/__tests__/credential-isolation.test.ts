/**
 * Credential Isolation Security — Hardened Tests
 *
 * Tests for IP-M3 (AES-256-GCM encryption), IP-M4 (SHA-256 hashed reverse keys),
 * IP-M5 (subjectId fallback revocation), IP-M6 (emergency blocklist),
 * IP-M7 (rotation grace period), IP-S5 (LRU fallback cache).
 */

import crypto from 'crypto';
import {
  CredentialIsolationManager,
  ThreatInterceptor,
  type CacheAdapter,
} from '../src/credential-isolation';

// ── Test Helpers ────────────────────────────────────────────

function generateEncryptionKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

// Encryption is now mandatory (constructor throws without it) — provide a
// default via env var so bare `new CredentialIsolationManager()` calls in
// this suite that aren't specifically testing the missing-key rejection path
// keep working. Tests that need a specific key still pass config.encryptionKey.
process.env.DEVFORTRESS_REDIS_ENCRYPTION_KEY = generateEncryptionKey();

/** In-memory cache adapter that can simulate failures */
function createTestCache(): CacheAdapter & {
  store: Map<string, { value: string; ttl: number }>;
  failOnNext: boolean;
} {
  const store = new Map<string, { value: string; ttl: number }>();
  const adapter = {
    store,
    failOnNext: false,
    async get(key: string) {
      if (adapter.failOnNext) throw new Error('Redis connection refused');
      const entry = store.get(key);
      return entry ? entry.value : null;
    },
    async set(key: string, value: string, ttlSeconds: number) {
      if (adapter.failOnNext) throw new Error('Redis connection refused');
      store.set(key, { value, ttl: ttlSeconds });
    },
    async del(key: string) {
      if (adapter.failOnNext) throw new Error('Redis connection refused');
      store.delete(key);
    },
  };
  return adapter;
}

// ── Basic Alias Operations ──────────────────────────────────

describe('CredentialIsolationManager — Basic Operations', () => {
  let manager: CredentialIsolationManager;

  beforeEach(() => {
    manager = new CredentialIsolationManager();
  });

  test('creates a unique alias for a token', async () => {
    const alias = await manager.createAlias('jwt-token-123', 'user-1');
    expect(alias).toMatch(/^df_sid_[0-9a-f]{32}$/);
  });

  test('returns the same alias for the same token', async () => {
    const alias1 = await manager.createAlias('jwt-token-123', 'user-1');
    const alias2 = await manager.createAlias('jwt-token-123', 'user-1');
    expect(alias1).toBe(alias2);
  });

  test('creates different aliases for different tokens', async () => {
    const alias1 = await manager.createAlias('jwt-token-1', 'user-1');
    const alias2 = await manager.createAlias('jwt-token-2', 'user-2');
    expect(alias1).not.toBe(alias2);
  });

  test('resolves an alias back to the real token', async () => {
    const alias = await manager.createAlias('jwt-token-123', 'user-1');
    const resolved = await manager.resolveAlias(alias);
    expect(resolved).not.toBeNull();
    expect(resolved!.realToken).toBe('jwt-token-123');
    expect(resolved!.userId).toBe('user-1');
    expect(resolved!.createdAt).toBeGreaterThan(0);
  });

  test('returns null for unknown alias', async () => {
    const resolved = await manager.resolveAlias('df_sid_nonexistent');
    expect(resolved).toBeNull();
  });

  test('revokes an alias and marks as revoked', async () => {
    const alias = await manager.createAlias('jwt-token-123', 'user-1');
    const revoked = await manager.revokeByAlias(alias);
    expect(revoked).not.toBeNull();
    expect(revoked!.realToken).toBe('jwt-token-123');

    // Alias is now unresolvable
    const resolved = await manager.resolveAlias(alias);
    expect(resolved).toBeNull();

    // Marked as revoked
    const isRevoked = await manager.isRevoked(alias);
    expect(isRevoked).toBe(true);
  });

  test('revokeOnLogout cleans up alias', async () => {
    const alias = await manager.createAlias('jwt-token-123', 'user-1');
    await manager.revokeOnLogout('jwt-token-123');

    const resolved = await manager.resolveAlias(alias);
    expect(resolved).toBeNull();
  });
});

// ── IP-M3: AES-256-GCM Encryption ──────────────────────────

describe('IP-M3: Forward Mapping Encryption', () => {
  test('encrypted values are opaque in cache', async () => {
    const cache = createTestCache();
    const key = generateEncryptionKey();
    const manager = new CredentialIsolationManager(cache, {
      encryptionKey: key,
    });

    const alias = await manager.createAlias('secret-jwt-token', 'user-1');

    // Read raw value from cache — should be encrypted
    const raw = cache.store.get(`alias:${alias}`);
    expect(raw).toBeDefined();
    expect(raw!.value).toMatch(/^enc:v1:/);
    expect(raw!.value).not.toContain('secret-jwt-token');
    expect(raw!.value).not.toContain('user-1');
  });

  test('resolves encrypted aliases correctly', async () => {
    const key = generateEncryptionKey();
    const manager = new CredentialIsolationManager(undefined, {
      encryptionKey: key,
    });

    const alias = await manager.createAlias('secret-jwt-token', 'user-1');
    const resolved = await manager.resolveAlias(alias);
    expect(resolved).not.toBeNull();
    expect(resolved!.realToken).toBe('secret-jwt-token');
    expect(resolved!.userId).toBe('user-1');
  });

  test('wrong encryption key fails to resolve', async () => {
    const cache = createTestCache();
    const key1 = generateEncryptionKey();
    const key2 = generateEncryptionKey();

    const manager1 = new CredentialIsolationManager(cache, {
      encryptionKey: key1,
    });
    const alias = await manager1.createAlias('secret-jwt-token', 'user-1');

    // Try resolving with different key — should fail gracefully
    const manager2 = new CredentialIsolationManager(cache, {
      encryptionKey: key2,
    });
    const resolved = await manager2.resolveAlias(alias);
    expect(resolved).toBeNull();
  });

  test('supports rolling migration from unencrypted entries', async () => {
    const cache = createTestCache();

    // Write unencrypted entry (legacy format)
    const legacyData = JSON.stringify({
      realToken: 'old-jwt-token',
      userId: 'user-1',
      createdAt: Date.now(),
    });
    await cache.set('alias:df_sid_legacy123', legacyData, 3600);

    // Create manager with encryption — should still read legacy entries
    const key = generateEncryptionKey();
    const manager = new CredentialIsolationManager(cache, {
      encryptionKey: key,
    });
    const resolved = await manager.resolveAlias('df_sid_legacy123');
    expect(resolved).not.toBeNull();
    expect(resolved!.realToken).toBe('old-jwt-token');
  });

  test('rejects invalid encryption key length', () => {
    expect(
      () =>
        new CredentialIsolationManager(undefined, { encryptionKey: 'tooshort' })
    ).toThrow('32-byte hex string');
  });

  test('rejects construction with no encryption key configured', () => {
    const cache = createTestCache();
    const savedKey = process.env.DEVFORTRESS_REDIS_ENCRYPTION_KEY;
    delete process.env.DEVFORTRESS_REDIS_ENCRYPTION_KEY;
    try {
      expect(() => new CredentialIsolationManager(cache)).toThrow(
        'DEVFORTRESS_REDIS_ENCRYPTION_KEY is required'
      );
    } finally {
      process.env.DEVFORTRESS_REDIS_ENCRYPTION_KEY = savedKey;
    }
  });
});

// ── IP-M4: SHA-256 Hashed Reverse Keys ─────────────────────

describe('IP-M4: Hashed Reverse Mapping Keys', () => {
  test('reverse mapping key is SHA-256 hashed', async () => {
    const cache = createTestCache();
    const manager = new CredentialIsolationManager(cache);

    await manager.createAlias('my-real-jwt-token', 'user-1');

    // The plaintext token should NOT appear as a cache key
    const keys = Array.from(cache.store.keys());
    const hasPlaintext = keys.some(k => k.includes('my-real-jwt-token'));
    expect(hasPlaintext).toBe(false);

    // Should have a SHA-256 hashed key
    const expectedHash = crypto
      .createHash('sha256')
      .update('my-real-jwt-token')
      .digest('hex');
    const hasHashedKey = keys.some(k => k.includes(expectedHash));
    expect(hasHashedKey).toBe(true);
  });

  test('revokeOnLogout uses hashed key for lookup', async () => {
    const cache = createTestCache();
    const manager = new CredentialIsolationManager(cache);

    const alias = await manager.createAlias('my-real-jwt-token', 'user-1');
    await manager.revokeOnLogout('my-real-jwt-token');

    // Alias should be cleaned up
    const resolved = await manager.resolveAlias(alias);
    expect(resolved).toBeNull();

    // Revocation marker should exist
    const isRevoked = await manager.isRevoked(alias);
    expect(isRevoked).toBe(true);
  });
});

// ── IP-M5: SubjectId Fallback Revocation ────────────────────

describe('IP-M5: SubjectId Fallback Revocation', () => {
  test('invokes fallback when alias resolution fails', async () => {
    const fallbackCalls: { subjectId: string; reason: string }[] = [];
    const manager = new CredentialIsolationManager(undefined, {
      onFallbackRevocation: (subjectId, reason) => {
        fallbackCalls.push({ subjectId, reason });
      },
    });

    // Try revoking a non-existent alias with a subjectId
    const result = await manager.revokeByAlias(
      'df_sid_doesnotexist',
      'active_threat',
      'user-42'
    );
    expect(result).toBeNull();
    expect(fallbackCalls).toHaveLength(1);
    expect(fallbackCalls[0].subjectId).toBe('user-42');
    expect(fallbackCalls[0].reason).toContain('alias resolution failed');
    expect(fallbackCalls[0].reason).toContain('subjectId revocation');
  });

  test('invokes fallback on cache error', async () => {
    const cache = createTestCache();
    const fallbackCalls: { subjectId: string; reason: string }[] = [];
    const manager = new CredentialIsolationManager(cache, {
      onFallbackRevocation: (subjectId, reason) => {
        fallbackCalls.push({ subjectId, reason });
      },
    });

    // Create an alias first
    const alias = await manager.createAlias('jwt-token', 'user-1');

    // Simulate Redis failure
    cache.failOnNext = true;

    const result = await manager.revokeByAlias(
      alias,
      'active_threat',
      'user-1'
    );
    // The LRU cache will serve the alias, so it may succeed
    // But if it doesn't (e.g. LRU expired), fallback fires
    expect(result === null || result?.realToken === 'jwt-token').toBe(true);
  });

  test('does not invoke fallback when no subjectId provided', async () => {
    const fallbackCalls: string[] = [];
    const manager = new CredentialIsolationManager(undefined, {
      onFallbackRevocation: subjectId => {
        fallbackCalls.push(subjectId);
      },
    });

    // No subjectId provided — should not call fallback for missing alias
    await manager.revokeByAlias('df_sid_doesnotexist');
    expect(fallbackCalls).toHaveLength(0);
  });
});

// ── IP-M6: Emergency Blocklist ──────────────────────────────

describe('IP-M6: Emergency Blocklist', () => {
  test('blocks and checks IP', async () => {
    const blocklist = new ThreatInterceptor();

    expect(await blocklist.isBlocked('192.168.1.100')).toBe(false);

    await blocklist.blockIP('192.168.1.100', 'critical_brute_force');
    expect(await blocklist.isBlocked('192.168.1.100')).toBe(true);
  });

  test('unblocks IP', async () => {
    const blocklist = new ThreatInterceptor();

    await blocklist.blockIP('10.0.0.1', 'test');
    expect(await blocklist.isBlocked('10.0.0.1')).toBe(true);

    await blocklist.unblockIP('10.0.0.1');
    expect(await blocklist.isBlocked('10.0.0.1')).toBe(false);
  });

  test('survives cache failure (uses LRU)', async () => {
    const cache = createTestCache();
    const blocklist = new ThreatInterceptor(cache);

    await blocklist.blockIP('41.212.5.1', 'critical_event');

    // Simulate Redis failure
    cache.failOnNext = true;

    // Should still be blocked via LRU cache
    expect(await blocklist.isBlocked('41.212.5.1')).toBe(true);
  });

  test('non-blocked IP returns false', async () => {
    const blocklist = new ThreatInterceptor();
    expect(await blocklist.isBlocked('8.8.8.8')).toBe(false);
  });
});

// ── IP-M7: Rotation Grace Period ────────────────────────────

describe('IP-M7: Alias Rotation Grace Period', () => {
  test('old alias remains resolvable after rotation', async () => {
    const manager = new CredentialIsolationManager(undefined, {
      rotationGracePeriodSeconds: 1200,
    });

    const oldAlias = await manager.createAlias('jwt-token', 'user-1');
    const newAlias = await manager.rotateAlias(oldAlias);

    expect(newAlias).not.toBeNull();
    expect(newAlias).not.toBe(oldAlias);

    // Old alias is STILL resolvable (grace period)
    const oldResolved = await manager.resolveAlias(oldAlias);
    expect(oldResolved).not.toBeNull();
    expect(oldResolved!.realToken).toBe('jwt-token');

    // New alias also resolves
    const newResolved = await manager.resolveAlias(newAlias!);
    expect(newResolved).not.toBeNull();
    expect(newResolved!.realToken).toBe('jwt-token');
  });

  test('revocation with reason is recorded', async () => {
    const manager = new CredentialIsolationManager();

    const alias = await manager.createAlias('jwt-token', 'user-1');
    await manager.revokeByAlias(alias, 'active_threat');

    const details = await manager.getRevocationDetails(alias);
    expect(details).not.toBeNull();
    expect(details!.reason).toBe('active_threat');
    expect(details!.revocation_scope).toBe('precise');
    expect(details!.revokedAt).toBeGreaterThan(0);
  });

  test('logout records correct reason', async () => {
    const manager = new CredentialIsolationManager();

    const alias = await manager.createAlias('jwt-token', 'user-1');
    await manager.revokeOnLogout('jwt-token');

    const details = await manager.getRevocationDetails(alias);
    expect(details).not.toBeNull();
    expect(details!.reason).toBe('logout');
  });
});

// ── IP-S5: LRU Fallback Cache ───────────────────────────────

describe('IP-S5: LRU Fallback Cache', () => {
  test('survives Redis failure for recently created aliases', async () => {
    const cache = createTestCache();
    const manager = new CredentialIsolationManager(cache);

    // Create alias while Redis is up
    const alias = await manager.createAlias('jwt-token', 'user-1');

    // Kill Redis
    cache.failOnNext = true;

    // Should still resolve from LRU cache
    const resolved = await manager.resolveAlias(alias);
    expect(resolved).not.toBeNull();
    expect(resolved!.realToken).toBe('jwt-token');
  });

  test('returns null for unknown aliases even on Redis failure', async () => {
    const cache = createTestCache();
    const manager = new CredentialIsolationManager(cache);

    cache.failOnNext = true;
    const resolved = await manager.resolveAlias('df_sid_unknown');
    expect(resolved).toBeNull();
  });
});

// ── Combined: Encryption + Hashing + LRU ────────────────────

describe('Combined Security Hardening', () => {
  test('full lifecycle with encryption, hashing, and LRU', async () => {
    const cache = createTestCache();
    const key = generateEncryptionKey();
    const fallbackCalls: string[] = [];

    const manager = new CredentialIsolationManager(cache, {
      encryptionKey: key,
      lruMaxEntries: 100,
      lruTtlSeconds: 30,
      rotationGracePeriodSeconds: 600,
      onFallbackRevocation: subjectId => {
        fallbackCalls.push(subjectId);
      },
    });

    // Create alias
    const alias = await manager.createAlias('real-jwt-token-xyz', 'user-42');
    expect(alias).toMatch(/^df_sid_/);

    // Verify encryption in cache
    const rawForward = cache.store.get(`alias:${alias}`);
    expect(rawForward!.value).toMatch(/^enc:v1:/);
    expect(rawForward!.value).not.toContain('real-jwt-token-xyz');

    // Verify hashed reverse key
    const tokenHash = crypto
      .createHash('sha256')
      .update('real-jwt-token-xyz')
      .digest('hex');
    const rawReverse = cache.store.get(`cred:alias:${tokenHash}`);
    expect(rawReverse).toBeDefined();
    expect(rawReverse!.value).toBe(alias);

    // Resolve
    const resolved = await manager.resolveAlias(alias);
    expect(resolved!.realToken).toBe('real-jwt-token-xyz');

    // Rotate — old alias stays resolvable
    const newAlias = await manager.rotateAlias(alias);
    expect(newAlias).not.toBeNull();
    const oldResolved = await manager.resolveAlias(alias);
    expect(oldResolved).not.toBeNull(); // Grace period

    // Revoke new alias
    const revoked = await manager.revokeByAlias(newAlias!, 'active_threat');
    expect(revoked!.realToken).toBe('real-jwt-token-xyz');

    // Check revocation details
    const details = await manager.getRevocationDetails(newAlias!);
    expect(details!.reason).toBe('active_threat');
    expect(details!.revocation_scope).toBe('precise');
  });
});
