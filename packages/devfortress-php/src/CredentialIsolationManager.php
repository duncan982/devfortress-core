<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use InvalidArgumentException;
use RuntimeException;
use Throwable;

/**
 * Credential Isolation Security — Session Indirection (Hardened).
 *
 * Replaces real session tokens with opaque, random aliases before they
 * leave the client app's trust boundary. DevFortress only ever sees the
 * alias — never the real token. Mirrors
 * packages/devfortress-sdk/src/credential-isolation.ts (IP-M3 through
 * IP-M7, IP-S5):
 *
 * - AES-256-GCM encryption of forward mapping values (IP-M3)
 * - SHA-256 hashed reverse mapping keys (IP-M4)
 * - SubjectId-level fallback revocation on cache failure (IP-M5)
 * - Local emergency blocklist (IP-M6) — see ThreatInterceptor
 * - Alias rotation grace period (IP-M7) — old aliases remain resolvable
 * - In-memory LRU fallback cache (IP-S5) — survives Redis outages
 */
final class CredentialIsolationManager
{
    private const ENCRYPTED_PREFIX = 'enc:v1:';
    public const REVOCATION_REASONS = ['active_threat', 'rotation_expired', 'logout'];

    private readonly CacheAdapterInterface $cache;
    private readonly string $encryptionKey;
    private readonly LRUCache $lru;
    private readonly int $rotationGracePeriod;
    /** @var (\Closure(string, string): void)|null */
    private readonly ?\Closure $onFallbackRevocation;

    /**
     * @param (callable(string, string): void)|null $onFallbackRevocation Invoked
     *        on fallback revocation (IP-M5) with the subjectId so the app can
     *        do broad session deletion.
     */
    public function __construct(
        ?CacheAdapterInterface $cache = null,
        ?string $encryptionKey = null,
        int $lruMaxEntries = 1000,
        int $lruTtlSeconds = 60,
        int $rotationGracePeriodSeconds = 1200,
        ?callable $onFallbackRevocation = null,
    ) {
        $this->cache = $cache ?? new MemoryCacheAdapter();
        $this->lru = new LRUCache($lruMaxEntries, $lruTtlSeconds);
        $this->rotationGracePeriod = $rotationGracePeriodSeconds;
        $this->onFallbackRevocation = $onFallbackRevocation !== null ? \Closure::fromCallable($onFallbackRevocation) : null;

        // Encryption is mandatory: credentials must never be cached in
        // plaintext. Fail loudly at construction time rather than silently
        // no-op'ing in encryptValue()/decryptValue().
        $key = $encryptionKey ?? (getenv('DEVFORTRESS_REDIS_ENCRYPTION_KEY') ?: null);
        if ($key === null || $key === '') {
            throw new InvalidArgumentException(
                'DEVFORTRESS_REDIS_ENCRYPTION_KEY is required — CredentialIsolationManager ' .
                'refuses to store credentials without encryption. Set this env var to a ' .
                '32-byte hex string (64 hex characters), e.g. `openssl rand -hex 32`, or ' .
                'pass $encryptionKey explicitly.',
            );
        }
        if (strlen($key) !== 64) {
            throw new InvalidArgumentException('DEVFORTRESS_REDIS_ENCRYPTION_KEY must be a 32-byte hex string (64 hex characters)');
        }
        $this->encryptionKey = $key;
    }

    /**
     * Generate a cryptographically random alias for a real session token.
     * The alias has NO mathematical relationship to the real token.
     *
     * IP-M3: Forward mapping value is AES-256-GCM encrypted.
     * IP-M4: Reverse mapping key uses SHA-256(realToken) instead of plaintext.
     * IP-S5: Writes to both the cache and the LRU fallback.
     */
    public function createAlias(string $realToken, string $userId, int $ttlSeconds = 3600): string
    {
        $tokenHash = self::hashToken($realToken);

        $existingAlias = $this->cacheGet("cred:alias:{$tokenHash}");
        if ($existingAlias !== null) {
            return $existingAlias;
        }

        $alias = 'df_sid_' . bin2hex(random_bytes(16));
        $data = ['realToken' => $realToken, 'userId' => $userId, 'createdAt' => self::nowMs()];

        $encryptedData = $this->encryptValue(json_encode($data, JSON_THROW_ON_ERROR));
        $this->cacheSet("alias:{$alias}", $encryptedData, $ttlSeconds);
        $this->cacheSet("cred:alias:{$tokenHash}", $alias, $ttlSeconds);

        return $alias;
    }

    /**
     * Resolve an alias back to the real token and user. Called ONLY when a
     * revocation webhook arrives from DevFortress.
     *
     * @return array{realToken: string, userId: string, createdAt: int}|null
     */
    public function resolveAlias(string $alias): ?array
    {
        $raw = $this->cacheGet("alias:{$alias}");
        if ($raw === null) {
            return null;
        }
        try {
            $decrypted = $this->decryptValue($raw);
            /** @var array{realToken: string, userId: string, createdAt: int} $data */
            $data = json_decode($decrypted, true, flags: JSON_THROW_ON_ERROR);

            // IP-M7: Alias is valid for revocation even if rotating
            // (canCreateNewEvents may be false, but resolution still works)
            return [
                'realToken' => $data['realToken'],
                'userId' => $data['userId'],
                'createdAt' => $data['createdAt'],
            ];
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Revoke a session by alias. The real token is resolved within the
     * client app — DevFortress never touches the real token.
     *
     * IP-M5: On cache failure, falls back to subjectId-level revocation.
     * IP-M7: Records revocation_reason in audit marker.
     *
     * @return array{realToken: string, userId: string, createdAt: int}|null
     */
    public function revokeByAlias(string $alias, string $reason = 'active_threat', ?string $subjectId = null): ?array
    {
        try {
            $resolved = $this->resolveAlias($alias);
            if ($resolved === null) {
                if ($subjectId !== null && $this->onFallbackRevocation !== null) {
                    ($this->onFallbackRevocation)($subjectId, "[DF] alias resolution failed for {$alias} — falling back to subjectId revocation");
                }

                return null;
            }

            $tokenHash = self::hashToken($resolved['realToken']);
            $this->cacheDel("alias:{$alias}");
            $this->cacheDel("cred:alias:{$tokenHash}");

            $marker = json_encode([
                'revoked' => true, 'reason' => $reason, 'revokedAt' => self::nowMs(), 'revocation_scope' => 'precise',
            ], JSON_THROW_ON_ERROR);
            $this->cacheSet("revoked:alias:{$alias}", $marker, 86_400);

            return $resolved;
        } catch (Throwable $e) {
            $fallbackSubject = $subjectId ?? 'unknown';
            if ($this->onFallbackRevocation !== null) {
                ($this->onFallbackRevocation)($fallbackSubject, "[DF] cache error during revokeByAlias({$alias}) — falling back to subjectId revocation. Error: {$e->getMessage()}");
            }
            try {
                $marker = json_encode([
                    'revoked' => true, 'reason' => $reason, 'revokedAt' => self::nowMs(), 'revocation_scope' => 'broad',
                ], JSON_THROW_ON_ERROR);
                $this->cacheSet("revoked:alias:{$alias}", $marker, 86_400);
            } catch (Throwable) {
                // Best-effort
            }

            return null;
        }
    }

    /**
     * Rotate alias — replaces the alias for a live session.
     *
     * IP-M7: Old alias is NOT deleted immediately. It gets a grace-period
     * TTL and stays resolvable for revocation purposes, but canCreateNewEvents
     * is set to false.
     */
    public function rotateAlias(string $oldAlias, int $ttlSeconds = 3600): ?string
    {
        $resolved = $this->resolveAlias($oldAlias);
        if ($resolved === null) {
            return null;
        }

        $rotatingData = $resolved + ['status' => 'rotating', 'canCreateNewEvents' => false];
        $encryptedRotating = $this->encryptValue(json_encode($rotatingData, JSON_THROW_ON_ERROR));
        $this->cacheSet("alias:{$oldAlias}", $encryptedRotating, $this->rotationGracePeriod);

        $tokenHash = self::hashToken($resolved['realToken']);
        $this->cacheDel("cred:alias:{$tokenHash}");

        return $this->createAlias($resolved['realToken'], $resolved['userId'], $ttlSeconds);
    }

    /**
     * Clean up alias when the user logs out normally. Always call this on
     * logout — don't wait for TTL expiry.
     */
    public function revokeOnLogout(string $realToken): void
    {
        $tokenHash = self::hashToken($realToken);
        $alias = $this->cacheGet("cred:alias:{$tokenHash}");
        if ($alias === null) {
            return;
        }

        $marker = json_encode([
            'revoked' => true, 'reason' => 'logout', 'revokedAt' => self::nowMs(), 'revocation_scope' => 'precise',
        ], JSON_THROW_ON_ERROR);
        $this->cacheSet("revoked:alias:{$alias}", $marker, 86_400);
        $this->cacheDel("alias:{$alias}");
        $this->cacheDel("cred:alias:{$tokenHash}");
    }

    /** Check if an alias was already revoked (idempotency for webhook retries). */
    public function isRevoked(string $alias): bool
    {
        return $this->cacheGet("revoked:alias:{$alias}") !== null;
    }

    /**
     * Get revocation details for an alias (IP-M7 audit support).
     *
     * @return array{reason: string, revokedAt: int, revocation_scope: string}|null
     */
    public function getRevocationDetails(string $alias): ?array
    {
        $raw = $this->cacheGet("revoked:alias:{$alias}");
        if ($raw === null) {
            return null;
        }
        try {
            /** @var array{reason: string, revokedAt: int, revocation_scope: string} $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);

            return $decoded;
        } catch (Throwable) {
            // Legacy format (just '1')
            return ['reason' => 'active_threat', 'revokedAt' => self::nowMs(), 'revocation_scope' => 'precise'];
        }
    }

    private function encryptValue(string $plaintext): string
    {
        $key = CredentialVault::hexDecode($this->encryptionKey);
        $iv = random_bytes(12);
        $tag = '';
        $encrypted = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($encrypted === false) {
            throw new RuntimeException('DevFortress\Sdk\CredentialIsolationManager: encryption failed');
        }

        return self::ENCRYPTED_PREFIX . bin2hex($iv) . ':' . bin2hex($encrypted) . ':' . bin2hex($tag);
    }

    private function decryptValue(string $ciphertext): string
    {
        if (!str_starts_with($ciphertext, self::ENCRYPTED_PREFIX)) {
            // Legacy unencrypted format — return as-is (rolling migration)
            return $ciphertext;
        }
        $parts = explode(':', substr($ciphertext, strlen(self::ENCRYPTED_PREFIX)));
        if (count($parts) !== 3) {
            throw new RuntimeException('Invalid encrypted format');
        }
        $key = CredentialVault::hexDecode($this->encryptionKey);
        $plaintext = openssl_decrypt(
            CredentialVault::hexDecode($parts[1]),
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            CredentialVault::hexDecode($parts[0]),
            CredentialVault::hexDecode($parts[2]),
        );
        if ($plaintext === false) {
            throw new RuntimeException('DevFortress\Sdk\CredentialIsolationManager: auth-tag verification failed');
        }

        return $plaintext;
    }

    private static function hashToken(string $realToken): string
    {
        return hash('sha256', $realToken);
    }

    private function cacheGet(string $key): ?string
    {
        try {
            $value = $this->cache->get($key);
            if ($value !== null) {
                // Backfill LRU on successful cache read
                $this->lru->set($key, $value);

                return $value;
            }
        } catch (Throwable) {
            // Cache failure — fall back to LRU (IP-S5)
        }

        return $this->lru->get($key);
    }

    private function cacheSet(string $key, string $value, int $ttlSeconds): void
    {
        // Always write to LRU first (can't fail)
        $this->lru->set($key, $value, $ttlSeconds);
        try {
            $this->cache->set($key, $value, $ttlSeconds);
        } catch (Throwable) {
            // LRU is set — cache failure is survivable
        }
    }

    private function cacheDel(string $key): void
    {
        $this->lru->del($key);
        try {
            $this->cache->del($key);
        } catch (Throwable) {
            // Best-effort
        }
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
