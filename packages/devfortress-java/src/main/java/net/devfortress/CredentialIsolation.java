package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Credential Isolation Security — Session Indirection (Hardened). Mirrors
 * {@code packages/devfortress-sdk/src/credential-isolation.ts}.
 *
 * <p>Replaces real session tokens with opaque, random aliases before they
 * leave the client app's trust boundary. DevFortress only ever sees the
 * alias — never the real token. Hardening: AES-256-GCM encryption of
 * forward-mapping values, SHA-256 hashed reverse-mapping keys, subjectId-level
 * fallback revocation on cache failure, alias rotation grace period, and an
 * in-memory LRU fallback cache that survives cache-adapter outages.
 */
public final class CredentialIsolation {
    private CredentialIsolation() {
    }

    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();

    /** A pluggable cache (Redis in production; {@link InMemoryCacheAdapter} for dev/test). */
    public interface CacheAdapter {
        CompletableFuture<String> get(String key);

        CompletableFuture<Void> set(String key, String value, int ttlSeconds);

        CompletableFuture<Void> del(String key);
    }

    /** In-process, non-persistent {@link CacheAdapter} — the development/test fallback. */
    public static final class InMemoryCacheAdapter implements CacheAdapter {
        private record Entry(String value, long expiresAtMs) {
        }

        private final Map<String, Entry> store = new HashMap<>();
        private final Object lock = new Object();

        @Override
        public CompletableFuture<String> get(String key) {
            synchronized (lock) {
                Entry entry = store.get(key);
                if (entry == null) {
                    return CompletableFuture.completedFuture(null);
                }
                if (nowMs() > entry.expiresAtMs()) {
                    store.remove(key);
                    return CompletableFuture.completedFuture(null);
                }
                return CompletableFuture.completedFuture(entry.value());
            }
        }

        @Override
        public CompletableFuture<Void> set(String key, String value, int ttlSeconds) {
            synchronized (lock) {
                store.put(key, new Entry(value, nowMs() + ttlSeconds * 1000L));
            }
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Void> del(String key) {
            synchronized (lock) {
                store.remove(key);
            }
            return CompletableFuture.completedFuture(null);
        }
    }

    /** Bounded, TTL'd in-memory LRU cache — the fallback path when {@link CacheAdapter} fails. */
    private static final class LruCache {
        private record Entry(String value, long expiresAtMs) {
        }

        private final int maxEntries;
        private final int defaultTtlSeconds;
        private final Map<String, Entry> cache = new HashMap<>();
        private final List<String> order = new ArrayList<>();
        private final Object lock = new Object();

        LruCache(int maxEntries, int defaultTtlSeconds) {
            this.maxEntries = maxEntries;
            this.defaultTtlSeconds = defaultTtlSeconds;
        }

        String get(String key) {
            synchronized (lock) {
                Entry entry = cache.get(key);
                if (entry == null) {
                    return null;
                }
                if (nowMs() > entry.expiresAtMs()) {
                    cache.remove(key);
                    order.remove(key);
                    return null;
                }
                // Move to end (most recently used).
                order.remove(key);
                order.add(key);
                return entry.value();
            }
        }

        void set(String key, String value) {
            set(key, value, defaultTtlSeconds);
        }

        void set(String key, String value, int ttlSeconds) {
            synchronized (lock) {
                if (!cache.containsKey(key) && cache.size() >= maxEntries && !order.isEmpty()) {
                    String oldest = order.remove(0);
                    cache.remove(oldest);
                }
                order.remove(key);
                order.add(key);
                cache.put(key, new Entry(value, nowMs() + ttlSeconds * 1000L));
            }
        }

        void del(String key) {
            synchronized (lock) {
                cache.remove(key);
                order.remove(key);
            }
        }

        boolean has(String key) {
            return get(key) != null;
        }
    }

    private static long nowMs() {
        return Instant.now().toEpochMilli();
    }

    /**
     * Local emergency blocklist — synchronous-fast-path, pre-webhook IP
     * blocking. When a critical event fires, the IP is written here BEFORE
     * the webhook is sent, ensuring the IP is blocked even if the webhook
     * receiver is down.
     */
    public static final class ThreatInterceptor {
        private final CacheAdapter cache;
        private final LruCache lru;
        private final int defaultTtlSeconds;

        public ThreatInterceptor() {
            this(null, 900);
        }

        public ThreatInterceptor(CacheAdapter cache, int ttlSeconds) {
            this.cache = cache != null ? cache : new InMemoryCacheAdapter();
            this.lru = new LruCache(5000, ttlSeconds);
            this.defaultTtlSeconds = ttlSeconds;
        }

        /** Block an IP immediately on critical event classification. */
        public CompletableFuture<Void> blockIp(String ip, String reason) {
            String value = "{\"reason\":\"" + reason + "\",\"blockedAt\":" + nowMs() + "}";
            lru.set("emergency:block:" + ip, value, defaultTtlSeconds);
            return cache.set("emergency:block:" + ip, value, defaultTtlSeconds)
                    .exceptionally(e -> null); // LRU is already set — cache-adapter failure doesn't prevent blocking.
        }

        public CompletableFuture<Void> blockIp(String ip) {
            return blockIp(ip, "critical_event");
        }

        /** Check if an IP is emergency-blocked. O(1) — safe for every request. */
        public CompletableFuture<Boolean> isBlocked(String ip) {
            if (lru.has("emergency:block:" + ip)) {
                return CompletableFuture.completedFuture(true);
            }
            return cache.get("emergency:block:" + ip)
                    .thenApply(val -> val != null)
                    .exceptionally(e -> false); // On cache-adapter failure, LRU was already checked.
        }

        /** Unblock an IP (manual override). */
        public CompletableFuture<Void> unblockIp(String ip) {
            lru.del("emergency:block:" + ip);
            return cache.del("emergency:block:" + ip).exceptionally(e -> null); // Best-effort.
        }
    }

    public enum RevocationReason {
        ACTIVE_THREAT("active_threat"),
        ROTATION_EXPIRED("rotation_expired"),
        LOGOUT("logout");

        final String wire;

        RevocationReason(String wire) {
            this.wire = wire;
        }

        public String wireValue() {
            return wire;
        }

        static RevocationReason fromWire(String wire) {
            for (RevocationReason r : values()) {
                if (r.wire.equals(wire)) {
                    return r;
                }
            }
            return ACTIVE_THREAT;
        }
    }

    public record IsolatedCredentialData(String realToken, String userId, long createdAt) {
    }

    public record RevocationDetails(RevocationReason reason, long revokedAt, String revocationScope) {
    }

    /** Builder-style config for {@link CredentialIsolationManager}. */
    public static final class Config {
        String encryptionKey;
        int lruMaxEntries = 1000;
        int lruTtlSeconds = 60;
        int rotationGracePeriodSeconds = 1200;
        java.util.function.BiFunction<String, String, CompletableFuture<Void>> onFallbackRevocation;

        /** AES-256-GCM encryption key for forward-mapping values (32-byte hex string, 64 hex characters). */
        public Config encryptionKey(String key) {
            this.encryptionKey = key;
            return this;
        }

        public Config lruMaxEntries(int n) {
            this.lruMaxEntries = n;
            return this;
        }

        public Config lruTtlSeconds(int n) {
            this.lruTtlSeconds = n;
            return this;
        }

        public Config rotationGracePeriodSeconds(int n) {
            this.rotationGracePeriodSeconds = n;
            return this;
        }

        /** Invoked on fallback revocation (cache failure) so the app can do broad session deletion. */
        public Config onFallbackRevocation(java.util.function.BiFunction<String, String, CompletableFuture<Void>> cb) {
            this.onFallbackRevocation = cb;
            return this;
        }
    }

    /** Credential Isolation Manager (hardened). See the class-level remarks for the hardening measures. */
    public static final class CredentialIsolationManager {
        private static final String ENCRYPTED_PREFIX = "enc:v1:";

        private final CacheAdapter cache;
        private final String encryptionKey;
        private final LruCache lru;
        private final int rotationGracePeriod;
        private final java.util.function.BiFunction<String, String, CompletableFuture<Void>> onFallbackRevocation;

        public CredentialIsolationManager(CacheAdapter cacheAdapter, Config config) {
            this.cache = cacheAdapter != null ? cacheAdapter : new InMemoryCacheAdapter();
            this.lru = new LruCache(config != null ? config.lruMaxEntries : 1000, config != null ? config.lruTtlSeconds : 60);
            this.rotationGracePeriod = config != null ? config.rotationGracePeriodSeconds : 1200;
            this.onFallbackRevocation = config != null ? config.onFallbackRevocation : null;

            // Encryption is mandatory: credentials must never be cached in plaintext. Fail loudly
            // at construction time rather than silently no-op'ing later.
            String key = config != null ? config.encryptionKey : null;
            if (key == null || key.isEmpty()) {
                throw new IllegalArgumentException(
                        "An encryption key is required — CredentialIsolationManager refuses to store credentials "
                        + "without encryption. Pass Config.encryptionKey as a 32-byte hex string (64 hex characters), "
                        + "e.g. from `openssl rand -hex 32`.");
            }
            if (key.length() != 64) {
                throw new IllegalArgumentException("encryptionKey must be a 32-byte hex string (64 hex characters)");
            }
            this.encryptionKey = key;
        }

        private String encryptValue(String plaintext) {
            return encryptRaw(plaintext, encryptionKey);
        }

        private String decryptValue(String ciphertext) {
            return decryptRaw(ciphertext, encryptionKey);
        }

        private static String encryptRaw(String plaintext, String keyHex) {
            byte[] key = HEX.parseHex(keyHex);
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
                byte[] combined = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
                byte[] ciphertext = new byte[combined.length - 16];
                byte[] authTag = new byte[16];
                System.arraycopy(combined, 0, ciphertext, 0, ciphertext.length);
                System.arraycopy(combined, ciphertext.length, authTag, 0, 16);
                return ENCRYPTED_PREFIX + HEX.formatHex(iv) + ":" + HEX.formatHex(ciphertext) + ":" + HEX.formatHex(authTag);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        private static String decryptRaw(String ciphertext, String keyHex) {
            if (!ciphertext.startsWith(ENCRYPTED_PREFIX)) {
                // Legacy unencrypted format — return as-is (rolling migration).
                return ciphertext;
            }
            String[] parts = ciphertext.substring(ENCRYPTED_PREFIX.length()).split(":");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid encrypted format");
            }
            byte[] iv = HEX.parseHex(parts[0]);
            byte[] encrypted = HEX.parseHex(parts[1]);
            byte[] authTag = HEX.parseHex(parts[2]);
            byte[] key = HEX.parseHex(keyHex);
            byte[] combined = new byte[encrypted.length + authTag.length];
            System.arraycopy(encrypted, 0, combined, 0, encrypted.length);
            System.arraycopy(authTag, 0, combined, encrypted.length, authTag.length);
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
                return new String(cipher.doFinal(combined), StandardCharsets.UTF_8);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        private CompletableFuture<String> cacheGet(String key) {
            return cache.get(key)
                    .handle((value, err) -> {
                        if (err == null && value != null) {
                            lru.set(key, value); // Backfill LRU on successful cache-adapter read.
                            return value;
                        }
                        return lru.get(key); // Cache-adapter failure (or miss) — fall back to LRU.
                    });
        }

        private CompletableFuture<Void> cacheSet(String key, String value, int ttlSeconds) {
            lru.set(key, value, ttlSeconds); // Always write to LRU first (synchronous, can't fail).
            return cache.set(key, value, ttlSeconds).exceptionally(e -> null); // LRU is set — cache-adapter failure is survivable.
        }

        private CompletableFuture<Void> cacheDel(String key) {
            lru.del(key);
            return cache.del(key).exceptionally(e -> null); // Best-effort.
        }

        private static String hashToken(String realToken) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(realToken.getBytes(StandardCharsets.UTF_8));
                return HEX.formatHex(digest);
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        /**
         * Generate a cryptographically random alias for a real session
         * token. The alias has NO mathematical relationship to the real
         * token.
         */
        public CompletableFuture<String> createAlias(String realToken, String userId, int ttlSeconds) {
            String tokenHash = hashToken(realToken);
            return cacheGet("cred:alias:" + tokenHash).thenCompose(existingAlias -> {
                if (existingAlias != null) {
                    return CompletableFuture.completedFuture(existingAlias);
                }

                byte[] randomBytes = new byte[16];
                RANDOM.nextBytes(randomBytes);
                String alias = "df_sid_" + HEX.formatHex(randomBytes);

                IsolatedCredentialData data = new IsolatedCredentialData(realToken, userId, nowMs());
                String encryptedData = encryptValue(toJson(data));

                return cacheSet("alias:" + alias, encryptedData, ttlSeconds)
                        .thenCompose(v -> cacheSet("cred:alias:" + tokenHash, alias, ttlSeconds))
                        .thenApply(v -> alias);
            });
        }

        public CompletableFuture<String> createAlias(String realToken, String userId) {
            return createAlias(realToken, userId, 3600);
        }

        /**
         * Resolve an alias back to the real token and user. Called ONLY
         * when a revocation webhook arrives from DevFortress. Valid for
         * revocation even if the alias is in a "rotating" state.
         */
        @SuppressWarnings("unchecked")
        public CompletableFuture<IsolatedCredentialData> resolveAlias(String alias) {
            return cacheGet("alias:" + alias).thenApply(raw -> {
                if (raw == null) {
                    return null;
                }
                try {
                    String decrypted = decryptValue(raw);
                    Map<String, Object> data = (Map<String, Object>) parseJson(decrypted);
                    return new IsolatedCredentialData(
                            (String) data.get("realToken"),
                            (String) data.get("userId"),
                            ((Number) data.get("createdAt")).longValue());
                } catch (RuntimeException e) {
                    return null;
                }
            });
        }

        /**
         * Revoke a session by alias. The real token is resolved within the
         * client app — DevFortress never touches the real token. On cache
         * failure, falls back to subjectId-level revocation. Returns the
         * resolved token data so the caller can perform the actual session
         * revocation.
         */
        public CompletableFuture<IsolatedCredentialData> revokeByAlias(String alias, RevocationReason reason, String subjectId) {
            return resolveAlias(alias).handle((resolved, resolveErr) -> {
                if (resolveErr != null) {
                    return CompletableFuture.<IsolatedCredentialData>failedFuture(resolveErr);
                }
                if (resolved == null) {
                    CompletableFuture<Void> fallback = (subjectId != null && onFallbackRevocation != null)
                            ? onFallbackRevocation.apply(subjectId, "[DF] alias resolution failed for " + alias
                                    + " — falling back to subjectId revocation")
                            : CompletableFuture.completedFuture(null);
                    return fallback.thenApply(v -> (IsolatedCredentialData) null);
                }

                String tokenHash = hashToken(resolved.realToken());
                return cacheDel("alias:" + alias)
                        .thenCompose(v -> cacheDel("cred:alias:" + tokenHash))
                        .thenCompose(v -> {
                            String marker = "{\"revoked\":true,\"reason\":\"" + reason.wireValue()
                                    + "\",\"revokedAt\":" + nowMs() + ",\"revocation_scope\":\"precise\"}";
                            return cacheSet("revoked:alias:" + alias, marker, 86400);
                        })
                        .thenApply(v -> resolved);
            }).thenCompose(f -> f).exceptionallyCompose(error -> {
                String fallbackSubject = subjectId != null ? subjectId : "unknown";
                CompletableFuture<Void> fallback = onFallbackRevocation != null
                        ? onFallbackRevocation.apply(fallbackSubject, "[DF] cache error during revokeByAlias(" + alias
                                + ") — falling back to subjectId revocation. Error: " + error.getMessage())
                        : CompletableFuture.completedFuture(null);
                return fallback.handle((v, e2) -> {
                    try {
                        String marker = "{\"revoked\":true,\"reason\":\"" + reason.wireValue()
                                + "\",\"revokedAt\":" + nowMs() + ",\"revocation_scope\":\"broad\"}";
                        cacheSet("revoked:alias:" + alias, marker, 86400).join();
                    } catch (RuntimeException ignored) {
                        // Best-effort.
                    }
                    return (IsolatedCredentialData) null;
                });
            });
        }

        public CompletableFuture<IsolatedCredentialData> revokeByAlias(String alias) {
            return revokeByAlias(alias, RevocationReason.ACTIVE_THREAT, null);
        }

        /**
         * Rotate alias — replaces the alias for a live session. The old
         * alias is NOT deleted immediately; it gets a grace-period TTL and
         * remains resolvable for revocation purposes.
         */
        public CompletableFuture<String> rotateAlias(String oldAlias, int ttlSeconds) {
            return resolveAlias(oldAlias).thenCompose(resolved -> {
                if (resolved == null) {
                    return CompletableFuture.completedFuture(null);
                }

                String rotatingJson = "{\"realToken\":" + jsonString(resolved.realToken())
                        + ",\"userId\":" + jsonString(resolved.userId())
                        + ",\"createdAt\":" + resolved.createdAt()
                        + ",\"status\":\"rotating\",\"canCreateNewEvents\":false}";
                String encryptedRotating = encryptValue(rotatingJson);

                String tokenHash = hashToken(resolved.realToken());
                return cacheSet("alias:" + oldAlias, encryptedRotating, rotationGracePeriod)
                        .thenCompose(v -> cacheDel("cred:alias:" + tokenHash))
                        .thenCompose(v -> createAlias(resolved.realToken(), resolved.userId(), ttlSeconds));
            });
        }

        /** Clean up alias when user logs out normally. Always call this on logout — don't wait for TTL expiry. */
        public CompletableFuture<Void> revokeOnLogout(String realToken) {
            String tokenHash = hashToken(realToken);
            return cacheGet("cred:alias:" + tokenHash).thenCompose(alias -> {
                if (alias == null) {
                    return CompletableFuture.completedFuture(null);
                }
                String marker = "{\"revoked\":true,\"reason\":\"logout\",\"revokedAt\":" + nowMs()
                        + ",\"revocation_scope\":\"precise\"}";
                return cacheSet("revoked:alias:" + alias, marker, 86400)
                        .thenCompose(v -> cacheDel("alias:" + alias))
                        .thenCompose(v -> cacheDel("cred:alias:" + tokenHash));
            });
        }

        /** Check if an alias was already revoked (idempotency for webhook retries). */
        public CompletableFuture<Boolean> isRevoked(String alias) {
            return cacheGet("revoked:alias:" + alias).thenApply(java.util.Objects::nonNull);
        }

        /** Get revocation details for an alias. */
        @SuppressWarnings("unchecked")
        public CompletableFuture<RevocationDetails> getRevocationDetails(String alias) {
            return cacheGet("revoked:alias:" + alias).thenApply(raw -> {
                if (raw == null) {
                    return null;
                }
                try {
                    Map<String, Object> data = (Map<String, Object>) parseJson(raw);
                    RevocationReason reason = RevocationReason.fromWire((String) data.get("reason"));
                    return new RevocationDetails(reason, ((Number) data.get("revokedAt")).longValue(),
                            (String) data.get("revocation_scope"));
                } catch (RuntimeException e) {
                    // Legacy format (just '1').
                    return new RevocationDetails(RevocationReason.ACTIVE_THREAT, nowMs(), "precise");
                }
            });
        }

        private static String toJson(IsolatedCredentialData data) {
            return "{\"realToken\":" + jsonString(data.realToken()) + ",\"userId\":" + jsonString(data.userId())
                    + ",\"createdAt\":" + data.createdAt() + "}";
        }

        private static String jsonString(String s) {
            return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }

        private static Object parseJson(String text) {
            return Json.decode(text);
        }
    }
}
