package net.devfortress;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * DevFortress SDK — A19: API Key Aliasing Service. Mirrors
 * {@code packages/devfortress-sdk/src/api-key-aliasing.ts}.
 *
 * <p>Provides alias lifecycle management for API keys: create, rotate,
 * revoke, inspect, and audit. Each alias is scoped to a workload (CI,
 * agent, browser, server) with fingerprint and scope binding.
 *
 * <p>Forward-map storage uses {@link CredentialVault}'s real AES-256-GCM
 * primitive — genuinely reversible via {@link #resolve}, unlike a one-way
 * HMAC digest.
 *
 * <p>Patent Pending — KIPI KE/P/2026/005972. Prior art:
 * https://www.tdcommons.org/dpubs_series/9907/
 */
public final class ApiKeyAliasingService {
    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();

    public enum Workload {
        CI, AGENT, PLUGIN, BROWSER, SERVER, CUSTOM
    }

    public enum AliasState {
        ACTIVE, ROTATING, REVOKED, EXPIRED
    }

    public static final class AliasRecord {
        public final String aliasId;
        String aliasKeyEncrypted; // The alias API key, encrypted at rest (JSON VaultEncryptedRecord).
        public final String primaryKeyHash;
        public final String label;
        public final Workload workload;
        public volatile AliasState state;
        public final String fingerprint;
        public final List<String> scope;
        public final long createdAt;
        public volatile Long expiresAt;
        public volatile long lastUsedAt;
        public volatile String rotatedFromId;
        public volatile String rotatedToId;
        public volatile int usageCount;

        AliasRecord(String aliasId, String aliasKeyEncrypted, String primaryKeyHash, Workload workload, String label,
                    String fingerprint, List<String> scope, long createdAt, Long expiresAt) {
            this.aliasId = aliasId;
            this.aliasKeyEncrypted = aliasKeyEncrypted;
            this.primaryKeyHash = primaryKeyHash;
            this.workload = workload;
            this.label = label;
            this.state = AliasState.ACTIVE;
            this.fingerprint = fingerprint;
            this.scope = scope;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.lastUsedAt = createdAt;
            this.usageCount = 0;
        }

        /** A copy with the encrypted key redacted — safe to hand back to a caller that only needs metadata. */
        public AliasRecord redacted() {
            AliasRecord copy = new AliasRecord(aliasId, "[REDACTED]", primaryKeyHash, workload, label, fingerprint, scope, createdAt, expiresAt);
            copy.state = state;
            copy.lastUsedAt = lastUsedAt;
            copy.rotatedFromId = rotatedFromId;
            copy.rotatedToId = rotatedToId;
            copy.usageCount = usageCount;
            return copy;
        }
    }

    public enum AuditEventType {
        ALIAS_CREATED, ALIAS_ROTATED, ALIAS_REVOKED, ALIAS_MISUSE_DETECTED, ALIAS_EXPIRED, ALIAS_USED
    }

    public record AuditEvent(AuditEventType type, String aliasId, String primaryKeyHash, Workload workload,
                              long timestamp, Map<String, Object> metadata) {
    }

    public record CreationResult(boolean success, AliasRecord alias, String aliasKey, String error) {
        static CreationResult failure(String error) {
            return new CreationResult(false, null, null, error);
        }
    }

    public record RotationResult(boolean success, String oldAliasId, AliasRecord newAlias, String newAliasKey,
                                  Long overlapExpiresAt, String error) {
        static RotationResult failure(String error) {
            return new RotationResult(false, null, null, null, null, error);
        }
    }

    public record ValidationResult(boolean valid, String aliasId, Workload workload, String primaryKeyHash,
                                    String reason, boolean anomalyDetected) {
        static ValidationResult invalid(String reason) {
            return new ValidationResult(false, null, null, null, reason, false);
        }
    }

    public record Stats(int totalAliases, int activeAliases, int rotatingAliases, int revokedAliases,
                         Map<Workload, Integer> byWorkload, int recentAnomalies) {
    }

    /** Builder-style config. */
    public static final class Config {
        int maxAliasesPerKey = 50;
        long rotationOverlapMs = 300_000;
        boolean anomalyDetection = true;
        int creationBurstThreshold = 10;
        String vaultSecret;

        public Config maxAliasesPerKey(int n) {
            this.maxAliasesPerKey = n;
            return this;
        }

        public Config rotationOverlapMs(long ms) {
            this.rotationOverlapMs = ms;
            return this;
        }

        public Config anomalyDetection(boolean enabled) {
            this.anomalyDetection = enabled;
            return this;
        }

        public Config creationBurstThreshold(int n) {
            this.creationBurstThreshold = n;
            return this;
        }

        /**
         * Application secret used to derive the forward-map's AES-256-GCM vault key (HKDF). If
         * omitted, a random per-instance key is generated at construction time — alias keys
         * remain resolvable for the lifetime of this service instance, but not across process
         * restarts.
         */
        public Config vaultSecret(String secret) {
            this.vaultSecret = secret;
            return this;
        }
    }

    private final Config config;
    private final Map<String, AliasRecord> aliases = new HashMap<>();
    private final Map<String, String> aliasKeyIndex = new HashMap<>(); // aliasKeyHash -> aliasId
    private final Map<String, Set<String>> primaryKeyAliases = new HashMap<>();
    private final List<AuditEvent> auditLog = new ArrayList<>();
    private final List<Long> creationTimestamps = new ArrayList<>();
    private final byte[] vaultKey;
    private final Object lock = new Object();

    public ApiKeyAliasingService() {
        this(new Config());
    }

    public ApiKeyAliasingService(Config config) {
        this.config = config;
        this.vaultKey = (config.vaultSecret != null && !config.vaultSecret.isEmpty())
                ? CredentialVault.deriveVaultKey(config.vaultSecret, "api-key-aliasing")
                : randomKey();
    }

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    /** Create a new alias for a primary API key. */
    public CreationResult createAlias(String primaryKeyHash, Workload workload, String label) {
        return createAlias(primaryKeyHash, workload, label, null, null, null);
    }

    public CreationResult createAlias(String primaryKeyHash, Workload workload, String label,
                                       String fingerprint, List<String> scope, Long expiresInMs) {
        long now = System.currentTimeMillis();

        synchronized (lock) {
            Set<String> existing = primaryKeyAliases.get(primaryKeyHash);
            if (existing != null && existing.size() >= config.maxAliasesPerKey) {
                return CreationResult.failure("Maximum aliases (" + config.maxAliasesPerKey + ") reached for this key");
            }

            if (config.anomalyDetection) {
                creationTimestamps.add(now);
                long recentCount = creationTimestamps.stream().filter(t -> now - t <= 3_600_000).count();
                if (recentCount > config.creationBurstThreshold) {
                    emitAudit(new AuditEvent(AuditEventType.ALIAS_MISUSE_DETECTED, "N/A", primaryKeyHash, workload, now,
                            Map.of("reason", "creation_burst", "count", recentCount)));
                    return CreationResult.failure("Alias creation burst detected: " + recentCount + " in 1 hour");
                }
            }

            byte[] aliasIdRandom = new byte[16];
            RANDOM.nextBytes(aliasIdRandom);
            String aliasId = "alias_" + HEX.formatHex(aliasIdRandom);
            byte[] aliasKeyRandom = new byte[24];
            RANDOM.nextBytes(aliasKeyRandom);
            String aliasKey = "vx_alias_" + HEX.formatHex(aliasKeyRandom);
            String aliasKeyHash = sha256Hex(aliasKey);

            AliasRecord record = new AliasRecord(aliasId, encryptAliasKey(aliasKey, primaryKeyHash), primaryKeyHash,
                    workload, label, fingerprint, scope, now, expiresInMs != null ? now + expiresInMs : null);

            aliases.put(aliasId, record);
            aliasKeyIndex.put(aliasKeyHash, aliasId);
            primaryKeyAliases.computeIfAbsent(primaryKeyHash, k -> new LinkedHashSet<>()).add(aliasId);

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("label", label);
            metadata.put("hasFingerprint", fingerprint != null);
            metadata.put("scope", scope);
            emitAudit(new AuditEvent(AuditEventType.ALIAS_CREATED, aliasId, primaryKeyHash, workload, now, metadata));

            return new CreationResult(true, record.redacted(), aliasKey, null);
        }
    }

    /** Rotate an alias with a zero-downtime overlap window. */
    public RotationResult rotateAlias(String aliasId) {
        long now = System.currentTimeMillis();
        synchronized (lock) {
            AliasRecord oldAlias = aliases.get(aliasId);
            if (oldAlias == null || oldAlias.state != AliasState.ACTIVE) {
                return RotationResult.failure("Alias " + aliasId + " not found or not active");
            }

            oldAlias.state = AliasState.ROTATING;
            oldAlias.expiresAt = now + config.rotationOverlapMs;

            CreationResult result = createAlias(oldAlias.primaryKeyHash, oldAlias.workload, oldAlias.label + " (rotated)",
                    oldAlias.fingerprint, oldAlias.scope, null);

            if (!result.success()) {
                oldAlias.state = AliasState.ACTIVE; // Rollback.
                return RotationResult.failure(result.error());
            }

            oldAlias.rotatedToId = result.alias().aliasId;
            aliases.get(result.alias().aliasId).rotatedFromId = aliasId;

            emitAudit(new AuditEvent(AuditEventType.ALIAS_ROTATED, aliasId, oldAlias.primaryKeyHash, oldAlias.workload, now,
                    Map.of("newAliasId", result.alias().aliasId, "overlapMs", config.rotationOverlapMs)));

            return new RotationResult(true, aliasId, result.alias(), result.aliasKey(), oldAlias.expiresAt, null);
        }
    }

    /** Revoke a specific alias without affecting other aliases. */
    public boolean revokeAlias(String aliasId, String reason) {
        synchronized (lock) {
            AliasRecord alias = aliases.get(aliasId);
            if (alias == null) {
                return false;
            }
            alias.state = AliasState.REVOKED;
            emitAudit(new AuditEvent(AuditEventType.ALIAS_REVOKED, aliasId, alias.primaryKeyHash, alias.workload,
                    System.currentTimeMillis(), Map.of("reason", reason != null ? reason : "manual_revocation")));
            return true;
        }
    }

    /** Validate an alias key for incoming requests. */
    public ValidationResult validateAliasKey(String aliasKey, String fingerprint) {
        String aliasKeyHash = sha256Hex(aliasKey);
        synchronized (lock) {
            String aliasId = aliasKeyIndex.get(aliasKeyHash);
            if (aliasId == null) {
                return ValidationResult.invalid("Unknown alias key");
            }
            AliasRecord alias = aliases.get(aliasId);
            if (alias == null) {
                return ValidationResult.invalid("Alias record not found");
            }

            long now = System.currentTimeMillis();

            if (alias.state == AliasState.REVOKED) {
                return new ValidationResult(false, aliasId, alias.workload, alias.primaryKeyHash, "Alias has been revoked", false);
            }

            if (alias.expiresAt != null && now > alias.expiresAt) {
                alias.state = AliasState.EXPIRED;
                emitAudit(new AuditEvent(AuditEventType.ALIAS_EXPIRED, aliasId, alias.primaryKeyHash, alias.workload, now, Map.of()));
                return new ValidationResult(false, aliasId, alias.workload, alias.primaryKeyHash, "Alias has expired", false);
            }

            boolean anomalyDetected = false;
            if (alias.fingerprint != null && fingerprint != null && !alias.fingerprint.equals(fingerprint)) {
                anomalyDetected = true;
                emitAudit(new AuditEvent(AuditEventType.ALIAS_MISUSE_DETECTED, aliasId, alias.primaryKeyHash, alias.workload, now,
                        Map.of("reason", "fingerprint_mismatch", "expectedFingerprint",
                                alias.fingerprint.substring(0, Math.min(8, alias.fingerprint.length())))));
            }

            alias.lastUsedAt = now;
            alias.usageCount++;
            emitAudit(new AuditEvent(AuditEventType.ALIAS_USED, aliasId, alias.primaryKeyHash, alias.workload, now, Map.of()));

            return new ValidationResult(!anomalyDetected, aliasId, alias.workload, alias.primaryKeyHash,
                    anomalyDetected ? "Fingerprint mismatch detected" : "Valid alias", anomalyDetected);
        }
    }

    public ValidationResult validateAliasKey(String aliasKey) {
        return validateAliasKey(aliasKey, null);
    }

    /** List all aliases for a primary key (encrypted key redacted). */
    public List<AliasRecord> listAliases(String primaryKeyHash) {
        synchronized (lock) {
            Set<String> ids = primaryKeyAliases.get(primaryKeyHash);
            if (ids == null) {
                return List.of();
            }
            List<AliasRecord> result = new ArrayList<>();
            for (String id : ids) {
                AliasRecord a = aliases.get(id);
                if (a != null) {
                    result.add(a.redacted());
                }
            }
            return result;
        }
    }

    /** Get alias statistics. */
    public Stats getStats() {
        synchronized (lock) {
            int active = 0;
            int rotating = 0;
            int revoked = 0;
            Map<Workload, Integer> byWorkload = new EnumMap<>(Workload.class);
            for (Workload w : Workload.values()) {
                byWorkload.put(w, 0);
            }
            for (AliasRecord a : aliases.values()) {
                if (a.state == AliasState.ACTIVE) {
                    active++;
                } else if (a.state == AliasState.ROTATING) {
                    rotating++;
                } else if (a.state == AliasState.REVOKED) {
                    revoked++;
                }
                byWorkload.merge(a.workload, 1, Integer::sum);
            }
            long oneHourAgo = System.currentTimeMillis() - 3_600_000;
            int recentAnomalies = (int) auditLog.stream()
                    .filter(e -> e.type() == AuditEventType.ALIAS_MISUSE_DETECTED && e.timestamp() > oneHourAgo)
                    .count();
            return new Stats(aliases.size(), active, rotating, revoked, byWorkload, recentAnomalies);
        }
    }

    /** Get audit log entries, most recent {@code limit}. */
    public List<AuditEvent> getAuditLog(int limit) {
        synchronized (lock) {
            int from = Math.max(0, auditLog.size() - limit);
            return new ArrayList<>(auditLog.subList(from, auditLog.size()));
        }
    }

    /**
     * Resolve a stored alias back to its real alias key. Returns null for an unknown/revoked/
     * expired alias, or if the stored ciphertext fails auth-tag verification (tampered/corrupted).
     */
    public String resolve(String aliasId) {
        synchronized (lock) {
            AliasRecord alias = aliases.get(aliasId);
            if (alias == null || alias.state == AliasState.REVOKED || alias.state == AliasState.EXPIRED) {
                return null;
            }
            try {
                CredentialVault.VaultEncryptedRecord record = parseVaultRecord(alias.aliasKeyEncrypted);
                String decrypted = CredentialVault.decrypt(record, vaultKey);
                int separator = decrypted.indexOf(':');
                return separator == -1 ? decrypted : decrypted.substring(separator + 1);
            } catch (RuntimeException e) {
                // Auth-tag verification failed (or malformed stored value) — never return garbage plaintext.
                return null;
            }
        }
    }

    private String encryptAliasKey(String aliasKey, String primaryKeyHash) {
        CredentialVault.VaultEncryptedRecord record = CredentialVault.encrypt(primaryKeyHash + ":" + aliasKey, vaultKey);
        return "{\"ciphertext\":\"" + record.ciphertext() + "\",\"iv\":\"" + record.iv() + "\",\"authTag\":\"" + record.authTag() + "\"}";
    }

    @SuppressWarnings("unchecked")
    private static CredentialVault.VaultEncryptedRecord parseVaultRecord(String json) {
        Map<String, Object> decoded = (Map<String, Object>) Json.decode(json);
        return new CredentialVault.VaultEncryptedRecord((String) decoded.get("ciphertext"), (String) decoded.get("iv"), (String) decoded.get("authTag"));
    }

    private void emitAudit(AuditEvent event) {
        auditLog.add(event);
        if (auditLog.size() > 10_000) {
            auditLog.subList(0, auditLog.size() - 10_000).clear();
        }
    }

    private static String sha256Hex(String value) {
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
