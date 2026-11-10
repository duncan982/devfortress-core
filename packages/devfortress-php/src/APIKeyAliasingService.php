<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use Throwable;

/**
 * API Key Aliasing Service (Invention A19).
 * Patent Pending — KIPI KE/P/2026/005972
 * Prior art: https://www.tdcommons.org/dpubs_series/9907/
 *
 * Mirrors packages/devfortress-sdk/src/api-key-aliasing.ts. Provides alias
 * lifecycle management for API keys: create, rotate, revoke, inspect, and
 * audit. Each alias is scoped to a workload (CI, agent, browser, server)
 * with fingerprint and scope binding. Forward-map storage uses the shared
 * CredentialVault primitive (real AES-256-GCM, resolvable).
 */
final class APIKeyAliasingService
{
    public const WORKLOADS = ['ci', 'agent', 'plugin', 'browser', 'server', 'custom'];

    /** @var array<string, AliasRecord> */
    private array $aliases = [];
    /** @var array<string, string> aliasKeyHash => aliasId */
    private array $aliasKeyIndex = [];
    /** @var array<string, list<string>> primaryKeyHash => list<aliasId> */
    private array $primaryKeyAliases = [];
    /** @var list<AliasAuditEvent> */
    private array $auditLog = [];
    /** @var list<int> */
    private array $creationTimestamps = [];
    private readonly string $vaultKey;

    public function __construct(
        private readonly int $maxAliasesPerKey = 50,
        private readonly int $rotationOverlapMs = 300_000,
        private readonly int $maxPrimaryKeys = 10_000,
        private readonly bool $anomalyDetection = true,
        private readonly int $creationBurstThreshold = 10,
        ?string $vaultSecret = null,
        private readonly bool $debug = false,
    ) {
        $this->vaultKey = $vaultSecret !== null
            ? CredentialVault::deriveVaultKey($vaultSecret, 'api-key-aliasing')
            : random_bytes(32);
    }

    /**
     * Create a new alias for a primary API key.
     *
     * @param list<string>|null $scope
     * @return array{success: true, alias: AliasRecord, aliasKey: string}|array{success: false, error: string}
     */
    public function createAlias(
        string $primaryKeyHash,
        string $workload,
        string $label,
        ?string $fingerprint = null,
        ?array $scope = null,
        ?int $expiresInMs = null,
    ): array {
        $now = self::nowMs();

        $existing = $this->primaryKeyAliases[$primaryKeyHash] ?? null;
        if ($existing !== null && count($existing) >= $this->maxAliasesPerKey) {
            return ['success' => false, 'error' => "Maximum aliases ({$this->maxAliasesPerKey}) reached for this key"];
        }

        if ($this->anomalyDetection) {
            $this->creationTimestamps[] = $now;
            $recentCreations = array_values(array_filter($this->creationTimestamps, static fn ($t) => $now - $t <= 3_600_000));
            if (count($recentCreations) > $this->creationBurstThreshold) {
                $this->emitAudit('alias_misuse_detected', 'N/A', $primaryKeyHash, $workload, $now, [
                    'reason' => 'creation_burst', 'count' => count($recentCreations),
                ]);

                return ['success' => false, 'error' => 'Alias creation burst detected: ' . count($recentCreations) . ' in 1 hour'];
            }
        }

        $aliasId = 'alias_' . bin2hex(random_bytes(16));
        $aliasKey = 'vx_alias_' . bin2hex(random_bytes(24));
        $aliasKeyHash = hash('sha256', $aliasKey);

        $record = new AliasRecord(
            aliasId: $aliasId,
            aliasKey: $this->encryptAliasKey($aliasKey, $primaryKeyHash),
            primaryKeyHash: $primaryKeyHash,
            workload: $workload,
            label: $label,
            fingerprint: $fingerprint,
            scope: $scope,
            createdAt: $now,
        );
        if ($expiresInMs !== null) {
            $record->expiresAt = $now + $expiresInMs;
        }

        $this->aliases[$aliasId] = $record;
        $this->aliasKeyIndex[$aliasKeyHash] = $aliasId;
        $this->primaryKeyAliases[$primaryKeyHash] ??= [];
        $this->primaryKeyAliases[$primaryKeyHash][] = $aliasId;

        $this->emitAudit('alias_created', $aliasId, $primaryKeyHash, $workload, $now, [
            'label' => $label, 'hasFingerprint' => $fingerprint !== null, 'scope' => $scope,
        ]);

        return ['success' => true, 'alias' => $record->redacted(), 'aliasKey' => $aliasKey];
    }

    /**
     * Rotate an alias with zero-downtime overlap window.
     *
     * @return array{success: true, oldAliasId: string, newAlias: AliasRecord, newAliasKey: string, overlapExpiresAt: int}|array{success: false, error: string}
     */
    public function rotateAlias(string $aliasId): array
    {
        $now = self::nowMs();
        $oldAlias = $this->aliases[$aliasId] ?? null;
        if ($oldAlias === null || $oldAlias->state !== 'active') {
            return ['success' => false, 'error' => "Alias {$aliasId} not found or not active"];
        }

        $oldAlias->state = 'rotating';
        $oldAlias->expiresAt = $now + $this->rotationOverlapMs;

        $result = $this->createAlias(
            $oldAlias->primaryKeyHash,
            $oldAlias->workload,
            "{$oldAlias->label} (rotated)",
            fingerprint: $oldAlias->fingerprint,
            scope: $oldAlias->scope,
        );

        if (!$result['success']) {
            $oldAlias->state = 'active'; // Rollback

            return ['success' => false, 'error' => $result['error']];
        }

        $oldAlias->rotatedToId = $result['alias']->aliasId;
        // The returned record is the redacted copy handed back to the caller;
        // the stored record is the one actually mutated for lineage tracking.
        $this->aliases[$result['alias']->aliasId]->rotatedFromId = $aliasId;

        $this->emitAudit('alias_rotated', $aliasId, $oldAlias->primaryKeyHash, $oldAlias->workload, $now, [
            'newAliasId' => $result['alias']->aliasId, 'overlapMs' => $this->rotationOverlapMs,
        ]);

        return [
            'success' => true,
            'oldAliasId' => $aliasId,
            'newAlias' => $result['alias'],
            'newAliasKey' => $result['aliasKey'],
            'overlapExpiresAt' => $oldAlias->expiresAt,
        ];
    }

    /** Revoke a specific alias without affecting other aliases. */
    public function revokeAlias(string $aliasId, ?string $reason = null): bool
    {
        $alias = $this->aliases[$aliasId] ?? null;
        if ($alias === null) {
            return false;
        }

        $alias->state = 'revoked';
        $this->emitAudit('alias_revoked', $aliasId, $alias->primaryKeyHash, $alias->workload, self::nowMs(), [
            'reason' => $reason ?? 'manual_revocation',
        ]);

        return true;
    }

    /**
     * Validate an alias key for incoming requests.
     *
     * @return array{valid: bool, aliasId?: string, workload?: string, primaryKeyHash?: string, reason: string, anomalyDetected?: bool}
     */
    public function validateAliasKey(string $aliasKey, ?string $fingerprint = null): array
    {
        $aliasKeyHash = hash('sha256', $aliasKey);
        $aliasId = $this->aliasKeyIndex[$aliasKeyHash] ?? null;
        if ($aliasId === null) {
            return ['valid' => false, 'reason' => 'Unknown alias key'];
        }

        $alias = $this->aliases[$aliasId] ?? null;
        if ($alias === null) {
            return ['valid' => false, 'reason' => 'Alias record not found'];
        }

        $now = self::nowMs();

        if ($alias->state === 'revoked') {
            return ['valid' => false, 'aliasId' => $aliasId, 'workload' => $alias->workload, 'reason' => 'Alias has been revoked'];
        }

        if ($alias->expiresAt !== null && $now > $alias->expiresAt) {
            $alias->state = 'expired';
            $this->emitAudit('alias_expired', $aliasId, $alias->primaryKeyHash, $alias->workload, $now);

            return ['valid' => false, 'aliasId' => $aliasId, 'workload' => $alias->workload, 'reason' => 'Alias has expired'];
        }

        $anomalyDetected = false;
        if ($alias->fingerprint !== null && $fingerprint !== null && $alias->fingerprint !== $fingerprint) {
            $anomalyDetected = true;
            $this->emitAudit('alias_misuse_detected', $aliasId, $alias->primaryKeyHash, $alias->workload, $now, [
                'reason' => 'fingerprint_mismatch', 'expectedFingerprint' => substr($alias->fingerprint, 0, 8),
            ]);
        }

        $alias->lastUsedAt = $now;
        $alias->usageCount++;

        $this->emitAudit('alias_used', $aliasId, $alias->primaryKeyHash, $alias->workload, $now);

        return [
            'valid' => !$anomalyDetected,
            'aliasId' => $aliasId,
            'workload' => $alias->workload,
            'primaryKeyHash' => $alias->primaryKeyHash,
            'reason' => $anomalyDetected ? 'Fingerprint mismatch detected' : 'Valid alias',
            'anomalyDetected' => $anomalyDetected,
        ];
    }

    /** @return list<AliasRecord> */
    public function listAliases(string $primaryKeyHash): array
    {
        $aliasIds = $this->primaryKeyAliases[$primaryKeyHash] ?? null;
        if ($aliasIds === null) {
            return [];
        }

        $result = [];
        foreach ($aliasIds as $id) {
            if (isset($this->aliases[$id])) {
                $result[] = $this->aliases[$id]->redacted();
            }
        }

        return $result;
    }

    /** @return array{totalAliases: int, activeAliases: int, rotatingAliases: int, revokedAliases: int, byWorkload: array<string, int>, recentAnomalies: int} */
    public function getStats(): array
    {
        $stats = [
            'totalAliases' => count($this->aliases),
            'activeAliases' => 0,
            'rotatingAliases' => 0,
            'revokedAliases' => 0,
            'byWorkload' => array_fill_keys(self::WORKLOADS, 0),
            'recentAnomalies' => 0,
        ];

        foreach ($this->aliases as $alias) {
            match ($alias->state) {
                'active' => $stats['activeAliases']++,
                'rotating' => $stats['rotatingAliases']++,
                'revoked' => $stats['revokedAliases']++,
                default => null,
            };
            $stats['byWorkload'][$alias->workload]++;
        }

        $oneHourAgo = self::nowMs() - 3_600_000;
        $stats['recentAnomalies'] = count(array_filter(
            $this->auditLog,
            static fn (AliasAuditEvent $e) => $e->type === 'alias_misuse_detected' && $e->timestamp > $oneHourAgo,
        ));

        return $stats;
    }

    /** @return list<AliasAuditEvent> */
    public function getAuditLog(int $limit = 100): array
    {
        return array_slice($this->auditLog, -$limit);
    }

    /**
     * Configured max tracked primary keys. Stored for API-shape parity with
     * Node's AliasConfig.maxPrimaryKeys — Node itself never enforces this
     * value anywhere in api-key-aliasing.ts either; this getter exists so
     * the field has a real read site rather than being silently dead.
     */
    public function getMaxPrimaryKeys(): int
    {
        return $this->maxPrimaryKeys;
    }

    /**
     * Resolve a stored alias back to its real alias key. Returns null for
     * an unknown/revoked/expired alias, or if the stored ciphertext fails
     * auth-tag verification (tampered/corrupted).
     */
    public function resolve(string $aliasId): ?string
    {
        $alias = $this->aliases[$aliasId] ?? null;
        if ($alias === null || in_array($alias->state, ['revoked', 'expired'], true)) {
            return null;
        }

        try {
            $record = self::decodeVaultRecord($alias->aliasKey);
            $decrypted = CredentialVault::decrypt($record, $this->vaultKey);
            $separatorIndex = strpos($decrypted, ':');

            return $separatorIndex === false ? $decrypted : substr($decrypted, $separatorIndex + 1);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * AES-256-GCM encrypt the alias key for forward-map storage. Returns a
     * JSON-serialized {ciphertext, iv, authTag} bundle — genuinely
     * reversible via resolve().
     */
    private function encryptAliasKey(string $aliasKey, string $primaryKeyHash): string
    {
        $record = CredentialVault::encrypt("{$primaryKeyHash}:{$aliasKey}", $this->vaultKey);

        return json_encode(['ciphertext' => $record->ciphertext, 'iv' => $record->iv, 'authTag' => $record->authTag], JSON_THROW_ON_ERROR);
    }

    private static function decodeVaultRecord(string $json): VaultEncryptedRecord
    {
        /** @var array{ciphertext: string, iv: string, authTag: string} $data */
        $data = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

        return new VaultEncryptedRecord($data['ciphertext'], $data['iv'], $data['authTag']);
    }

    /** @param array<string, mixed>|null $metadata */
    private function emitAudit(string $type, string $aliasId, string $primaryKeyHash, string $workload, int $timestamp, ?array $metadata = null): void
    {
        $this->auditLog[] = new AliasAuditEvent($type, $aliasId, $primaryKeyHash, $workload, $timestamp, $metadata);
        // Cap audit log at 10K entries
        if (count($this->auditLog) > 10_000) {
            $this->auditLog = array_slice($this->auditLog, count($this->auditLog) - 10_000);
        }
        if ($this->debug) {
            error_log("[A19-Alias] {$type}: {$aliasId} ({$workload})");
        }
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
