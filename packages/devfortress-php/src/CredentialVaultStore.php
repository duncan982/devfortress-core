<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * A self-contained, in-memory vault instance: encrypts + stores real
 * credentials under an alias, later resolves the alias back to plaintext.
 * Used wherever a class needs its own alias-keyed encrypted store (rather
 * than a shared module-level store).
 */
final class CredentialVaultStore
{
    private const MAX_TRACKED_RECORDS = 50_000;

    /** @var array<string, array{record: VaultEncryptedRecord, key: string}> */
    private array $store = [];

    public function __construct(private readonly int $maxEntries = self::MAX_TRACKED_RECORDS)
    {
    }

    public function register(string $alias, string $realCredential, string $key): VaultEncryptedRecord
    {
        $record = CredentialVault::encrypt($realCredential, $key);
        if (array_key_exists($alias, $this->store)) {
            unset($this->store[$alias]);
        } elseif (count($this->store) >= $this->maxEntries && $this->store !== []) {
            unset($this->store[array_key_first($this->store)]);
        }
        $this->store[$alias] = ['record' => $record, 'key' => $key];

        return $record;
    }

    /** Throws (does not return garbage plaintext) on auth-tag mismatch. */
    public function resolve(string $alias): ?string
    {
        $stored = $this->store[$alias] ?? null;
        if ($stored === null) {
            return null;
        }

        return CredentialVault::decrypt($stored['record'], $stored['key']);
    }

    public function revoke(string $alias): bool
    {
        if (!array_key_exists($alias, $this->store)) {
            return false;
        }
        unset($this->store[$alias]);

        return true;
    }

    public function has(string $alias): bool
    {
        return array_key_exists($alias, $this->store);
    }
}
