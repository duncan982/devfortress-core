<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use RuntimeException;

/**
 * Shared AES-256-GCM reversible-encryption primitive.
 *
 * Mirrors packages/devfortress-sdk/src/credential-vault.ts (and the Go/Ruby
 * SDKs' own ports of the same primitive). A generic reversible-encryption
 * primitive; ApiKeyAliasingService
 * and Tier2Gated\IdentityProjection each wire into their own alias-keyed stores.
 *
 * Key derivation: HKDF-SHA256 with a zero salt and a namespaced info string,
 * matching Tier2Gated\AliasGenerator's hkdfAlias.
 */
final class CredentialVault
{
    private function __construct()
    {
    }

    /** Derive a 32-byte AES-256 key from an application secret + context via HKDF-SHA256. */
    public static function deriveVaultKey(string $applicationSecret, string $context): string
    {
        $info = "devfortress.credential-vault.{$context}";

        return hash_hkdf('sha256', $applicationSecret, 32, $info, str_repeat("\0", 32));
    }

    /** Pure primitive: encrypt a real credential with an explicit 32-byte key. */
    public static function encrypt(string $realCredential, string $key): VaultEncryptedRecord
    {
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($realCredential, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($ciphertext === false) {
            throw new RuntimeException('DevFortress\Sdk\CredentialVault: encryption failed');
        }

        return new VaultEncryptedRecord(bin2hex($ciphertext), bin2hex($iv), bin2hex($tag));
    }

    /**
     * Pure primitive: decrypt a ciphertext bundle with an explicit key.
     * Throws (does not return garbage plaintext) on auth-tag mismatch.
     */
    public static function decrypt(VaultEncryptedRecord $record, string $key): string
    {
        $plaintext = openssl_decrypt(
            self::hexDecode($record->ciphertext),
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            self::hexDecode($record->iv),
            self::hexDecode($record->authTag),
        );
        if ($plaintext === false) {
            throw new RuntimeException('DevFortress\Sdk\CredentialVault: auth-tag verification failed');
        }

        return $plaintext;
    }

    /** @internal shared with CredentialIsolationManager's own hex2bin() calls. */
    public static function hexDecode(string $hex): string
    {
        $binary = hex2bin($hex);
        if ($binary === false) {
            throw new RuntimeException('DevFortress\Sdk\CredentialVault: malformed hex string');
        }

        return $binary;
    }
}
