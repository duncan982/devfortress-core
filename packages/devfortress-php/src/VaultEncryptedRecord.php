<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Hex-encoded AES-256-GCM ciphertext bundle. */
final class VaultEncryptedRecord
{
    public function __construct(
        public readonly string $ciphertext,
        public readonly string $iv,
        public readonly string $authTag,
    ) {
    }
}
