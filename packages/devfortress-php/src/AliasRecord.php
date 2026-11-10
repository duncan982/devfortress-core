<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** API key alias record (A19). Mutable: state/usage change in place over its lifecycle. */
final class AliasRecord
{
    public string $state;
    public ?int $expiresAt;
    public int $lastUsedAt;
    public ?string $rotatedFromId = null;
    public ?string $rotatedToId = null;
    public int $usageCount = 0;

    /** @param list<string>|null $scope */
    public function __construct(
        public readonly string $aliasId,
        public string $aliasKey,
        public readonly string $primaryKeyHash,
        public readonly string $workload,
        public readonly string $label,
        public readonly ?string $fingerprint,
        public readonly ?array $scope,
        public readonly int $createdAt,
    ) {
        $this->state = 'active';
        $this->expiresAt = null;
        $this->lastUsedAt = $createdAt;
    }

    public function redacted(): self
    {
        $copy = clone $this;
        $copy->aliasKey = '[REDACTED]';

        return $copy;
    }
}
