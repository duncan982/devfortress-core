<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** One audit-log entry for API key alias lifecycle events (A19). */
final class AliasAuditEvent
{
    /** @param array<string, mixed>|null $metadata */
    public function __construct(
        public readonly string $type,
        public readonly string $aliasId,
        public readonly string $primaryKeyHash,
        public readonly string $workload,
        public readonly int $timestamp,
        public readonly ?array $metadata = null,
    ) {
    }
}
