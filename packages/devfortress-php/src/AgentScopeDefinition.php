<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Sanctioned tool scope for an agent (IP-C5). Mutable: allowedTools/updatedAt change in place. */
final class AgentScopeDefinition
{
    /** @param list<string> $allowedTools */
    public function __construct(
        public readonly string $agentId,
        public array $allowedTools,
        public readonly bool $strictMode,
        public readonly int $createdAt,
        public int $updatedAt,
    ) {
    }
}
