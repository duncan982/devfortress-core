<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Agent credential alias metadata (IP-C2). Mutable: quarantine fields change in place. */
final class AgentCredentialAliasData
{
    public bool $quarantined = false;
    public ?string $quarantineReason = null;
    public ?int $quarantinedAt = null;

    /** @param array{containerId?: string, expectedEgressPath?: string, expectedProcessSignature?: string}|null $executionContext */
    public function __construct(
        public readonly string $alias,
        public readonly string $agentId,
        public readonly string $credentialType,
        public readonly int $createdAt,
        public readonly ?array $executionContext = null,
    ) {
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'alias' => $this->alias,
            'agentId' => $this->agentId,
            'credentialType' => $this->credentialType,
            'createdAt' => $this->createdAt,
            'quarantined' => $this->quarantined,
            'quarantineReason' => $this->quarantineReason,
            'quarantinedAt' => $this->quarantinedAt,
            'executionContext' => $this->executionContext,
        ];
    }
}
