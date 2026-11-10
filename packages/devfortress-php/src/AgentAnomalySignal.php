<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** One detected agent-behavior anomaly (IP-C4). */
final class AgentAnomalySignal
{
    /** @param array<string, mixed> $details */
    public function __construct(
        public readonly string $type,
        public readonly string $agentId,
        public readonly string $severity,
        public readonly string $description,
        public readonly int $detectedAt,
        public readonly array $details,
    ) {
    }
}
