<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** A completed (or in-progress) agent session, fed to AgentBaselineEngine/AgentAnomalyDetector. */
final class AgentSessionRecord
{
    /** @param list<array{tool: string, durationMs?: int, dataBytes?: int}> $toolCalls */
    public function __construct(
        public readonly string $sessionId,
        public readonly string $agentId,
        public readonly array $toolCalls,
        public readonly int $startedAt,
        public readonly ?int $endedAt = null,
        public readonly int $totalDataBytes = 0,
    ) {
    }
}
