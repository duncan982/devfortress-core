<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Agent behavioral baseline (IP-C3). Mutable: updated as new sessions arrive. */
final class AgentBaselineMetrics
{
    /** @param list<string> $topTools */
    public function __construct(
        public readonly float $avgToolsPerSession,
        public readonly float $toolDiversityEntropy,
        public readonly float $avgDataVolumeBytes,
        public readonly float $avgSessionDurationMs,
        public readonly array $topTools,
        public readonly int $totalSessions,
        public readonly int $createdAt,
        public int $lastUpdatedAt,
        public ?string $taskDefinition = null,
    ) {
    }
}
