<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Mutable per-session loop-detection state for AgentLoopDetector. */
final class AgentLoopSession
{
    public int $cycles = 0;
    public int $totalTokens = 0;
    /** @var list<string> */
    public array $toolHistory = [];
    /** @var list<string> */
    public array $argHashes = [];
    /** @var list<float> */
    public array $progressMetrics = [];
    public bool $paused = false;

    public function __construct(
        public readonly string $agentId,
        public readonly int $startedAt,
    ) {
    }
}
