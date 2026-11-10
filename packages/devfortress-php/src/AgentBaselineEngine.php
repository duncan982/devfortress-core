<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * Agent Behavioral Baseline (IP-C3). Records normal tool patterns for N
 * sessions: avg tools/session, tool diversity entropy, data volumes,
 * session duration, over a 30-day rolling window. Mirrors
 * packages/devfortress-sdk/src/agent-security.ts's AgentBaselineEngine.
 */
final class AgentBaselineEngine
{
    private const BASELINE_WINDOW_DAYS = 30;
    private const MIN_SESSIONS_FOR_BASELINE = 5;

    /** @var array<string, list<AgentSessionRecord>> */
    private array $sessions = [];
    /** @var array<string, AgentBaselineMetrics> */
    private array $baselines = [];

    /** Record a completed agent session for baseline building. */
    public function recordSession(AgentSessionRecord $record): void
    {
        $sessions = $this->sessions[$record->agentId] ?? [];

        $windowStart = self::nowMs() - self::BASELINE_WINDOW_DAYS * 24 * 60 * 60 * 1000;
        $filtered = array_values(array_filter($sessions, static fn (AgentSessionRecord $s) => $s->startedAt > $windowStart));
        $filtered[] = $record;
        $this->sessions[$record->agentId] = $filtered;

        if (count($filtered) >= self::MIN_SESSIONS_FOR_BASELINE) {
            $this->recalculateBaseline($record->agentId);
        }
    }

    /**
     * Establish a baseline from a task definition (IP-C3). Call this at the
     * start to register what "normal" looks like.
     */
    public function agentBaseline(string $agentId, string $taskDefinition): ?AgentBaselineMetrics
    {
        $existing = $this->baselines[$agentId] ?? null;
        if ($existing !== null) {
            $existing->taskDefinition = $taskDefinition;
            $existing->lastUpdatedAt = self::nowMs();

            return $existing;
        }

        $sessions = $this->sessions[$agentId] ?? [];
        if (count($sessions) < self::MIN_SESSIONS_FOR_BASELINE) {
            return null;
        }

        return $this->recalculateBaseline($agentId, $taskDefinition);
    }

    public function getBaseline(string $agentId): ?AgentBaselineMetrics
    {
        return $this->baselines[$agentId] ?? null;
    }

    /** @return list<AgentSessionRecord> */
    public function sessionsFor(string $agentId): array
    {
        return $this->sessions[$agentId] ?? [];
    }

    /**
     * Whether newValue is a 3σ deviation from values.
     *
     * @param list<int> $values
     */
    public function is3SigmaDeviation(array $values, float $newValue): bool
    {
        if (count($values) < 2) {
            return false;
        }
        $mean = array_sum($values) / count($values);
        $sd = self::stdDev($values);
        if ($sd === 0.0) {
            return $newValue !== $mean;
        }

        return abs($newValue - $mean) > 3 * $sd;
    }

    private function recalculateBaseline(string $agentId, ?string $taskDefinition = null): AgentBaselineMetrics
    {
        $sessions = $this->sessions[$agentId] ?? [];

        $toolsPerSession = array_map(static fn (AgentSessionRecord $s) => count($s->toolCalls), $sessions);
        $avgToolsPerSession = count($sessions) > 0 ? array_sum($toolsPerSession) / count($sessions) : 0.0;

        $allTools = [];
        foreach ($sessions as $s) {
            foreach ($s->toolCalls as $tc) {
                $allTools[] = $tc['tool'];
            }
        }
        $toolDiversityEntropy = AgentBehaviorMath::shannonEntropy($allTools);

        $dataVolumes = array_map(static fn (AgentSessionRecord $s) => $s->totalDataBytes, $sessions);
        $avgDataVolumeBytes = count($sessions) > 0 ? array_sum($dataVolumes) / count($sessions) : 0.0;

        $durations = [];
        foreach ($sessions as $s) {
            if ($s->endedAt !== null) {
                $durations[] = $s->endedAt - $s->startedAt;
            }
        }
        $avgSessionDurationMs = count($durations) > 0 ? array_sum($durations) / count($durations) : 0.0;

        $toolFreq = [];
        foreach ($allTools as $tool) {
            $toolFreq[$tool] = ($toolFreq[$tool] ?? 0) + 1;
        }
        arsort($toolFreq);
        $topTools = array_slice(array_keys($toolFreq), 0, 10);

        $hasExisting = array_key_exists($agentId, $this->baselines);
        $baseline = new AgentBaselineMetrics(
            avgToolsPerSession: $avgToolsPerSession,
            toolDiversityEntropy: $toolDiversityEntropy,
            avgDataVolumeBytes: $avgDataVolumeBytes,
            avgSessionDurationMs: $avgSessionDurationMs,
            topTools: $topTools,
            totalSessions: count($sessions),
            createdAt: $hasExisting ? $this->baselines[$agentId]->createdAt : self::nowMs(),
            lastUpdatedAt: self::nowMs(),
            taskDefinition: $taskDefinition ?? ($hasExisting ? $this->baselines[$agentId]->taskDefinition : null),
        );

        $this->baselines[$agentId] = $baseline;

        return $baseline;
    }

    /** @param list<float|int> $values */
    private static function stdDev(array $values): float
    {
        if (count($values) < 2) {
            return 0.0;
        }
        $mean = array_sum($values) / count($values);
        $sqDiffs = array_map(static fn ($v) => ($v - $mean) ** 2, $values);

        return sqrt(array_sum($sqDiffs) / count($values));
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
