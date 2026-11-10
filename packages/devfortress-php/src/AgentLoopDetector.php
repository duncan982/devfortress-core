<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — A10: Agent Loop Detector.
 *
 * Instruments the SDK to track agent execution cycles and token
 * consumption. Detects infinite loops via cycle count, time budget, and
 * token budget thresholds. Implements an automatic circuit breaker: pause
 * agent, alert owner. Distinguishes legitimate long operations from
 * runaway loops via progress metrics. Mirrors
 * packages/devfortress-sdk/src/agent-loop-detector.ts.
 */
final class AgentLoopDetector
{
    /** @var array<string, AgentLoopSession> */
    private array $sessions = [];

    public function __construct(
        private readonly int $maxCycles = 20,
        private readonly int $maxDurationMs = 120_000,
        private readonly int $maxTokens = 100_000,
        private readonly int $progressUniqueTools = 2,
        private readonly int $progressWindowCycles = 5,
        private readonly int $maxSessions = 50_000,
        private readonly bool $debug = false,
    ) {
    }

    /**
     * Record a new execution cycle for an agent session. Check
     * result['loop'] and result['action'].
     *
     * @param array<string, mixed>|null $toolArgs
     * @return array{loop: bool, reason: string, action: string, cycles: int, totalTokens: int, elapsedMs: int, makingProgress: bool, repetitionScore: float}
     */
    public function recordCycle(
        string $agentId,
        string $sessionId,
        ?int $tokensUsed = null,
        ?string $toolName = null,
        ?array $toolArgs = null,
        ?float $progressMetric = null,
    ): array {
        $session = $this->getOrCreateSession($agentId, $sessionId);
        $now = self::nowMs();

        if ($session->paused) {
            return $this->buildResult($session, $now, true, 'agent_paused', 'TERMINATE');
        }

        $session->cycles++;
        $session->totalTokens += $tokensUsed ?? 0;

        if ($toolName !== null) {
            $session->toolHistory[] = $toolName;
        }
        if ($toolArgs !== null) {
            $session->argHashes[] = self::hashArgs($toolArgs);
        }
        if ($progressMetric !== null) {
            $session->progressMetrics[] = $progressMetric;
        }

        $elapsedMs = $now - $session->startedAt;
        $makingProgress = $this->checkProgress($session);

        if ($session->cycles >= $this->maxCycles && !$makingProgress) {
            $session->paused = true;

            return $this->buildResult($session, $now, true, 'max_cycles', 'PAUSE_AGENT');
        }

        if ($elapsedMs >= $this->maxDurationMs) {
            $session->paused = true;

            return $this->buildResult($session, $now, true, 'max_duration', 'PAUSE_AGENT');
        }

        if ($session->totalTokens >= $this->maxTokens) {
            $session->paused = true;

            return $this->buildResult($session, $now, true, 'max_tokens', 'PAUSE_AGENT');
        }

        $repetitionScore = $this->computeRepetitionScore($session);
        if ($repetitionScore > 0.8 && $session->cycles > 5 && !$makingProgress) {
            $session->paused = true;

            return $this->buildResult($session, $now, true, 'repetitive_pattern', 'PAUSE_AGENT');
        }

        if (
            $session->cycles >= $this->maxCycles * 0.8
            || $elapsedMs >= $this->maxDurationMs * 0.8
            || $session->totalTokens >= $this->maxTokens * 0.8
        ) {
            return $this->buildResult($session, $now, false, 'approaching_limit', 'WARN');
        }

        return $this->buildResult($session, $now, false, 'within_limits', 'CONTINUE');
    }

    /** Clear a session. */
    public function clearSession(string $sessionId): void
    {
        unset($this->sessions[$sessionId]);
    }

    /** Release an agent from paused state (after human review). */
    public function releaseAgent(string $sessionId): bool
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session === null) {
            return false;
        }
        $session->paused = false;
        $session->cycles = 0;
        $session->totalTokens = 0;
        $session->toolHistory = [];
        $session->argHashes = [];

        return true;
    }

    public function isPaused(string $sessionId): bool
    {
        return array_key_exists($sessionId, $this->sessions) && $this->sessions[$sessionId]->paused;
    }

    /** @return array{exists: bool, cycles: int, tokens: int, elapsedMs: int, paused: bool} */
    public function getMetrics(string $sessionId): array
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session === null) {
            return ['exists' => false, 'cycles' => 0, 'tokens' => 0, 'elapsedMs' => 0, 'paused' => false];
        }

        return [
            'exists' => true,
            'cycles' => $session->cycles,
            'tokens' => $session->totalTokens,
            'elapsedMs' => self::nowMs() - $session->startedAt,
            'paused' => $session->paused,
        ];
    }

    public function destroy(): void
    {
        $this->sessions = [];
    }

    private function getOrCreateSession(string $agentId, string $sessionId): AgentLoopSession
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session === null) {
            if (count($this->sessions) >= $this->maxSessions) {
                unset($this->sessions[array_key_first($this->sessions)]);
            }
            $session = new AgentLoopSession($agentId, self::nowMs());
            $this->sessions[$sessionId] = $session;
        }

        return $session;
    }

    private function checkProgress(AgentLoopSession $session): bool
    {
        $recentTools = array_slice($session->toolHistory, -$this->progressWindowCycles);
        $uniqueInWindow = count(array_unique($recentTools));

        if ($uniqueInWindow >= $this->progressUniqueTools) {
            return true;
        }

        if (count($session->progressMetrics) >= 2) {
            $recent = array_slice($session->progressMetrics, -3);
            $increasing = true;
            foreach ($recent as $i => $v) {
                if ($i !== 0 && $v <= $recent[$i - 1]) {
                    $increasing = false;
                    break;
                }
            }
            if ($increasing) {
                return true;
            }
        }

        return false;
    }

    private function computeRepetitionScore(AgentLoopSession $session): float
    {
        if (count($session->argHashes) < 3) {
            return 0.0;
        }
        $recent = array_slice($session->argHashes, -10);
        $uniqueHashes = count(array_unique($recent));

        return 1 - $uniqueHashes / count($recent);
    }

    /** @param array<string, mixed> $args */
    private static function hashArgs(array $args): string
    {
        ksort($args);
        $str = json_encode($args, JSON_THROW_ON_ERROR);
        $hash = 0;
        $len = strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $char = ord($str[$i]);
            $hash = self::int32((($hash << 5) - $hash) + $char);
        }

        return self::base36($hash);
    }

    /** Emulate JS's (x | 0) 32-bit signed integer truncation. */
    private static function int32(int $value): int
    {
        $value &= 0xFFFFFFFF;
        if ($value & 0x80000000) {
            $value -= 0x100000000;
        }

        return $value;
    }

    /** Signed base-36, matching JS's Number.prototype.toString(36). */
    private static function base36(int $value): string
    {
        if ($value === 0) {
            return '0';
        }
        $negative = $value < 0;
        $value = abs($value);
        $digits = '0123456789abcdefghijklmnopqrstuvwxyz';
        $out = '';
        while ($value > 0) {
            $out = $digits[$value % 36] . $out;
            $value = intdiv($value, 36);
        }

        return $negative ? "-{$out}" : $out;
    }

    /** @return array{loop: bool, reason: string, action: string, cycles: int, totalTokens: int, elapsedMs: int, makingProgress: bool, repetitionScore: float} */
    private function buildResult(AgentLoopSession $session, int $now, bool $loop, string $reason, string $action): array
    {
        $elapsedMs = $now - $session->startedAt;
        $makingProgress = $this->checkProgress($session);
        $repetitionScore = $this->computeRepetitionScore($session);

        if ($this->debug) {
            error_log("[A10] Agent {$session->agentId}: {$reason} — cycles={$session->cycles}, tokens={$session->totalTokens}, elapsed={$elapsedMs}ms, action={$action}");
        }

        return [
            'loop' => $loop,
            'reason' => $reason,
            'action' => $action,
            'cycles' => $session->cycles,
            'totalTokens' => $session->totalTokens,
            'elapsedMs' => $elapsedMs,
            'makingProgress' => $makingProgress,
            'repetitionScore' => $repetitionScore,
        ];
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
