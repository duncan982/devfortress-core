<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — A7: Tool-Call Sequence Validator.
 *
 * Validates AI agent tool calls against an authorized directed acyclic
 * graph (DAG). Detects out-of-sequence tool calls that indicate prompt
 * injection attacks — e.g., an agent jumping directly to `place_order`
 * without first calling `add_to_cart`.
 *
 * Graduated response: log -> rate-limit -> block -> revoke session.
 * Mirrors packages/devfortress-sdk/src/tool-call-sequence-validator.ts.
 */
final class ToolCallSequenceValidator
{
    private const MAX_SESSIONS = 50_000;

    /** @var array<string, ToolCallSession> */
    private array $sessions = [];

    /**
     * @param array<string, array{requires: list<string>, maxCalls?: int, riskLevel?: string}> $graph
     */
    public function __construct(
        private readonly array $graph,
        private readonly int $maxViolations = 3,
        private readonly int $violationWindowMs = 300_000,
        private readonly bool $graduatedResponse = true,
        private readonly bool $debug = false,
    ) {
    }

    /**
     * Validate a tool call against the authorized sequence graph. Mutates
     * this session's call history/violation state, so calling this twice
     * with the same arguments does not return the same result the second
     * time — never treat it as pure/memoizable.
     *
     * @phpstan-impure
     * @return array{allowed: bool, reason: string, action: string, promptInjectionLikely: bool, violationCount: int, callHistory: list<string>, missingPrerequisites?: list<string>}
     */
    public function validate(string $sessionId, string $toolName, ?int $timestampMs = null): array
    {
        $session = $this->getOrCreateSession($sessionId);
        $now = $timestampMs ?? self::nowMs();

        // Prune old violations
        $session->violations = array_values(array_filter(
            $session->violations,
            fn (array $v): bool => $now - $v['timestamp'] < $this->violationWindowMs,
        ));

        $graphNode = $this->graph[$toolName] ?? null;

        if ($graphNode === null) {
            $session->violations[] = ['timestamp' => $now, 'tool' => $toolName, 'reason' => 'unknown_tool'];

            return $this->buildResult($session, false, 'unknown_tool', $toolName, []);
        }

        $missingPrereqs = array_values(array_filter(
            $graphNode['requires'],
            fn (string $req): bool => !in_array($req, $session->callHistory, true),
        ));

        if ($missingPrereqs !== []) {
            $session->violations[] = [
                'timestamp' => $now, 'tool' => $toolName, 'reason' => 'missing_prerequisites: ' . implode(', ', $missingPrereqs),
            ];

            return $this->buildResult($session, false, 'out_of_sequence', $toolName, $missingPrereqs);
        }

        $maxCalls = $graphNode['maxCalls'] ?? 0;
        $currentCalls = $session->callCounts[$toolName] ?? 0;
        if ($maxCalls > 0 && $currentCalls >= $maxCalls) {
            $session->violations[] = [
                'timestamp' => $now, 'tool' => $toolName, 'reason' => "max_calls_exceeded: {$currentCalls}/{$maxCalls}",
            ];

            return $this->buildResult($session, false, 'max_calls_exceeded', $toolName, []);
        }

        // Valid — record the call
        $session->callHistory[] = $toolName;
        $session->callCounts[$toolName] = $currentCalls + 1;

        if ($this->debug) {
            error_log("[A7] Session {$sessionId}: {$toolName} ALLOWED (history: " . implode(' -> ', $session->callHistory) . ')');
        }

        return [
            'allowed' => true,
            'reason' => 'valid_sequence',
            'action' => 'allow',
            'promptInjectionLikely' => false,
            'violationCount' => count($session->violations),
            'callHistory' => $session->callHistory,
        ];
    }

    /** Reset a session's state (e.g., after quarantine release). */
    public function resetSession(string $sessionId): void
    {
        unset($this->sessions[$sessionId]);
    }

    /** @return list<string> */
    public function getHistory(string $sessionId): array
    {
        return array_key_exists($sessionId, $this->sessions) ? $this->sessions[$sessionId]->callHistory : [];
    }

    public function clearSession(string $sessionId): void
    {
        unset($this->sessions[$sessionId]);
    }

    /** @return array{exists: bool, callCount: int, violationCount: int, history: list<string>} */
    public function getSessionStats(string $sessionId): array
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session === null) {
            return ['exists' => false, 'callCount' => 0, 'violationCount' => 0, 'history' => []];
        }

        return [
            'exists' => true,
            'callCount' => count($session->callHistory),
            'violationCount' => count($session->violations),
            'history' => $session->callHistory,
        ];
    }

    /** Destroy all sessions and free memory. */
    public function destroy(): void
    {
        $this->sessions = [];
    }

    private function getOrCreateSession(string $sessionId): ToolCallSession
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session === null) {
            if (count($this->sessions) >= self::MAX_SESSIONS) {
                unset($this->sessions[array_key_first($this->sessions)]);
            }
            $session = new ToolCallSession(self::nowMs());
            $this->sessions[$sessionId] = $session;
        }

        return $session;
    }

    /**
     * @param list<string> $missingPrerequisites
     * @return array{allowed: bool, reason: string, action: string, promptInjectionLikely: bool, violationCount: int, callHistory: list<string>, missingPrerequisites?: list<string>}
     */
    private function buildResult(ToolCallSession $session, bool $allowed, string $reason, string $toolName, array $missingPrerequisites): array
    {
        $violationCount = count($session->violations);

        $action = 'log';
        if ($this->graduatedResponse) {
            if ($violationCount >= $this->maxViolations) {
                $action = 'revoke_session';
            } elseif ($violationCount >= 2) {
                $action = 'block';
            } elseif ($violationCount >= 1) {
                $action = 'rate_limit';
            }
        } else {
            $action = 'block';
        }

        $graphNode = $this->graph[$toolName] ?? null;
        $riskLevel = $graphNode['riskLevel'] ?? null;
        $promptInjectionLikely = $reason === 'out_of_sequence' && in_array($riskLevel, ['high', 'critical'], true);

        if ($this->debug) {
            error_log("[A7] Session violation: {$toolName} — {$reason} (violations: {$violationCount}, action: {$action})");
        }

        $result = [
            'allowed' => $allowed,
            'reason' => $reason,
            'action' => $action,
            'promptInjectionLikely' => $promptInjectionLikely,
            'violationCount' => $violationCount,
            'callHistory' => $session->callHistory,
        ];
        if ($missingPrerequisites !== []) {
            $result['missingPrerequisites'] = $missingPrerequisites;
        }

        return $result;
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
