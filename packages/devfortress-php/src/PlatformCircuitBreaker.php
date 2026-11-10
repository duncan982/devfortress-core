<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Platform Circuit Breaker.
 *
 * Mirrors packages/devfortress-sdk/src/circuit-breaker.ts. Monitors
 * connectivity to the DevFortress platform and provides automatic
 * failover from external to internal closed-loop mode.
 *
 * Three states:
 *
 *   'closed':    Platform is reachable, external CL is active
 *   'open':      Platform is unreachable, internal CL takes over
 *   'half-open': Testing if the platform has recovered
 *
 * Transition rules:
 *
 *   closed -> open:      After $failureThreshold consecutive failures
 *   open -> half-open:   After $recoveryTimeSeconds elapsed
 *   half-open -> closed: First successful call
 *   half-open -> open:   First failed call
 *
 * @phpstan-type CircuitState 'closed'|'open'|'half-open'
 * @phpstan-type CircuitBreakerDiagnostics array{
 *     state: CircuitState,
 *     failureCount: int,
 *     lastFailureTime: float,
 *     secondsUntilRecoveryAttempt: float,
 *     rulesStale: bool,
 *     staleDurationSeconds: float,
 * }
 */
final class PlatformCircuitBreaker
{
    /** Rules older than 5 minutes without a platform sync are considered stale. */
    public const STALE_THRESHOLD_SECONDS = 300;

    /** @var CircuitState */
    private string $state = 'closed';
    private int $failureCount = 0;
    private float $lastFailureTime = 0.0;

    /** When internal rules became stale (circuit opened); null if not stale. */
    private ?float $staleSince = null;

    public function __construct(
        private readonly int $failureThreshold = 3,
        private readonly float $recoveryTimeSeconds = 60.0,
        /** @var (\Closure(CircuitState, CircuitState, string): void)|null */
        private readonly ?\Closure $onStateChange = null,
    ) {
    }

    /**
     * Returns whether external platform calls should be attempted
     * (true if closed or half-open).
     */
    public function shouldCallExternal(): bool
    {
        if ($this->state === 'closed') {
            return true;
        }

        if ($this->state === 'open') {
            if (microtime(true) - $this->lastFailureTime >= $this->recoveryTimeSeconds) {
                $this->transition('half-open', 'recovery_timeout_elapsed');

                return true; // allow one test call
            }

            return false;
        }

        // half-open: allow the test call.
        return true;
    }

    /** Records a successful external call. */
    public function recordSuccess(): void
    {
        if ($this->state === 'half-open') {
            $this->transition('closed', 'test_call_succeeded');
        }
        $this->failureCount = 0;
        $this->staleSince = null;
    }

    /** Records a failed external call. */
    public function recordFailure(): void
    {
        $this->failureCount++;
        $this->lastFailureTime = microtime(true);

        if ($this->state === 'half-open') {
            $this->transition('open', 'test_call_failed');

            return;
        }

        if ($this->state === 'closed' && $this->failureCount >= $this->failureThreshold) {
            $this->transition('open', 'consecutive_failures');
        }
    }

    /** @return CircuitState */
    public function getState(): string
    {
        return $this->state;
    }

    /** @return CircuitBreakerDiagnostics */
    public function getDiagnostics(): array
    {
        $secondsUntilRecovery = 0.0;
        if ($this->state === 'open') {
            $elapsed = microtime(true) - $this->lastFailureTime;
            $secondsUntilRecovery = $elapsed < $this->recoveryTimeSeconds
                ? $this->recoveryTimeSeconds - $elapsed
                : 0.0;
        }

        $staleDuration = $this->staleSince !== null ? microtime(true) - $this->staleSince : 0.0;

        return [
            'state' => $this->state,
            'failureCount' => $this->failureCount,
            'lastFailureTime' => $this->lastFailureTime,
            'secondsUntilRecoveryAttempt' => $secondsUntilRecovery,
            'rulesStale' => $staleDuration > self::STALE_THRESHOLD_SECONDS,
            'staleDurationSeconds' => $staleDuration,
        ];
    }

    /** Forces the circuit breaker back to the closed state. */
    public function reset(): void
    {
        $this->transition('closed', 'manual_reset');
        $this->failureCount = 0;
        $this->lastFailureTime = 0.0;
        $this->staleSince = null;
    }

    /**
     * Returns whether internal rules are stale (no platform sync for
     * longer than STALE_THRESHOLD_SECONDS).
     */
    public function isRulesStale(): bool
    {
        return $this->staleSince !== null
            && (microtime(true) - $this->staleSince) > self::STALE_THRESHOLD_SECONDS;
    }

    /** @param CircuitState $to */
    private function transition(string $to, string $reason): void
    {
        $from = $this->state;
        if ($from === $to) {
            return;
        }
        $this->state = $to;

        if ($to === 'open' && $this->staleSince === null) {
            $this->staleSince = microtime(true);
        }

        if ($this->onStateChange !== null) {
            try {
                ($this->onStateChange)($from, $to, $reason);
            } catch (\Throwable) {
                // Callback errors should not break the circuit breaker.
            }
        }
    }
}
