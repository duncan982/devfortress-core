<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Clock Drift Anomaly Detector (Invention A18).
 *
 * Mirrors packages/devfortress-sdk/src/security-extensions.ts's
 * ClockDriftDetector. TODO 419/422 — one of the 20 Node-only claims
 * identified by the 2026-11-02 patent audit; ported to Python and Go in
 * that session, here extended to PHP.
 *
 * Compares a client-supplied timestamp against server time and
 * classifies the drift into an escalating action: allow, warn (audit
 * with server time), use_server_time (enforce server-authoritative
 * timestamps), or reject (possible timestamp manipulation).
 *
 * @phpstan-type ClockDriftResult array{
 *     valid: bool,
 *     driftMs: float,
 *     severity: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL',
 *     action: 'allow'|'warn'|'use_server_time'|'reject',
 *     reason: string,
 * }
 * @phpstan-type ClockDriftTrend array{avgDrift: float, increasing: bool}
 */
final class ClockDriftDetector
{
    private const MAX_HISTORY_PER_CLIENT = 100;

    /** @var array<string, list<float>> */
    private array $driftHistory = [];

    public function __construct(
        private readonly float $acceptableThresholdMs = 30_000.0,
        private readonly float $suspiciousThresholdMs = 120_000.0,
        private readonly float $criticalThresholdMs = 300_000.0,
    ) {
    }

    /**
     * Check a client timestamp (epoch milliseconds) against server time.
     *
     * @return array{valid: bool, driftMs: float, severity: string, action: string, reason: string}
     */
    public function check(float $clientTimestampMs, ?string $clientId = null): array
    {
        $serverTimeMs = microtime(true) * 1000;
        $driftMs = abs($clientTimestampMs - $serverTimeMs);
        $direction = $clientTimestampMs > $serverTimeMs ? 'ahead' : 'behind';

        if ($clientId !== null) {
            $this->driftHistory[$clientId] ??= [];
            $this->driftHistory[$clientId][] = $driftMs;
            while (count($this->driftHistory[$clientId]) > self::MAX_HISTORY_PER_CLIENT) {
                array_shift($this->driftHistory[$clientId]);
            }
        }

        if ($driftMs <= $this->acceptableThresholdMs) {
            return [
                'valid' => true, 'driftMs' => $driftMs, 'severity' => 'LOW', 'action' => 'allow',
                'reason' => sprintf('Clock drift %.0fms (%s) within acceptable range', $driftMs, $direction),
            ];
        }

        if ($driftMs <= $this->suspiciousThresholdMs) {
            return [
                'valid' => true, 'driftMs' => $driftMs, 'severity' => 'MEDIUM', 'action' => 'warn',
                'reason' => sprintf('Clock drift %.0fms (%s) — suspicious, using server time for audit', $driftMs, $direction),
            ];
        }

        if ($driftMs <= $this->criticalThresholdMs) {
            return [
                'valid' => true, 'driftMs' => $driftMs, 'severity' => 'HIGH', 'action' => 'use_server_time',
                'reason' => sprintf('Clock drift %.0fms (%s) — enforcing server-authoritative timestamps', $driftMs, $direction),
            ];
        }

        return [
            'valid' => false, 'driftMs' => $driftMs, 'severity' => 'CRITICAL', 'action' => 'reject',
            'reason' => sprintf('Clock drift %.0fms (%s) exceeds critical threshold — possible timestamp manipulation', $driftMs, $direction),
        ];
    }

    /**
     * Returns the drift trend for a client, or null if fewer than 3 samples.
     *
     * @return array{avgDrift: float, increasing: bool}|null
     */
    public function getDriftTrend(string $clientId): ?array
    {
        $history = $this->driftHistory[$clientId] ?? null;
        if ($history === null || count($history) < 3) {
            return null;
        }

        $avgDrift = array_sum($history) / count($history);
        $recent = array_slice($history, -3);
        $recentAvg = array_sum($recent) / 3;

        return ['avgDrift' => $avgDrift, 'increasing' => $recentAvg > $avgDrift * 1.2];
    }

    /** @return array{trackedClients: int} */
    public function getStats(): array
    {
        return ['trackedClients' => count($this->driftHistory)];
    }
}
