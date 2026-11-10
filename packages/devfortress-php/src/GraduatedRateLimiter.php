<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Graduated Rate Limiter (Invention A3).
 *
 * Mirrors packages/devfortress-sdk/src/graduated-rate-limiter.ts.
 * Implements alias-scoped graduated rate limiting with multi-stage
 * response escalation. Addresses GAP-A3-1 through GAP-A3-4:
 *
 *   GAP-A3-1: Latency jitter (+/-20%) in soft-limit injection
 *   GAP-A3-2: Per-endpoint hierarchical rate limits (configurable)
 *   GAP-A3-3: Burst detection (1-second micro-window)
 *   GAP-A3-4: Escalating cooldowns (60s->120s->240s, revoke after 3)
 *
 * Four-stage graduated response:
 *
 *   Stage 1: Observation (< 50% of limit)
 *   Stage 2: Warning (50%-75% of limit)
 *   Stage 3: Soft-limit with latency injection (75%-100% of limit)
 *   Stage 4: Hard-block with escalating cooldowns (>= 100% of limit)
 *   Stage 5: Alias revocation (>= 120% of limit or 3 consecutive blocks)
 *
 * @phpstan-type RateLimitStage 'observation'|'warning'|'soft_limit'|'hard_block'|'revocation'
 * @phpstan-type RateLimitResult array{
 *     stage: RateLimitStage,
 *     currentRate: int,
 *     limit: int,
 *     ratio: float,
 *     injectedLatencyMs: int,
 *     blocked: bool,
 *     revoke: bool,
 *     cooldownSeconds: int,
 *     remaining: int,
 *     burstDetected: bool,
 * }
 */
final class GraduatedRateLimiter
{
    /**
     * @var array<string, array{
     *     timestamps: list<float>,
     *     cooldownUntil: float,
     *     consecutiveBlocks: int,
     *     revoked: bool,
     *     burstTimestamps: list<float>,
     * }>
     */
    private array $entries = [];

    /** @var list<string> insertion order, for oldest-first eviction */
    private array $order = [];

    /** @var array<string, int> */
    private array $endpointLimits;

    /** @param array<string, int> $endpointLimits */
    public function __construct(
        private readonly int $defaultLimit = 100,
        private readonly float $windowSeconds = 60.0,
        private readonly int $softLimitBaseLatencyMs = 2000,
        private readonly int $maxEntries = 50_000,
        array $endpointLimits = [],
        private readonly int $burstLimit = 20,
        private readonly int $initialCooldownSeconds = 60,
        private readonly int $maxConsecutiveBlocks = 3,
    ) {
        $this->endpointLimits = $endpointLimits;
    }

    /**
     * Checks the rate limit for an alias (identified by $key, typically
     * an IP or session ID). Records the request and returns the
     * graduated response. $endpoint is optional and enables
     * per-endpoint limits (GAP-A3-2).
     *
     * @return RateLimitResult
     */
    public function check(string $key, ?string $endpoint = null): array
    {
        $now = microtime(true);
        $entry = $this->entries[$key] ?? [
            'timestamps' => [],
            'cooldownUntil' => 0.0,
            'consecutiveBlocks' => 0,
            'revoked' => false,
            'burstTimestamps' => [],
        ];
        $existed = array_key_exists($key, $this->entries);

        if ($entry['revoked']) {
            return [
                'stage' => 'revocation', 'currentRate' => 0, 'limit' => 0, 'ratio' => INF,
                'injectedLatencyMs' => 0, 'blocked' => true, 'revoke' => false,
                'cooldownSeconds' => 0, 'remaining' => 0, 'burstDetected' => false,
            ];
        }

        if ($entry['cooldownUntil'] > $now) {
            $cooldownRemaining = (int) ceil($entry['cooldownUntil'] - $now);

            return [
                'stage' => 'hard_block', 'currentRate' => count($entry['timestamps']),
                'limit' => $this->effectiveLimit($endpoint), 'ratio' => 1.0,
                'injectedLatencyMs' => 0, 'blocked' => true, 'revoke' => false,
                'cooldownSeconds' => $cooldownRemaining, 'remaining' => 0, 'burstDetected' => false,
            ];
        }

        $windowStart = $now - $this->windowSeconds;
        $entry['timestamps'] = array_values(array_filter(
            $entry['timestamps'],
            static fn (float $t): bool => $t > $windowStart,
        ));

        // GAP-A3-3: clean burst micro-window (1 second).
        $burstWindowStart = $now - 1.0;
        $entry['burstTimestamps'] = array_values(array_filter(
            $entry['burstTimestamps'],
            static fn (float $t): bool => $t > $burstWindowStart,
        ));

        $entry['timestamps'][] = $now;
        $entry['burstTimestamps'][] = $now;

        if (!$existed && count($this->entries) >= $this->maxEntries) {
            $this->evictOldest();
        }
        if (!$existed) {
            $this->order[] = $key;
        }
        $this->entries[$key] = $entry;

        $limit = $this->effectiveLimit($endpoint);
        $currentRate = count($entry['timestamps']);
        $ratio = $currentRate / $limit;

        // GAP-A3-3: burst detection.
        $burstDetected = count($entry['burstTimestamps']) > $this->burstLimit;

        if ($ratio >= 1.2 || $entry['consecutiveBlocks'] >= $this->maxConsecutiveBlocks) {
            $entry['revoked'] = true;
            $this->entries[$key] = $entry;

            return [
                'stage' => 'revocation', 'currentRate' => $currentRate, 'limit' => $limit, 'ratio' => $ratio,
                'injectedLatencyMs' => 0, 'blocked' => true, 'revoke' => true,
                'cooldownSeconds' => 0, 'remaining' => 0, 'burstDetected' => $burstDetected,
            ];
        }

        if ($ratio >= 1.0 || $burstDetected) {
            $entry['consecutiveBlocks']++;
            $cooldownMultiplier = 2 ** ($entry['consecutiveBlocks'] - 1);
            $cooldownSeconds = $this->initialCooldownSeconds * $cooldownMultiplier;
            $entry['cooldownUntil'] = $now + $cooldownSeconds;
            $this->entries[$key] = $entry;

            return [
                'stage' => 'hard_block', 'currentRate' => $currentRate, 'limit' => $limit, 'ratio' => $ratio,
                'injectedLatencyMs' => 0, 'blocked' => true, 'revoke' => false,
                'cooldownSeconds' => $cooldownSeconds, 'remaining' => 0, 'burstDetected' => $burstDetected,
            ];
        }

        if ($ratio >= 0.75) {
            $entry['consecutiveBlocks'] = 0;
            $this->entries[$key] = $entry;

            $progress = ($ratio - 0.75) / 0.25;
            $baseLatency = $this->softLimitBaseLatencyMs * ($progress ** 2);
            // GAP-A3-1: add +/-20% random jitter.
            $jitter = 0.8 + (0.4 * (mt_rand() / mt_getrandmax()));
            $injectedLatencyMs = (int) round($baseLatency * $jitter);

            return [
                'stage' => 'soft_limit', 'currentRate' => $currentRate, 'limit' => $limit, 'ratio' => $ratio,
                'injectedLatencyMs' => $injectedLatencyMs, 'blocked' => false, 'revoke' => false,
                'cooldownSeconds' => 0, 'remaining' => max(0, $limit - $currentRate), 'burstDetected' => $burstDetected,
            ];
        }

        if ($ratio >= 0.5) {
            $entry['consecutiveBlocks'] = 0;
            $this->entries[$key] = $entry;

            return [
                'stage' => 'warning', 'currentRate' => $currentRate, 'limit' => $limit, 'ratio' => $ratio,
                'injectedLatencyMs' => 0, 'blocked' => false, 'revoke' => false,
                'cooldownSeconds' => 0, 'remaining' => max(0, $limit - $currentRate), 'burstDetected' => false,
            ];
        }

        $entry['consecutiveBlocks'] = 0;
        $this->entries[$key] = $entry;

        return [
            'stage' => 'observation', 'currentRate' => $currentRate, 'limit' => $limit, 'ratio' => $ratio,
            'injectedLatencyMs' => 0, 'blocked' => false, 'revoke' => false,
            'cooldownSeconds' => 0, 'remaining' => max(0, $limit - $currentRate), 'burstDetected' => false,
        ];
    }

    /** Manually revokes an alias (e.g. from an external security decision). */
    public function revokeAlias(string $key): void
    {
        $entry = $this->entries[$key] ?? null;
        if ($entry === null) {
            $this->entries[$key] = [
                'timestamps' => [], 'cooldownUntil' => 0.0, 'consecutiveBlocks' => 0,
                'revoked' => true, 'burstTimestamps' => [],
            ];
            $this->order[] = $key;
        } else {
            $entry['revoked'] = true;
            $this->entries[$key] = $entry;
        }
    }

    /** Resets an alias's rate limit state (e.g. after an admin override). */
    public function resetAlias(string $key): void
    {
        unset($this->entries[$key]);
    }

    /** Returns whether an alias has been revoked. */
    public function isRevoked(string $key): bool
    {
        return $this->entries[$key]['revoked'] ?? false;
    }

    /**
     * Sets per-endpoint rate limits (merged into any existing endpoint limits). GAP-A3-2.
     *
     * @param array<string, int> $limits
     */
    public function setEndpointLimits(array $limits): void
    {
        $this->endpointLimits = [...$this->endpointLimits, ...$limits];
    }

    /** Returns the current number of tracked aliases. */
    public function size(): int
    {
        return count($this->entries);
    }

    private function effectiveLimit(?string $endpoint): int
    {
        if ($endpoint === null || $this->endpointLimits === []) {
            return $this->defaultLimit;
        }

        if (array_key_exists($endpoint, $this->endpointLimits)) {
            return $this->endpointLimits[$endpoint];
        }

        foreach ($this->endpointLimits as $pattern => $limit) {
            if (str_ends_with($pattern, '*') && str_starts_with($endpoint, substr($pattern, 0, -1))) {
                return $limit;
            }
        }

        return $this->defaultLimit;
    }

    private function evictOldest(): void
    {
        while ($this->order !== []) {
            $oldest = array_shift($this->order);
            if (array_key_exists($oldest, $this->entries)) {
                unset($this->entries[$oldest]);

                return;
            }
        }
    }
}
