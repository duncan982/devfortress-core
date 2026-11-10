<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Unified Audit Trail (CL-M3).
 *
 * Mirrors packages/devfortress-sdk/src/unified-audit.ts. Merges internal
 * and external closed-loop audit events into a single in-memory timeline
 * with consistent fields regardless of source.
 *
 * NOTE on tamper-evidence: this is an in-memory log only — it is not
 * cryptographically signed or hash-chained, and neither is Node's own
 * UnifiedAuditTrail. The HMAC-signed, hash-chained tamper-evident audit
 * trail (TODO 265/266/272) is a separate, server-side Next.js module
 * (lib/audit-trail-signer.ts) operating directly on the LiveThreatEvent
 * Postgres table. It has no SDK-side analog in any language, including
 * Node, so this port does not and cannot provide tamper-evidence either.
 *
 * @phpstan-type AuditSource 'internal'|'external'|'hybrid'
 * @phpstan-type UnifiedAuditEntry array{
 *     eventId: string,
 *     timestamp: float,
 *     source: AuditSource,
 *     tier: int,
 *     decision: string,
 *     score: float,
 *     severity: string,
 *     latencyMs: float,
 *     ip: string,
 *     path: string,
 *     method: string,
 *     matchedRules: list<string>,
 *     userId?: string|null,
 *     agentId?: string|null,
 *     sessionId?: string|null,
 *     fallbackMode?: bool,
 *     meta?: array<string, mixed>|null,
 * }
 */
final class UnifiedAuditTrail
{
    private const DEDUP_WINDOW_SECONDS = 5.0;
    private const DEDUP_MAP_CAP = 10_000;
    private const DEFAULT_MAX_ENTRIES = 100_000;

    /** @var list<UnifiedAuditEntry> */
    private array $entries = [];

    /** @var array<string, float> eventId => timestamp (seconds) */
    private array $recentEventIds = [];

    /**
     * @var array{
     *     internalDecisions: int, externalDecisions: int, hybridDecisions: int,
     *     fallbackEvents: int, totalBlocks: int, totalAllows: int, totalRateLimits: int,
     *     internalLatencySum: float, externalLatencySum: float,
     * }
     */
    private array $stats = [
        'internalDecisions' => 0, 'externalDecisions' => 0, 'hybridDecisions' => 0,
        'fallbackEvents' => 0, 'totalBlocks' => 0, 'totalAllows' => 0, 'totalRateLimits' => 0,
        'internalLatencySum' => 0.0, 'externalLatencySum' => 0.0,
    ];

    private readonly ?\Closure $onEntry;

    /** @param (callable(UnifiedAuditEntry): void)|null $onEntry */
    public function __construct(
        private readonly int $maxEntries = self::DEFAULT_MAX_ENTRIES,
        ?callable $onEntry = null,
        private readonly bool $debug = false,
    ) {
        $this->onEntry = $onEntry === null ? null : \Closure::fromCallable($onEntry);
    }

    /**
     * Records an audit entry from any source. S27: the same eventId
     * within the 5s dedup window is merged (external overrides
     * internal), not duplicated.
     *
     * @param UnifiedAuditEntry $entry
     */
    public function record(array $entry): void
    {
        $now = microtime(true);
        $existing = $this->recentEventIds[$entry['eventId']] ?? null;
        if ($existing !== null && ($now - $existing) < self::DEDUP_WINDOW_SECONDS) {
            if ($entry['source'] === 'external') {
                foreach ($this->entries as $i => $e) {
                    if ($e['eventId'] === $entry['eventId'] && $e['source'] === 'internal') {
                        $this->entries[$i] = [...$e, ...$entry, 'source' => 'hybrid'];
                        if ($this->debug) {
                            fwrite(STDERR, "[DF Audit] DEDUP: merged {$entry['eventId']} (external overrides internal)\n");
                        }
                        break;
                    }
                }
            }
            return;
        }

        $this->recentEventIds[$entry['eventId']] = $now;
        if (count($this->recentEventIds) > self::DEDUP_MAP_CAP) {
            $cutoff = $now - self::DEDUP_WINDOW_SECONDS;
            foreach ($this->recentEventIds as $id => $ts) {
                if ($ts < $cutoff) {
                    unset($this->recentEventIds[$id]);
                }
            }
        }

        if (count($this->entries) >= $this->maxEntries) {
            array_splice($this->entries, 0, (int) ($this->maxEntries * 0.1));
        }
        $this->entries[] = $entry;
        $this->updateStats($entry);

        if ($this->onEntry !== null) {
            try {
                ($this->onEntry)($entry);
            } catch (\Throwable) {
                // Callback errors must not break the audit trail.
            }
        }

        if ($this->debug) {
            fwrite(
                STDERR,
                sprintf(
                    "[DF Audit] %s:tier%d %s score=%s %s %s %s (%sms)\n",
                    $entry['source'],
                    $entry['tier'],
                    $entry['decision'],
                    $entry['score'],
                    $entry['ip'],
                    $entry['method'],
                    $entry['path'],
                    $entry['latencyMs'],
                ),
            );
        }
    }

    /**
     * Queries audit entries with filters.
     *
     * @return list<UnifiedAuditEntry>
     */
    public function query(
        ?string $source = null,
        ?string $decision = null,
        ?string $ip = null,
        ?string $userId = null,
        ?string $agentId = null,
        ?float $minScore = null,
        ?float $since = null,
        int $limit = 100,
    ): array {
        $result = $this->entries;

        if ($source !== null) {
            $result = array_values(array_filter($result, static fn (array $e) => $e['source'] === $source));
        }
        if ($decision !== null) {
            $result = array_values(array_filter($result, static fn (array $e) => $e['decision'] === $decision));
        }
        if ($ip !== null) {
            $result = array_values(array_filter($result, static fn (array $e) => $e['ip'] === $ip));
        }
        if ($userId !== null) {
            $result = array_values(array_filter($result, static fn (array $e) => ($e['userId'] ?? null) === $userId));
        }
        if ($agentId !== null) {
            $result = array_values(array_filter($result, static fn (array $e) => ($e['agentId'] ?? null) === $agentId));
        }
        if ($minScore !== null) {
            $result = array_values(array_filter($result, static fn (array $e) => $e['score'] >= $minScore));
        }
        if ($since !== null) {
            $result = array_values(array_filter($result, static fn (array $e) => $e['timestamp'] >= $since));
        }

        return $limit > 0 ? array_slice($result, -$limit) : $result;
    }

    /**
     * Returns aggregated statistics.
     *
     * @return array{
     *     total: int, internalDecisions: int, externalDecisions: int, hybridDecisions: int,
     *     fallbackEvents: int, totalBlocks: int, totalAllows: int, totalRateLimits: int,
     *     avgInternalLatencyMs: int, avgExternalLatencyMs: int,
     * }
     */
    public function getStats(): array
    {
        $avgInternal = $this->stats['internalDecisions'] > 0
            ? (int) round($this->stats['internalLatencySum'] / $this->stats['internalDecisions'])
            : 0;
        $avgExternal = $this->stats['externalDecisions'] > 0
            ? (int) round($this->stats['externalLatencySum'] / $this->stats['externalDecisions'])
            : 0;

        return [
            'total' => count($this->entries),
            'internalDecisions' => $this->stats['internalDecisions'],
            'externalDecisions' => $this->stats['externalDecisions'],
            'hybridDecisions' => $this->stats['hybridDecisions'],
            'fallbackEvents' => $this->stats['fallbackEvents'],
            'totalBlocks' => $this->stats['totalBlocks'],
            'totalAllows' => $this->stats['totalAllows'],
            'totalRateLimits' => $this->stats['totalRateLimits'],
            'avgInternalLatencyMs' => $avgInternal,
            'avgExternalLatencyMs' => $avgExternal,
        ];
    }

    /**
     * Returns source:decision counts, for dashboard visualization.
     *
     * @return array<string, int>
     */
    public function getDecisionDistribution(): array
    {
        $dist = [];
        foreach ($this->entries as $e) {
            $key = $e['source'] . ':' . $e['decision'];
            $dist[$key] = ($dist[$key] ?? 0) + 1;
        }
        return $dist;
    }

    /**
     * Returns latency histogram buckets.
     *
     * @return array{under1ms: int, under5ms: int, under50ms: int, under200ms: int, under1s: int, over1s: int}
     */
    public function getLatencyHistogram(): array
    {
        $hist = ['under1ms' => 0, 'under5ms' => 0, 'under50ms' => 0, 'under200ms' => 0, 'under1s' => 0, 'over1s' => 0];
        foreach ($this->entries as $e) {
            $ms = $e['latencyMs'];
            if ($ms < 1) {
                $hist['under1ms']++;
            } elseif ($ms < 5) {
                $hist['under5ms']++;
            } elseif ($ms < 50) {
                $hist['under50ms']++;
            } elseif ($ms < 200) {
                $hist['under200ms']++;
            } elseif ($ms < 1000) {
                $hist['under1s']++;
            } else {
                $hist['over1s']++;
            }
        }
        return $hist;
    }

    /** Exports entries as JSON (for compliance/archival). */
    public function exportJson(?float $since = null): string
    {
        $entries = $this->entries;
        if ($since !== null) {
            $entries = array_values(array_filter($entries, static fn (array $e) => $e['timestamp'] >= $since));
        }
        return (string) json_encode($entries, JSON_PRETTY_PRINT);
    }

    /** Resets the audit trail (for testing). @internal */
    public function reset(): void
    {
        $this->entries = [];
        $this->recentEventIds = [];
        $this->stats = [
            'internalDecisions' => 0, 'externalDecisions' => 0, 'hybridDecisions' => 0,
            'fallbackEvents' => 0, 'totalBlocks' => 0, 'totalAllows' => 0, 'totalRateLimits' => 0,
            'internalLatencySum' => 0.0, 'externalLatencySum' => 0.0,
        ];
    }

    /** @param UnifiedAuditEntry $entry */
    private function updateStats(array $entry): void
    {
        if ($entry['source'] === 'internal') {
            $this->stats['internalDecisions']++;
            $this->stats['internalLatencySum'] += $entry['latencyMs'];
        } elseif ($entry['source'] === 'external') {
            $this->stats['externalDecisions']++;
            $this->stats['externalLatencySum'] += $entry['latencyMs'];
        } else {
            $this->stats['hybridDecisions']++;
            if ($entry['tier'] > 0) {
                $this->stats['internalLatencySum'] += $entry['latencyMs'];
            } else {
                $this->stats['externalLatencySum'] += $entry['latencyMs'];
            }
        }

        if ($entry['fallbackMode'] ?? false) {
            $this->stats['fallbackEvents']++;
        }

        match ($entry['decision']) {
            'block' => $this->stats['totalBlocks']++,
            'allow' => $this->stats['totalAllows']++,
            'rate_limit' => $this->stats['totalRateLimits']++,
            default => null,
        };
    }
}
