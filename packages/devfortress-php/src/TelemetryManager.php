<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use DevFortress\Sdk\Transport\CurlTransport;
use DevFortress\Sdk\Transport\TransportInterface;
use InvalidArgumentException;
use Throwable;

/**
 * DevFortress SDK — Telemetry Heartbeat (CV-M2).
 *
 * Sends anonymised usage telemetry to the platform. No PII is
 * transmitted — only aggregate counts and operational metadata.
 *
 * If heartbeat stops, the platform dashboard shows:
 *   "SDK offline — upgrade to Hybrid for guaranteed visibility."
 *
 * Mirrors packages/devfortress-sdk/src/telemetry.ts. As with
 * LicenseManager, Node's start() schedules its own unref'd setInterval;
 * PHP has no persistent process to hang that off by default, so
 * isHeartbeatDue() exposes the same "has the interval elapsed" decision
 * for the host to act on instead (sendHeartbeat() on a cron tick, a
 * queue worker loop, or once per incoming request past the interval).
 *
 * @phpstan-type TelemetrySnapshot array{eventCount: int, blockCount: int, rateLimitCount: int, clMode: string, tier: string, sdkVersion: string, modelExpired: bool, licenseDegraded: bool, integrityHash: string, uptimeSeconds: int, p99LatencyMs: float}
 */
final class TelemetryManager
{
    private const DEFAULT_HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
    private const HEARTBEAT_TIMEOUT_SECONDS = 5.0;
    private const MAX_LATENCY_SAMPLES = 100;

    private readonly TransportInterface $transport;
    private readonly RequestSigner $signer;
    private readonly int $heartbeatIntervalMs;
    private readonly ?LoggerInterface $logger;

    // Counters (reset after each successful heartbeat).
    private int $eventCount = 0;
    private int $blockCount = 0;
    private int $rateLimitCount = 0;

    // Latency tracking (reservoir-sampled). Not kept as `list<float>`: the
    // reservoir-sampling replace below assigns at an arbitrary existing
    // index, which PHPStan can't prove preserves list-ness even though it
    // always stays a 0-based contiguous array in practice.
    /** @var array<int, float> */
    private array $latencies = [];

    private int $startedAt;
    private ?int $lastHeartbeatAt = null;
    /** @var (callable(): array<string, mixed>)|null */
    private $snapshotProvider = null;

    public function __construct(
        private readonly string $apiKey,
        private readonly string $endpoint,
        ?int $heartbeatIntervalMs = null,
        ?LoggerInterface $logger = null,
        ?TransportInterface $transport = null,
    ) {
        if ($apiKey === '') {
            throw new InvalidArgumentException('DevFortress\Sdk\TelemetryManager: an API key is required');
        }
        $this->heartbeatIntervalMs = $heartbeatIntervalMs ?? self::DEFAULT_HEARTBEAT_INTERVAL_MS;
        $this->logger = $logger;
        $this->transport = $transport ?? new CurlTransport();
        $this->signer = new RequestSigner($apiKey);
        $this->startedAt = self::nowMs();
    }

    /**
     * Mark telemetry as started and register an optional snapshot
     * enricher. See the class doc comment: there is no periodic timer
     * here, call sendHeartbeat() yourself (guarded by isHeartbeatDue()
     * if desired).
     *
     * @param (callable(): array<string, mixed>)|null $snapshotProvider
     */
    public function start(?callable $snapshotProvider = null): void
    {
        $this->snapshotProvider = $snapshotProvider;
        $this->startedAt = self::nowMs();
        $this->log('info', sprintf('Telemetry heartbeat started (interval: %ds)', intdiv($this->heartbeatIntervalMs, 1000)));
    }

    /** Record an observed event. */
    public function recordEvent(): void
    {
        $this->eventCount++;
    }

    /** Record a blocked event. */
    public function recordBlock(): void
    {
        $this->blockCount++;
    }

    /** Record a rate-limited event. */
    public function recordRateLimit(): void
    {
        $this->rateLimitCount++;
    }

    /** Record observe latency for p99 calculation. */
    public function recordLatency(float $ms): void
    {
        if (count($this->latencies) >= self::MAX_LATENCY_SAMPLES) {
            // Reservoir sampling: replace a random element.
            $idx = random_int(0, count($this->latencies) - 1);
            $this->latencies[$idx] = $ms;
        } else {
            $this->latencies[] = $ms;
        }
    }

    /** Whether heartbeatIntervalMs has elapsed since the last heartbeat (or none has been sent yet). */
    public function isHeartbeatDue(): bool
    {
        return $this->lastHeartbeatAt === null
            || (self::nowMs() - $this->lastHeartbeatAt) >= $this->heartbeatIntervalMs;
    }

    /**
     * Send a heartbeat to the platform. Fire-and-forget — failures are
     * logged at debug level only (telemetry, not security-critical; see
     * LicenseManager::checkLicense for the path that does log visibly on
     * a real degradation). Never throws into the host.
     *
     * Returns whether the heartbeat was delivered.
     */
    public function sendHeartbeat(): bool
    {
        $enriched = $this->snapshotProvider !== null ? ($this->snapshotProvider)() : [];

        $clMode = $enriched['clMode'] ?? null;
        $tier = $enriched['tier'] ?? null;
        $sdkVersion = $enriched['sdkVersion'] ?? null;

        /** @var TelemetrySnapshot $snapshot */
        $snapshot = [
            'eventCount' => $this->eventCount,
            'blockCount' => $this->blockCount,
            'rateLimitCount' => $this->rateLimitCount,
            'clMode' => is_string($clMode) ? $clMode : 'external',
            'tier' => is_string($tier) ? $tier : 'starter',
            'sdkVersion' => is_string($sdkVersion) ? $sdkVersion : Client::VERSION,
            'modelExpired' => (bool) ($enriched['modelExpired'] ?? false),
            'licenseDegraded' => (bool) ($enriched['licenseDegraded'] ?? false),
            'integrityHash' => is_string($enriched['integrityHash'] ?? null) ? $enriched['integrityHash'] : '',
            'uptimeSeconds' => intdiv(self::nowMs() - $this->startedAt, 1000),
            'p99LatencyMs' => $this->computeP99(),
        ];

        $url = rtrim($this->endpoint, '/') . '/api/sdk/heartbeat';
        $body = json_encode(['timestamp' => self::nowMs(), ...$snapshot], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        try {
            // Signed with a key ID and a fresh nonce per beat: the key is never sent.
            $headers = $this->signer->sign('POST', RequestSigner::requestTargetFromUrl($url), $body)
                + ['Content-Type' => 'application/json'];
            $this->transport->send('POST', $url, $headers, $body, self::HEARTBEAT_TIMEOUT_SECONDS);

            $this->lastHeartbeatAt = self::nowMs();
            $this->log('debug', "Heartbeat sent: events={$snapshot['eventCount']}, blocks={$snapshot['blockCount']}, uptime={$snapshot['uptimeSeconds']}s");

            // Reset counters after successful send.
            $this->eventCount = 0;
            $this->blockCount = 0;
            $this->rateLimitCount = 0;
            $this->latencies = [];

            return true;
        } catch (Throwable $e) {
            $this->lastHeartbeatAt = self::nowMs();
            $this->log('debug', "Heartbeat failed: {$e->getMessage()}");

            return false;
        }
    }

    /** Compute p99 latency from sampled observations. */
    private function computeP99(): float
    {
        if ($this->latencies === []) {
            return 0.0;
        }
        $sorted = $this->latencies;
        sort($sorted);
        $idx = (int) floor(count($sorted) * 0.99);

        return $sorted[min($idx, count($sorted) - 1)];
    }

    /**
     * Get current telemetry state (for diagnostics).
     *
     * @return array{eventCount: int, blockCount: int, rateLimitCount: int, uptimeSeconds: int}
     */
    public function getState(): array
    {
        return [
            'eventCount' => $this->eventCount,
            'blockCount' => $this->blockCount,
            'rateLimitCount' => $this->rateLimitCount,
            'uptimeSeconds' => intdiv(self::nowMs() - $this->startedAt, 1000),
        ];
    }

    /** Stop sending heartbeats and clean up. There is no timer to clear (see class doc comment). */
    public function destroy(): void
    {
        $this->snapshotProvider = null;
    }

    private function log(string $level, string $message): void
    {
        try {
            $this->logger?->log($level, "[DevFortress:Telemetry] {$message}");
        } catch (Throwable) {
            // A failing logger must not reach the host application either.
        }
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}

/**
 * DevFortress SDK — Anomaly-Gated Metering: Aggregate Telemetry Rollup Buffer.
 *
 * Option B (2026-08-27): CLEAN/unflagged traffic no longer gets a full,
 * billed event row per request. Instead, this buffer accumulates
 * lightweight per-alias/IP-per-hour counters in memory (request count,
 * unique endpoints seen, error count, latency sum) and flushes them as a
 * small number of upsert-increment rows to
 * POST /api/events/telemetry-rollup on demand — not per request. This is
 * what feeds the population-level baseline needs without counting toward
 * the customer's billed event quota. Mirrors
 * packages/devfortress-sdk/src/telemetry-rollup-buffer.ts.
 *
 * Node keys its in-memory Map on a composite `${aliasOrIpKey}\0${periodKey}`
 * — a literal embedded NUL byte, chosen precisely because it cannot occur
 * in either component. PHP associative array keys must be string|int, so
 * the same NUL-delimited string is used here as the bucket key: identical
 * collision-free bucketing semantics, just PHP's native string-key idiom
 * instead of a Map instance.
 *
 * @phpstan-type RollupBucket array{aliasOrIpKey: string, periodKey: string, requestCount: int, endpoints: array<string, true>, errorCount: int, latencySumMs: float, windowStart: int, windowEnd: int}
 */
final class TelemetryRollupBuffer
{
    // Bounded per-bucket endpoint tracking — uniqueEndpoints is an approximation
    // (this is non-billing, best-effort aggregate telemetry, not an exact count).
    private const MAX_ENDPOINTS_TRACKED_PER_BUCKET = 50;
    // Matches TelemetryManager's DEFAULT_HEARTBEAT_INTERVAL_MS — this is
    // aggregate, non-billing telemetry, not real-time-critical, so a wider
    // batching window means fewer platform requests.
    private const DEFAULT_FLUSH_INTERVAL_MS = 5 * 60 * 1000;
    private const DEFAULT_MAX_BUFFERED_KEYS = 500;
    private const FLUSH_TIMEOUT_SECONDS = 15.0;

    /** The NUL separator Node's bucketKey template literal embeds between aliasOrIpKey and periodKey. */
    private const BUCKET_KEY_SEPARATOR = "\0";

    private readonly TransportInterface $transport;
    private readonly RequestSigner $signer;
    private readonly int $flushIntervalMs;
    private readonly int $maxBufferedKeys;
    private readonly bool $debug;
    private readonly ?LoggerInterface $logger;

    /** @var array<string, RollupBucket> */
    private array $buckets = [];

    public function __construct(
        private readonly string $apiKey,
        private readonly string $endpoint,
        ?int $flushIntervalMs = null,
        ?int $maxBufferedKeys = null,
        bool $debug = false,
        ?LoggerInterface $logger = null,
        ?TransportInterface $transport = null,
    ) {
        if ($apiKey === '') {
            throw new InvalidArgumentException('DevFortress\Sdk\TelemetryRollupBuffer: an API key is required');
        }
        $this->flushIntervalMs = $flushIntervalMs ?? self::DEFAULT_FLUSH_INTERVAL_MS;
        $this->maxBufferedKeys = $maxBufferedKeys ?? self::DEFAULT_MAX_BUFFERED_KEYS;
        $this->debug = $debug;
        $this->logger = $logger;
        $this->transport = $transport ?? new CurlTransport();
        $this->signer = new RequestSigner($apiKey);
    }

    /**
     * Hour-bucket period key, e.g. "2026-08-27T14" — matches
     * AliasTelemetryRollup.periodKey. $nowMs defaults to the current time
     * (epoch milliseconds); pass it explicitly only for tests.
     */
    public static function hourlyPeriodKey(?int $nowMs = null): string
    {
        $ts = $nowMs ?? self::nowMs();

        return gmdate('Y-m-d\TH', intdiv($ts, 1000));
    }

    /** Configured flush interval, exposed so a host-driven scheduler can reuse it as a polling cadence. */
    public function getFlushIntervalMs(): int
    {
        return $this->flushIntervalMs;
    }

    /**
     * Buffer one clean (non-flagged) request's contribution. Synchronous,
     * no network call — actual delivery happens on the next flush().
     */
    public function add(string $aliasOrIpKey, string $endpointPath, bool $isError, float $latencyMs): void
    {
        $periodKey = self::hourlyPeriodKey();
        $bucketKey = $aliasOrIpKey . self::BUCKET_KEY_SEPARATOR . $periodKey;
        $now = self::nowMs();

        if (!isset($this->buckets[$bucketKey])) {
            // Bound total buffered keys so a burst of unique IPs can't grow
            // memory unbounded — force an early flush and drop this one
            // contribution. Acceptable: this is approximate, non-billing
            // aggregate telemetry.
            if (count($this->buckets) >= $this->maxBufferedKeys) {
                $this->flush();

                return;
            }
            $this->buckets[$bucketKey] = [
                'aliasOrIpKey' => $aliasOrIpKey,
                'periodKey' => $periodKey,
                'requestCount' => 0,
                'endpoints' => [],
                'errorCount' => 0,
                'latencySumMs' => 0.0,
                'windowStart' => $now,
                'windowEnd' => $now,
            ];
        }

        $bucket = $this->buckets[$bucketKey];
        $bucket['requestCount']++;
        if (count($bucket['endpoints']) < self::MAX_ENDPOINTS_TRACKED_PER_BUCKET) {
            $bucket['endpoints'][$endpointPath] = true;
        }
        if ($isError) {
            $bucket['errorCount']++;
        }
        $bucket['latencySumMs'] += $latencyMs;
        $bucket['windowEnd'] = $now;
        $this->buckets[$bucketKey] = $bucket;
    }

    /** Number of distinct (aliasOrIpKey, periodKey) buckets currently buffered. */
    public function bufferedKeyCount(): int
    {
        return count($this->buckets);
    }

    /** Flush all buffered buckets to the platform in one batch request. */
    public function flush(): void
    {
        if ($this->buckets === []) {
            return;
        }

        $contributions = [];
        foreach ($this->buckets as $bucket) {
            $contributions[] = [
                'aliasOrIpKey' => $bucket['aliasOrIpKey'],
                'periodKey' => $bucket['periodKey'],
                'requestCount' => $bucket['requestCount'],
                'uniqueEndpointsInBatch' => count($bucket['endpoints']),
                'errorCount' => $bucket['errorCount'],
                'latencySumMs' => $bucket['latencySumMs'],
                'windowStart' => $bucket['windowStart'],
                'windowEnd' => $bucket['windowEnd'],
            ];
        }
        $this->buckets = [];

        $url = rtrim($this->endpoint, '/') . '/api/events/telemetry-rollup';

        try {
            $body = json_encode(['contributions' => $contributions], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $headers = $this->signer->sign('POST', RequestSigner::requestTargetFromUrl($url), $body)
                + ['Content-Type' => 'application/json'];
            $this->transport->send('POST', $url, $headers, $body, self::FLUSH_TIMEOUT_SECONDS);
        } catch (Throwable $e) {
            // Best-effort — aggregate telemetry is not billing-relevant, so
            // dropping a batch on transient failure is acceptable (unlike
            // the full event relay path, which retries).
            if ($this->debug) {
                $this->log('debug', 'telemetry rollup flush failed: ' . $e->getMessage());
            }
        }
    }

    /** Drop any unflushed buckets without sending them. There is no timer to clear (see class doc comment). */
    public function destroy(): void
    {
        $this->buckets = [];
    }

    private function log(string $level, string $message): void
    {
        try {
            $this->logger?->log($level, "[DevFortress] {$message}");
        } catch (Throwable) {
            // A failing logger must not reach the host application either.
        }
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
