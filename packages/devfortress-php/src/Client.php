<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use Closure;
use DevFortress\Sdk\Transport\CurlTransport;
use DevFortress\Sdk\Transport\TransportException;
use DevFortress\Sdk\Transport\TransportInterface;
use InvalidArgumentException;
use JsonException;
use Throwable;

/**
 * DevFortress event client (external mode).
 *
 * Events are queued in memory and delivered in batches ({"events": [...]},
 * server maximum 100) by flush(). Every request is signed with the request
 * signature contract (see RequestSigner): the API key never goes on the wire,
 * only a key ID does.
 *
 * Retry: up to $retries attempts, exponential backoff, only on 5xx and network
 * errors. 4xx responses are never retried. Every attempt is signed again with a
 * fresh nonce and timestamp.
 *
 * Delivery never throws into the host application: a failed delivery comes back
 * as a DeliveryResult and is logged. Only a missing API key throws, at
 * construction.
 */
final class Client
{
    public const VERSION = '0.1.0';
    public const DEFAULT_ENDPOINT = 'https://www.devfortress.net/api/events/ingest';
    public const DEFAULT_TIMEOUT = 15.0;
    public const DEFAULT_RETRIES = 3;
    public const DEFAULT_BATCH_SIZE = 25;
    public const MAX_SERVER_BATCH = 100;

    private readonly RequestSigner $signer;
    private readonly TransportInterface $transport;
    private readonly ?LoggerInterface $logger;
    private readonly string $requestTarget;
    private readonly int $retries;
    private readonly int $batchSize;
    /** @var Closure(float): void */
    private readonly Closure $sleeper;

    /** @var list<array<string, mixed>> */
    private array $queue = [];
    private bool $shutdownRegistered = false;

    /**
     * Closed-loop mode. 'external' (default) is unchanged legacy behavior —
     * no internal engine, no observe()/isBlocked() behavior. 'internal' and
     * 'hybrid' instantiate {@see InternalClosedLoopEngine} (TODO 407 port);
     * 'hybrid' additionally gets a {@see PlatformCircuitBreaker} guarding
     * the external-enrichment leg. Mirrors Node's DevFortressCore and this
     * SDK family's Python port (`DevFortressClient(mode=...)`).
     */
    public readonly string $mode;
    public readonly ?InternalClosedLoopEngine $internalEngine;
    public readonly ?PlatformCircuitBreaker $circuitBreaker;

    /**
     * @param object|null $logger Any PSR-3 logger, or a DevFortress\Sdk\LoggerInterface
     * @param array<string, mixed> $defaults Fields merged into every event (appId, environment, ...)
     * @param string $privacy "standard", or "strict" for no user agents and hashed IPs
     * @param (Closure(float): void)|null $sleeper Backoff sleep, replaceable in tests
     * @param string $mode Closed-loop mode: "external" (default — no behavior change for existing callers), "internal", or "hybrid". Any other value falls back to "external".
     * @param array<string, mixed> $internalCLOptions Constructor arguments forwarded to {@see InternalClosedLoopEngine} (named-argument shape), for internal/hybrid mode. `enableExternalRelay` and `onRelay` are always controlled by $mode/Client itself and are ignored here unless `onRelay` is explicitly non-null (then it is preserved instead of the default platform relay).
     */
    public function __construct(
        string $apiKey,
        private readonly string $endpoint = self::DEFAULT_ENDPOINT,
        private readonly float $timeout = self::DEFAULT_TIMEOUT,
        int $retries = self::DEFAULT_RETRIES,
        ?object $logger = null,
        private readonly array $defaults = [],
        private readonly string $privacy = 'standard',
        int $batchSize = self::DEFAULT_BATCH_SIZE,
        private readonly float $backoffBase = 1.0,
        ?TransportInterface $transport = null,
        ?Closure $sleeper = null,
        string $mode = 'external',
        array $internalCLOptions = [],
        private readonly int $circuitBreakerFailureThreshold = 3,
        private readonly float $circuitBreakerRecoveryTimeSeconds = 60.0,
    ) {
        if ($apiKey === '') {
            throw new InvalidArgumentException('DevFortress\Sdk\Client: an API key is required');
        }
        $this->signer = new RequestSigner($apiKey);
        $this->requestTarget = RequestSigner::requestTargetFromUrl($endpoint);
        $this->transport = $transport ?? new CurlTransport();
        $this->retries = max(1, $retries);
        $this->batchSize = max(1, $batchSize);
        $this->logger = self::wrapLogger($logger);
        $this->sleeper = $sleeper ?? static function (float $seconds): void {
            if ($seconds > 0) {
                usleep((int) round($seconds * 1_000_000));
            }
        };

        // ── Mode / internal closed-loop engine ──────────────────────────
        // Readonly properties: each assigned exactly once below (not
        // null-then-overwritten) — PHP readonly forbids a second write.
        $this->mode = in_array($mode, ['external', 'internal', 'hybrid'], true) ? $mode : 'external';

        $this->internalEngine = ($this->mode === 'internal' || $this->mode === 'hybrid')
            ? $this->buildInternalEngine($internalCLOptions)
            : null;

        $this->circuitBreaker = $this->mode === 'hybrid'
            ? new PlatformCircuitBreaker($this->circuitBreakerFailureThreshold, $this->circuitBreakerRecoveryTimeSeconds)
            : null;
    }

    /**
     * Builds the internal engine for internal/hybrid mode from a loosely
     * typed options bag (e.g. forwarded from a framework config array),
     * defensively narrowing each value instead of spreading `mixed`
     * values directly into {@see InternalClosedLoopEngine}'s named
     * constructor arguments.
     *
     * @param array<string, mixed> $options
     */
    private function buildInternalEngine(array $options): InternalClosedLoopEngine
    {
        $onRelay = is_callable($options['onRelay'] ?? null) ? $options['onRelay'] : null;
        if ($this->mode === 'hybrid' && $onRelay === null) {
            $onRelay = $this->relayInternalDecisionToPlatform(...);
        }

        return new InternalClosedLoopEngine(
            failMode: ($options['failMode'] ?? null) === 'open' ? 'open' : 'closed',
            enableExternalRelay: $this->mode === 'hybrid',
            maxBlockedEntries: is_int($options['maxBlockedEntries'] ?? null) ? $options['maxBlockedEntries'] : 10_000,
            maxRateLimitEntries: is_int($options['maxRateLimitEntries'] ?? null) ? $options['maxRateLimitEntries'] : 50_000,
            maxAuditEntries: is_int($options['maxAuditEntries'] ?? null) ? $options['maxAuditEntries'] : 100_000,
            defaultBlockTtlSeconds: is_int($options['defaultBlockTtlSeconds'] ?? null) ? $options['defaultBlockTtlSeconds'] : 3600,
            tier2Scorer: is_callable($options['tier2Scorer'] ?? null) ? $options['tier2Scorer'] : null,
            blockThreshold: is_numeric($options['blockThreshold'] ?? null) ? (float) $options['blockThreshold'] : 85.0,
            rateLimitThreshold: is_numeric($options['rateLimitThreshold'] ?? null) ? (float) $options['rateLimitThreshold'] : 60.0,
            rateLimitMax: is_int($options['rateLimitMax'] ?? null) ? $options['rateLimitMax'] : 100,
            rateLimitWindowSeconds: is_numeric($options['rateLimitWindowSeconds'] ?? null) ? (float) $options['rateLimitWindowSeconds'] : 60.0,
            debug: (bool) ($options['debug'] ?? false),
            onAction: is_callable($options['onAction'] ?? null) ? $options['onAction'] : null,
            onRelay: $onRelay,
        );
    }

    /**
     * Queue one event. The queue is sent when it reaches the batch size, when
     * flush() is called, or at shutdown if registerShutdownFlush() was used.
     *
     * @param array<string, mixed>|Event $event
     */
    public function trackEvent(array|Event $event): void
    {
        $this->enqueue([$event]);
    }

    /**
     * Queue several events.
     *
     * @param list<array<string, mixed>|Event> $events
     */
    public function trackEvents(array $events): void
    {
        $this->enqueue($events);
    }

    /**
     * Send everything queued, in chunks of at most 100 events. Events that fail
     * to deliver are logged and dropped, not re-queued.
     *
     * @return list<DeliveryResult>
     */
    public function flush(): array
    {
        $events = $this->queue;
        $this->queue = [];

        $results = [];
        foreach (array_chunk($events, self::MAX_SERVER_BATCH) as $chunk) {
            $results[] = $this->post(['events' => $chunk]);
        }

        return $results;
    }

    /** Number of events waiting to be flushed. */
    public function pendingEvents(): int
    {
        return count($this->queue);
    }

    /** True when the platform accepts a signed test event with this key. */
    public function testConnection(): bool
    {
        $result = $this->post($this->prepare([
            'eventType' => 'custom',
            'ip' => '127.0.0.1',
            'method' => 'GET',
            'path' => '/__devfortress/test',
            'severity' => 'LOW',
            'authPhase' => 'pre_auth',
            'actionTaken' => 'monitored',
            'responseLatencyMs' => 0,
            'clMode' => 'external',
            'metadata' => ['test' => true, 'sdk' => 'php'],
        ]));

        return $result->ok;
    }

    /**
     * Flush whatever is still queued when the PHP process ends. Under FPM the
     * response is finished first, so the visitor does not wait for delivery.
     * For plain PHP; frameworks with their own terminate hook should flush there.
     */
    public function registerShutdownFlush(): void
    {
        if ($this->shutdownRegistered) {
            return;
        }
        $this->shutdownRegistered = true;
        register_shutdown_function(function (): void {
            if ($this->queue === []) {
                return;
            }
            if (function_exists('fastcgi_finish_request')) {
                fastcgi_finish_request();
            }
            $this->flush();
        });
    }

    // ── Internal / hybrid closed-loop mode ──────────────────────────────
    // Mirrors Node's DevFortressCore.observeInternal()/observeHybrid(): a
    // pre-response gate the caller invokes (typically from middleware)
    // before the request reaches the application. Mode is set at
    // construction time (`mode:` named arg); external mode has no
    // observe() behaviour here — external-mode reporting stays in the
    // existing after-response middleware path, unchanged.

    /**
     * Evaluate a request through internal/hybrid closed-loop mode.
     *
     * Returns `['flagged' => true, 'eventId' => ..., 'confidence' => ...,
     * 'decision' => ..., 'matchedRules' => [...]]` if the request should
     * be blocked/rate-limited/challenged/quarantined, else `null`
     * (allowed). No-op (returns `null`) in external mode.
     *
     * @param array<string, mixed> $req InternalCLRequest shape (see {@see InternalClosedLoopEngine})
     * @return array{flagged: true, eventId: string, confidence: float, decision: string, matchedRules: list<string>}|null
     */
    public function observe(array $req): ?array
    {
        if ($this->mode === 'internal') {
            return $this->observeInternal($req);
        }
        if ($this->mode === 'hybrid') {
            return $this->observeHybrid($req);
        }

        return null;
    }

    /**
     * @param array<string, mixed> $req
     * @return array{flagged: true, eventId: string, confidence: float, decision: string, matchedRules: list<string>}|null
     */
    private function observeInternal(array $req): ?array
    {
        if ($this->internalEngine === null) {
            return null;
        }
        $result = $this->internalEngine->evaluate($req);
        if ($result['decision'] !== 'allow') {
            return [
                'flagged' => true,
                'eventId' => $result['eventId'],
                'confidence' => $result['score'] / 100,
                'decision' => $result['decision'],
                'matchedRules' => $result['matchedRules'],
            ];
        }

        return null;
    }

    /**
     * @param array<string, mixed> $req
     * @return array{flagged: true, eventId: string, confidence: float, decision: string, matchedRules: list<string>}|null
     */
    private function observeHybrid(array $req): ?array
    {
        // Step 1: internal evaluation (immediate, sub-ms, no round-trip).
        $internalResult = $this->observeInternal($req);
        if ($internalResult !== null) {
            // The internal engine's own onRelay callback (wired in the
            // constructor) already handles the Tier-3 relay for this
            // decision — no second relay call here, matching Node's
            // TODO-210 double-billing fix and Python's own hybrid wiring.
            return $internalResult;
        }

        // Step 2: external enrichment, circuit-breaker gated.
        //
        // KNOWN LIMITATION (flagged explicitly, not silently claimed as
        // full parity): Node's observeHybrid() calls observeExternal()
        // here to fetch a real platform-side enrichment verdict. This
        // port does not yet make that platform call — it only exercises
        // the circuit breaker's success/failure bookkeeping around a
        // no-op enrichment step, so clean traffic is allowed and the
        // circuit stays closed, but a request that internal mode missed
        // and only the platform's own cross-customer intelligence would
        // have caught is not enriched here. Matches Python's own
        // documented limitation in `client.py::_observe_hybrid` (and this
        // SDK's established practice of documenting a real limitation
        // rather than overclaiming — compare the same-request-only
        // enforcement limitation documented on ResponseWebhookClient).
        if ($this->circuitBreaker !== null && $this->circuitBreaker->shouldCallExternal()) {
            $this->circuitBreaker->recordSuccess();
        }

        return null;
    }

    /**
     * Whether $ip is currently blocked by the internal engine's in-memory
     * cache. Always false in external mode (no internal engine exists).
     */
    public function isBlocked(string $ip): bool
    {
        if ($this->internalEngine === null) {
            return false;
        }

        return $this->internalEngine->isIPBlocked($ip);
    }

    /**
     * Tier-3 relay target for hybrid mode — wired as the internal
     * engine's `onRelay` callback in the constructor. Reuses the existing
     * trackEvent()/retry path, same as every other outbound event from
     * this client, rather than opening a second HTTP path.
     *
     * @param array<string, mixed> $result InternalCLResult shape (see InternalClosedLoopEngine)
     * @param array<string, mixed> $req InternalCLRequest shape (see InternalClosedLoopEngine)
     */
    /**
     * Wired as the internal engine's onRelay callback, invoked
     * synchronously within evaluate() (see {@see InternalClosedLoopEngine}'s
     * own doc comment on why: evaluation itself must stay zero-network and
     * deterministic). trackEvent() below only enqueues — fast, in-memory,
     * safe to call synchronously here — and registerShutdownFlush() (idempotent;
     * safe to call every time this fires) ensures the queue is actually
     * flushed at process shutdown, after the response has already been sent
     * (fastcgi_finish_request() first, under FPM). Previously this relied
     * entirely on DevFortressMiddleware::terminate()'s own, unrelated
     * external-mode flush() call happening to also flush whatever this
     * method had queued — which only happened to work because a 403
     * response also looks classifier-worthy to buildEvent(); an excluded
     * path or a differently-shaped block response would have left the
     * relay event stuck in the queue with nothing to flush it, since this
     * demo never calls registerShutdownFlush() itself. Found live, via
     * this port's own end-to-end demo proof against a real platform.
     */
    private function relayInternalDecisionToPlatform(array $result, array $req): void
    {
        $matchedRules = $result['matchedRules'] ?? [];
        $eventType = $matchedRules[0] ?? ('icl_' . $result['decision']);
        $score = (float) $result['score'];
        $severity = $score >= 85 ? 'CRITICAL' : ($score >= 60 ? 'HIGH' : ($score >= 35 ? 'MEDIUM' : 'LOW'));
        $actionMap = [
            'allow' => 'allowed',
            'block' => 'blocked',
            'rate_limit' => 'rate_limited',
            'challenge' => 'challenge_required',
            'quarantine' => 'flagged',
        ];

        try {
            $this->trackEvent([
                'eventType' => $eventType,
                'ip' => $req['ip'],
                'severity' => $severity,
                'method' => $req['method'],
                'path' => $req['path'],
                'userAgent' => $req['userAgent'] ?? null,
                'authPhase' => !empty($req['userId']) ? 'post_auth' : 'pre_auth',
                'actionTaken' => $actionMap[$result['decision']] ?? 'flagged',
                'responseLatencyMs' => (int) round(($result['evaluationTimeUs'] ?? 0) / 1000),
                'clMode' => 'hybrid',
                'metadata' => [
                    'source' => 'internal-closed-loop-engine',
                    'tier' => $result['tier'],
                    'matchedRules' => $matchedRules,
                    'internalEventId' => $result['eventId'],
                    'sessionId' => $req['sessionId'] ?? null,
                    'agentId' => $req['agentId'] ?? null,
                ],
            ]);
            $this->registerShutdownFlush();
        } catch (Throwable $e) {
            $this->log('warning', 'DevFortress: internal-decision relay failed: ' . $e->getMessage());
        }
    }

    /** @param list<array<string, mixed>|Event> $events */
    private function enqueue(array $events): void
    {
        try {
            foreach ($events as $event) {
                $this->queue[] = $this->prepare($event instanceof Event ? $event->toArray() : $event);
            }
            if (count($this->queue) >= $this->batchSize) {
                $this->flush();
            }
        } catch (Throwable $e) {
            $this->log('error', 'DevFortress: could not queue event: ' . $e->getMessage());
        }
    }

    /**
     * @param array<string, mixed> $event
     *
     * @return array<string, mixed>
     */
    private function prepare(array $event): array
    {
        $item = array_merge($this->defaults, $event);
        if (!isset($item['timestamp'])) {
            $item['timestamp'] = gmdate('Y-m-d\TH:i:s') . sprintf('.%03dZ', (int) (fmod(microtime(true), 1) * 1000));
        }
        if ($this->privacy === 'strict') {
            unset($item['userAgent']);
            if (isset($item['ip']) && is_string($item['ip'])) {
                $item['ip'] = substr(hash('sha256', $item['ip']), 0, 16);
            }
        }
        if (array_key_exists('metadata', $item) && $item['metadata'] === []) {
            $item['metadata'] = new \stdClass();
        }

        return $item;
    }

    /** @param array<string, mixed> $payload */
    private function post(array $payload): DeliveryResult
    {
        try {
            $raw = json_encode(
                $payload,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $e) {
            return $this->fail(new DeliveryResult(false, null, null, 'could not encode payload: ' . $e->getMessage(), 0));
        }

        $last = new DeliveryResult(false, null, null, 'no delivery attempt was made', 0);
        for ($attempt = 1; $attempt <= $this->retries; $attempt++) {
            // A fresh nonce and timestamp on every attempt, so a retry is not a replay.
            $headers = $this->signer->sign('POST', $this->requestTarget, $raw) + [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'User-Agent' => 'devfortress-sdk-php/' . self::VERSION,
            ];

            $response = null;
            try {
                $response = $this->transport->send('POST', $this->endpoint, $headers, $raw, $this->timeout);
            } catch (TransportException $e) {
                $last = new DeliveryResult(false, null, null, 'request failed: ' . $e->getMessage(), $attempt);
            } catch (Throwable $e) {
                return $this->fail(new DeliveryResult(false, null, null, 'unexpected error: ' . $e->getMessage(), $attempt));
            }

            if ($response !== null) {
                $body = self::decode($response->body);
                if ($response->statusCode >= 200 && $response->statusCode < 300) {
                    return new DeliveryResult(true, $response->statusCode, $body, null, $attempt);
                }
                $last = new DeliveryResult(false, $response->statusCode, $body, 'HTTP ' . $response->statusCode, $attempt);
                if ($response->statusCode < 500) {
                    return $this->fail($last); // 3xx and 4xx: never retried
                }
            }

            if ($attempt < $this->retries) {
                ($this->sleeper)($this->backoffBase * (2 ** ($attempt - 1)));
            }
        }

        return $this->fail($last);
    }

    private function fail(DeliveryResult $result): DeliveryResult
    {
        $this->log('warning', 'DevFortress: delivery failed: ' . ($result->error ?? 'unknown error'), [
            'status' => $result->statusCode,
            'attempts' => $result->attempts,
        ]);

        return $result;
    }

    private static function decode(string $body): mixed
    {
        if ($body === '') {
            return [];
        }
        $decoded = json_decode($body, true);

        return json_last_error() === JSON_ERROR_NONE ? $decoded : $body;
    }

    /** @param array<string, mixed> $context */
    private function log(string $level, string $message, array $context = []): void
    {
        try {
            $this->logger?->log($level, $message, $context);
        } catch (Throwable) {
            // A failing logger must not reach the host application either.
        }
    }

    private static function wrapLogger(?object $logger): ?LoggerInterface
    {
        if ($logger === null) {
            return null;
        }
        if ($logger instanceof LoggerInterface) {
            return $logger;
        }
        if (!method_exists($logger, 'log')) {
            throw new InvalidArgumentException('DevFortress\Sdk\Client: the logger must provide a PSR-3 style log() method');
        }

        return new class ($logger) implements LoggerInterface {
            public function __construct(private readonly object $inner)
            {
            }

            public function log(mixed $level, string|\Stringable $message, array $context = []): void
            {
                /** @var callable $call */
                $call = [$this->inner, 'log'];
                $call($level, $message, $context);
            }
        };
    }
}
