<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use DevFortress\Sdk\Transport\CurlTransport;
use DevFortress\Sdk\Transport\TransportException;
use DevFortress\Sdk\Transport\TransportInterface;

/**
 * Delivers closed-loop response commands (session revocation, IP block) to
 * a single customer-configured webhook endpoint — the outbound direction
 * of the closed loop, complementing WebhookVerifier::verify (the inbound
 * direction: verifying a command the platform sent to this application).
 * Every delivery is HMAC-SHA256 signed the same way WebhookVerifier checks
 * it (hex HMAC over "{timestamp}.{body}"), rate limited per endpoint
 * (60/min, S28 webhook flooding protection), and awaited with a short SLA
 * timeout. Mirrors the outbound-delivery half of
 * packages/devfortress-sdk/src/devfortress.ts (deliverSessionRevocation /
 * deliverIPBlock / checkWebhookRateLimit).
 */
final class ResponseWebhookClient
{
    private const RATE_WINDOW_SECONDS = 60;
    private const RATE_LIMIT = 60;
    private const BLOCK_CACHE_MAX_ENTRIES = 10_000;
    private const DEFAULT_BLOCK_CACHE_TTL_SECONDS = 3600;

    private readonly TransportInterface $transport;
    /** @var array<string, array{count: int, windowStart: float}> */
    private array $buckets = [];
    private readonly LRUCache $blockCache;

    public function __construct(
        private readonly ?string $url,
        private readonly ?string $secret,
        ?TransportInterface $transport = null,
    ) {
        $this->transport = $transport ?? new CurlTransport();
        $this->blockCache = new LRUCache(self::BLOCK_CACHE_MAX_ENTRIES, self::DEFAULT_BLOCK_CACHE_TTL_SECONDS);
    }

    /**
     * Reports whether $ip was locally cached as blocked by a prior
     * recordInboundCommand() call — local-only, no network call. Mirrors
     * Node's own external-mode isBlocked()/memGet pair and Python's
     * ClosedLoopEngine.is_blocked_ip (TODO 358): this SDK previously
     * delivered and verified block/revocation commands but never
     * self-enforced them locally, leaving every embedding app to implement
     * its own cache.
     */
    public function isIPBlocked(string $ip): bool
    {
        return $this->blockCache->has("blocked:ip:{$ip}");
    }

    /**
     * Reports whether $userId was locally cached as blocked by a prior
     * recordInboundCommand() call — local-only, no network call.
     */
    public function isUserBlocked(string $userId): bool
    {
        return $this->blockCache->has("blocked:user:{$userId}");
    }

    /**
     * Locally caches the block/revocation decision carried by an
     * already-verified inbound command (see WebhookVerifier::verify and
     * json_decode()), so a subsequent isIPBlocked()/isUserBlocked() call
     * enforces it without a remote round-trip.
     *
     * An "ip_block" command is cached only when its severity is "critical"
     * or "high" (or unset — deliverIPBlock() defaults to "high" when the
     * sender leaves it empty), matching Node/Python's own severity gate. A
     * "session_revocation" command carries no severity field on this SDK's
     * wire shape (see deliverSessionRevocation()'s body) — its delivery
     * already represents a decided enforcement action, so it is always
     * cached.
     *
     * @param array<string, mixed> $command decoded inbound JSON command body
     */
    public function recordInboundCommand(array $command): void
    {
        $ttlSeconds = isset($command['ttl_seconds']) ? (int) $command['ttl_seconds'] : self::DEFAULT_BLOCK_CACHE_TTL_SECONDS;

        switch ($command['type'] ?? null) {
            case 'ip_block':
                $severity = $command['severity'] ?? null;
                if ($severity !== null && !in_array($severity, ['high', 'critical'], true)) {
                    return;
                }
                $ip = $command['ip'] ?? null;
                if (is_string($ip) && $ip !== '') {
                    $this->blockCache->set("blocked:ip:{$ip}", '1', $ttlSeconds);
                }
                break;
            case 'session_revocation':
                $userId = $command['user_id'] ?? null;
                $ip = $command['ip'] ?? null;
                if (is_string($userId) && $userId !== '') {
                    $this->blockCache->set("blocked:user:{$userId}", '1', $ttlSeconds);
                }
                if (is_string($ip) && $ip !== '') {
                    $this->blockCache->set("blocked:ip:{$ip}", '1', $ttlSeconds);
                }
                break;
        }
    }

    /**
     * Deliver a session-revocation command, awaiting acknowledgement with a
     * 2-second SLA timeout.
     *
     * @return array{delivered: bool, ackMs: int}
     */
    public function deliverSessionRevocation(string $sessionId, ?string $userId, string $reason, ?string $ip = null): array
    {
        if ($this->url === null || $this->url === '' || $this->secret === null || $this->secret === '') {
            return ['delivered' => false, 'ackMs' => 0];
        }
        if (!$this->checkWebhookRateLimit($this->url)) {
            return ['delivered' => false, 'ackMs' => 0];
        }

        $timestamp = self::nowIso();
        $body = json_encode([
            'type' => 'session_revocation', 'session_id' => $sessionId, 'user_id' => $userId,
            'reason' => $reason, 'ip' => $ip, 'issued_at' => $timestamp,
        ], JSON_THROW_ON_ERROR);

        return $this->deliver($timestamp, $body, 2.0);
    }

    /**
     * Deliver an IP-block command so the customer can enforce at the edge
     * (CDN/WAF/load balancer), awaiting acknowledgement with a 5-second SLA
     * timeout.
     *
     * @return array{delivered: bool, ackMs: int}
     */
    public function deliverIPBlock(string $ip, string $reason, int $ttlSeconds = 3600, string $severity = 'high'): array
    {
        if ($this->url === null || $this->url === '' || $this->secret === null || $this->secret === '') {
            return ['delivered' => false, 'ackMs' => 0];
        }
        if (!$this->checkWebhookRateLimit($this->url)) {
            return ['delivered' => false, 'ackMs' => 0];
        }

        $timestamp = self::nowIso();
        $body = json_encode([
            'type' => 'ip_block', 'ip' => $ip, 'reason' => $reason, 'ttl_seconds' => $ttlSeconds,
            'severity' => $severity, 'issued_at' => $timestamp,
        ], JSON_THROW_ON_ERROR);

        return $this->deliver($timestamp, $body, 5.0);
    }

    /** @return array{delivered: bool, ackMs: int} */
    private function deliver(string $timestamp, string $body, float $timeoutSeconds): array
    {
        $signature = hash_hmac('sha256', "{$timestamp}.{$body}", (string) $this->secret);
        $headers = [
            'Content-Type' => 'application/json',
            WebhookVerifier::SIGNATURE_HEADER => $signature,
            WebhookVerifier::TIMESTAMP_HEADER => $timestamp,
        ];
        $start = microtime(true);
        try {
            $this->transport->send('POST', (string) $this->url, $headers, $body, $timeoutSeconds);

            return ['delivered' => true, 'ackMs' => (int) round((microtime(true) - $start) * 1000)];
        } catch (TransportException) {
            return ['delivered' => false, 'ackMs' => (int) round((microtime(true) - $start) * 1000)];
        }
    }

    /**
     * S28 webhook flooding protection: at most RATE_LIMIT deliveries per
     * endpoint per RATE_WINDOW_SECONDS.
     */
    private function checkWebhookRateLimit(string $endpointUrl): bool
    {
        $now = microtime(true);
        $bucket = $this->buckets[$endpointUrl] ?? null;

        if ($bucket === null || ($now - $bucket['windowStart']) >= self::RATE_WINDOW_SECONDS) {
            $this->buckets[$endpointUrl] = ['count' => 1, 'windowStart' => $now];

            return true;
        }

        if ($bucket['count'] >= self::RATE_LIMIT) {
            return false;
        }

        $this->buckets[$endpointUrl]['count']++;

        return true;
    }

    private static function nowIso(): string
    {
        $now = microtime(true);
        $ms = (int) round(($now - floor($now)) * 1000);

        return gmdate('Y-m-d\TH:i:s', (int) $now) . sprintf('.%03dZ', $ms);
    }
}
