<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use Throwable;

/**
 * Local emergency blocklist (IP-M6) — synchronous, pre-webhook IP blocking.
 * When a critical event fires, the IP is written here BEFORE the webhook is
 * sent, ensuring the IP is blocked even if the webhook receiver is down.
 */
final class ThreatInterceptor
{
    private readonly CacheAdapterInterface $cache;
    private readonly LRUCache $lru;
    /** Default TTL: 15 minutes (10 min webhook retry window + 5 min safety). */
    private readonly int $defaultTtlSeconds;

    public function __construct(?CacheAdapterInterface $cache = null, int $ttlSeconds = 900)
    {
        $this->cache = $cache ?? new MemoryCacheAdapter();
        $this->lru = new LRUCache(5000, $ttlSeconds);
        $this->defaultTtlSeconds = $ttlSeconds;
    }

    /** Block an IP immediately on critical event classification. */
    public function blockIP(string $ip, string $reason = 'critical_event'): void
    {
        $value = json_encode(['reason' => $reason, 'blockedAt' => (int) round(microtime(true) * 1000)], JSON_THROW_ON_ERROR);
        $this->lru->set("emergency:block:{$ip}", $value, $this->defaultTtlSeconds);
        try {
            $this->cache->set("emergency:block:{$ip}", $value, $this->defaultTtlSeconds);
        } catch (Throwable) {
            // LRU cache is already set — cache failure doesn't prevent blocking
        }
    }

    /** Check if an IP is emergency-blocked. O(1) — safe for every request. */
    public function isBlocked(string $ip): bool
    {
        if ($this->lru->has("emergency:block:{$ip}")) {
            return true;
        }
        try {
            return $this->cache->get("emergency:block:{$ip}") !== null;
        } catch (Throwable) {
            return false; // On cache failure, LRU was already checked
        }
    }

    /** Unblock an IP (manual override). */
    public function unblockIP(string $ip): void
    {
        $this->lru->del("emergency:block:{$ip}");
        try {
            $this->cache->del("emergency:block:{$ip}");
        } catch (Throwable) {
            // Best-effort
        }
    }
}
