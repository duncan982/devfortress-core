<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** In-memory LRU cache (IP-S5) — fallback for Redis. */
final class LRUCache
{
    /** @var array<string, array{value: string, expiresAt: float}> */
    private array $cache = [];

    public function __construct(
        private readonly int $maxEntries = 1000,
        private readonly int $defaultTtlSeconds = 60,
    ) {
    }

    public function get(string $key): ?string
    {
        $entry = $this->cache[$key] ?? null;
        if ($entry === null) {
            return null;
        }
        if (microtime(true) > $entry['expiresAt']) {
            unset($this->cache[$key]);

            return null;
        }
        // Move to end (most recently used)
        unset($this->cache[$key]);
        $this->cache[$key] = $entry;

        return $entry['value'];
    }

    public function set(string $key, string $value, ?int $ttlSeconds = null): void
    {
        if (count($this->cache) >= $this->maxEntries && !array_key_exists($key, $this->cache)) {
            unset($this->cache[array_key_first($this->cache)]);
        }
        $this->cache[$key] = [
            'value' => $value,
            'expiresAt' => microtime(true) + ($ttlSeconds ?? $this->defaultTtlSeconds),
        ];
    }

    public function del(string $key): void
    {
        unset($this->cache[$key]);
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }
}
