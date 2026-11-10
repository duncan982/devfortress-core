<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** In-memory cache adapter (development fallback). One instance per process. */
final class MemoryCacheAdapter implements CacheAdapterInterface
{
    /** @var array<string, array{value: string, expiresAt: float}> */
    private array $store = [];

    public function get(string $key): ?string
    {
        $entry = $this->store[$key] ?? null;
        if ($entry === null) {
            return null;
        }
        if (microtime(true) > $entry['expiresAt']) {
            unset($this->store[$key]);

            return null;
        }

        return $entry['value'];
    }

    public function set(string $key, string $value, int $ttlSeconds): void
    {
        $this->store[$key] = ['value' => $value, 'expiresAt' => microtime(true) + $ttlSeconds];
    }

    public function del(string $key): void
    {
        unset($this->store[$key]);
    }
}
