<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Bounded Map.
 *
 * Mirrors packages/devfortress-sdk/src/internal-closed-loop-engine.ts's
 * generic, public BoundedMap. A bounded, LRU-ish map: once at capacity,
 * set() evicts the oldest-inserted entry still present. get() does not
 * change eviction order (eviction order is insertion order of
 * still-present keys, mirroring Node's Map-backed original, which
 * relies on the first key of Map::keys() for the oldest key, not
 * last-accessed).
 *
 * Distinct from the existing {@see LRUCache}, which is TTL-based and
 * string-value-only (IP-S5's webhook-block cache) — this type has no
 * expiry and is generic over value type, matching Node's BoundedMap
 * exactly.
 *
 * @template TValue
 */
final class BoundedMap
{
    /** @var array<string, TValue> */
    private array $store = [];

    /** @var list<string> insertion order, for oldest-first eviction */
    private array $order = [];

    public function __construct(private readonly int $maxSize)
    {
    }

    /** @return TValue|null */
    public function get(string $key): mixed
    {
        return $this->store[$key] ?? null;
    }

    /** @param TValue $value */
    public function set(string $key, mixed $value): void
    {
        $existed = array_key_exists($key, $this->store);
        if (!$existed && count($this->store) >= $this->maxSize) {
            $this->evictOldest();
        }
        if (!$existed) {
            $this->order[] = $key;
        }
        $this->store[$key] = $value;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }

    public function delete(string $key): bool
    {
        $existed = array_key_exists($key, $this->store);
        unset($this->store[$key]);

        return $existed;
    }

    public function size(): int
    {
        return count($this->store);
    }

    public function clear(): void
    {
        $this->store = [];
        $this->order = [];
    }

    /** @return list<TValue> */
    public function values(): array
    {
        return array_values($this->store);
    }

    /** @return list<string> */
    public function keys(): array
    {
        return array_keys($this->store);
    }

    /** @param callable(TValue, string): void $callback */
    public function forEach(callable $callback): void
    {
        foreach ($this->store as $key => $value) {
            $callback($value, $key);
        }
    }

    private function evictOldest(): void
    {
        while ($this->order !== []) {
            $oldest = array_shift($this->order);
            if (array_key_exists($oldest, $this->store)) {
                unset($this->store[$oldest]);

                return;
            }
        }
    }
}
