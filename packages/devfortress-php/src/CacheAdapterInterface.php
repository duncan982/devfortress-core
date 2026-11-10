<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * Pluggable cache backend for CredentialIsolationManager / ThreatInterceptor.
 * Implement against your Redis client for production use; falls back to
 * MemoryCacheAdapter for development/testing.
 */
interface CacheAdapterInterface
{
    public function get(string $key): ?string;

    public function set(string $key, string $value, int $ttlSeconds): void;

    public function del(string $key): void;
}
