/**
 * Caching utility for VortexSecure
 * Provides in-memory caching for serverless functions (Vercel free tier compatible)
 * Includes LRU eviction and TTL support
 */

import { logInfo, logWarn, logDebug } from './logger';

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  lastAccessed: number;
}

interface CacheOptions {
  maxSize?: number; // Maximum number of entries
  defaultTTL?: number; // Default TTL in seconds
}

class InMemoryCache {
  private cache: Map<string, CacheEntry<unknown>>;
  private maxSize: number;
  private defaultTTL: number;

  constructor(options: CacheOptions = {}) {
    this.cache = new Map();
    this.maxSize = options.maxSize || 100;
    this.defaultTTL = options.defaultTTL || 300; // 5 minutes default

    logInfo('In-memory cache initialized', {
      maxSize: this.maxSize,
      defaultTTL: this.defaultTTL,
    });
  }

  /**
   * Get value from cache
   */
  get<T>(key: string): T | null {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined;

    if (!entry) {
      logDebug('Cache miss', { key });
      return null;
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      logDebug('Cache expired', { key });
      this.cache.delete(key);
      return null;
    }

    // Update last accessed time for LRU
    entry.lastAccessed = Date.now();
    logDebug('Cache hit', { key });
    return entry.value;
  }

  /**
   * Set value in cache
   */
  set<T>(key: string, value: T, ttl?: number): void {
    // Evict least recently used if at capacity
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      this.evictLRU();
    }

    const expiresAt = Date.now() + (ttl || this.defaultTTL) * 1000;
    const entry: CacheEntry<T> = {
      value,
      expiresAt,
      lastAccessed: Date.now(),
    };

    this.cache.set(key, entry);
    logDebug('Cache set', { key, ttl: ttl || this.defaultTTL });
  }

  /**
   * Delete value from cache
   */
  delete(key: string): boolean {
    const deleted = this.cache.delete(key);
    if (deleted) {
      logDebug('Cache delete', { key });
    }
    return deleted;
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    const size = this.cache.size;
    this.cache.clear();
    logInfo('Cache cleared', { entriesRemoved: size });
  }

  /**
   * Get cache statistics
   */
  getStats() {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      defaultTTL: this.defaultTTL,
    };
  }

  /**
   * Evict least recently used entry
   */
  private evictLRU(): void {
    let lruKey: string | null = null;
    let lruTime = Infinity;

    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccessed < lruTime) {
        lruTime = entry.lastAccessed;
        lruKey = key;
      }
    }

    if (lruKey) {
      this.cache.delete(lruKey);
      logWarn('Cache LRU eviction', { evictedKey: lruKey });
    }
  }

  /**
   * Clean expired entries
   */
  cleanExpired(): number {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logInfo('Cache cleanup', { expiredEntriesRemoved: cleaned });
    }

    return cleaned;
  }
}

// Export singleton instance
export const cache = new InMemoryCache({
  maxSize: 100,
  defaultTTL: 300, // 5 minutes
});

/**
 * Cache wrapper for async functions
 */
export async function withCache<T>(
  key: string,
  fn: () => Promise<T>,
  ttl?: number
): Promise<T> {
  // Try to get from cache
  const cached = cache.get<T>(key);
  if (cached !== null) {
    return cached;
  }

  // Execute function and cache result
  const result = await fn();
  cache.set(key, result, ttl);
  return result;
}

/**
 * Cache key builder
 */
export function buildCacheKey(
  ...parts: (string | number | undefined)[]
): string {
  return parts.filter(Boolean).join(':');
}

// Periodic cleanup (run every 5 minutes)
if (typeof setInterval !== 'undefined') {
  setInterval(
    () => {
      cache.cleanExpired();
    },
    5 * 60 * 1000
  );
}
