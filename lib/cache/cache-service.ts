/**
 * Redis Cache Service
 * Provides caching layer for performance optimization
 * 
 * Features:
 * - Key-value caching with TTL
 * - Cache invalidation strategies
 * - Performance metrics tracking
 * - Graceful fallback when Redis unavailable
 */

import { logInfo, logError } from '@core/lib/logger';

/**
 * Cache configuration
 */
interface CacheConfig {
  enabled: boolean;
  host: string;
  port: number;
  password?: string;
  ttl: number; // Default TTL in seconds
  maxMemory?: string;
  evictionPolicy?: string;
}

/**
 * Cache entry metadata
 */
interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  hits: number;
  createdAt: number;
}

/**
 * Cache statistics
 */
export interface CacheStats {
  hits: number;
  misses: number;
  keys: number;
  hitRate: number;
  memoryUsage?: number;
}

/**
 * In-memory cache fallback (when Redis unavailable)
 */
class InMemoryCache {
  private cache = new Map<string, CacheEntry<unknown>>();
  private stats = { hits: 0, misses: 0 };

  get<T>(key: string): T | null {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined;

    if (!entry) {
      this.stats.misses++;
      return null;
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      this.stats.misses++;
      return null;
    }

    entry.hits++;
    this.stats.hits++;
    return entry.value;
  }

  set<T>(key: string, value: T, ttlSeconds: number): void {
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + ttlSeconds * 1000,
      hits: 0,
      createdAt: Date.now(),
    });
  }

  delete(key: string): void {
    this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
    this.stats = { hits: 0, misses: 0 };
  }

  getStats(): CacheStats {
    return {
      hits: this.stats.hits,
      misses: this.stats.misses,
      keys: this.cache.size,
      hitRate: this.stats.hits / (this.stats.hits + this.stats.misses || 1),
    };
  }
}

/**
 * Cache service with Redis and in-memory fallback
 */
class CacheService {
  private memoryCache = new InMemoryCache();
  private config: CacheConfig;
  private redisAvailable = false;

  constructor(config: CacheConfig) {
    this.config = config;
    this.initialize();
  }

  private async initialize(): Promise<void> {
    if (!this.config.enabled) {
      logInfo('Cache disabled, using in-memory fallback');
      return;
    }

    // In production, would connect to Redis here
    // For now, using in-memory cache
    logInfo('Cache initialized with in-memory fallback');
  }

  /**
   * Get value from cache
   */
  async get<T>(key: string): Promise<T | null> {
    try {
      // Try Redis first (if available)
      if (this.redisAvailable) {
        // Redis implementation would go here
        return null;
      }

      // Fallback to in-memory cache
      return this.memoryCache.get<T>(key);
    } catch (error) {
      logError('Cache get error', { key, error });
      return null;
    }
  }

  /**
   * Set value in cache
   */
  async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    const ttl = ttlSeconds || this.config.ttl;

    try {
      if (this.redisAvailable) {
        // Redis implementation would go here
        return;
      }

      // Fallback to in-memory cache
      this.memoryCache.set(key, value, ttl);
      logInfo('Cache set', { key, ttl });
    } catch (error) {
      logError('Cache set error', { key, error });
    }
  }

  /**
   * Delete value from cache
   */
  async delete(key: string): Promise<void> {
    try {
      if (this.redisAvailable) {
        // Redis implementation would go here
        return;
      }

      this.memoryCache.delete(key);
      logInfo('Cache deleted', { key });
    } catch (error) {
      logError('Cache delete error', { key, error });
    }
  }

  /**
   * Clear all cache entries
   */
  async clear(): Promise<void> {
    try {
      if (this.redisAvailable) {
        // Redis implementation would go here
        return;
      }

      this.memoryCache.clear();
      logInfo('Cache cleared');
    } catch (error) {
      logError('Cache clear error', { error });
    }
  }

  /**
   * Get cache statistics
   */
  async getStats(): Promise<CacheStats> {
    try {
      if (this.redisAvailable) {
        // Redis implementation would go here
        return { hits: 0, misses: 0, keys: 0, hitRate: 0 };
      }

      return this.memoryCache.getStats();
    } catch (error) {
      logError('Cache stats error', { error });
      return { hits: 0, misses: 0, keys: 0, hitRate: 0 };
    }
  }

  /**
   * Cache wrapper for functions
   */
  async cached<T>(
    key: string,
    fn: () => Promise<T>,
    ttlSeconds?: number
  ): Promise<T> {
    // Try to get from cache
    const cached = await this.get<T>(key);
    if (cached !== null) {
      return cached;
    }

    // Execute function and cache result
    const result = await fn();
    await this.set(key, result, ttlSeconds);
    return result;
  }

  /**
   * Invalidate cache by pattern
   */
  async invalidatePattern(pattern: string): Promise<number> {
    try {
      logInfo('Cache invalidation', { pattern });
      // Pattern matching implementation would go here
      return 0;
    } catch (error) {
      logError('Cache invalidation error', { pattern, error });
      return 0;
    }
  }
}

/**
 * Default cache configuration
 */
const defaultConfig: CacheConfig = {
  enabled: process.env.REDIS_ENABLED === 'true',
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  password: process.env.REDIS_PASSWORD,
  ttl: 300, // 5 minutes default
  maxMemory: '256mb',
  evictionPolicy: 'allkeys-lru',
};

/**
 * Singleton cache instance
 */
export const cache = new CacheService(defaultConfig);

/**
 * Cache key generators for common patterns
 */
export const CacheKeys = {
  user: (userId: string) => `user:${userId}`,
  project: (projectId: string) => `project:${projectId}`,
  threats: (honeypotId: string, timeRange: string) => 
    `threats:${honeypotId}:${timeRange}`,
  insights: (projectId: string) => `insights:${projectId}`,
  apiGeneration: (hash: string) => `api-gen:${hash}`,
  subscriptionStatus: (userId: string) => `subscription:${userId}`,
};

/**
 * Standard TTL values
 */
export const CacheTTL = {
  short: 60, // 1 minute
  medium: 300, // 5 minutes
  long: 3600, // 1 hour
  day: 86400, // 24 hours
};
