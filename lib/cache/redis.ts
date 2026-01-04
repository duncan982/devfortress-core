/**
 * Redis Cache Implementation
 * Enhanced caching with Redis support for production environments
 * Falls back to in-memory cache when Redis is not available
 *
 * To enable Redis:
 * 1. Install: npm install @upstash/redis
 * 2. Set environment variables: REDIS_URL, REDIS_TOKEN (or UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN)
 */

import { cache as memoryCache, buildCacheKey } from '../cache';
import { logInfo, logError, logDebug } from '../logger';

/**
 * Redis client type (dynamically imported)
 */
type RedisClient = {
  get: <T>(key: string) => Promise<T | null>;
  set: (key: string, value: string) => Promise<void>;
  setex: (key: string, ttl: number, value: string) => Promise<void>;
  del: (key: string) => Promise<void>;
  exists: (key: string) => Promise<number>;
  incrby: (key: string, by: number) => Promise<number>;
  expire: (key: string, ttl: number) => Promise<void>;
  ttl: (key: string) => Promise<number>;
};

/**
 * Redis client instance (lazy loaded)
 */
let redisClient: RedisClient | null = null;

/**
 * Initialize Redis client
 */
async function getRedisClient(): Promise<RedisClient | null> {
  if (redisClient) {
    return redisClient;
  }

  const redisUrl = process.env.REDIS_URL || process.env.UPSTASH_REDIS_REST_URL;
  const redisToken =
    process.env.REDIS_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!redisUrl || !redisToken) {
    logInfo('Redis not configured, using in-memory cache');
    return null;
  }

  try {
    // Dynamically import Redis to avoid errors if package is not installed
    const { Redis } = await import('@upstash/redis');

    redisClient = new Redis({
      url: redisUrl,
      token: redisToken,
    }) as unknown as RedisClient;

    logInfo('Redis client initialized');
    return redisClient;
  } catch (error) {
    logError(
      'Redis package not installed or initialization failed, using memory cache',
      error
    );
    return null;
  }
}

/**
 * Enhanced cache with Redis support
 */
export class DistributedCache {
  private redis: RedisClient | null = null;
  private initialized = false;

  async ensureInitialized() {
    if (!this.initialized) {
      this.redis = await getRedisClient();
      this.initialized = true;
    }
  }

  /**
   * Get value from cache (tries Redis first, falls back to memory)
   */
  async get<T>(key: string): Promise<T | null> {
    await this.ensureInitialized();

    try {
      // Try Redis first
      if (this.redis) {
        const value = await this.redis.get<T>(key);
        if (value !== null) {
          logDebug('Redis cache hit', { key });
          return value;
        }
      }

      // Fall back to memory cache
      const memValue = memoryCache.get<T>(key);
      if (memValue !== null) {
        logDebug('Memory cache hit', { key });
        return memValue;
      }

      logDebug('Cache miss', { key });
      return null;
    } catch (error) {
      logError('Cache get error', error);
      // Fall back to memory cache on error
      return memoryCache.get<T>(key);
    }
  }

  /**
   * Set value in cache (writes to both Redis and memory)
   */
  async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    await this.ensureInitialized();

    try {
      // Write to Redis
      if (this.redis) {
        if (ttlSeconds) {
          await this.redis.setex(key, ttlSeconds, JSON.stringify(value));
        } else {
          await this.redis.set(key, JSON.stringify(value));
        }
        logDebug('Redis cache set', { key, ttl: ttlSeconds });
      }

      // Also write to memory cache for faster local access
      memoryCache.set(key, value, ttlSeconds);
    } catch (error) {
      logError('Cache set error', error);
      // Fall back to memory cache on error
      memoryCache.set(key, value, ttlSeconds);
    }
  }

  /**
   * Delete value from cache
   */
  async delete(key: string): Promise<void> {
    try {
      if (this.redis) {
        await this.redis.del(key);
      }
      memoryCache.delete(key);
      logDebug('Cache delete', { key });
    } catch (error) {
      logError('Cache delete error', error);
      memoryCache.delete(key);
    }
  }

  /**
   * Delete multiple keys matching a pattern
   */
  async deletePattern(pattern: string): Promise<void> {
    try {
      if (this.redis) {
        // Note: Redis SCAN is not directly available in Upstash REST API
        // For pattern deletion, we'll need to track keys or use a different approach
        logDebug('Pattern delete requested', { pattern });
        // For now, clear memory cache
        memoryCache.clear();
      } else {
        memoryCache.clear();
      }
    } catch (error) {
      logError('Pattern delete error', error);
    }
  }

  /**
   * Check if key exists
   */
  async exists(key: string): Promise<boolean> {
    try {
      if (this.redis) {
        const result = await this.redis.exists(key);
        return result === 1;
      }
      return memoryCache.get(key) !== null;
    } catch (error) {
      logError('Cache exists error', error);
      return memoryCache.get(key) !== null;
    }
  }

  /**
   * Increment a counter
   */
  async increment(key: string, by: number = 1): Promise<number> {
    try {
      if (this.redis) {
        return await this.redis.incrby(key, by);
      }
      // Fallback: increment in memory
      const current = memoryCache.get<number>(key) || 0;
      const newValue = current + by;
      memoryCache.set(key, newValue);
      return newValue;
    } catch (error) {
      logError('Cache increment error', error);
      return 0;
    }
  }

  /**
   * Set expiration on existing key
   */
  async expire(key: string, ttlSeconds: number): Promise<void> {
    try {
      if (this.redis) {
        await this.redis.expire(key, ttlSeconds);
      }
      // Memory cache doesn't support expiration updates
    } catch (error) {
      logError('Cache expire error', error);
    }
  }

  /**
   * Get time to live for a key
   */
  async ttl(key: string): Promise<number> {
    try {
      if (this.redis) {
        return await this.redis.ttl(key);
      }
      return -1; // Unknown for memory cache
    } catch (error) {
      logError('Cache TTL error', error);
      return -1;
    }
  }
}

// Export singleton instance
export const distributedCache = new DistributedCache();

/**
 * Cache wrapper for async functions with Redis support
 */
export async function withDistributedCache<T>(
  key: string,
  fn: () => Promise<T>,
  ttlSeconds?: number
): Promise<T> {
  // Try to get from cache
  const cached = await distributedCache.get<T>(key);
  if (cached !== null) {
    return cached;
  }

  // Execute function and cache result
  const result = await fn();
  await distributedCache.set(key, result, ttlSeconds);
  return result;
}

/**
 * Cache invalidation strategies
 */
export const CacheInvalidation = {
  /**
   * Invalidate cache for a specific user
   */
  async invalidateUser(userId: string): Promise<void> {
    const patterns = [
      buildCacheKey('user', userId),
      buildCacheKey('user-projects', userId),
      buildCacheKey('user-subscriptions', userId),
      buildCacheKey('user-credits', userId),
    ];

    for (const pattern of patterns) {
      await distributedCache.delete(pattern);
    }

    logInfo('User cache invalidated', { userId });
  },

  /**
   * Invalidate cache for a specific API project
   */
  async invalidateProject(projectId: string): Promise<void> {
    const patterns = [
      buildCacheKey('project', projectId),
      buildCacheKey('project-specs', projectId),
      buildCacheKey('project-security', projectId),
    ];

    for (const pattern of patterns) {
      await distributedCache.delete(pattern);
    }

    logInfo('Project cache invalidated', { projectId });
  },

  /**
   * Invalidate analytics cache
   */
  async invalidateAnalytics(): Promise<void> {
    const patterns = [
      buildCacheKey('analytics', 'revenue'),
      buildCacheKey('analytics', 'churn'),
      buildCacheKey('analytics', 'features'),
      buildCacheKey('system', 'metrics'),
    ];

    for (const pattern of patterns) {
      await distributedCache.delete(pattern);
    }

    logInfo('Analytics cache invalidated');
  },

  /**
   * Invalidate all cache (use sparingly)
   */
  async invalidateAll(): Promise<void> {
    await distributedCache.deletePattern('*');
    logInfo('All cache invalidated');
  },
};

/**
 * Common cache TTLs (in seconds)
 */
export const CacheTTL = {
  SHORT: 60, // 1 minute
  MEDIUM: 300, // 5 minutes
  LONG: 900, // 15 minutes
  HOUR: 3600, // 1 hour
  DAY: 86400, // 24 hours
};

export { buildCacheKey };
