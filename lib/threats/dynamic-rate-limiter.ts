/**
 * Dynamic Rate Limiting Service
 * Integrates with anomaly detection to dynamically adjust rate limits
 */

import { prisma } from '../prisma';
import { logInfo, logWarn, logError } from '../logger';
import { cache } from '../cache';

export interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Max requests per window
  blockDurationMs?: number; // How long to block if limit exceeded
}

export interface DynamicRateLimitRule {
  ip: string;
  reason: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  config: RateLimitConfig;
  expiresAt: Date;
}

// Default rate limits
const DEFAULT_RATE_LIMITS: Record<string, RateLimitConfig> = {
  NORMAL: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100,
  },
  SUSPICIOUS: {
    windowMs: 60 * 1000,
    maxRequests: 20,
  },
  BLOCKED: {
    windowMs: 60 * 1000,
    maxRequests: 0,
    blockDurationMs: 60 * 60 * 1000, // 1 hour
  },
};

export class DynamicRateLimiter {
  private cachePrefix = 'dynamic_rate_limit:';

  /**
   * Apply rate limit based on anomaly detection result
   */
  async applyAnomalyBasedRateLimit(
    ip: string,
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    reason: string
  ): Promise<DynamicRateLimitRule> {
    try {
      const config = this.getRateLimitForSeverity(severity);
      const expiresAt = new Date(
        Date.now() + (config.blockDurationMs || 60 * 60 * 1000)
      );

      const rule: DynamicRateLimitRule = {
        ip,
        reason,
        severity,
        config,
        expiresAt,
      };

      // Store in cache for quick lookup
      await cache.set(
        `${this.cachePrefix}${ip}`,
        rule,
        Math.floor((config.blockDurationMs || 60 * 60 * 1000) / 1000)
      );

      logInfo('Applied dynamic rate limit', {
        ip,
        severity,
        config,
      });

      return rule;
    } catch (error) {
      logError('Error applying dynamic rate limit', { error, ip });
      throw error;
    }
  }

  /**
   * Get rate limit configuration for a severity level
   */
  private getRateLimitForSeverity(
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  ): RateLimitConfig {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return DEFAULT_RATE_LIMITS.BLOCKED;
      case 'MEDIUM':
        return DEFAULT_RATE_LIMITS.SUSPICIOUS;
      case 'LOW':
      default:
        return DEFAULT_RATE_LIMITS.NORMAL;
    }
  }

  /**
   * Check if an IP is currently rate limited
   */
  async checkRateLimit(ip: string): Promise<{
    limited: boolean;
    rule?: DynamicRateLimitRule;
    remaining?: number;
  }> {
    try {
      const rule = await cache.get<DynamicRateLimitRule>(
        `${this.cachePrefix}${ip}`
      );

      if (!rule) {
        return { limited: false };
      }

      // Check if rule has expired
      if (new Date() > new Date(rule.expiresAt)) {
        await this.removeRateLimit(ip);
        return { limited: false };
      }

      // Check request count within window
      const requestKey = `${this.cachePrefix}requests:${ip}`;
      const requestCount = (await cache.get<number>(requestKey)) || 0;

      if (requestCount >= rule.config.maxRequests) {
        return {
          limited: true,
          rule,
          remaining: 0,
        };
      }

      // Increment request count
      await cache.set(
        requestKey,
        requestCount + 1,
        Math.floor(rule.config.windowMs / 1000)
      );

      return {
        limited: false,
        rule,
        remaining: rule.config.maxRequests - requestCount - 1,
      };
    } catch (error) {
      logError('Error checking rate limit', { error, ip });
      // Fail open - don't block on error
      return { limited: false };
    }
  }

  /**
   * Remove rate limit for an IP (e.g., after manual review)
   */
  async removeRateLimit(ip: string): Promise<void> {
    try {
      cache.delete(`${this.cachePrefix}${ip}`);
      cache.delete(`${this.cachePrefix}requests:${ip}`);
      logInfo('Removed dynamic rate limit', { ip });
    } catch (error) {
      logError('Error removing rate limit', { error, ip });
    }
  }

  /**
   * Get all active rate limits for a user's honeypots
   */
  async getActiveRateLimits(userId: string): Promise<DynamicRateLimitRule[]> {
    try {
      // Get all honeypots for user
      const honeypots = await prisma.honeypot.findMany({
        where: { ownerId: userId },
        select: { id: true },
      });

      const honeypotIds = honeypots.map(h => h.id);

      // Get recent threat events with blocked IPs
      const recentThreats = await prisma.threatEvent.findMany({
        where: {
          honeypotId: { in: honeypotIds },
          detectedAt: {
            gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
          },
          severity: {
            in: ['HIGH', 'CRITICAL'],
          },
        },
        distinct: ['sourceIp'],
        select: {
          sourceIp: true,
          severity: true,
        },
      });

      // Check which IPs are currently rate limited
      const activeLimits: DynamicRateLimitRule[] = [];

      for (const threat of recentThreats) {
        const rule = await cache.get<DynamicRateLimitRule>(
          `${this.cachePrefix}${threat.sourceIp}`
        );

        if (rule && new Date() <= new Date(rule.expiresAt)) {
          activeLimits.push(rule);
        }
      }

      return activeLimits;
    } catch (error) {
      logError('Error getting active rate limits', { error, userId });
      return [];
    }
  }

  /**
   * Escalate rate limit (make it stricter)
   */
  async escalateRateLimit(ip: string): Promise<void> {
    try {
      const existingRule = await cache.get<DynamicRateLimitRule>(
        `${this.cachePrefix}${ip}`
      );

      if (!existingRule) {
        logWarn('Cannot escalate - no existing rate limit', { ip });
        return;
      }

      // Escalate severity
      const newSeverity = this.escalateSeverity(existingRule.severity);
      await this.applyAnomalyBasedRateLimit(
        ip,
        newSeverity,
        `Escalated: ${existingRule.reason}`
      );

      logInfo('Escalated rate limit', {
        ip,
        oldSeverity: existingRule.severity,
        newSeverity,
      });
    } catch (error) {
      logError('Error escalating rate limit', { error, ip });
    }
  }

  /**
   * Escalate severity to next level
   */
  private escalateSeverity(
    current: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  ): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    switch (current) {
      case 'LOW':
        return 'MEDIUM';
      case 'MEDIUM':
        return 'HIGH';
      case 'HIGH':
      case 'CRITICAL':
        return 'CRITICAL';
    }
  }
}

// Singleton instance
export const dynamicRateLimiter = new DynamicRateLimiter();
