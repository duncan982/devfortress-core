/**
 * Role-Based Rate Limiting Service
 * Implements different rate limits based on user roles with abuse detection
 */

import { NextRequest, NextResponse } from 'next/server';
import { getRouteSession } from './auth/session';
import { logWarn, logError } from './logger';
import { cache } from './cache';
import { adminAlertService } from './alerts';
import { hasPrivilegedRole } from './auth/subscription-middleware';
import { getUserSubscription } from './payments/subscription-service';
import { SubscriptionTier } from './payments/types';

export interface RoleRateLimitConfig {
  windowMs: number;
  maxRequests: number;
  abuseThreshold: number; // Requests per window that trigger alerts
}

const ROLE_RATE_LIMITS: Record<string, RoleRateLimitConfig> = {
  OWNER: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 1000,
    abuseThreshold: 500,
  },
  ADMIN: {
    windowMs: 60 * 1000,
    maxRequests: 500,
    abuseThreshold: 200,
  },
  DEVELOPER: {
    windowMs: 60 * 1000,
    maxRequests: 100,
    abuseThreshold: 50,
  },
  VIEWER: {
    windowMs: 60 * 1000,
    maxRequests: 50,
    abuseThreshold: 25,
  },
};

/**
 * FREE tier for users without subscription (self-hosted/free users on hosted version)
 * Very restrictive to encourage subscription or self-hosting
 */
// const FREE_TIER_RATE_LIMIT: RoleRateLimitConfig = {
//   windowMs: 24 * 60 * 60 * 1000, // 24 hours
//   maxRequests: 10, // 10 requests per day
//   abuseThreshold: 5,
// };

const PLAN_RATE_LIMITS: Record<SubscriptionTier, RoleRateLimitConfig> =
  {
    // FREE: FREE_TIER_RATE_LIMIT, // Commented out - FREE tier removed
    [SubscriptionTier.STARTER]: {
      windowMs: 60 * 1000,
      maxRequests: 50,
      abuseThreshold: 25,
    },
    [SubscriptionTier.PRO]: {
      windowMs: 60 * 1000,
      maxRequests: 200,
      abuseThreshold: 100,
    },
    [SubscriptionTier.ENTERPRISE]: {
      windowMs: 60 * 1000,
      maxRequests: 500,
      abuseThreshold: 250,
    },
  };

const HONEYPOT_DAILY_LIMIT = 5; // Admin honeypot creation limit per day

export class RoleBasedRateLimiter {
  private cachePrefix = 'role_rate_limit:';
  private honeypotCachePrefix = 'honeypot_limit:';

  /**
   * Check rate limit for a request based on user role
   */
  async checkRateLimit(
    request: NextRequest,
    path: string
  ): Promise<{
    allowed: boolean;
    remaining: number;
    resetTime: number;
    abuseDetected: boolean;
  }> {
    try {
      const session = await getRouteSession();

      if (!session?.user) {
        // Anonymous users get lowest limit
        return this.checkAnonymousLimit(request);
      }

      const role = session.user.role || 'VIEWER';

      // Check if user has active subscription and is privileged (for testing)
      const isPrivileged = hasPrivilegedRole(role);
      let config = ROLE_RATE_LIMITS[role] || ROLE_RATE_LIMITS.VIEWER;

      if (isPrivileged) {
        const subscription = await getUserSubscription(session.user.id);
        if (subscription) {
          const planConfig =
            PLAN_RATE_LIMITS[subscription.plan as SubscriptionTier];
          if (planConfig) {
            config = planConfig;
          }
        }
      }

      const key = `${this.cachePrefix}${session.user.id}:${path}`;
      const now = Date.now();
      const windowStart = Math.floor(now / config.windowMs) * config.windowMs;

      const cacheKey = `${key}:${windowStart}`;
      const current = ((await cache.get(cacheKey)) as number) || 0;
      const newCount = current + 1;

      const remaining = Math.max(0, config.maxRequests - newCount);
      const allowed = newCount <= config.maxRequests;
      const abuseDetected = newCount >= config.abuseThreshold;

      if (allowed) {
        await cache.set(cacheKey, newCount, config.windowMs / 1000);
      }

      if (abuseDetected) {
        logWarn('Rate limit abuse detected', {
          userId: session.user.id,
          role,
          path,
          requestCount: newCount,
          threshold: config.abuseThreshold,
        });
        // Send admin alert for abuse detection
        await adminAlertService.sendRateLimitAbuseAlert(
          session.user.id,
          session.user.email,
          role,
          path,
          newCount,
          config.abuseThreshold
        );
      }

      return {
        allowed,
        remaining,
        resetTime: windowStart + config.windowMs,
        abuseDetected,
      };
    } catch (error) {
      logError('Rate limit check failed', { error, path });
      // Allow request on error to avoid blocking legitimate traffic
      return {
        allowed: true,
        remaining: 999,
        resetTime: Date.now() + 60000,
        abuseDetected: false,
      };
    }
  }

  /**
   * Check honeypot creation limit for admin users
   */
  async checkHoneypotLimit(userId: string): Promise<{
    allowed: boolean;
    remaining: number;
    resetTime: number;
  }> {
    const now = new Date();
    const today = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate()
    ).getTime();
    const tomorrow = today + 24 * 60 * 60 * 1000;

    const cacheKey = `${this.honeypotCachePrefix}${userId}:${today}`;
    const current = ((await cache.get(cacheKey)) as number) || 0;
    const newCount = current + 1;

    const allowed = newCount <= HONEYPOT_DAILY_LIMIT;
    const remaining = Math.max(0, HONEYPOT_DAILY_LIMIT - newCount);

    if (allowed) {
      await cache.set(cacheKey, newCount, (tomorrow - now.getTime()) / 1000);
    }

    return {
      allowed,
      remaining,
      resetTime: tomorrow,
    };
  }

  private async checkAnonymousLimit(request: NextRequest): Promise<{
    allowed: boolean;
    remaining: number;
    resetTime: number;
    abuseDetected: boolean;
  }> {
    const ip =
      request.headers.get('x-forwarded-for') ||
      request.headers.get('x-real-ip') ||
      'unknown';

    // Use STARTER tier limits for anonymous/unauthenticated users (FREE tier removed)
    const config = PLAN_RATE_LIMITS[SubscriptionTier.STARTER];
    const key = `${this.cachePrefix}anon:${ip}`;
    const now = Date.now();
    const windowStart = Math.floor(now / config.windowMs) * config.windowMs;

    const cacheKey = `${key}:${windowStart}`;
    const current = ((await cache.get(cacheKey)) as number) || 0;
    const newCount = current + 1;

    const remaining = Math.max(0, config.maxRequests - newCount);
    const allowed = newCount <= config.maxRequests;
    const abuseDetected = newCount >= config.abuseThreshold;

    if (allowed) {
      await cache.set(cacheKey, newCount, config.windowMs / 1000);
    }

    if (!allowed) {
      logWarn('Free tier rate limit exceeded for anonymous user', {
        ip,
        requestCount: newCount,
        limit: config.maxRequests,
      });
    }

    return {
      allowed,
      remaining,
      resetTime: windowStart + config.windowMs,
      abuseDetected,
    };
  }
}

export const roleRateLimiter = new RoleBasedRateLimiter();

/**
 * Middleware function for API routes
 */
export async function withRoleBasedRateLimit(
  request: NextRequest,
  handler: () => Promise<NextResponse>
): Promise<NextResponse> {
  const path = request.nextUrl.pathname;

  const limitResult = await roleRateLimiter.checkRateLimit(request, path);

  if (!limitResult.allowed) {
    return NextResponse.json(
      {
        error: 'Rate limit exceeded',
        retryAfter: Math.ceil((limitResult.resetTime - Date.now()) / 1000),
      },
      {
        status: 429,
        headers: {
          'X-RateLimit-Remaining': limitResult.remaining.toString(),
          'X-RateLimit-Reset': limitResult.resetTime.toString(),
          'Retry-After': Math.ceil(
            (limitResult.resetTime - Date.now()) / 1000
          ).toString(),
        },
      }
    );
  }

  // Add rate limit headers
  const response = await handler();
  response.headers.set(
    'X-RateLimit-Remaining',
    limitResult.remaining.toString()
  );
  response.headers.set('X-RateLimit-Reset', limitResult.resetTime.toString());

  if (limitResult.abuseDetected) {
    response.headers.set('X-Abuse-Detected', 'true');
  }

  return response;
}
