/**
 * Session Management Service
 * Implements short-lived token management and continuous verification
 */

import { PrismaClient } from '@prisma/client';
import { logInfo, logError, logWarn } from '../logger';
import crypto from 'crypto';

const prisma = new PrismaClient();

// Session configuration
const SESSION_DURATION = 15 * 60 * 1000; // 15 minutes
const REFRESH_TOKEN_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_SESSIONS_PER_USER = 5;

export interface SessionData {
  id: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  refreshExpiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
  lastActivity: Date;
}

export interface CreateSessionParams {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  mfaVerified?: boolean;
}

/**
 * Create a new session with short-lived access token
 */
export async function createSession(
  params: CreateSessionParams
): Promise<SessionData> {
  try {
    const { userId, ipAddress, userAgent, mfaVerified = false } = params;

    // Clean up old sessions if user has too many
    await cleanupOldSessions(userId);

    // Generate tokens
    const accessToken = generateToken();
    const refreshToken = generateToken();

    const now = new Date();
    const expiresAt = new Date(now.getTime() + SESSION_DURATION);
    const refreshExpiresAt = new Date(now.getTime() + REFRESH_TOKEN_DURATION);

    // Create session
    const session = await prisma.userSession.create({
      data: {
        userId,
        accessToken,
        refreshToken,
        expiresAt,
        refreshExpiresAt,
        ipAddress,
        userAgent,
        lastActivity: now,
        mfaVerified,
      },
    });

    logInfo('Session created', {
      userId,
      sessionId: session.id,
      ipAddress,
      mfaVerified,
    });

    return {
      id: session.id,
      userId: session.userId,
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      expiresAt: session.expiresAt,
      refreshExpiresAt: session.refreshExpiresAt,
      ipAddress: session.ipAddress || undefined,
      userAgent: session.userAgent || undefined,
      lastActivity: session.lastActivity,
    };
  } catch (error) {
    logError('Error creating session', { error, params });
    throw error;
  }
}

/**
 * Track failed validation attempts for suspicious activity detection
 */
async function trackFailedValidation(accessToken: string): Promise<void> {
  try {
    // Extract partial token for tracking (first 8 characters)
    const tokenPrefix = accessToken.substring(0, 8);

    // For now, just log suspicious activity
    // In a production system, you might want to:
    // 1. Store failed attempts in a cache (Redis)
    // 2. Use a rate limiter
    // 3. Implement progressive delays
    // 4. Send alerts for high-frequency failures

    logWarn('Session validation failed', {
      tokenPrefix,
      timestamp: new Date().toISOString(),
    });

    // Placeholder for future suspicious activity detection
    // This could be enhanced with Redis caching for tracking
    // failed attempts per IP/token pattern
  } catch (error) {
    logError('Error tracking failed validation', { error, accessToken });
  }
}
export async function validateSession(
  accessToken: string
): Promise<SessionData | null> {
  try {
    const session = await prisma.userSession.findUnique({
      where: { accessToken },
    });

    if (!session) {
      // Track failed validation attempts
      await trackFailedValidation(accessToken);
      return null;
    }

    // Check if session is expired
    if (new Date() > session.expiresAt) {
      logWarn('Session expired', { sessionId: session.id });
      return null;
    }

    // Check if session is revoked
    if (session.revokedAt) {
      logWarn('Session revoked', { sessionId: session.id });
      return null;
    }

    // Update last activity
    await prisma.userSession.update({
      where: { id: session.id },
      data: { lastActivity: new Date() },
    });

    return {
      id: session.id,
      userId: session.userId,
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      expiresAt: session.expiresAt,
      refreshExpiresAt: session.refreshExpiresAt,
      ipAddress: session.ipAddress || undefined,
      userAgent: session.userAgent || undefined,
      lastActivity: session.lastActivity,
    };
  } catch (error) {
    logError('Error validating session', { error, accessToken });
    return null;
  }
}

/**
 * Refresh an access token using a refresh token
 */
export async function refreshSession(
  refreshToken: string
): Promise<SessionData | null> {
  try {
    const session = await prisma.userSession.findUnique({
      where: { refreshToken },
    });

    if (!session) {
      return null;
    }

    // Check if refresh token is expired
    if (new Date() > session.refreshExpiresAt) {
      logWarn('Refresh token expired', { sessionId: session.id });
      return null;
    }

    // Check if session is revoked
    if (session.revokedAt) {
      logWarn('Session revoked', { sessionId: session.id });
      return null;
    }

    // Generate new access token
    const newAccessToken = generateToken();
    const now = new Date();
    const newExpiresAt = new Date(now.getTime() + SESSION_DURATION);

    // Update session
    const updatedSession = await prisma.userSession.update({
      where: { id: session.id },
      data: {
        accessToken: newAccessToken,
        expiresAt: newExpiresAt,
        lastActivity: now,
      },
    });

    logInfo('Session refreshed', {
      sessionId: session.id,
      userId: session.userId,
    });

    return {
      id: updatedSession.id,
      userId: updatedSession.userId,
      accessToken: updatedSession.accessToken,
      refreshToken: updatedSession.refreshToken,
      expiresAt: updatedSession.expiresAt,
      refreshExpiresAt: updatedSession.refreshExpiresAt,
      ipAddress: updatedSession.ipAddress || undefined,
      userAgent: updatedSession.userAgent || undefined,
      lastActivity: updatedSession.lastActivity,
    };
  } catch (error) {
    logError('Error refreshing session', { error, refreshToken });
    return null;
  }
}

/**
 * Revoke a session
 */
export async function revokeSession(sessionId: string): Promise<void> {
  try {
    await prisma.userSession.update({
      where: { id: sessionId },
      data: { revokedAt: new Date() },
    });

    logInfo('Session revoked', { sessionId });
  } catch (error) {
    logError('Error revoking session', { error, sessionId });
  }
}

/**
 * Revoke all sessions for a user
 */
export async function revokeAllUserSessions(userId: string): Promise<void> {
  try {
    await prisma.userSession.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: { revokedAt: new Date() },
    });

    logInfo('All user sessions revoked', { userId });
  } catch (error) {
    logError('Error revoking all user sessions', { error, userId });
  }
}

/**
 * Get all active sessions for a user
 */
export async function getUserSessions(userId: string): Promise<SessionData[]> {
  try {
    const sessions = await prisma.userSession.findMany({
      where: {
        userId,
        revokedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
      orderBy: {
        lastActivity: 'desc',
      },
    });

    return sessions.map(session => ({
      id: session.id,
      userId: session.userId,
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      expiresAt: session.expiresAt,
      refreshExpiresAt: session.refreshExpiresAt,
      ipAddress: session.ipAddress || undefined,
      userAgent: session.userAgent || undefined,
      lastActivity: session.lastActivity,
    }));
  } catch (error) {
    logError('Error getting user sessions', { error, userId });
    return [];
  }
}

/**
 * Detect suspicious session activity
 */
export async function detectSuspiciousActivity(
  sessionId: string,
  currentIp?: string,
  currentUserAgent?: string
): Promise<{ suspicious: boolean; reasons: string[] }> {
  try {
    const session = await prisma.userSession.findUnique({
      where: { id: sessionId },
    });

    if (!session) {
      return { suspicious: true, reasons: ['Session not found'] };
    }

    const reasons: string[] = [];

    // Check for IP address change
    if (session.ipAddress && currentIp && session.ipAddress !== currentIp) {
      reasons.push('IP address changed');
    }

    // Check for user agent change
    if (
      session.userAgent &&
      currentUserAgent &&
      session.userAgent !== currentUserAgent
    ) {
      reasons.push('User agent changed');
    }

    // Check for inactive session being used
    const inactiveThreshold = 60 * 60 * 1000; // 1 hour
    if (
      new Date().getTime() - session.lastActivity.getTime() >
      inactiveThreshold
    ) {
      reasons.push('Session inactive for extended period');
    }

    const suspicious = reasons.length > 0;

    if (suspicious) {
      logWarn('Suspicious session activity detected', {
        sessionId,
        reasons,
      });
    }

    return { suspicious, reasons };
  } catch (error) {
    logError('Error detecting suspicious activity', { error, sessionId });
    return { suspicious: false, reasons: [] };
  }
}

/**
 * Clean up old sessions for a user
 */
async function cleanupOldSessions(userId: string): Promise<void> {
  try {
    const activeSessions = await prisma.userSession.findMany({
      where: {
        userId,
        revokedAt: null,
      },
      orderBy: {
        lastActivity: 'desc',
      },
    });

    if (activeSessions.length >= MAX_SESSIONS_PER_USER) {
      // Revoke oldest sessions
      const sessionsToRevoke = activeSessions.slice(MAX_SESSIONS_PER_USER - 1);
      await Promise.all(
        sessionsToRevoke.map(session => revokeSession(session.id))
      );

      logInfo('Old sessions cleaned up', {
        userId,
        revokedCount: sessionsToRevoke.length,
      });
    }
  } catch (error) {
    logError('Error cleaning up old sessions', { error, userId });
  }
}

/**
 * Generate a secure random token
 */
function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Clean up expired sessions (run as cron job)
 */
export async function cleanupExpiredSessions(): Promise<number> {
  try {
    const result = await prisma.userSession.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          { refreshExpiresAt: { lt: new Date() } },
        ],
      },
    });

    logInfo('Expired sessions cleaned up', { count: result.count });
    return result.count;
  } catch (error) {
    logError('Error cleaning up expired sessions', { error });
    return 0;
  }
}
