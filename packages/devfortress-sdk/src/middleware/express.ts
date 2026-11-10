/**
 * Express.js Middleware for DevFortress Surveillance
 */

import { Request, Response, NextFunction } from 'express';
import { DevFortressClient } from '../client';
import type {
  DevFortressMiddlewareOptions,
  LiveThreatEvent,
  SeverityLevel,
  AuthPhase,
  ActionTaken,
} from '../types';

/**
 * Create Express middleware for automatic threat monitoring
 */
export function devfortressMiddleware(options: DevFortressMiddlewareOptions) {
  const client = new DevFortressClient(options);
  const {
    captureBody = false,
    captureHeaders = false,
    excludePaths = [],
    sanitize,
    onRequest,
    onError,
    mode = 'external',
  } = options;

  return async function devfortressMiddlewareHandler(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    // Skip excluded paths
    if (excludePaths.some(path => req.path.startsWith(path))) {
      return next();
    }

    const startTime = Date.now();

    // Capture response
    const originalSend = res.send;

    res.send = function (this: Response, body: unknown): Response {
      return originalSend.call(this, body);
    } as typeof res.send;

    // Wait for response to finish
    res.on('finish', async () => {
      try {
        const responseTime = Date.now() - startTime;
        const statusCode = res.statusCode;

        // Determine if this is a security event
        let eventType: LiveThreatEvent['eventType'] | null = null;
        let severity: SeverityLevel = 'LOW';
        let reason: string | undefined;

        // Check for authentication failures
        if (statusCode === 401 || statusCode === 403) {
          eventType = 'auth_failure';
          severity = 'MEDIUM';
          reason = 'Authentication or authorization failed';
        }
        // Check for validation errors
        else if (statusCode === 400 || statusCode === 422) {
          eventType = 'validation_error';
          severity = 'LOW';
          reason = 'Request validation failed';
        }
        // Check for rate limiting
        else if (statusCode === 429) {
          eventType = 'rate_limit_exceeded';
          severity = 'MEDIUM';
          reason = 'Rate limit exceeded';
        }
        // Check for server errors
        else if (statusCode >= 500) {
          eventType = '5xx_error';
          severity = 'HIGH';
          reason = `Server error: ${statusCode}`;
        }
        // Check for client errors
        else if (statusCode >= 400) {
          eventType = '4xx_error';
          severity = 'LOW';
          reason = `Client error: ${statusCode}`;
        }

        // Check for suspicious patterns
        const suspiciousPatterns = detectSuspiciousPatterns(req);
        if (suspiciousPatterns.length > 0) {
          eventType = 'suspicious_pattern';
          severity = 'HIGH';
          reason = `Suspicious patterns detected: ${suspiciousPatterns.join(', ')}`;
        }

        // Allow custom event detection
        if (onRequest) {
          const customEvent = onRequest(req);
          if (customEvent) {
            eventType = customEvent.eventType || eventType;
            severity = customEvent.severity || severity;
            reason = customEvent.reason || reason;
          }
        }

        // Only track if we detected an event
        if (eventType) {
          let metadata: Record<string, unknown> = {
            method: req.method,
            path: req.path,
            query: req.query,
            responseTime,
          };

          if (captureHeaders) {
            metadata.headers = req.headers;
          }

          if (captureBody && req.body) {
            metadata.body = req.body;
          }

          // Sanitize metadata if function provided
          if (sanitize) {
            metadata = sanitize(metadata);
          }

          // Determine auth phase: if a userId is present, this is post-auth
          const reqAny = req as unknown as Record<string, unknown>;
          const userObj = reqAny.user as Record<string, unknown> | undefined;
          const userId: string | null =
            (typeof reqAny.userId === 'string' ? reqAny.userId : null) ||
            (typeof userObj?.id === 'string' ? userObj.id : null);
          const sessionId: string | null =
            (typeof reqAny.sessionId === 'string' ? reqAny.sessionId : null) ||
            (typeof req.headers['x-session-id'] === 'string'
              ? req.headers['x-session-id']
              : null);
          const authPhase: AuthPhase = userId ? 'post_auth' : 'pre_auth';

          // Determine action taken based on status code and event type
          let actionTaken: ActionTaken = 'monitored';
          if (statusCode === 429) {
            actionTaken = 'rate_limited';
          } else if (statusCode === 403) {
            actionTaken = 'blocked';
          } else if (statusCode === 401 && userId) {
            actionTaken = 'session_revoked';
          } else if (statusCode === 401) {
            actionTaken = 'blocked';
          } else if (statusCode >= 400 && statusCode < 500) {
            actionTaken = 'flagged';
          } else if (
            statusCode >= 200 &&
            statusCode < 300 &&
            suspiciousPatterns.length > 0
          ) {
            actionTaken = 'flagged';
          } else if (statusCode >= 200 && statusCode < 300) {
            actionTaken = 'allowed';
          }

          // Session remains active if action is not blocking/revoking
          const sessionActiveAfterAction = ![
            'blocked',
            'session_revoked',
          ].includes(actionTaken);

          const event: LiveThreatEvent = {
            eventType,
            ip: getClientIp(req),
            method: req.method,
            path: req.path,
            userAgent: req.get('user-agent') || null,
            statusCode,
            responseTime,
            metadata: { ...metadata },
            severity,
            reason,
            // v3.1 observability fields
            clMode: mode,
            authPhase,
            actionTaken,
            responseLatencyMs: responseTime,
            userId: userId || null,
            sessionId: sessionId || null,
            sessionActiveAfterAction,
          };

          // Track event asynchronously (non-blocking)
          client.trackEvent(event).catch(error => {
            if (onError) {
              onError(error);
            }
          });
        }
      } catch (error) {
        if (onError) {
          onError(error as Error);
        }
      }
    });

    next();
  };
}

/**
 * Get client IP address from request
 */
function getClientIp(req: Request): string {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    '0.0.0.0'
  );
}

/**
 * Detect suspicious patterns in request
 */
function detectSuspiciousPatterns(req: Request): string[] {
  const patterns: string[] = [];

  // SQL Injection patterns
  const sqlPatterns = [
    /('\s*\bor\b\s+'[^']*'\s*=\s*')/i,
    /(\bunion\b\s+\bselect\b)/i,
    /(\bdrop\b\s+\btable\b)/i,
    /(\binsert\b\s+\binto\b)/i,
    /('\s*or\s*'1'\s*=\s*'1)/i,
    /(;\s*--)/,
  ];

  // XSS patterns
  const xssPatterns = [
    /<script[^>]*>[\s\S]*?<\/script>/i,
    /<iframe[^>]*>[\s\S]*?<\/iframe>/i,
    /javascript:/i,
    /onerror\s*=\s*/i,
    /onload\s*=\s*/i,
  ];

  // Path traversal patterns
  const traversalPatterns = [
    /\.\.[\/\\]/,
    /\/etc\/passwd/i,
    /\/windows\/system32/i,
  ];

  let requestString: string;
  try {
    requestString = JSON.stringify({
      url: req.url,
      query: req.query,
      body: req.body,
    }).slice(0, 10000); // Limit size to prevent performance issues
  } catch {
    requestString = req.url || '';
  }

  // Check SQL injection
  if (sqlPatterns.some(pattern => pattern.test(requestString))) {
    patterns.push('sql_injection');
  }

  // Check XSS
  if (xssPatterns.some(pattern => pattern.test(requestString))) {
    patterns.push('xss');
  }

  // Check path traversal
  if (traversalPatterns.some(pattern => pattern.test(requestString))) {
    patterns.push('path_traversal');
  }

  // Check for excessive failed auth attempts
  if (req.headers['x-devfortress-failed-attempts']) {
    const attempts = parseInt(
      req.headers['x-devfortress-failed-attempts'] as string,
      10
    );
    if (attempts > 5) {
      patterns.push('brute_force');
    }
  }

  return patterns;
}
