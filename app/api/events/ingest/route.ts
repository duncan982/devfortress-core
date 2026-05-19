/**
 * API Route: Live Event Ingestion - Premium A3
 *
 * POST /api/events/ingest - Ingest live events from SDK
 * Authenticated via surveillance API key
 *
 * Accepts events from SDK v4.0+ (snake_case) and v4.3+ (camelCase).
 * Snake_case fields are normalized to camelCase before validation.
 * v4.3 observability fields default to sensible values when absent.
 */

import { NextRequest, NextResponse } from 'next/server';
import {
  validateSurveillanceApiKey,
  ingestLiveEvent,
  type IncomingLiveEvent,
} from '@core/lib/surveillance/live-surveillance';
import { logError, logWarn, logDebug } from '@core/lib/logger';
import { z } from 'zod';

/**
 * Edge Runtime is NOT possible for this route because:
 *   - live-surveillance.ts imports Prisma (Node.js-only ORM)
 *   - Prisma requires fs, net, tls — unavailable in Edge
 * Explicitly set nodejs to prevent accidental Edge fallback.
 */
export const runtime = 'nodejs';

/** Standard CORS headers for cross-origin SDK calls */
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers':
    'Content-Type, Authorization, X-API-Key, X-DevFortress-Key',
};

/**
 * Normalize raw SDK payload from snake_case to camelCase.
 *
 * The vendored SDK v4.0.0 sends: event_type, user_agent, status_code, body_summary
 * The platform expects: eventType, userAgent, statusCode, body
 * This function bridges the gap so both old and new SDK payloads are accepted.
 *
 * Also extracts v4.3 observability fields from metadata when they're embedded
 * there by the client application (e.g. HubCommerce puts authPhase/actionTaken
 * in metadata).
 */
function normalizeRawPayload(raw: Record<string, any>): Record<string, any> {
  const normalized = { ...raw };

  // ── Snake_case → camelCase field mapping ──────────────────────────────
  if (raw.event_type && !raw.eventType) {
    normalized.eventType = raw.event_type;
    delete normalized.event_type;
  }
  if (raw.user_agent && !raw.userAgent) {
    normalized.userAgent = raw.user_agent;
    delete normalized.user_agent;
  }
  if (raw.status_code != null && raw.statusCode == null) {
    normalized.statusCode = raw.status_code;
    delete normalized.status_code;
  }
  if (raw.body_summary && !raw.body) {
    normalized.body = raw.body_summary;
    delete normalized.body_summary;
  }
  if (raw.response_latency_ms != null && raw.responseLatencyMs == null) {
    normalized.responseLatencyMs = raw.response_latency_ms;
    delete normalized.response_latency_ms;
  }
  if (raw.response_time != null && raw.responseTime == null) {
    normalized.responseTime = raw.response_time;
    delete normalized.response_time;
  }
  if (raw.request_path && !raw.requestPath) {
    normalized.requestPath = raw.request_path;
    delete normalized.request_path;
  }
  if (raw.cl_mode && !raw.clMode) {
    normalized.clMode = raw.cl_mode;
    delete normalized.cl_mode;
  }
  if (raw.auth_phase && !raw.authPhase) {
    normalized.authPhase = raw.auth_phase;
    delete normalized.auth_phase;
  }
  if (raw.action_taken && !raw.actionTaken) {
    normalized.actionTaken = raw.action_taken;
    delete normalized.action_taken;
  }
  if (raw.user_id && !raw.userId) {
    normalized.userId = raw.user_id;
    delete normalized.user_id;
  }
  if (raw.session_id && !raw.sessionId) {
    normalized.sessionId = raw.session_id;
    delete normalized.session_id;
  }
  if (raw.app_id && !raw.appId) {
    normalized.appId = raw.app_id;
    delete normalized.app_id;
  }

  // ── Extract v4.3 fields from metadata when embedded there ─────────────
  const meta = normalized.metadata || normalized.meta || {};
  if (!normalized.authPhase && meta.authPhase) {
    normalized.authPhase = meta.authPhase;
  }
  if (!normalized.actionTaken && meta.actionTaken) {
    normalized.actionTaken = meta.actionTaken;
  }
  if (!normalized.clMode && meta.clMode) {
    normalized.clMode = meta.clMode;
  }

  // ── Strip SDK-only fields that aren't in the Zod schema ───────────────
  delete normalized.api_key;
  delete normalized.sdk_version;
  delete normalized.meta;

  // ── Default v4.3 observability fields when absent ─────────────────────
  // These are required by the schema but older SDK versions don't send them.
  // Track field quality (Items #1-6 / M13) — log when mandatory fields are missing
  const missingFields: string[] = [];
  if (!normalized.clMode) {
    missingFields.push('clMode');
    normalized.clMode = 'external';
  }
  if (!normalized.authPhase) {
    missingFields.push('authPhase');
    normalized.authPhase = 'pre_auth';
  }
  if (!normalized.actionTaken) {
    missingFields.push('actionTaken');
    normalized.actionTaken = 'monitored';
  }
  if (normalized.responseLatencyMs == null) {
    missingFields.push('responseLatencyMs');
    normalized.responseLatencyMs = 0;
  }
  if (!normalized.userId) {
    missingFields.push('userId');
  }
  if (normalized.sessionActiveAfterAction == null) {
    missingFields.push('sessionActiveAfterAction');
  }

  // Log field quality warning for SDK version tracking (M13)
  if (missingFields.length > 0) {
    logDebug('SDK event missing v4.3 mandatory fields', {
      missingFields,
      eventType: normalized.eventType,
      sdkVersion: raw.sdk_version || raw.sdkVersion || 'unknown',
    });
  }

  // ── Ensure metadata is an object ──────────────────────────────────────
  if (normalized.metadata && typeof normalized.metadata !== 'object') {
    normalized.metadata = {};
  }

  return normalized;
}

/**
 * Schema for validating incoming events.
 * v4.3 observability fields are present after normalizeRawPayload applies defaults.
 */
const eventSchema = z.object({
  eventType: z.string().min(1),
  timestamp: z.union([z.string(), z.date()]).optional(),
  ip: z.string().min(1),
  userAgent: z.string().optional(),
  requestPath: z.string().optional(),
  path: z.string().optional(), // Alias for requestPath (SDK compatibility)
  statusCode: z.number().optional(),
  method: z.string().min(1),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.unknown().optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  metadata: z.record(z.string(), z.any()).optional(),
  // v3.1 observability fields — defaults applied by normalizeRawPayload
  userId: z.string().nullable().optional(),
  sessionId: z.string().nullable().optional(),
  clMode: z.string().min(1).max(50),
  authPhase: z.string().min(1).max(50),
  // Free-form string — accepts predefined values (blocked, rate_limited, etc.)
  // AND custom actions (account_suspended, mfa_enforced, gdpr_export_blocked, etc.)
  // Predefined display badges: blocked, rate_limited, session_revoked,
  // captcha_challenged, flagged, allowed, monitored, key_rotated
  // Any other value displays as a plain grey badge.
  actionTaken: z.string().min(1).max(100),
  responseLatencyMs: z.number(),
  sessionActiveAfterAction: z.boolean().optional(),
  appId: z.string().optional(),
  environment: z.string().optional(),
  responseTime: z.number().nullable().optional(), // SDK compat alias
  // v4.0 agentic fields
  isAgent: z.boolean().optional(),
  agentId: z.string().optional(),
  agentType: z.string().optional(),
});

const batchEventSchema = z.object({
  events: z.array(eventSchema).min(1).max(100),
});

/**
 * Normalize validated event fields for storage.
 * Maps `path` → `requestPath` and `responseTime` → `responseLatencyMs`.
 */
function normalizeEvent(event: z.infer<typeof eventSchema>): IncomingLiveEvent {
  const { path, responseTime, ...rest } = event;
  return {
    ...rest,
    requestPath: rest.requestPath || path,
    responseLatencyMs: rest.responseLatencyMs || (responseTime ?? undefined),
  } as IncomingLiveEvent;
}

/**
 * POST /api/events/ingest
 *
 * Ingest live threat events from user's APIs via SDK
 */
export async function POST(req: NextRequest) {
  try {
    // Parse request body first — SDK sends api_key in the body, not headers
    let body: Record<string, any>;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid or empty JSON body', code: 'INVALID_BODY' },
        { status: 400, headers: corsHeaders }
      );
    }

    // Extract API key — supports headers AND body for SDK compatibility
    // SDK v4.0 sends api_key in the request body payload
    const authHeader = req.headers.get('authorization');
    const apiKey = authHeader?.startsWith('Bearer ')
      ? authHeader.substring(7)
      : req.headers.get('x-api-key') ||
        req.headers.get('x-devfortress-key') ||
        (body?.api_key as string) ||
        null;

    if (!apiKey) {
      return NextResponse.json(
        { error: 'API key required', code: 'UNAUTHORIZED' },
        { status: 401, headers: corsHeaders }
      );
    }

    // Validate API key
    const validation = await validateSurveillanceApiKey(apiKey);

    if (!validation.valid || !validation.project) {
      logWarn('Invalid surveillance API key', { error: validation.error });
      return NextResponse.json(
        { error: validation.error || 'Invalid API key', code: 'UNAUTHORIZED' },
        { status: 401, headers: corsHeaders }
      );
    }

    const { project } = validation;

    // A19B: Verify SDK request signature (graceful degradation for pre-v4.9 clients)
    const { verifySDKRequest } = await import('@/lib/verify-sdk-request');
    const sdkVerification = await verifySDKRequest(req);
    if (!sdkVerification.verified) {
      if (sdkVerification.reason === 'timestamp_expired') {
        return NextResponse.json(
          {
            error: 'Request verification failed',
            reason: sdkVerification.reason,
          },
          { status: 400 }
        );
      }
      console.warn('[A19B] Verification failed:', sdkVerification.reason);
    }

    // Mode enforcement: downgrade unsupported CL modes
    const tierModes: Record<string, string[]> = {
      STARTER: ['external'],
      PRO: ['external', 'internal'],
      TEAM: ['external', 'internal', 'hybrid'],
      TEAMS: ['external', 'internal', 'hybrid'],
      ENTERPRISE: ['external', 'internal', 'hybrid'],
      ENTERPRISE_PLUS: ['external', 'internal', 'hybrid'],
    };

    const ownerTier: string = (project as any).tier ?? 'STARTER';
    const allowedModes: string[] = tierModes[ownerTier] ?? tierModes.STARTER;

    function enforceTierMode(
      event: Record<string, unknown>
    ): Record<string, unknown> {
      const requested = (event.clMode as string) ?? 'external';
      if (!allowedModes.includes(requested)) {
        return {
          ...event,
          clMode: allowedModes[0] ?? 'external',
          tierDowngraded: true,
        };
      }
      return event;
    }

    // Check if batch or single event
    if (body.events) {
      // Batch ingestion — normalize each event before validation
      const normalizedEvents = (body.events as Record<string, unknown>[]).map(
        normalizeRawPayload
      );
      const parseResult = batchEventSchema.safeParse({
        events: normalizedEvents,
      });

      if (!parseResult.success) {
        return NextResponse.json(
          {
            error: 'Invalid request body',
            details: parseResult.error.issues,
          },
          { status: 400 }
        );
      }

      const results: Array<{
        success: boolean;
        eventId?: string;
        event_id?: string;
        error?: string;
      }> = [];

      for (const event of parseResult.data.events) {
        const enforced = enforceTierMode(
          event as unknown as Record<string, unknown>
        );
        const result = await ingestLiveEvent(
          project.id,
          project.ownerId,
          project.tier,
          normalizeEvent(enforced as unknown as z.infer<typeof eventSchema>)
        );
        results.push({
          ...result,
          event_id: result.eventId, // SDK reads event_id (snake_case)
        });
      }

      const successCount = results.filter(r => r.success).length;
      const failedCount = results.length - successCount;

      return NextResponse.json(
        {
          success: true,
          processed: results.length,
          successful: successCount,
          failed: failedCount,
          results,
        },
        { headers: corsHeaders }
      );
    } else {
      // Single event — normalize snake_case → camelCase before validation
      const normalizedBody = normalizeRawPayload(body);
      const parseResult = eventSchema.safeParse(normalizedBody);

      if (!parseResult.success) {
        return NextResponse.json(
          {
            error: 'Invalid event format',
            details: parseResult.error.issues,
          },
          { status: 400 }
        );
      }

      const enforced = enforceTierMode(
        parseResult.data as unknown as Record<string, unknown>
      );
      const result = await ingestLiveEvent(
        project.id,
        project.ownerId,
        project.tier,
        normalizeEvent(enforced as unknown as z.infer<typeof eventSchema>)
      );

      if (!result.success) {
        // Differentiate rate limit (429) from server errors (500)
        const isRateLimited =
          result.error?.includes('Rate limit') ||
          result.error?.includes('Monthly event limit reached');
        return NextResponse.json(
          {
            error: result.error,
            code: isRateLimited ? 'RATE_LIMITED' : 'INGESTION_FAILED',
          },
          { status: isRateLimited ? 429 : 500, headers: corsHeaders }
        );
      }

      return NextResponse.json(
        {
          success: true,
          eventId: result.eventId,
          event_id: result.eventId, // SDK reads event_id (snake_case)
        },
        { headers: corsHeaders }
      );
    }
  } catch (error) {
    logError('Event ingestion failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500, headers: corsHeaders }
    );
  }
}

/**
 * OPTIONS - CORS preflight
 */
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      ...corsHeaders,
      'Access-Control-Max-Age': '86400',
    },
  });
}
