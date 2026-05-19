/**
 * API Route: Live Event Ingestion
 *
 * POST /api/events/ingest - Ingest live events from SDK
 * Authenticated via surveillance API key
 *
 * Accepts events from SDK v4.0+ (snake_case) and v4.3+ (camelCase).
 * Snake_case fields are normalized to camelCase before validation.
 * v4.3 observability fields default to sensible values when absent.
 */

import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient, Prisma } from '@prisma/client';
import { z } from 'zod';

// Prisma singleton — prevents multiple instances in dev hot-reload
declare global {
  var __prismaIngest: PrismaClient | undefined;
}
const prisma = globalThis.__prismaIngest ?? new PrismaClient();
if (process.env.NODE_ENV !== 'production') globalThis.__prismaIngest = prisma;

/**
 * Edge Runtime is NOT possible for this route because Prisma requires Node.js.
 */
export const runtime = 'nodejs';

/** Standard CORS headers for cross-origin SDK calls */
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers':
    'Content-Type, Authorization, X-API-Key, X-DevFortress-Key',
};

/** Validate API key against DB and return project info */
async function validateSurveillanceApiKey(
  apiKey: string
): Promise<
  | { valid: true; project: { id: string; ownerId: string; tier: string } }
  | { valid: false; error: string }
> {
  try {
    const project = await prisma.apiProject.findFirst({
      where: { surveillanceApiKey: apiKey },
      select: {
        id: true,
        createdById: true,
        createdBy: {
          select: {
            subscriptions: {
              where: { status: { in: ['ACTIVE', 'TRIALING'] } },
              orderBy: { createdAt: 'desc' },
              take: 1,
              select: { plan: true },
            },
          },
        },
      },
    });
    if (!project) {
      return { valid: false, error: 'Invalid API key' };
    }
    const plan = project.createdBy.subscriptions[0]?.plan;
    // Self-hosted instances default to ENTERPRISE so all CL modes are available
    const tier = (plan as string | undefined) ?? 'ENTERPRISE';
    return {
      valid: true,
      project: { id: project.id, ownerId: project.createdById, tier },
    };
  } catch {
    return { valid: false, error: 'Key validation failed' };
  }
}

/** Write a validated event to the database */
async function ingestLiveEvent(
  projectId: string,
  event: NormalizedEvent
): Promise<{ success: boolean; eventId?: string; error?: string }> {
  try {
    const record = await prisma.liveThreatEvent.create({
      data: {
        projectId,
        eventType: event.eventType,
        ip: event.ip,
        userAgent: event.userAgent,
        requestPath: event.requestPath,
        statusCode: event.statusCode,
        method: event.method,
        headers: event.headers as Record<string, string> | undefined,
        body: event.body as Prisma.InputJsonValue | undefined,
        severity: (event.severity ?? 'MEDIUM') as
          | 'LOW'
          | 'MEDIUM'
          | 'HIGH'
          | 'CRITICAL',
        metadata: event.metadata as Prisma.InputJsonValue | undefined,
        userId: event.userId ?? undefined,
        sessionId: event.sessionId ?? undefined,
        clMode: event.clMode,
        authPhase: event.authPhase,
        actionTaken: event.actionTaken,
        responseLatencyMs: event.responseLatencyMs,
        sessionActiveAfterAction: event.sessionActiveAfterAction,
        appId: event.appId,
        environment: event.environment,
        timestamp: event.timestamp
          ? new Date(event.timestamp as string)
          : new Date(),
      },
      select: { id: true },
    });
    return { success: true, eventId: record.id };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Ingestion failed',
    };
  }
}

/**
 * Normalize raw SDK payload from snake_case to camelCase.
 */
function normalizeRawPayload(raw: Record<string, any>): Record<string, any> {
  const normalized = { ...raw };

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

  const meta = normalized.metadata || normalized.meta || {};
  if (!normalized.authPhase && meta.authPhase)
    normalized.authPhase = meta.authPhase;
  if (!normalized.actionTaken && meta.actionTaken)
    normalized.actionTaken = meta.actionTaken;
  if (!normalized.clMode && meta.clMode) normalized.clMode = meta.clMode;

  delete normalized.api_key;
  delete normalized.sdk_version;
  delete normalized.meta;

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
  if (!normalized.userId) missingFields.push('userId');
  if (normalized.sessionActiveAfterAction == null)
    missingFields.push('sessionActiveAfterAction');

  if (missingFields.length > 0) {
    console.debug(
      '[events/ingest] SDK missing v4.3 fields:',
      missingFields.join(', ')
    );
  }

  if (normalized.metadata && typeof normalized.metadata !== 'object') {
    normalized.metadata = {};
  }

  return normalized;
}

const eventSchema = z.object({
  eventType: z.string().min(1),
  timestamp: z.union([z.string(), z.date()]).optional(),
  ip: z.string().min(1),
  userAgent: z.string().optional(),
  requestPath: z.string().optional(),
  path: z.string().optional(),
  statusCode: z.number().optional(),
  method: z.string().min(1),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.unknown().optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  metadata: z.record(z.string(), z.any()).optional(),
  userId: z.string().nullable().optional(),
  sessionId: z.string().nullable().optional(),
  clMode: z.string().min(1).max(50),
  authPhase: z.string().min(1).max(50),
  actionTaken: z.string().min(1).max(100),
  responseLatencyMs: z.number(),
  sessionActiveAfterAction: z.boolean().optional(),
  appId: z.string().optional(),
  environment: z.string().optional(),
  responseTime: z.number().nullable().optional(),
  isAgent: z.boolean().optional(),
  agentId: z.string().optional(),
  agentType: z.string().optional(),
});

const batchEventSchema = z.object({
  events: z.array(eventSchema).min(1).max(100),
});

function normalizeEvent(event: z.infer<typeof eventSchema>) {
  const { path, responseTime, ...rest } = event;
  return {
    ...rest,
    requestPath: rest.requestPath || path,
    responseLatencyMs: rest.responseLatencyMs ?? responseTime ?? 0,
  };
}

type NormalizedEvent = ReturnType<typeof normalizeEvent>;

/**
 * POST /api/events/ingest
 */
export async function POST(req: NextRequest) {
  try {
    let body: Record<string, any>;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid or empty JSON body', code: 'INVALID_BODY' },
        { status: 400, headers: corsHeaders }
      );
    }

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

    const validation = await validateSurveillanceApiKey(apiKey);

    if (!validation.valid) {
      console.warn('[events/ingest] Invalid API key:', validation.error);
      return NextResponse.json(
        { error: validation.error || 'Invalid API key', code: 'UNAUTHORIZED' },
        { status: 401, headers: corsHeaders }
      );
    }

    const { project } = validation;

    const tierModes: Record<string, string[]> = {
      STARTER: ['external'],
      PRO: ['external', 'internal'],
      TEAM: ['external', 'internal', 'hybrid'],
      TEAMS: ['external', 'internal', 'hybrid'],
      ENTERPRISE: ['external', 'internal', 'hybrid'],
      ENTERPRISE_PLUS: ['external', 'internal', 'hybrid'],
    };

    const allowedModes: string[] = tierModes[project.tier] ?? tierModes.STARTER;

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

    if (body.events) {
      const normalizedEvents = (body.events as Record<string, unknown>[]).map(
        normalizeRawPayload
      );
      const parseResult = batchEventSchema.safeParse({
        events: normalizedEvents,
      });

      if (!parseResult.success) {
        return NextResponse.json(
          { error: 'Invalid request body', details: parseResult.error.issues },
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
          normalizeEvent(enforced as unknown as z.infer<typeof eventSchema>)
        );
        results.push({ ...result, event_id: result.eventId });
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
      const normalizedBody = normalizeRawPayload(body);
      const parseResult = eventSchema.safeParse(normalizedBody);

      if (!parseResult.success) {
        return NextResponse.json(
          { error: 'Invalid event format', details: parseResult.error.issues },
          { status: 400 }
        );
      }

      const enforced = enforceTierMode(
        parseResult.data as unknown as Record<string, unknown>
      );
      const result = await ingestLiveEvent(
        project.id,
        normalizeEvent(enforced as unknown as z.infer<typeof eventSchema>)
      );

      if (!result.success) {
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
          event_id: result.eventId,
        },
        { headers: corsHeaders }
      );
    }
  } catch (error) {
    console.error(
      '[events/ingest] Failed:',
      error instanceof Error ? error.message : error
    );
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
