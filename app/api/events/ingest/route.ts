/**
 * API Route: Live Event Ingestion
 *
 * POST /api/events/ingest - Ingest live events from SDK
 * Authenticated by a signed request (key ID) or, for older clients, the API key
 *
 * Accepts events from SDK v4.0+ (snake_case) and v4.3+ (camelCase).
 * Snake_case fields are normalized to camelCase before validation.
 * v4.3 observability fields default to sensible values when absent.
 */

import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient, Prisma } from '@prisma/client';
import { z } from 'zod';
import { createHash, createHmac, timingSafeEqual } from 'crypto';

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
    'Content-Type, Authorization, X-API-Key, X-DevFortress-Key, X-DevFortress-Key-Id, X-DevFortress-Signature-Version, X-DevFortress-Nonce, X-DevFortress-Timestamp, X-DevFortress-Payload-Hash, X-DevFortress-Signature',
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

/**
 * SDK request authentication, self-contained for the open-core build.
 * Contract: signature v2 (canonical string
 * `{METHOD}.{requestTarget}.{timestamp}.{nonce}.{sha256hex(body)}`, HMAC-SHA256
 * keyed with the project API key). Two paths:
 *  - signed (`X-DevFortress-Key-Id`): the key never travels; a missing or
 *    invalid signature is a 401 whatever the enforcement flag says;
 *  - legacy (API key in a header or the body): accepted unless
 *    ENABLE_SDK_SIGNATURE_ENFORCEMENT=true, in which case it must be signed.
 * A key ID together with an API key is a 400.
 */
const SIGNATURE_VERSION = '2';
const TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000;
const NONCE_TTL_MS = 2 * TIMESTAMP_TOLERANCE_MS;
const NONCE_MAX_ENTRIES = 100_000;
const NONCE_MAX_LENGTH = 128;
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

// Insertion order == registration order, so expired entries sit at the head.
const seenNonces = new Map<string, number>();

function registerNonce(scope: string, nonce: string): boolean {
  const now = Date.now();
  for (const [k, at] of seenNonces) {
    if (now - at < NONCE_TTL_MS) break;
    seenNonces.delete(k);
  }
  const key = `${scope}:${nonce}`;
  if (seenNonces.has(key)) return false;
  if (seenNonces.size >= NONCE_MAX_ENTRIES) {
    const oldest = seenNonces.keys().next().value;
    if (oldest !== undefined) seenNonces.delete(oldest);
  }
  seenNonces.set(key, now);
  return true;
}

/** First 32 hex characters of SHA-256(UTF-8 key). Same as the platform's. */
function deriveKeyId(apiKey: string): string {
  return createHash('sha256').update(apiKey, 'utf8').digest('hex').slice(0, 32);
}

/** Path plus `?query` exactly as the runtime reports it (no host). */
function requestTargetOf(req: Request): string {
  const url = req.url;
  const schemeEnd = url.indexOf('://');
  const start = url.indexOf('/', schemeEnd === -1 ? 0 : schemeEnd + 3);
  return start === -1 ? '/' : url.slice(start);
}

function safeEqualHex(a: string, b: string): boolean {
  return (
    a.length === b.length &&
    timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
  );
}

type SignatureCheck =
  | { ok: true }
  | { ok: false; status: number; reason: string };

function checkSignature(
  req: Request,
  rawBody: string,
  apiKey: string,
  scope: string
): SignatureCheck {
  const nonce = req.headers.get('X-DevFortress-Nonce');
  const signature = req.headers.get('X-DevFortress-Signature');
  const payloadHash = req.headers.get('X-DevFortress-Payload-Hash');
  const timestamp = req.headers.get('X-DevFortress-Timestamp');
  const version = req.headers.get('X-DevFortress-Signature-Version');

  if (!nonce || !signature || !payloadHash || !timestamp) {
    return { ok: false, status: 401, reason: 'signature_missing' };
  }
  if (version !== SIGNATURE_VERSION) {
    return { ok: false, status: 401, reason: 'signature_version_unsupported' };
  }
  const hash = createHash('sha256').update(rawBody, 'utf8').digest('hex');
  const expected = createHmac('sha256', apiKey)
    .update(
      `${req.method.toUpperCase()}.${requestTargetOf(req)}.${timestamp}.${nonce}.${hash}`,
      'utf8'
    )
    .digest('hex');
  if (
    !safeEqualHex(payloadHash.toLowerCase(), hash) ||
    !safeEqualHex(signature.toLowerCase(), expected)
  ) {
    return { ok: false, status: 401, reason: 'signature_invalid' };
  }
  const ts = Number(timestamp);
  if (
    !Number.isFinite(ts) ||
    Math.abs(Date.now() - ts) > TIMESTAMP_TOLERANCE_MS
  ) {
    return { ok: false, status: 400, reason: 'timestamp_expired' };
  }
  if (nonce.length > NONCE_MAX_LENGTH) {
    return { ok: false, status: 400, reason: 'nonce_invalid' };
  }
  if (!registerNonce(scope, nonce)) {
    return { ok: false, status: 409, reason: 'nonce_replayed' };
  }
  return { ok: true };
}

function verificationFailed(status: number, reason: string, cors = true) {
  return NextResponse.json(
    { error: 'Request verification failed', reason },
    { status, ...(cors && { headers: corsHeaders }) }
  );
}

type ProjectInfo = { id: string; ownerId: string; tier: string };

async function findProject(
  where: { surveillanceApiKey: string } | { surveillanceKeyId: string }
) {
  const project = await prisma.apiProject.findFirst({
    where,
    select: {
      id: true,
      createdById: true,
      surveillanceApiKey: true,
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
  if (!project) return null;
  const plan = project.createdBy.subscriptions[0]?.plan;
  return {
    info: {
      id: project.id,
      ownerId: project.createdById,
      // Self-hosted instances default to ENTERPRISE so all CL modes are available
      tier: (plan as string | undefined) ?? 'ENTERPRISE',
    } as ProjectInfo,
    signingKey: project.surveillanceApiKey,
  };
}

/** Returns the authenticated project, or the response to send. */
async function authenticateSdkRequest(
  req: NextRequest,
  body: Record<string, any>,
  rawBody: string
): Promise<{ project: ProjectInfo } | { response: NextResponse }> {
  const keyId = req.headers.get('x-devfortress-key-id');
  const authHeader = req.headers.get('authorization');
  const presentedKey = authHeader?.startsWith('Bearer ')
    ? authHeader.substring(7)
    : req.headers.get('x-api-key') ||
      req.headers.get('x-devfortress-key') ||
      (body?.api_key as string) ||
      null;

  if (keyId && presentedKey) {
    return { response: verificationFailed(400, 'ambiguous_credentials') };
  }

  if (keyId) {
    const found = KEY_ID_PATTERN.test(keyId)
      ? await findProject({ surveillanceKeyId: keyId }).catch(() => null)
      : null;
    if (!found || !found.signingKey) {
      // Same 401 as a bad signature: do not reveal which key IDs exist.
      const present = [
        'X-DevFortress-Nonce',
        'X-DevFortress-Timestamp',
        'X-DevFortress-Payload-Hash',
        'X-DevFortress-Signature',
      ].every(h => req.headers.get(h));
      return {
        response: verificationFailed(
          401,
          present ? 'signature_invalid' : 'signature_missing'
        ),
      };
    }
    const check = checkSignature(req, rawBody, found.signingKey, found.info.id);
    if (!check.ok) {
      return {
        response: verificationFailed(
          check.status,
          check.reason,
          check.status === 401
        ),
      };
    }
    return { project: found.info };
  }

  if (!presentedKey) {
    return {
      response: NextResponse.json(
        { error: 'API key required', code: 'UNAUTHORIZED' },
        { status: 401, headers: corsHeaders }
      ),
    };
  }
  const validation = await validateSurveillanceApiKey(presentedKey);
  if (!validation.valid) {
    console.warn('[events/ingest] Invalid API key:', validation.error);
    return {
      response: NextResponse.json(
        { error: validation.error || 'Invalid API key', code: 'UNAUTHORIZED' },
        { status: 401, headers: corsHeaders }
      ),
    };
  }

  // Legacy path: the signature is only required when enforcement is on.
  const enforce = process.env.ENABLE_SDK_SIGNATURE_ENFORCEMENT === 'true';
  const hasSignatureHeaders =
    req.headers.get('X-DevFortress-Signature') ||
    req.headers.get('X-DevFortress-Nonce');
  if (enforce || hasSignatureHeaders) {
    const check = checkSignature(
      req,
      rawBody,
      presentedKey,
      validation.project.id
    );
    if (!check.ok && (enforce || check.status !== 401)) {
      return {
        response: verificationFailed(
          check.status,
          check.reason,
          check.status === 401
        ),
      };
    }
  }
  return { project: validation.project };
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
    // The raw text is kept so the signature is checked over the exact bytes
    // the client signed.
    let body: Record<string, any>;
    let rawBody = '';
    try {
      rawBody = await req.text();
      body = JSON.parse(rawBody);
    } catch {
      return NextResponse.json(
        { error: 'Invalid or empty JSON body', code: 'INVALID_BODY' },
        { status: 400, headers: corsHeaders }
      );
    }

    const auth = await authenticateSdkRequest(req, body, rawBody);
    if ('response' in auth) return auth.response;

    const { project } = auth;

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
