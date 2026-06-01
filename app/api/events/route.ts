/**
 * API Route: Live Event Query
 *
 * GET /api/events?projectId=...&limit=100          — fetch recent events
 * GET /api/events?projectId=...&statsOnly=true     — fetch stats only
 *
 * Auth: Supabase session cookie (dashboard use only).
 * Open-core compatible — no @core/* imports.
 */

import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { PrismaClient } from '@prisma/client';

declare global {
  var __prismaEventsQuery: PrismaClient | undefined;
}
const prisma = globalThis.__prismaEventsQuery ?? new PrismaClient();
if (process.env.NODE_ENV !== 'production')
  globalThis.__prismaEventsQuery = prisma;

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll() {
            return cookieStore.getAll();
          },
          setAll() {
            /* read-only in route handlers */
          },
        },
      }
    );

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const projectId = searchParams.get('projectId');
    const statsOnly = searchParams.get('statsOnly') === 'true';
    const limit = Math.min(parseInt(searchParams.get('limit') ?? '100', 10), 500);
    const severity = searchParams.get('severity') ?? undefined;
    const eventType = searchParams.get('eventType') ?? undefined;

    if (!projectId) {
      return NextResponse.json(
        { error: 'projectId is required' },
        { status: 400 }
      );
    }

    // Verify the project belongs to this user
    const project = await prisma.apiProject.findFirst({
      where: { id: projectId, createdById: user.id },
      select: { id: true },
    });

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found or access denied' },
        { status: 404 }
      );
    }

    // Build where clause
    const where: Record<string, unknown> = { projectId };
    if (severity) where.severity = severity.toUpperCase();
    if (eventType) where.eventType = eventType;

    if (statsOnly) {
      const [total, bySeverityRaw] = await Promise.all([
        prisma.liveThreatEvent.count({ where }),
        prisma.liveThreatEvent.groupBy({
          by: ['severity'],
          where,
          _count: { severity: true },
        }),
      ]);

      const bySeverity: Record<string, number> = {};
      for (const row of bySeverityRaw) {
        bySeverity[row.severity] = row._count.severity;
      }

      return NextResponse.json({ total, bySeverity });
    }

    const events = await prisma.liveThreatEvent.findMany({
      where,
      orderBy: { timestamp: 'desc' },
      take: limit,
      select: {
        id: true,
        eventType: true,
        timestamp: true,
        ip: true,
        userAgent: true,
        requestPath: true,
        method: true,
        statusCode: true,
        severity: true,
        clMode: true,
        authPhase: true,
        actionTaken: true,
        responseLatencyMs: true,
        sessionActiveAfterAction: true,
        userId: true,
        sessionId: true,
        metadata: true,
        appId: true,
        environment: true,
      },
    });

    return NextResponse.json({
      events,
      total: events.length,
    });
  } catch (error) {
    console.error(
      '[api/events] Query failed:',
      error instanceof Error ? error.message : error
    );
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
