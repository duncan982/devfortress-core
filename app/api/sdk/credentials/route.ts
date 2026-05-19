/**
 * API Route: SDK Credential Management
 *
 * POST /api/sdk/credentials - Create project + generate SDK credentials
 * GET  /api/sdk/credentials - List user's projects with SDK credentials
 * DELETE /api/sdk/credentials - Revoke SDK credentials for a project
 */

import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { PrismaClient } from '@prisma/client';
import { randomBytes } from 'crypto';
import { z } from 'zod';

// Prisma singleton — prevents multiple instances in dev hot-reload
declare global {
  var __prismaCredentials: PrismaClient | undefined;
}
const prisma = globalThis.__prismaCredentials ?? new PrismaClient();
if (process.env.NODE_ENV !== 'production')
  globalThis.__prismaCredentials = prisma;

function generateSurveillanceApiKey(): string {
  return `vx_live_${randomBytes(24).toString('hex')}`;
}

function generateWebhookSecret(): string {
  return `whsec_${randomBytes(32).toString('hex')}`;
}

const createSchema = z.object({
  name: z.string().min(1).max(100),
  projectType: z.enum(['application', 'api', 'agent']).default('application'),
  description: z.string().max(500).optional(),
});

/**
 * POST /api/sdk/credentials
 * Create a new project and generate SDK credentials in one step.
 */
export async function POST(request: NextRequest) {
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

    const body = await request.json();
    const parsed = createSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: 'Invalid input', details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    const { name, projectType, description } = parsed.data;

    const baseSlug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
    const uniqueSuffix = Date.now().toString(36);
    const slug = `${baseSlug}-${uniqueSuffix}`;

    const apiKey = generateSurveillanceApiKey();
    const webhookSecret = generateWebhookSecret();

    const project = await prisma.apiProject.create({
      data: {
        name,
        slug,
        description:
          description || `${projectType} project for SDK surveillance`,
        framework: projectType,
        metadata: {
          projectType,
          sdkVersion: '4.3.0',
          createdFrom: 'credentials-dashboard',
        },
        createdById: user.id,
        surveillanceApiKey: apiKey,
        webhookSecret,
      },
      select: {
        id: true,
        name: true,
        slug: true,
        framework: true,
        surveillanceApiKey: true,
        webhookSecret: true,
        createdAt: true,
        metadata: true,
      },
    });

    console.info(
      '[sdk/credentials] Created project',
      project.id,
      'for user',
      user.id
    );

    return NextResponse.json({
      success: true,
      credential: {
        projectId: project.id,
        projectName: project.name,
        projectType,
        apiKey: project.surveillanceApiKey,
        webhookSecret: project.webhookSecret,
        createdAt: project.createdAt,
        status: 'active',
      },
    });
  } catch (error) {
    console.error(
      '[sdk/credentials] Creation failed:',
      error instanceof Error ? error.message : error
    );
    return NextResponse.json(
      { error: 'Failed to create credentials' },
      { status: 500 }
    );
  }
}

/**
 * GET /api/sdk/credentials
 * List all projects with their SDK credentials.
 */
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

    let projects: Array<{
      id: string;
      name: string;
      framework: string | null;
      surveillanceApiKey: string | null;
      webhookSecret: string | null;
      createdAt: Date;
      metadata: unknown;
    }> = [];

    try {
      projects = await prisma.apiProject.findMany({
        where: {
          createdById: user.id,
          surveillanceApiKey: { not: null },
        },
        select: {
          id: true,
          name: true,
          framework: true,
          surveillanceApiKey: true,
          webhookSecret: true,
          createdAt: true,
          metadata: true,
        },
        orderBy: { createdAt: 'desc' },
      });
    } catch {
      projects = [];
    }

    const credentials = projects.map(p => {
      const metadata = p.metadata as Record<string, unknown> | null;
      return {
        projectId: p.id,
        projectName: p.name,
        projectType:
          (metadata?.projectType as string) || p.framework || 'application',
        apiKey: p.surveillanceApiKey,
        webhookSecret: p.webhookSecret,
        createdAt: p.createdAt,
        status: p.surveillanceApiKey ? 'active' : 'revoked',
      };
    });

    return NextResponse.json({ credentials });
  } catch (error) {
    console.error(
      '[sdk/credentials] Listing failed:',
      error instanceof Error ? error.message : error
    );
    return NextResponse.json(
      { error: 'Failed to list credentials' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/sdk/credentials
 * Revoke SDK credentials for a project.
 */
export async function DELETE(request: NextRequest) {
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

    if (!projectId) {
      return NextResponse.json(
        { error: 'projectId is required' },
        { status: 400 }
      );
    }

    const project = await prisma.apiProject.findFirst({
      where: { id: projectId, createdById: user.id },
    });

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 });
    }

    await prisma.apiProject.update({
      where: { id: projectId },
      data: {
        surveillanceApiKey: null,
        webhookSecret: null,
      },
    });

    console.info(
      '[sdk/credentials] Revoked project',
      projectId,
      'for user',
      user.id
    );

    return NextResponse.json({
      success: true,
      message: 'Credentials revoked',
    });
  } catch (error) {
    console.error(
      '[sdk/credentials] Revocation failed:',
      error instanceof Error ? error.message : error
    );
    return NextResponse.json(
      { error: 'Failed to revoke credentials' },
      { status: 500 }
    );
  }
}
