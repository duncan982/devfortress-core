/**
 * API Route: SDK Credential Management
 *
 * POST /api/sdk/credentials - Create project + generate SDK credentials
 * GET  /api/sdk/credentials - List user's projects with SDK credentials
 * DELETE /api/sdk/credentials - Revoke SDK credentials for a project
 *
 * MVP Focus: Collect Phase — SDK Surveillance
 */

import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { prisma, safePrismaQuery } from '@core/lib/prisma';
import {
  generateSurveillanceApiKey,
  generateWebhookSecret,
} from '@core/lib/surveillance/live-surveillance';
import { logError, logInfo } from '@core/lib/logger';
import { z } from 'zod';

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

    // Generate unique slug from project name
    const baseSlug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
    const uniqueSuffix = Date.now().toString(36);
    const slug = `${baseSlug}-${uniqueSuffix}`;

    // Generate API key and webhook secret
    const apiKey = generateSurveillanceApiKey();
    const webhookSecret = generateWebhookSecret();

    // Create project with SDK credentials in one transaction
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

    logInfo('SDK credentials created', {
      projectId: project.id,
      projectType,
      userId: user.id,
    });

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
    logError('SDK credential creation failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
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

    const projects = await safePrismaQuery(
      () =>
        prisma.apiProject.findMany({
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
        }),
      []
    );

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
    logError('SDK credential listing failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
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

    // Verify ownership
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

    logInfo('SDK credentials revoked', {
      projectId,
      userId: user.id,
    });

    return NextResponse.json({
      success: true,
      message: 'Credentials revoked',
    });
  } catch (error) {
    logError('SDK credential revocation failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return NextResponse.json(
      { error: 'Failed to revoke credentials' },
      { status: 500 }
    );
  }
}
