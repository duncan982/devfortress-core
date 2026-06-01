import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

declare global {
  var __prismaProjects: PrismaClient | undefined;
}
const prisma = globalThis.__prismaProjects ?? new PrismaClient();
if (process.env.NODE_ENV !== 'production') globalThis.__prismaProjects = prisma;

export const runtime = 'nodejs';

export async function GET() {
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
          setAll(cookiesToSet) {
            try {
              cookiesToSet.forEach(({ name, value, options }) =>
                cookieStore.set(name, value, options)
              );
            } catch {}
          },
        },
      }
    );

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const dbUser = await prisma.user.findUnique({
      where: { email: user.email! },
      select: { id: true },
    });

    if (!dbUser) {
      return NextResponse.json({ projects: [] });
    }

    const projects = await prisma.apiProject.findMany({
      where: { createdById: dbUser.id },
      select: {
        id: true,
        name: true,
        slug: true,
        description: true,
        framework: true,
        language: true,
        createdAt: true,
        surveillanceApiKey: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    const projectsWithDefaults = projects.map(p => ({
      ...p,
      totalThreats: 0,
      highThreats: 0,
      honeypotCount: 0,
      activeHoneypots: 0,
    }));

    return NextResponse.json({ projects: projectsWithDefaults });
  } catch (error) {
    console.error('Failed to fetch projects', error);
    return NextResponse.json(
      { error: 'Failed to fetch projects' },
      { status: 500 }
    );
  }
}
