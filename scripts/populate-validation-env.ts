import { PrismaClient } from '@prisma/client';
import { randomUUID } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const prisma = new PrismaClient();

const DEV_EMAIL = process.env.NEXT_PUBLIC_DEV_USER_EMAIL;
if (!DEV_EMAIL) {
  console.error('ERROR: NEXT_PUBLIC_DEV_USER_EMAIL not set in environment');
  process.exit(1);
}

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

const HC_TEST_EMAIL = 'vendor@demo.nexuscommerce.io';
const HC_TEST_PASSWORD = 'Demo@2024!';

const VALIDATION_ENV_PATH = join(
  process.cwd(),
  'validations',
  'validation.env'
);

function mask(value: string): string {
  return value.slice(0, 10) + '...';
}

async function main() {
  try {
    let user = await prisma.user.findFirst({ where: { email: DEV_EMAIL } });
    if (!user) {
      console.warn(
        `WARN: No user with email ${DEV_EMAIL} — falling back to first user in DB`
      );
      user = await prisma.user.findFirst({ orderBy: { createdAt: 'asc' } });
    }
    if (!user) {
      console.error('ERROR: No users found in database');
      process.exit(1);
    }
    console.log(`Found user: ${user.email} (id: ${user.id})`);

    let project = await prisma.apiProject.findFirst({
      where: { createdById: user.id },
      orderBy: { createdAt: 'asc' },
    });

    if (!project) {
      console.log('No existing ApiProject — creating one...');
      project = await prisma.apiProject.create({
        data: {
          name: 'open-core-validation',
          slug: 'open-core-validation',
          createdById: user.id,
          surveillanceApiKey: `vx_oc_${randomUUID().replace(/-/g, '').slice(0, 32)}`,
          webhookSecret: `whs_oc_${randomUUID().replace(/-/g, '').slice(0, 32)}`,
        },
      });
      console.log(`Created ApiProject: ${project.id}`);
    } else {
      console.log(`Found existing ApiProject: ${project.id}`);
      if (!project.surveillanceApiKey || !project.webhookSecret) {
        project = await prisma.apiProject.update({
          where: { id: project.id },
          data: {
            surveillanceApiKey:
              project.surveillanceApiKey ??
              `vx_oc_${randomUUID().replace(/-/g, '').slice(0, 32)}`,
            webhookSecret:
              project.webhookSecret ??
              `whs_oc_${randomUUID().replace(/-/g, '').slice(0, 32)}`,
          },
        });
        console.log('Updated ApiProject with missing keys');
      }
    }

    const API_KEY = project.surveillanceApiKey!;
    const PROJECT_ID = project.id;
    const WEBHOOK_SECRET = project.webhookSecret!;

    let content = readFileSync(VALIDATION_ENV_PATH, 'utf-8');

    const replacements: Array<[RegExp, string]> = [
      [
        /^LOCAL_DEVFORTRESS_API_KEY=.*/m,
        `LOCAL_DEVFORTRESS_API_KEY=${API_KEY}`,
      ],
      [
        /^LOCAL_DEVFORTRESS_PROJECT_ID=.*/m,
        `LOCAL_DEVFORTRESS_PROJECT_ID=${PROJECT_ID}`,
      ],
      [
        /^LOCAL_DEVFORTRESS_WEBHOOK_SECRET=.*/m,
        `LOCAL_DEVFORTRESS_WEBHOOK_SECRET=${WEBHOOK_SECRET}`,
      ],
      [/^DEVFORTRESS_API_KEY=.*/m, `DEVFORTRESS_API_KEY=${API_KEY}`],
      [/^DEVFORTRESS_PROJECT_ID=.*/m, `DEVFORTRESS_PROJECT_ID=${PROJECT_ID}`],
      [
        /^DEVFORTRESS_WEBHOOK_SECRET=.*/m,
        `DEVFORTRESS_WEBHOOK_SECRET=${WEBHOOK_SECRET}`,
      ],
      [/^HC_TEST_EMAIL=.*/m, `HC_TEST_EMAIL=${HC_TEST_EMAIL}`],
      [/^HC_TEST_PASSWORD=.*/m, `HC_TEST_PASSWORD=${HC_TEST_PASSWORD}`],
      [
        /^SUPABASE_SERVICE_ROLE_KEY=.*/m,
        `SUPABASE_SERVICE_ROLE_KEY=${SUPABASE_SERVICE_ROLE_KEY}`,
      ],
      [/^SUPABASE_URL=.*/m, `SUPABASE_URL=${SUPABASE_URL}`],
      [
        /^NEXT_PUBLIC_SUPABASE_URL=.*/m,
        `NEXT_PUBLIC_SUPABASE_URL=${SUPABASE_URL}`,
      ],
    ];

    for (const [pattern, replacement] of replacements) {
      content = content.replace(pattern, replacement);
    }

    writeFileSync(VALIDATION_ENV_PATH, content, 'utf-8');

    console.log('\n=== Populated validation.env ===');
    console.log(`LOCAL_DEVFORTRESS_API_KEY:     ${mask(API_KEY)}`);
    console.log(`LOCAL_DEVFORTRESS_PROJECT_ID:  ${PROJECT_ID}`);
    console.log(`LOCAL_DEVFORTRESS_WEBHOOK_SECRET: ${mask(WEBHOOK_SECRET)}`);
    console.log(`DEVFORTRESS_API_KEY:            ${mask(API_KEY)}`);
    console.log(`DEVFORTRESS_PROJECT_ID:         ${PROJECT_ID}`);
    console.log(`DEVFORTRESS_WEBHOOK_SECRET:     ${mask(WEBHOOK_SECRET)}`);
    console.log(`HC_TEST_EMAIL:                  ${HC_TEST_EMAIL}`);
    console.log(
      `SUPABASE_SERVICE_ROLE_KEY:      ${mask(SUPABASE_SERVICE_ROLE_KEY)}`
    );
    console.log(`NEXT_PUBLIC_SUPABASE_URL:       ${SUPABASE_URL}`);
    console.log('================================\n');

    process.exit(0);
  } catch (err) {
    console.error('ERROR:', err);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();
