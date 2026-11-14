/**
 * seed-open-core-user.ts
 * Creates the dev/admin user in the open-core local Supabase instance.
 * Idempotent — safe to run multiple times.
 * Run with: npx tsx --env-file=.env.local scripts/seed-open-core-user.ts
 *
 * This file is gitignored and never committed.
 */
import { createClient } from '@supabase/supabase-js';
import { PrismaClient } from '@prisma/client';
import ws from 'ws';

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;
const DEV_EMAIL = process.env.NEXT_PUBLIC_DEV_USER_EMAIL!;
const DEV_PASSWORD = process.env.NEXT_PUBLIC_DEV_USER_PASSWORD!;

if (!SUPABASE_URL || !SERVICE_ROLE_KEY || !DEV_EMAIL || !DEV_PASSWORD) {
  console.error('Missing required env vars. Ensure .env.local is loaded.');
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
  realtime: { transport: ws },
});

declare global {
  var __prismaSeed: PrismaClient | undefined;
}
const prisma = globalThis.__prismaSeed ?? new PrismaClient();

/** Show only the last 4 characters of a secret, for operator confirmation. */
function maskSecret(value: string): string {
  if (value.length <= 4) return '*'.repeat(value.length);
  return '*'.repeat(value.length - 4) + value.slice(-4);
}

async function main() {
  console.log(`\nSeeding open-core Supabase user: ${DEV_EMAIL}\n`);

  // 1. Check if user already exists in Supabase auth
  const { data: existingUsers, error: listError } =
    await supabaseAdmin.auth.admin.listUsers();

  if (listError) {
    console.error('Failed to list Supabase users:', listError.message);
    process.exit(1);
  }

  const existing = existingUsers.users.find(u => u.email === DEV_EMAIL);

  let supabaseUserId: string;

  if (existing) {
    console.log(`  ✅ Auth user already exists: ${existing.id}`);
    supabaseUserId = existing.id;

    // Update password in case it changed
    const { error: updateError } =
      await supabaseAdmin.auth.admin.updateUserById(existing.id, {
        password: DEV_PASSWORD,
        email_confirm: true,
      });
    if (updateError) {
      console.warn('  ⚠ Could not update password:', updateError.message);
    } else {
      console.log('  ✅ Password confirmed/updated');
    }
  } else {
    // Create user via admin API — email pre-confirmed, no email required
    const { data: created, error: createError } =
      await supabaseAdmin.auth.admin.createUser({
        email: DEV_EMAIL,
        password: DEV_PASSWORD,
        email_confirm: true,
      });

    if (createError || !created?.user) {
      console.error('Failed to create auth user:', createError?.message);
      process.exit(1);
    }

    supabaseUserId = created.user.id;
    console.log(`  ✅ Auth user created: ${supabaseUserId}`);
  }

  // 2. Upsert matching Prisma User row (uses Supabase auth UUID as id)
  const prismaUser = await prisma.user.upsert({
    where: { id: supabaseUserId },
    update: {
      email: DEV_EMAIL,
      name: 'Dev Admin',
      role: 'OWNER',
    },
    create: {
      id: supabaseUserId,
      email: DEV_EMAIL,
      name: 'Dev Admin',
      role: 'OWNER',
    },
  });

  console.log(`  ✅ Prisma User row upserted: ${prismaUser.id}`);
  console.log(`\n  Login credentials:`);
  console.log(`    Email    : ${DEV_EMAIL}`);
  // Never print the raw secret: the operator already set it in .env.local.
  // Masked confirmation lets them verify which password is active without
  // putting the plaintext value in scrollback/CI logs.
  console.log(
    `    Password : ${maskSecret(DEV_PASSWORD)} (set via NEXT_PUBLIC_DEV_USER_PASSWORD in .env.local)`
  );
  console.log(`    URL      : http://localhost:3001/auth/signin\n`);

  await prisma.$disconnect();
}

main().catch(err => {
  console.error('Seed failed:', err);
  process.exit(1);
});
