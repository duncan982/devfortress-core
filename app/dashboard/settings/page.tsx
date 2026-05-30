import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';

export const dynamic = 'force-dynamic';

export default async function SettingsPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect('/auth/signin');
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="flex flex-col gap-6">
        <div className="mb-2">
          <h1 className="text-3xl font-bold text-neutral-900 dark:text-white">
            Settings
          </h1>
        </div>
        <p className="text-neutral-600 dark:text-neutral-400">
          Manage your account preferences and settings
        </p>

        <div className="bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700 rounded-lg p-6">
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-white mb-4">
            Account
          </h2>
          <div>
            <p className="font-medium text-neutral-900 dark:text-white mb-1">Email</p>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">{user.email}</p>
          </div>
        </div>

        <div className="bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700 rounded-lg p-6">
          <h2 className="text-xl font-semibold text-neutral-900 dark:text-white mb-4">
            Hosted Platform
          </h2>
          <p className="text-sm text-neutral-600 dark:text-neutral-400 mb-4">
            Profile management, notification preferences, theme settings, and privacy controls
            are available on the DevFortress hosted platform.
          </p>
          <a
            href="https://devfortress.net"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center text-sm font-semibold text-primary-600 hover:text-primary-700 dark:text-primary-400"
          >
            Learn more →
          </a>
        </div>

        <div className="mt-2">
          <Link
            href="/auth/signout"
            className="text-sm font-medium text-neutral-500 hover:text-red-600 dark:text-neutral-400 dark:hover:text-red-400 transition-colors"
          >
            Sign out
          </Link>
        </div>
      </div>
    </div>
  );
}
