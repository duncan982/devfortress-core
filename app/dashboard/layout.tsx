import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import Link from 'next/link';

const NAV_ITEMS = [
  { label: 'Overview',     href: '/dashboard',                     icon: '⬡' },
  { label: 'Surveillance', href: '/dashboard/collect/surveillance', icon: '◉' },
  { label: 'Collect',      href: '/dashboard/collect',              icon: '⊙' },
  { label: 'Credentials',  href: '/dashboard/credentials',          icon: '⚿' },
  { label: 'Agents',       href: '/dashboard/agents',               icon: '⟳' },
  { label: 'Settings',     href: '/dashboard/settings',             icon: '⚙' },
] as const;

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect('/auth/signin');
  }

  return (
    <div className="flex min-h-screen bg-neutral-50 dark:bg-neutral-950">
      <aside className="hidden w-60 flex-col border-r border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900 lg:flex">
        <div className="border-b border-neutral-200 px-6 py-5 dark:border-neutral-800">
          <Link href="/dashboard" className="text-lg font-bold text-neutral-900 dark:text-white">
            DevFortress
          </Link>
          <p className="mt-0.5 font-mono text-[10px] uppercase tracking-widest text-neutral-400 dark:text-neutral-600">
            Self-Hosted
          </p>
        </div>

        <nav className="flex-1 space-y-0.5 px-3 py-4">
          {NAV_ITEMS.map(item => (
            <Link
              key={item.href}
              href={item.href}
              className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-white"
            >
              <span className="text-base">{item.icon}</span>
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="mx-3 mb-3 rounded-xl border border-primary-200/60 bg-primary-50/60 px-3 py-3 dark:border-primary-900/30 dark:bg-primary-950/20">
          <p className="mb-1 text-[11px] font-semibold text-primary-700 dark:text-primary-300">
            Hosted Platform
          </p>
          <p className="mb-2 text-[11px] text-neutral-500 dark:text-neutral-400">
            Threat intelligence, automated response, billing, and more.
          </p>
          <a
            href="https://devfortress.net/pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[11px] font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400"
          >
            View plans →
          </a>
        </div>

        <div className="border-t border-neutral-200 px-4 py-4 dark:border-neutral-800">
          <p className="truncate text-xs text-neutral-400 dark:text-neutral-600">
            {user.email}
          </p>
          <Link
            href="/auth/signout"
            className="mt-2 block text-xs text-neutral-400 hover:text-neutral-600 dark:text-neutral-600 dark:hover:text-neutral-400"
          >
            Sign out
          </Link>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  );
}
