'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export function Footer() {
  const pathname = usePathname();

  // Hide footer on admin pages (admin has its own layout)
  if (pathname.startsWith('/admin')) {
    return null;
  }

  return (
    <footer className="border-t border-neutral-200 bg-white/90 backdrop-blur-sm transition-colors duration-200 dark:border-neutral-800 dark:bg-neutral-950/95">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="text-center text-sm text-neutral-600 dark:text-neutral-400">
          © 2025 DevFortress. All rights reserved. |{' '}
          <Link
            href="/terms"
            className="hover:text-neutral-900 dark:hover:text-neutral-100"
          >
            Terms
          </Link>{' '}
          |{' '}
          <Link
            href="/privacy"
            className="hover:text-neutral-900 dark:hover:text-neutral-100"
          >
            Privacy
          </Link>{' '}
          |{' '}
          <Link
            href="/help"
            className="hover:text-primary-600 dark:hover:text-primary-300"
          >
            Help Center
          </Link>{' '}
          |{' '}
          <Link
            href="/security"
            className="hover:text-neutral-900 dark:hover:text-neutral-100"
          >
            Security
          </Link>
        </div>
      </div>
    </footer>
  );
}
