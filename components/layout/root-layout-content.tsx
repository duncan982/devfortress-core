/**
 * Root Layout Content Component
 * Conditionally renders the content wrapper based on the current route
 * Admin pages have their own layout and don't need the default wrapper
 */

'use client';

import { usePathname } from 'next/navigation';
import { ReactNode } from 'react';
import { Footer } from '@core/components/ui/footer';

interface RootLayoutContentProps {
  children: ReactNode;
}

export function RootLayoutContent({ children }: RootLayoutContentProps) {
  const pathname = usePathname();

  // Admin pages have their own complete layout with sidebar navigation
  // They don't need the standard page wrapper with header/footer
  const isAdminRoute = pathname.startsWith('/admin');

  if (isAdminRoute) {
    // Admin pages render directly without additional wrappers
    // The admin layout handles all styling and navigation
    return <main id="main-content">{children}</main>;
  }

  // Standard pages get the default layout with header, footer, and consistent styling
  return (
    <div className="flex min-h-screen flex-col bg-neutral-50 text-neutral-900 transition-colors duration-200 dark:bg-neutral-950 dark:text-neutral-100">
      <main id="main-content" className="flex-1">
        {children}
      </main>
      <Footer />
    </div>
  );
}
