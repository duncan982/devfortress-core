/**
 * Unified Breadcrumb Navigation Component
 * Consistent navigation for all Active Defense Feedback Loop pages
 */

'use client';

import Link from 'next/link';
import { ChevronRight } from 'lucide-react';
import type { BreadcrumbItem } from './breadcrumb-constants';

interface BreadcrumbNavProps {
  items: BreadcrumbItem[];
  currentPage: string;
}

export function BreadcrumbNav({ items, currentPage }: BreadcrumbNavProps) {
  return (
    <nav className="flex items-center gap-2 text-sm text-neutral-500 dark:text-neutral-400">
      {items.map((item, index) => (
        <div key={`${item.href}-${index}`} className="flex items-center gap-2">
          <Link
            href={item.href}
            className="hover:text-primary-600 dark:hover:text-primary-400 transition-colors"
          >
            {item.label}
          </Link>
          <ChevronRight className="h-4 w-4" data-testid="chevron-right" />
        </div>
      ))}
      <span className="text-neutral-900 dark:text-white font-medium">
        {currentPage}
      </span>
    </nav>
  );
}
