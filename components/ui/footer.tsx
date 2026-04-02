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
    <footer className="border-t border-neutral-200 bg-neutral-50 transition-colors duration-200 dark:border-neutral-800 dark:bg-neutral-950">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        {/* Multi-column links */}
        <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
          {/* Product */}
          <div>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-neutral-900 dark:text-neutral-100">
              Product
            </h3>
            <ul className="space-y-2">
              {[
                { href: '/features', label: 'Features' },
                { href: '/pricing', label: 'Pricing' },
                { href: '/compare', label: 'Compare' },
                { href: '/enterprise', label: 'Enterprise' },
                { href: '/status', label: 'Status' },
              ].map(link => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-neutral-600 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-neutral-900 dark:text-neutral-100">
              Resources
            </h3>
            <ul className="space-y-2">
              {[
                { href: '/docs', label: 'Documentation' },
                { href: '/docs/faq', label: 'FAQ' },
                { href: '/help', label: 'Help Center' },
                { href: '/docs/developer-guide', label: 'Developer Guide' },
                { href: '/contact', label: 'Contact' },
              ].map(link => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-neutral-600 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Legal */}
          <div>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-neutral-900 dark:text-neutral-100">
              Legal
            </h3>
            <ul className="space-y-2">
              {[
                { href: '/terms', label: 'Terms of Service' },
                { href: '/privacy', label: 'Privacy Policy' },
                { href: '/privacy/data-collected', label: 'Data We Collect' },
                { href: '/legal/dpa', label: 'GDPR DPA' },
                { href: '/legal/baa', label: 'HIPAA BAA' },
              ].map(link => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-neutral-600 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Security */}
          <div>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-neutral-900 dark:text-neutral-100">
              Security
            </h3>
            <ul className="space-y-2">
              {[
                { href: '/security', label: 'Security Overview' },
                { href: '/transparency', label: 'Transparency Report' },
                { href: '/features/defend', label: 'Threat Defense' },
                { href: '/features/collect', label: 'Data Collection' },
              ].map(link => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-neutral-600 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-10 border-t border-neutral-200 pt-6 dark:border-neutral-800">
          <div className="flex flex-col items-center justify-between gap-3 sm:flex-row">
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              © {new Date().getFullYear()} DevFortress. All rights reserved.
            </p>
            <div className="flex items-center gap-4">
              <a
                href="https://github.com/duncan982/devfortress"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-neutral-500 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
              >
                GitHub
              </a>
              <a
                href="mailto:support@devfortress.net"
                className="text-sm text-neutral-500 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
              >
                support@devfortress.net
              </a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
