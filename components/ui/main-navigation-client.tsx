/**
 * Main Navigation Client Component
 * Client-side navigation logic with authentication awareness
 * Desktop: all links visible in header bar with icons and labels
 * Mobile: hamburger menu that opens vertical navigation overlay
 */

'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, useEffect, useRef, useCallback } from 'react';
import { ThemeToggleButton } from './theme-toggle';
import { JobStatusIndicator } from './job-status-indicator';
import { NotificationBellIndicator } from './notification-bell-indicator';
import { useAuthSession } from '@core/components/providers/session-provider';

interface NavLink {
  href: string;
  label: string;
  icon?: React.ReactNode;
  requiresAuth?: boolean;
  external?: boolean;
}

interface MainNavigationClientProps {
  isAuthenticated: boolean;
  hasActiveSubscription?: boolean;
}

export function MainNavigationClient({
  isAuthenticated: serverAuthenticated,
  hasActiveSubscription: serverHasActiveSubscription = false,
}: MainNavigationClientProps) {
  const pathname = usePathname();
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const mobileMenuRef = useRef<HTMLDivElement>(null);
  const { session, status, isInitialized, signOut } = useAuthSession();

  // Use client-side session status, fallback to server-side during initialization
  const isAuthenticated = isInitialized
    ? status === 'authenticated'
    : serverAuthenticated;

  // Check if user has active subscription based on role (client-side)
  // Admin, Developer, Owner roles always get priority support
  const privilegedRoles = ['ADMIN', 'DEVELOPER', 'OWNER'];
  const hasActiveSubscription =
    isInitialized && isAuthenticated
      ? privilegedRoles.includes(session?.user?.role || '')
      : serverHasActiveSubscription;

  // Close user menu when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        userMenuRef.current &&
        !userMenuRef.current.contains(event.target as Node)
      ) {
        setUserMenuOpen(false);
      }
    }

    if (userMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () =>
        document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [userMenuOpen]);

  // Close mobile menu when route changes
  const [lastPathname, setLastPathname] = useState(pathname);
  if (lastPathname !== pathname) {
    setLastPathname(pathname);
    if (mobileMenuOpen) {
      setMobileMenuOpen(false);
    }
  }

  const closeMobileMenu = useCallback(() => {
    setMobileMenuOpen(false);
  }, []);

  const parseBooleanFlag = (value?: string) => {
    if (!value) {
      return false;
    }

    const normalized = value.trim().toLowerCase();
    return ['true', '1', 'yes', 'y', 'on'].includes(normalized);
  };

  // NEXT_PUBLIC_ env vars are replaced at build time, safe for client components
  const isPortalFeatureEnabled = parseBooleanFlag(
    process.env.NEXT_PUBLIC_PORTAL_ENABLED
  );

  // Hide navigation on onboarding page and admin pages (admin has its own layout)
  if (pathname === '/onboarding' || pathname?.startsWith('/admin')) {
    return null;
  }

  const navLinks: NavLink[] = [
    {
      href: '/',
      label: 'Home',
      icon: (
        <svg
          className="h-5 w-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
          />
        </svg>
      ),
    },
    ...(isAuthenticated && isPortalFeatureEnabled
      ? [
          {
            href: '/portal',
            label: 'Portal',
            icon: (
              <svg
                className="h-5 w-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
                />
              </svg>
            ),
          },
        ]
      : []),
    {
      href: '/help',
      label: 'Help Center',
      icon: (
        <svg
          className="h-5 w-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      ),
    },
    // Community link - shown for free tier users (those without active subscriptions)
    ...(!hasActiveSubscription
      ? [
          {
            href: 'https://github.com/duncan982/devfortress/discussions',
            label: 'Community',
            external: true,
            icon: (
              <svg
                className="h-5 w-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                />
              </svg>
            ),
          },
        ]
      : []),
    // Consulting link - visible to all users
    {
      href: '/consulting',
      label: 'Consulting',
      icon: (
        <svg
          className="h-5 w-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
          />
        </svg>
      ),
    },
    // Priority Support link for paid tier users
    ...(hasActiveSubscription
      ? [
          {
            href: '/support',
            label: 'Priority Support',
            icon: (
              <svg
                className="h-5 w-5 text-primary-600 dark:text-primary-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 9.192l-3.536 3.536M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-5 0a4 4 0 11-8 0 4 4 0 018 0z"
                />
              </svg>
            ),
          },
        ]
      : []),
    // Pricing link - always visible for all users
    {
      href: '/pricing',
      label: 'Pricing',
      icon: (
        <svg
          className="h-5 w-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      ),
    },
  ];

  const isActive = (href: string) => {
    if (href === '/') {
      return pathname === '/';
    }
    return pathname?.startsWith(href);
  };

  return (
    <nav
      className="sticky top-0 z-50 border-b border-neutral-200 bg-neutral-50 transition-colors duration-200 dark:border-neutral-800 dark:bg-neutral-950 relative"
      aria-label="Main navigation"
    >
      <div className="mx-auto max-w-7xl min-w-0 px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 min-w-0 items-center justify-between">
          {/* Logo */}
          <div className="flex items-center">
            <Link href="/" className="flex items-center space-x-2">
              <div
                className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary-600 text-white font-bold"
                aria-hidden="true"
              >
                DF
              </div>
              <span className="hidden text-xl font-semibold text-neutral-900 dark:text-neutral-100 sm:block">
                DevFortress
              </span>
            </Link>
          </div>

          {/* Desktop Navigation - Right-aligned, hidden on mobile */}
          <div className="hidden md:flex min-w-0 items-center gap-1 lg:gap-1.5 ml-auto">
            {navLinks.map(link =>
              link.external ? (
                <a
                  key={link.href}
                  href={link.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-[13px] font-medium transition-colors text-neutral-700 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-900 dark:hover:text-neutral-100"
                >
                  {link.icon && (
                    <span className="flex h-4 w-4 items-center justify-center text-neutral-500 dark:text-neutral-400">
                      {link.icon}
                    </span>
                  )}
                  <span>{link.label}</span>
                  <svg
                    className="h-3 w-3 opacity-50"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                    />
                  </svg>
                </a>
              ) : (
                <Link
                  key={link.href}
                  href={link.href}
                  className={`inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-[13px] font-medium transition-colors ${
                    isActive(link.href)
                      ? 'bg-neutral-100 text-primary-600 dark:bg-neutral-800 dark:text-primary-300'
                      : 'text-neutral-700 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-900 dark:hover:text-neutral-100'
                  }`}
                >
                  {link.icon && (
                    <span className="flex h-4 w-4 items-center justify-center text-neutral-500 dark:text-neutral-400">
                      {link.icon}
                    </span>
                  )}
                  <span>{link.label}</span>
                </Link>
              )
            )}

            {/* Separator */}
            <div className="mx-1 h-5 w-px bg-neutral-200 dark:bg-neutral-700" />

            {/* Job Status Indicator - shows when there are active jobs */}
            {isAuthenticated && <JobStatusIndicator />}

            {/* Notification Bell */}
            {isAuthenticated && <NotificationBellIndicator />}

            {/* Auth Section */}
            {!isInitialized ? (
              <div className="h-8 w-16 animate-pulse rounded-lg bg-neutral-200 dark:bg-neutral-700" />
            ) : !isAuthenticated ? (
              <Link
                href="/auth/signin"
                className="inline-flex items-center rounded-lg bg-primary-600 px-3 py-1.5 text-[13px] font-semibold text-white transition-colors hover:bg-primary-700"
              >
                Sign In
              </Link>
            ) : (
              <div ref={userMenuRef} className="relative">
                <button
                  onClick={() => setUserMenuOpen(!userMenuOpen)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-neutral-200 px-2.5 py-1.5 text-[13px] font-medium text-neutral-700 transition-colors hover:border-neutral-300 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:border-neutral-600 dark:hover:bg-neutral-800"
                  aria-expanded={userMenuOpen}
                  aria-haspopup="true"
                  aria-label="User menu"
                >
                  <span className="max-w-[100px] truncate">
                    {session?.user?.name || session?.user?.email || 'User'}
                  </span>
                  <svg
                    className={`h-3.5 w-3.5 transition-transform ${userMenuOpen ? 'rotate-180' : ''}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </button>

                {userMenuOpen && (
                  <div className="absolute right-0 z-50 mt-2 w-48 rounded-lg border border-neutral-200 bg-white py-1 shadow-lg dark:border-neutral-700 dark:bg-neutral-800">
                    <div className="px-3 py-2 border-b border-neutral-200 dark:border-neutral-700">
                      <p className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
                        {session?.user?.name || 'User'}
                      </p>
                      <p className="text-xs text-neutral-500 dark:text-neutral-400 truncate">
                        {session?.user?.email}
                      </p>
                    </div>
                    <Link
                      href="/dashboard"
                      onClick={() => setUserMenuOpen(false)}
                      className="flex w-full items-center px-3 py-2 text-sm text-neutral-700 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-neutral-700"
                    >
                      <svg
                        className="mr-2 h-4 w-4"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
                        />
                      </svg>
                      Dashboard
                    </Link>
                    <Link
                      href="/dashboard/settings"
                      onClick={() => setUserMenuOpen(false)}
                      className="flex w-full items-center px-3 py-2 text-sm text-neutral-700 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-neutral-700"
                    >
                      <svg
                        className="mr-2 h-4 w-4"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                        />
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                        />
                      </svg>
                      Settings
                    </Link>
                    <div className="border-t border-neutral-200 dark:border-neutral-700 my-1" />
                    <button
                      onClick={() => {
                        setUserMenuOpen(false);
                        signOut();
                      }}
                      className="flex w-full items-center px-3 py-2 text-sm text-neutral-700 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-neutral-700"
                    >
                      <svg
                        className="mr-2 h-4 w-4"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                        />
                      </svg>
                      Sign Out
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Theme Toggle */}
            <div className="ml-1 border-l border-neutral-200 pl-1 dark:border-neutral-800">
              <ThemeToggleButton />
            </div>
          </div>

          {/* Hamburger menu — always visible, compact dropdown below icon */}
          <div className="flex items-center gap-1.5 ml-2 shrink-0">
            {/* Job Status (mobile only — desktop shows in nav row) */}
            <span className="md:hidden">
              {isAuthenticated && <JobStatusIndicator />}
            </span>

            {/* Notification Bell (mobile only) */}
            <span className="md:hidden">
              {isAuthenticated && <NotificationBellIndicator />}
            </span>

            {/* Theme Toggle (mobile only — desktop shows in nav row) */}
            <span className="md:hidden">
              <ThemeToggleButton />
            </span>

            {/* Hamburger Menu Button — relative anchor for dropdown */}
            <div className="relative" ref={mobileMenuRef}>
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="inline-flex items-center justify-center rounded-lg p-2 text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-100"
                aria-expanded={mobileMenuOpen}
                aria-label="Toggle navigation menu"
              >
                {mobileMenuOpen ? (
                  <svg
                    className="h-6 w-6"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                ) : (
                  <svg
                    className="h-6 w-6"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 6h16M4 12h16M4 18h16"
                    />
                  </svg>
                )}
              </button>

              {/* Dropdown Menu — positioned directly below the hamburger button */}
              {mobileMenuOpen && (
                <>
                  {/* Transparent backdrop to capture clicks outside the dropdown */}
                  <div
                    className="fixed inset-0 z-40"
                    onClick={closeMobileMenu}
                    aria-hidden="true"
                  />

                  {/* Compact dropdown panel — right-aligned directly below hamburger */}
                  <div
                    className="absolute right-0 top-full z-50 mt-2 w-64 max-h-[calc(100vh-5rem)] overflow-y-auto rounded-xl border border-neutral-200 bg-white shadow-xl ring-1 ring-black/5 dark:border-neutral-700 dark:bg-neutral-900 dark:ring-white/5"
                    style={{ transformOrigin: 'top right' }}
                    aria-label="Navigation menu"
                  >
                    {/* Navigation Links */}
                    <div className="py-2">
                      {navLinks.map(link =>
                        link.external ? (
                          <a
                            key={link.href}
                            href={link.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={closeMobileMenu}
                            className="flex items-center gap-3 px-4 py-2.5 text-sm font-medium text-neutral-700 transition-colors hover:bg-neutral-50 dark:text-neutral-300 dark:hover:bg-neutral-800"
                          >
                            {link.icon && (
                              <span className="flex h-5 w-5 items-center justify-center text-neutral-400 dark:text-neutral-500 [&>svg]:h-5 [&>svg]:w-5 shrink-0">
                                {link.icon}
                              </span>
                            )}
                            <span className="flex-1">{link.label}</span>
                            <svg
                              className="h-3 w-3 text-neutral-400"
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                              />
                            </svg>
                          </a>
                        ) : (
                          <Link
                            key={link.href}
                            href={link.href}
                            onClick={closeMobileMenu}
                            className={`flex items-center gap-3 px-4 py-2.5 text-sm font-medium transition-colors ${
                              isActive(link.href)
                                ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'
                                : 'text-neutral-700 hover:bg-neutral-50 dark:text-neutral-300 dark:hover:bg-neutral-800'
                            }`}
                          >
                            {link.icon && (
                              <span className="flex h-5 w-5 items-center justify-center text-neutral-400 dark:text-neutral-500 [&>svg]:h-5 [&>svg]:w-5 shrink-0">
                                {link.icon}
                              </span>
                            )}
                            <span>{link.label}</span>
                          </Link>
                        )
                      )}
                    </div>

                    {/* Divider + Auth */}
                    <div className="border-t border-neutral-100 dark:border-neutral-800">
                      {!isInitialized ? (
                        <div className="px-3.5 py-2.5">
                          <div className="h-6 animate-pulse rounded bg-neutral-200 dark:bg-neutral-700" />
                        </div>
                      ) : !isAuthenticated ? (
                        <div className="p-3">
                          <Link
                            href="/auth/signin"
                            onClick={closeMobileMenu}
                            className="flex w-full items-center justify-center rounded-lg bg-primary-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-primary-700"
                          >
                            Sign In
                          </Link>
                        </div>
                      ) : (
                        <>
                          {/* User info */}
                          <div className="px-4 py-2.5">
                            <p className="text-sm font-medium text-neutral-900 truncate dark:text-neutral-100">
                              {session?.user?.name || 'User'}
                            </p>
                            <p className="text-xs text-neutral-500 truncate dark:text-neutral-400">
                              {session?.user?.email}
                            </p>
                          </div>
                          <div className="border-t border-neutral-100 py-1.5 dark:border-neutral-800">
                            <Link
                              href="/dashboard"
                              onClick={closeMobileMenu}
                              className="flex items-center gap-3 px-4 py-2.5 text-sm text-neutral-700 hover:bg-neutral-50 dark:text-neutral-300 dark:hover:bg-neutral-800"
                            >
                              <svg
                                className="h-4 w-4 text-neutral-400"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
                                />
                              </svg>
                              Dashboard
                            </Link>
                            <Link
                              href="/dashboard/settings"
                              onClick={closeMobileMenu}
                              className="flex items-center gap-3 px-4 py-2.5 text-sm text-neutral-700 hover:bg-neutral-50 dark:text-neutral-300 dark:hover:bg-neutral-800"
                            >
                              <svg
                                className="h-4 w-4 text-neutral-400"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                                />
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                                />
                              </svg>
                              Settings
                            </Link>
                          </div>
                          <div className="border-t border-neutral-100 py-1.5 dark:border-neutral-800">
                            <button
                              onClick={() => {
                                closeMobileMenu();
                                signOut();
                              }}
                              className="flex w-full items-center gap-3 px-4 py-2.5 text-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-950/30"
                            >
                              <svg
                                className="h-4 w-4"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                                />
                              </svg>
                              Sign Out
                            </button>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
