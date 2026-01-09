'use client';

import Link from 'next/link';
import { useAuthSession } from '@core/components/providers/session-provider';

/**
 * Client-side auth-aware content that shows different UI based on authentication state.
 * This component uses the client-side session provider to avoid stale server-side cache.
 */
export function AuthAwareHomeContent() {
  const { status, isInitialized } = useAuthSession();
  const isAuthenticated = status === 'authenticated';

  // Don't render anything until auth is initialized to prevent flash
  if (!isInitialized) {
    return null;
  }

  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="mt-4">
      <Link
        href="/dashboard"
        className="inline-flex items-center rounded-lg bg-primary-600 px-6 py-3 text-sm font-semibold text-white hover:bg-primary-700"
      >
        Go to Dashboard →
      </Link>
    </div>
  );
}

/**
 * Auth-aware feature card link that shows dashboard link when authenticated,
 * or learn more link with "Sign up to access" when not authenticated.
 */
export function AuthAwareFeatureLink({
  authenticatedHref,
  authenticatedLabel,
  unauthenticatedHref,
  unauthenticatedLabel,
  className,
  showSignUpHint = true,
}: {
  authenticatedHref: string;
  authenticatedLabel: string;
  unauthenticatedHref: string;
  unauthenticatedLabel: string;
  className?: string;
  showSignUpHint?: boolean;
}) {
  const { status, isInitialized } = useAuthSession();
  const isAuthenticated = isInitialized && status === 'authenticated';

  if (isAuthenticated) {
    return (
      <Link href={authenticatedHref} className={className}>
        {authenticatedLabel}
      </Link>
    );
  }

  return (
    <div className="mt-4">
      <Link href={unauthenticatedHref} className={className}>
        {unauthenticatedLabel}
      </Link>
      {showSignUpHint && (
        <p className="mt-2 text-xs text-neutral-500 dark:text-neutral-500">
          Sign up to access
        </p>
      )}
    </div>
  );
}

/**
 * Get Started button that only shows when user is not authenticated.
 */
export function AuthAwareGetStartedButton() {
  const { status, isInitialized } = useAuthSession();
  const isAuthenticated = isInitialized && status === 'authenticated';

  // Don't show button if authenticated
  if (isAuthenticated) {
    return null;
  }

  return (
    <Link
      href="/auth/signin"
      className="rounded-lg bg-primary-600 px-6 py-3 font-semibold text-white hover:bg-primary-700"
    >
      Get Started
    </Link>
  );
}

/**
 * Auth-aware link component that shows different links based on auth state.
 * @param authenticatedHref - Link destination when authenticated
 * @param authenticatedLabel - Link text when authenticated
 * @param unauthenticatedHref - Link destination when not authenticated
 * @param unauthenticatedLabel - Link text when not authenticated
 */
export function AuthAwareLink({
  authenticatedHref,
  authenticatedLabel,
  unauthenticatedHref,
  unauthenticatedLabel,
  className,
}: {
  authenticatedHref: string;
  authenticatedLabel: string;
  unauthenticatedHref: string;
  unauthenticatedLabel: string;
  className?: string;
}) {
  const { status, isInitialized } = useAuthSession();
  const isAuthenticated = status === 'authenticated';

  // Show unauthenticated state during initialization to prevent flash
  const href =
    isInitialized && isAuthenticated ? authenticatedHref : unauthenticatedHref;
  const label =
    isInitialized && isAuthenticated
      ? authenticatedLabel
      : unauthenticatedLabel;

  return (
    <Link href={href} className={className}>
      {label}
    </Link>
  );
}
