/**
 * Main Navigation Header Component
 * Responsive navigation bar with links to key sections including Help Center
 */

import { getServerSession } from '@core/lib/auth/session';
import { getUserSubscription } from '@core/lib/payments/subscription-service';
import { logError } from '@core/lib/logger';
import { MainNavigationClient } from './main-navigation-client';

export async function MainNavigation() {
  const session = await getServerSession();
  const isAuthenticated = Boolean(session);

  let hasActiveSubscription = false;
  if (session?.user?.id) {
    // Admin users (ADMIN, DEVELOPER, OWNER) should not see pricing link
    if (
      session.user.role === 'ADMIN' ||
      session.user.role === 'DEVELOPER' ||
      session.user.role === 'OWNER'
    ) {
      hasActiveSubscription = true;
    } else {
      try {
        const subscription = await getUserSubscription(session.user.id);
        hasActiveSubscription =
          subscription?.status === 'ACTIVE' ||
          subscription?.status === 'TRIALING';
      } catch (error) {
        // Log error but don't fail navigation
        logError('Failed to fetch subscription status for navigation', {
          error: error instanceof Error ? error.message : String(error),
          userId: session.user.id,
        });
      }
    }
  }

  return (
    <MainNavigationClient
      isAuthenticated={isAuthenticated}
      hasActiveSubscription={hasActiveSubscription}
    />
  );
}
