/**
 * Custom hook to check user's subscription status
 * Returns loading state, subscription status, and error
 */

import { useState, useEffect } from 'react';
import { useAuthSession } from '@core/components/providers/session-provider';

interface SubscriptionStatus {
  hasSubscription: boolean;
  plan: string | null;
  status: string | null;
}

export function useSubscriptionStatus() {
  const { session, status: authStatus } = useAuthSession();
  const [subscriptionStatus, setSubscriptionStatus] = useState<SubscriptionStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authStatus !== 'authenticated' || !session?.user?.id) {
      setSubscriptionStatus(null);
      setLoading(false);
      return;
    }

    // Check if user has privileged role (admin, developer, owner)
    const role = session.user.role;
    const isPrivilegedUser = role === 'ADMIN' || role === 'DEVELOPER' || role === 'OWNER';

    if (isPrivilegedUser) {
      setSubscriptionStatus({ hasSubscription: true, plan: 'PREMIUM', status: 'ACTIVE' });
      setLoading(false);
      return;
    }

    // Fetch subscription status from API
    const fetchSubscriptionStatus = async () => {
      try {
        setLoading(true);
        const response = await fetch('/api/subscription/status');
        if (!response.ok) {
          throw new Error('Failed to fetch subscription status');
        }
        const data = await response.json();
        setSubscriptionStatus({
          hasSubscription: data.hasSubscription,
          plan: data.plan,
          status: data.status,
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
        setSubscriptionStatus({ hasSubscription: false, plan: null, status: null });
      } finally {
        setLoading(false);
      }
    };

    fetchSubscriptionStatus();
  }, [session, authStatus]);

  return { subscriptionStatus, loading, error };
}