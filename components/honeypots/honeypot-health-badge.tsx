'use client';

/**
 * Honeypot Health Status Badge
 * Displays the live health status of a honeypot
 */

import { useEffect, useState } from 'react';

interface HoneypotHealthBadgeProps {
  honeypotId: string;
}

interface HealthStatus {
  healthy: boolean;
  message?: string;
  lastChecked?: string;
}

export default function HoneypotHealthBadge({ honeypotId }: HoneypotHealthBadgeProps) {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function checkHealth() {
      try {
        const response = await fetch(`/api/honeypots/${honeypotId}/health`);
        if (response.ok) {
          const data = await response.json();
          setHealth(data);
        } else {
          setHealth({ healthy: false, message: 'Check failed' });
        }
      } catch {
        setHealth({ healthy: false, message: 'Error checking health' });
      } finally {
        setLoading(false);
      }
    }

    checkHealth();
  }, [honeypotId]);

  if (loading) {
    return (
      <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-100 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200">
        Checking...
      </span>
    );
  }

  if (!health) {
    return (
      <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-100 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200">
        Unknown
      </span>
    );
  }

  return (
    <span
      className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
        health.healthy
          ? 'bg-success-100 text-success-800 dark:bg-success-900 dark:text-success-200'
          : 'bg-error-100 text-error-800 dark:bg-error-900 dark:text-error-200'
      }`}
      title={health.message}
    >
      {health.healthy ? 'Active' : 'Inactive'}
    </span>
  );
}