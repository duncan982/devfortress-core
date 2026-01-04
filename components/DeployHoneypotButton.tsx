/**
 * Deploy Honeypot Button Component
 * Handles client-side honeypot deployment with loading states and error handling
 */

'use client';

import { useState } from 'react';
import { HoneypotStatus } from '@prisma/client';

interface DeployHoneypotButtonProps {
  honeypotId: string;
  currentStatus: HoneypotStatus;
}

export default function DeployHoneypotButton({
  honeypotId,
  currentStatus,
}: DeployHoneypotButtonProps) {
  const [isDeploying, setIsDeploying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleDeploy = async () => {
    if (currentStatus !== HoneypotStatus.INACTIVE) return;

    setIsDeploying(true);
    setError(null);
    setSuccess(false);

    try {
      const response = await fetch(`/api/honeypots/${honeypotId}/deploy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repoName: undefined, // Let the system generate a name
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Deployment failed');
      }

      setSuccess(true);

      // Refresh the page to show updated status
      setTimeout(() => {
        window.location.reload();
      }, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Deployment failed');
    } finally {
      setIsDeploying(false);
    }
  };

  if (currentStatus !== HoneypotStatus.INACTIVE) {
    return null;
  }

  return (
    <div className="flex flex-col gap-2">
      <button
        onClick={handleDeploy}
        disabled={isDeploying}
        className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {isDeploying ? 'Deploying...' : 'Deploy Honeypot'}
      </button>

      {error && (
        <div className="rounded-lg bg-error-50 border border-error-200 p-3 dark:bg-error-950 dark:border-error-800">
          <p className="text-sm text-error-800 dark:text-error-200">{error}</p>
        </div>
      )}

      {success && (
        <div className="rounded-lg bg-success-50 border border-success-200 p-3 dark:bg-success-950 dark:border-success-800">
          <p className="text-sm text-success-800 dark:text-success-200">
            Deployment initiated! The honeypot will be active shortly.
          </p>
        </div>
      )}

      {isDeploying && (
        <div className="rounded-lg bg-primary-50 border border-primary-200 p-3 dark:bg-primary-950 dark:border-primary-800">
          <div className="flex items-center gap-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary-600"></div>
            <p className="text-sm text-primary-800 dark:text-primary-200">
              Generating honeypot code and deploying to Vercel...
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
