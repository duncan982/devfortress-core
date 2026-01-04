/**
 * Accept Invitation Component
 * Handles accepting team invitations
 */

'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { logError } from '@core/lib/logger/client';

interface AcceptInvitationProps {
  token: string;
}

export function AcceptInvitation({ token }: AcceptInvitationProps) {
  const [isAccepting, setIsAccepting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const router = useRouter();

  const handleAccept = async () => {
    setIsAccepting(true);
    setError('');

    try {
      const response = await fetch('/api/invitations/accept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to accept invitation');
      }

      const data = await response.json();
      setSuccess(true);

      // Redirect to team page after a short delay
      setTimeout(() => {
        router.push(`/dashboard/teams/${data.team.id}/manage`);
      }, 2000);
    } catch (err) {
      logError('Failed to accept invitation', { error: err });
      setError(
        err instanceof Error ? err.message : 'Failed to accept invitation'
      );
    } finally {
      setIsAccepting(false);
    }
  };

  if (success) {
    return (
      <div className="text-center">
        <div className="mb-6">
          <div className="mx-auto h-16 w-16 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
            <svg
              className="h-8 w-8 text-green-600 dark:text-green-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M5 13l4 4L19 7"
              />
            </svg>
          </div>
        </div>
        <h1 className="text-2xl font-bold text-neutral-900 dark:text-white mb-2">
          Welcome to the team!
        </h1>
        <p className="text-neutral-600 dark:text-neutral-400 mb-6">
          You have successfully joined the team. Redirecting you to the team
          page...
        </p>
      </div>
    );
  }

  return (
    <div className="text-center">
      <div className="mb-6">
        <div className="mx-auto h-16 w-16 rounded-full bg-primary-100 dark:bg-primary-900/20 flex items-center justify-center">
          <svg
            className="h-8 w-8 text-primary-600 dark:text-primary-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"
            />
          </svg>
        </div>
      </div>

      <h1 className="text-2xl font-bold text-neutral-900 dark:text-white mb-2">
        Team Invitation
      </h1>
      <p className="text-neutral-600 dark:text-neutral-400 mb-6">
        You&apos;ve been invited to join a team. Accept the invitation to start
        collaborating.
      </p>

      {error && (
        <div className="mb-6 rounded-lg bg-error-50 p-4 text-sm text-error-700 dark:bg-error-900/20 dark:text-error-400">
          {error}
        </div>
      )}

      <button
        onClick={handleAccept}
        disabled={isAccepting}
        className="w-full rounded-lg bg-primary-600 px-4 py-3 text-white hover:bg-primary-700 disabled:opacity-50 font-medium"
      >
        {isAccepting ? 'Accepting...' : 'Accept Invitation'}
      </button>

      <p className="mt-4 text-sm text-neutral-500 dark:text-neutral-400">
        By accepting, you&apos;ll be added to the team with the assigned role.
      </p>
    </div>
  );
}
