'use client';

import { useState } from 'react';

interface GenerateInsightsButtonProps {
  apiProjectId?: string;
  quotaRemaining: number;
  variant?: 'primary' | 'secondary' | 'inline';
  className?: string;
}

export function GenerateInsightsButton({
  apiProjectId,
  quotaRemaining,
  variant = 'primary',
  className = '',
}: GenerateInsightsButtonProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    setSuccess(false);

    try {
      const body: Record<string, unknown> = {};
      if (apiProjectId) {
        body.apiProjectId = apiProjectId;
      }
      // The /api/insights/generate endpoint defaults to session user's ownerId

      const res = await fetch('/api/insights/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await res.json();

      if (!res.ok) {
        if (res.status === 404 && data.error?.includes('No threat data')) {
          setError(
            'No threat data available yet. Deploy honeypots first to collect threat data, then generate insights.'
          );
        } else if (res.status === 429) {
          setError(
            'Monthly insight generation quota exceeded. Upgrade your plan for more.'
          );
        } else {
          setError(data.error || 'Failed to generate insights');
        }
        return;
      }

      setSuccess(true);
      // Reload the page to show the new insights
      setTimeout(() => {
        window.location.reload();
      }, 1500);
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const isDisabled = loading || quotaRemaining <= 0;

  const baseStyles = {
    primary:
      'rounded-lg bg-purple-600 px-6 py-2.5 text-sm font-medium text-white hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors',
    secondary:
      'rounded-lg border border-purple-300 bg-white px-4 py-2 text-sm font-medium text-purple-700 hover:bg-purple-50 dark:border-purple-700 dark:bg-neutral-800 dark:text-purple-300 dark:hover:bg-neutral-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors',
    inline:
      'rounded-md bg-purple-600 px-4 py-1.5 text-xs font-medium text-white hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors',
  };

  return (
    <div className={className}>
      <button
        onClick={handleGenerate}
        disabled={isDisabled}
        className={baseStyles[variant]}
      >
        {loading ? (
          <span className="flex items-center gap-2">
            <svg
              className="h-4 w-4 animate-spin"
              viewBox="0 0 24 24"
              fill="none"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
            Analyzing Threat Data...
          </span>
        ) : success ? (
          <span className="flex items-center gap-2">
            ✅ Insights Generated!
          </span>
        ) : (
          <span className="flex items-center gap-2">
            🔄 Generate Insights
            {quotaRemaining > 0 && (
              <span className="opacity-75">({quotaRemaining} remaining)</span>
            )}
          </span>
        )}
      </button>

      {error && (
        <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>
      )}

      {quotaRemaining <= 0 && !loading && (
        <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
          Quota exhausted.{' '}
          <a
            href="/pricing"
            className="text-purple-600 underline dark:text-purple-400"
          >
            Upgrade
          </a>{' '}
          for more insight generations.
        </p>
      )}
    </div>
  );
}
