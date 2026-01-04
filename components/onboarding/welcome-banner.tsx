'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';

interface WelcomeBannerProps {
  userName: string | null;
  progressPercent: number;
}

/**
 * Welcome Banner Component
 * Shows on dashboard for users with incomplete onboarding
 */
export function WelcomeBanner({
  userName,
  progressPercent,
}: WelcomeBannerProps) {
  const router = useRouter();
  const [dismissed, setDismissed] = useState(false);

  if (dismissed || progressPercent === 100) {
    return null;
  }

  return (
    <div className="bg-gradient-to-r from-primary-600 to-indigo-600 rounded-lg shadow-lg p-6 mb-6 text-white relative overflow-hidden">
      {/* Background decoration */}
      <div className="absolute top-0 right-0 -mr-4 -mt-4 w-32 h-32 bg-white opacity-10 rounded-full" />
      <div className="absolute bottom-0 left-0 -ml-8 -mb-8 w-40 h-40 bg-white opacity-10 rounded-full" />

      <div className="relative">
        <button
          onClick={() => setDismissed(true)}
          className="absolute top-0 right-0 text-white hover:text-neutral-200 transition-colors"
          aria-label="Dismiss banner"
        >
          <svg
            className="w-5 h-5"
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
        </button>

        <div className="flex items-start gap-4">
          <div className="flex-shrink-0">
            <div className="w-12 h-12 bg-white bg-opacity-20 rounded-full flex items-center justify-center">
              <span className="text-2xl">👋</span>
            </div>
          </div>

          <div className="flex-1">
            <h2 className="text-2xl font-bold mb-2">
              Welcome{userName ? `, ${userName}` : ''}! 🚀
            </h2>
            <p className="text-primary-100 mb-4">
              You&apos;re {progressPercent}% of the way through setting up your
              account. Let&apos;s complete your onboarding to unlock all
              features!
            </p>

            {/* Progress bar */}
            <div className="mb-4">
              <div className="flex justify-between items-center mb-1">
                <span className="text-sm text-primary-100">Setup Progress</span>
                <span className="text-sm font-semibold">
                  {progressPercent}%
                </span>
              </div>
              <div className="w-full bg-white bg-opacity-20 rounded-full h-2">
                <div
                  className="bg-white h-2 rounded-full transition-all duration-300"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
            </div>

            <button
              onClick={() => router.push('/onboarding')}
              className="inline-flex items-center px-6 py-2 bg-white text-primary-600 font-semibold rounded-lg hover:bg-primary-50 transition-colors"
            >
              Continue Setup
              <svg
                className="w-5 h-5 ml-2"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M13 7l5 5m0 0l-5 5m5-5H6"
                />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
