'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

type UserTier = 'starter' | 'pro' | 'enterprise' | 'admin';

interface UserTierSwitcherProps {
  currentTier: UserTier;
}

export function UserTierSwitcher({ currentTier }: UserTierSwitcherProps) {
  const [selectedTier, setSelectedTier] = useState<UserTier>(currentTier);
  const router = useRouter();

  const handleTierChange = async (tier: UserTier) => {
    const roleMap: Record<UserTier, string> = {
      starter: 'VIEWER',
      pro: 'DEVELOPER',
      enterprise: 'ADMIN',
      admin: 'OWNER',
    };
    try {
      const response = await fetch('/api/user/update-role', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ role: roleMap[tier] }),
      });

      if (response.ok) {
        setSelectedTier(tier);
        router.refresh();
      } else {
        // Handle error
      }
    } catch {
      // Handle error
    }
  };

  const tiers: { value: UserTier; label: string; description: string }[] = [
    {
      value: 'starter',
      label: 'Starter Tier',
      description: 'Basic API generation, limited features',
    },
    {
      value: 'pro',
      label: 'Pro Tier',
      description: 'Advanced API generation, unlimited features',
    },
    {
      value: 'enterprise',
      label: 'Enterprise Tier',
      description: 'Full enterprise features, team collaboration',
    },
    {
      value: 'admin',
      label: 'Admin Tier',
      description: 'Administrative access, system management',
    },
  ];

  return (
    <div className="rounded-2xl border border-orange-200 bg-orange-50 p-6 dark:border-orange-700 dark:bg-orange-950/50">
      <div className="mb-4 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-orange-100 text-orange-600 dark:bg-orange-900/80 dark:text-orange-200">
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
              d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
            />
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
            />
          </svg>
        </div>
        <div>
          <h3 className="text-lg font-semibold text-orange-900 dark:text-orange-200">
            User Tier Testing (Dev Mode)
          </h3>
          <p className="text-sm text-orange-700 dark:text-orange-200/80">
            Simulate different user tiers for testing
          </p>
        </div>
      </div>

      <div className="space-y-3">
        {tiers.map(tier => (
          <label
            key={tier.value}
            className="flex items-center gap-3 cursor-pointer"
          >
            <input
              type="radio"
              name="userTier"
              value={tier.value}
              checked={selectedTier === tier.value}
              onChange={() => handleTierChange(tier.value)}
              className="text-orange-600 focus:ring-orange-500 dark:text-orange-400 dark:focus:ring-orange-400"
            />
            <div>
              <div className="font-medium text-orange-900 dark:text-orange-200">
                {tier.label}
              </div>
              <div className="text-sm text-orange-700 dark:text-orange-200/70">
                {tier.description}
              </div>
            </div>
          </label>
        ))}
      </div>

      <div className="mt-4 text-xs text-orange-600 dark:text-orange-300">
        Current tier:{' '}
        <strong className="dark:text-orange-200">
          {currentTier.toUpperCase()}
        </strong>
      </div>
    </div>
  );
}
