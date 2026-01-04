/**
 * User Profile Settings Component
 * Allows users to edit their profile information
 */
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { logError } from '@core/lib/logger/client';

interface ProfileFormProps {
  user: {
    name?: string | null;
    email?: string | null;
    image?: string | null;
  };
}

export function ProfileForm({ user }: ProfileFormProps) {
  const router = useRouter();
  const [name, setName] = useState(user.name || '');
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setMessage('');

    try {
      const response = await fetch('/api/user/profile', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });

      if (!response.ok) {
        throw new Error('Failed to update profile');
      }

      setMessage('Profile updated successfully!');
      router.refresh();
    } catch (error) {
      logError('Failed to update profile', error);
      setMessage('Failed to update profile. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label
          htmlFor="name"
          className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2"
        >
          Name
        </label>
        <input
          id="name"
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          className="w-full px-4 py-2 border border-neutral-300 dark:border-neutral-600 rounded-md bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
          placeholder="Your name"
        />
      </div>

      <div>
        <label
          htmlFor="email"
          className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2"
        >
          Email
        </label>
        <input
          id="email"
          type="email"
          value={user.email || ''}
          disabled
          className="w-full px-4 py-2 border border-neutral-300 dark:border-neutral-600 rounded-md bg-neutral-100 dark:bg-neutral-800 text-neutral-500 dark:text-neutral-400 cursor-not-allowed"
        />
        <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
          Email cannot be changed
        </p>
      </div>

      {message && (
        <div
          className={`p-3 rounded-md ${
            message.includes('success')
              ? 'bg-success-50 dark:bg-success-900/20 text-success-700 dark:text-success-400'
              : 'bg-error-50 dark:bg-error-900/20 text-error-700 dark:text-error-400'
          }`}
        >
          {message}
        </div>
      )}

      <button
        type="submit"
        disabled={isLoading || !name}
        className="px-6 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-neutral-400 dark:disabled:bg-neutral-600 text-white rounded-md font-medium transition-colors disabled:cursor-not-allowed"
      >
        {isLoading ? 'Saving...' : 'Save Changes'}
      </button>
    </form>
  );
}
