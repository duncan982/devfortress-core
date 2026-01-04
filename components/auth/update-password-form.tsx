'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { createSupabaseClientComponentClient } from '@core/lib/supabase/client';

export function UpdatePasswordForm() {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    // Check if user is authenticated via reset link
    const checkSession = async () => {
      const supabase = await createSupabaseClientComponentClient();
      const {
        data: { session },
      } = await supabase.auth.getSession();
      if (!session) {
        router.push('/auth/signin?error=invalid_reset_link');
      }
    };
    checkSession();
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setErrorMessage('Password must be at least 8 characters');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const supabase = await createSupabaseClientComponentClient();
      const { error } = await supabase.auth.updateUser({ password });

      if (error) {
        setErrorMessage(error.message);
      } else {
        router.push('/auth/signin?message=Password updated successfully');
      }
    } catch {
      setErrorMessage('An error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-neutral-50 px-6 py-12 dark:bg-neutral-950">
      <main className="w-full max-w-md rounded-3xl border border-neutral-200 bg-white p-10 shadow-xl dark:border-neutral-800 dark:bg-neutral-950">
        <header className="mb-8 text-center">
          <h1 className="text-3xl font-semibold text-neutral-900 dark:text-neutral-100">
            Update Password
          </h1>
          <p className="mt-3 text-sm text-neutral-600 dark:text-neutral-400">
            Enter your new password below.
          </p>
        </header>

        {errorMessage && (
          <div className="mb-6 rounded-lg border border-error-300 bg-error-50 p-4 text-sm text-error-900 dark:border-error-700 dark:bg-red-950 dark:text-error-200">
            {errorMessage}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="password"
              className="block text-sm font-medium text-neutral-700 dark:text-neutral-300"
            >
              New Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              className="mt-1 block w-full px-3 py-2 border border-neutral-300 rounded-md shadow-sm placeholder-neutral-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-neutral-800 dark:border-neutral-600 dark:text-neutral-100 dark:placeholder-neutral-500"
              placeholder="Enter new password"
            />
          </div>
          <div>
            <label
              htmlFor="confirmPassword"
              className="block text-sm font-medium text-neutral-700 dark:text-neutral-300"
            >
              Confirm Password
            </label>
            <input
              id="confirmPassword"
              type="password"
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              required
              className="mt-1 block w-full px-3 py-2 border border-neutral-300 rounded-md shadow-sm placeholder-neutral-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-neutral-800 dark:border-neutral-600 dark:text-neutral-100 dark:placeholder-neutral-500"
              placeholder="Confirm new password"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {isLoading ? 'Updating...' : 'Update Password'}
          </button>
        </form>
      </main>
    </div>
  );
}
