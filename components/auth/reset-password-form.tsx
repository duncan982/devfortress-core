'use client';

import { useState } from 'react';
import { createSupabaseClientComponentClient } from '@core/lib/supabase/client';

interface ResetPasswordFormProps {
  message?: string;
  error?: string;
}

export function ResetPasswordForm({ message, error }: ResetPasswordFormProps) {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setSuccessMessage(null);

    try {
      const supabase = await createSupabaseClientComponentClient();
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/auth/update-password`,
      });

      if (error) {
        setSuccessMessage(`Error: ${error.message}`);
      } else {
        setSuccessMessage('Check your email for a password reset link');
      }
    } catch {
      setSuccessMessage('An error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-neutral-50 px-6 py-12 dark:bg-neutral-950">
      <main className="w-full max-w-md rounded-3xl border border-neutral-200 bg-white p-10 shadow-xl dark:border-neutral-800 dark:bg-neutral-950">
        <header className="mb-8 text-center">
          <h1 className="text-3xl font-semibold text-neutral-900 dark:text-neutral-100">
            Reset Password
          </h1>
          <p className="mt-3 text-sm text-neutral-600 dark:text-neutral-400">
            Enter your email address and we&apos;ll send you a link to reset
            your password.
          </p>
        </header>

        {message && (
          <div className="mb-6 rounded-lg border border-blue-300 bg-blue-50 p-4 text-sm text-blue-900 dark:border-blue-700 dark:bg-blue-950 dark:text-blue-200">
            {message}
          </div>
        )}

        {error && (
          <div className="mb-6 rounded-lg border border-error-300 bg-error-50 p-4 text-sm text-error-900 dark:border-error-700 dark:bg-red-950 dark:text-error-200">
            {error}
          </div>
        )}

        {successMessage && (
          <div className="mb-6 rounded-lg border border-green-300 bg-green-50 p-4 text-sm text-green-900 dark:border-green-700 dark:bg-green-950 dark:text-green-200">
            {successMessage}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="email"
              className="block text-sm font-medium text-neutral-700 dark:text-neutral-300"
            >
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              className="mt-1 block w-full px-3 py-2 border border-neutral-300 rounded-md shadow-sm placeholder-neutral-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-neutral-800 dark:border-neutral-600 dark:text-neutral-100 dark:placeholder-neutral-500"
              placeholder="Enter your email"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {isLoading ? 'Sending...' : 'Send Reset Link'}
          </button>
        </form>

        <footer className="mt-6 text-center">
          <a
            href="/auth/signin"
            className="text-sm text-blue-600 hover:text-blue-500 dark:text-blue-400"
          >
            Back to Sign In
          </a>
        </footer>
      </main>
    </div>
  );
}
