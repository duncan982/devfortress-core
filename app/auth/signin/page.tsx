'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { createClient } from '@/lib/supabase/client';

type SignInMode = 'password' | 'magic-link';

const DEV_EMAIL = process.env.NEXT_PUBLIC_DEV_USER_EMAIL;
const DEV_PASSWORD = process.env.NEXT_PUBLIC_DEV_USER_PASSWORD;

export default function SignInPage() {
  const router = useRouter();
  const [mode, setMode] = useState<SignInMode>('password');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [magicLinkSent, setMagicLinkSent] = useState(false);

  const supabase = createClient();

  async function handlePasswordSignIn(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) { setError(error.message); setLoading(false); return; }
    router.push('/dashboard');
    router.refresh();
  }

  async function handleMagicLink(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const { error } = await supabase.auth.signInWithOtp({
      email,
      options: { emailRedirectTo: `${window.location.origin}/auth/callback` },
    });
    if (error) { setError(error.message); setLoading(false); return; }
    setMagicLinkSent(true);
    setLoading(false);
  }

  async function handleQuickSignIn() {
    if (!DEV_EMAIL || !DEV_PASSWORD) return;
    setLoading(true);
    setError(null);
    const { error } = await supabase.auth.signInWithPassword({
      email: DEV_EMAIL,
      password: DEV_PASSWORD,
    });
    if (error) { setError(error.message); setLoading(false); return; }
    router.push('/dashboard');
    router.refresh();
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-white dark:bg-neutral-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <Link href="/" className="text-2xl font-bold text-neutral-900 dark:text-white">
            DevFortress
          </Link>
          <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-400">
            Sign in to your self-hosted instance
          </p>
        </div>

        <div className="rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
          <div className="mb-6 flex rounded-lg bg-neutral-100 p-1 dark:bg-neutral-800">
            <button type="button" onClick={() => setMode('password')}
              className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
                mode === 'password'
                  ? 'bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white'
                  : 'text-neutral-500 hover:text-neutral-700 dark:text-neutral-400'
              }`}>Password</button>
            <button type="button" onClick={() => setMode('magic-link')}
              className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
                mode === 'magic-link'
                  ? 'bg-white text-neutral-900 shadow-sm dark:bg-neutral-700 dark:text-white'
                  : 'text-neutral-500 hover:text-neutral-700 dark:text-neutral-400'
              }`}>Magic Link</button>
          </div>

          {magicLinkSent ? (
            <div className="py-4 text-center">
              <p className="font-semibold text-neutral-900 dark:text-white">Check your email</p>
              <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">We sent a sign-in link to {email}</p>
            </div>
          ) : (
            <form onSubmit={mode === 'password' ? handlePasswordSignIn : handleMagicLink} className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">Email</label>
                <input id="email" type="email" required value={email} onChange={e => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="w-full rounded-lg border border-neutral-300 bg-white px-3.5 py-2.5 text-sm text-neutral-900 placeholder-neutral-400 outline-none transition-colors focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 dark:border-neutral-700 dark:bg-neutral-800 dark:text-white dark:placeholder-neutral-500" />
              </div>
              {mode === 'password' && (
                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">Password</label>
                  <input id="password" type="password" required value={password} onChange={e => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full rounded-lg border border-neutral-300 bg-white px-3.5 py-2.5 text-sm text-neutral-900 placeholder-neutral-400 outline-none transition-colors focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20 dark:border-neutral-700 dark:bg-neutral-800 dark:text-white dark:placeholder-neutral-500" />
                </div>
              )}
              {error && (
                <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-400">{error}</p>
              )}
              <button type="submit" disabled={loading}
                className="w-full rounded-lg bg-primary-600 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-primary-700 disabled:opacity-50">
                {loading ? 'Signing in…' : mode === 'password' ? 'Sign in' : 'Send magic link'}
              </button>
            </form>
          )}

          {process.env.NODE_ENV === 'development' && DEV_EMAIL && DEV_PASSWORD && (
            <div className="mt-6 border-t border-neutral-200 pt-4 dark:border-neutral-700">
              <p className="mb-2 text-xs font-medium uppercase tracking-wide text-neutral-400 dark:text-neutral-500">Quick Sign In (Dev)</p>
              <button type="button" onClick={handleQuickSignIn} disabled={loading}
                className="w-full rounded-lg border border-neutral-200 bg-neutral-50 px-4 py-2 text-sm text-neutral-700 transition-colors hover:bg-neutral-100 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700">
                Sign in as {DEV_EMAIL}
              </button>
            </div>
          )}
        </div>

        <p className="mt-6 text-center text-xs text-neutral-400 dark:text-neutral-600">
          Self-hosted DevFortress ·{' '}
          <a href="https://devfortress.net" target="_blank" rel="noopener noreferrer"
            className="underline hover:text-neutral-600 dark:hover:text-neutral-400">devfortress.net</a>
        </p>
      </div>
    </div>
  );
}
