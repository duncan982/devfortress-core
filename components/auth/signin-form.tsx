'use client';

// Version: v4.0.1 - 2026-01-07 - Fix client-side env import causing process.env bundling issues
import { useState, useEffect, useRef } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { createSupabaseClientComponentClient } from '@core/lib/supabase/client';
import { logError, logWarn, logInfo } from '@core/lib/logger/client';
import { Turnstile, type TurnstileInstance } from '@marsidev/react-turnstile';
import { shouldUseLocalAuth } from '@core/lib/auth/local-auth';
// Audit logging temporarily disabled due to sign-in hanging issues
// import { AuditLogService, AuditAction } from '@core/lib/compliance/audit-log';

// Dev login role options following industry standard RBAC
type DevLoginRole = 'OWNER' | 'ADMIN' | 'DEVELOPER';

interface SignInFormProps {
  message?: string;
  isGitHubConfigured?: boolean;
  supabaseClientFactory?: () => ReturnType<
    typeof createSupabaseClientComponentClient
  >;
  onSignInSuccess?: (destination: string) => void;
}

export function SignInForm({
  message,
  isGitHubConfigured = true,
  supabaseClientFactory,
  onSignInSuccess,
}: SignInFormProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [devLoginRole, setDevLoginRole] = useState<DevLoginRole>('OWNER');
  const [captchaToken, setCaptchaToken] = useState<string>('');
  const [useLocalAuth, setUseLocalAuth] = useState(false);
  const [showDevLogin, setShowDevLogin] = useState(false);
  const captchaRef = useRef<TurnstileInstance>(null);
  const searchParams = useSearchParams();
  const router = useRouter();
  const error = searchParams?.get('error');
  const timedOut = searchParams?.get('timeout');
  const nextUrl = searchParams?.get('next');

  useEffect(() => {
    shouldUseLocalAuth().then(setUseLocalAuth);
    // Show dev login panel on localhost when NEXT_PUBLIC_DEV_LOGIN_ENABLED is set
    // NEXT_PUBLIC_* vars are inlined at build time by Next.js
    const devLoginEnabled =
      process.env.NEXT_PUBLIC_DEV_LOGIN_ENABLED === 'true';
    if (
      typeof window !== 'undefined' &&
      devLoginEnabled &&
      (window.location.hostname === 'localhost' ||
        window.location.hostname === '127.0.0.1')
    ) {
      setShowDevLogin(true);
    }
  }, []);

  // Helper function to provide detailed, user-friendly error messages
  const getDetailedAuthErrorMessage = (errorMessage: string): string => {
    const lowerError = errorMessage.toLowerCase();

    if (lowerError.includes('invalid login credentials')) {
      return 'Invalid email or password. Please check your credentials and try again.';
    }
    if (lowerError.includes('email not confirmed')) {
      return 'Please check your email and click the confirmation link before signing in.';
    }
    if (lowerError.includes('too many requests')) {
      return 'Too many sign-in attempts. Please wait a few minutes before trying again.';
    }
    if (lowerError.includes('user not found')) {
      return 'No account found with this email address. Please sign up first.';
    }
    if (lowerError.includes('password is too weak')) {
      return 'Password does not meet security requirements. Please choose a stronger password.';
    }
    if (lowerError.includes('network')) {
      return 'Network error. Please check your internet connection and try again.';
    }
    if (lowerError.includes('service unavailable')) {
      return 'Authentication service is temporarily unavailable. Please try again later.';
    }

    // For unknown errors, provide a generic but helpful message
    return 'Sign-in failed. Please try again or contact support if the issue persists.';
  };

  const derivedMessage = (() => {
    if (message) {
      return message;
    }

    if (timedOut) {
      return 'You were signed out due to inactivity. Please sign in again to continue.';
    }

    if (error) {
      if (error === 'missing_code') {
        return 'Authorization code missing. Please try signing in again.';
      }
      if (error === 'auth_failed') {
        return 'Authentication failed. Please check your credentials and try again.';
      }
      if (error === 'configuration') {
        return 'Authentication service is temporarily unavailable. Please try again later.';
      }
      if (error === 'unauthorized') {
        return 'Access denied. This account is not authorized to access the application.';
      }
      if (error === 'invalid_reset_link') {
        return 'The password reset link is invalid or has expired. Please request a new one.';
      }
      return 'An authentication error occurred. Please try again or contact support if the issue persists.';
    }

    // Check if in development mode using runtime detection (avoid process.env on client)
    const isDevelopment =
      typeof window !== 'undefined' && window.location.hostname === 'localhost';

    if (!isGitHubConfigured && !isDevelopment) {
      return 'No authentication providers are configured. Please contact support.';
    }

    if (!isGitHubConfigured && isDevelopment) {
      return 'GitHub authentication is not configured. Use the Dev Login button for development access.';
    }

    return undefined;
  })();

  const getSupabaseClient =
    supabaseClientFactory ?? createSupabaseClientComponentClient;

  const handleGitHubSignIn = async () => {
    if (!isGitHubConfigured) {
      logWarn('GitHub sign-in attempted but not configured');
      return;
    }

    setIsLoading(true);
    try {
      const supabase = await getSupabaseClient();
      const redirectTo = nextUrl
        ? `${window.location.origin}/auth/callback?next=${encodeURIComponent(nextUrl)}`
        : `${window.location.origin}/auth/callback`;

      await supabase.auth.signInWithOAuth({
        provider: 'github',
        options: {
          redirectTo,
        },
      });
      // Removed logging to prevent hanging in preview environments
    } catch (error) {
      logError('GitHub sign-in failed', { error });
      setErrorMessage('Failed to initiate GitHub sign-in. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDevSignIn = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/auth/dev', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: devLoginRole }),
      });
      if (response.ok) {
        logInfo('Dev sign-in successful', { role: devLoginRole });
        // Redirect to nextUrl if provided, otherwise home
        const destination = nextUrl || '/';
        router.push(destination);
      } else {
        const data = await response.json();
        logError('Dev sign-in failed', {
          status: response.status,
          error: data.error,
        });
        setErrorMessage(data.error || 'Dev login failed');
        // Audit disabled - was causing sign-in hanging issues
        // if (process.env.NODE_ENV !== 'test') {
        //   try {
        //     await AuditLogService.log({
        //       action: AuditAction.USER_LOGIN,
        //       resource: 'AUTH',
        //       level: 'ERROR',
        //       message: 'Failed dev login attempt',
        //       context: {
        //         ipAddress: undefined,
        //         userAgent: navigator.userAgent,
        //         metadata: { error: data.error, status: response.status },
        //       },
        //     });
        //   } catch (auditError) {
        //     logError('Failed to audit dev login failure', auditError);
        //   }
        // }
      }
    } catch (error) {
      logError('Dev sign-in error', { error });
      setErrorMessage('Dev login failed');
      // Audit disabled - was causing sign-in hanging issues
    } finally {
      setIsLoading(false);
    }
  };

  const handleLocalAuthSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage(null);

    try {
      const supabase = await getSupabaseClient();
      const { error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) {
        setErrorMessage(getDetailedAuthErrorMessage(error.message));
        return;
      }

      logInfo('Local auth sign-in successful', { email });
      // Redirect to nextUrl if provided, otherwise home
      const destination = nextUrl || '/';
      router.push(destination);
    } catch (error) {
      logError('Local auth sign-in error', { error });
      setErrorMessage('Sign-in failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleEmailSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage(null);

    // Check CAPTCHA
    if (!captchaToken) {
      setErrorMessage('Please complete the CAPTCHA');
      setIsLoading(false);
      return;
    }

    // Brute force protection
    if (loginAttempts >= 5) {
      logWarn('Brute force protection triggered', {
        email,
        attempts: loginAttempts,
      });
      setErrorMessage('Too many failed attempts. Please try again later.');
      captchaRef.current?.reset();
      setCaptchaToken('');
      setIsLoading(false);

      // Audit disabled - was causing sign-in hanging issues
      return;
    }

    try {
      const response = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, captchaToken }),
      });

      const data = await response.json();

      if (response.ok) {
        logInfo('Email sign-in successful', { email });
        // Reset attempts on success
        setLoginAttempts(0);

        // Check MFA status - assuming client can check after redirect
        const destination = nextUrl || '/dashboard';

        if (onSignInSuccess) {
          onSignInSuccess(destination);
        } else {
          router.push(destination);
        }
      } else {
        logError('Email sign-in failed', { email, error: data.error });
        setErrorMessage(
          getDetailedAuthErrorMessage(data.error || 'Sign-in failed')
        );
        setLoginAttempts(prev => prev + 1);
        setCaptchaToken('');
      }
    } catch (error) {
      logError('Email sign-in error', { email, error });
      setErrorMessage('An error occurred during sign in');
      setLoginAttempts(prev => prev + 1);
      setCaptchaToken('');
    } finally {
      setIsLoading(false);
    }
  };

  const handleEmailSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage(null);

    // Check CAPTCHA
    if (!captchaToken) {
      setErrorMessage('Please complete the CAPTCHA');
      setIsLoading(false);
      return;
    }

    // Password strength validation
    if (password.length < 8) {
      logWarn('Weak password in signup attempt', { email });
      setErrorMessage('Password must be at least 8 characters long');
      setCaptchaToken('');
      setIsLoading(false);

      // Audit disabled - was causing sign-in hanging issues
      return;
    }
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      logWarn('Weak password in signup attempt', { email });
      setErrorMessage(
        'Password must contain at least one uppercase letter, one lowercase letter, and one number'
      );
      setCaptchaToken('');
      setIsLoading(false);

      // Audit disabled - was causing sign-in hanging issues
      return;
    }

    try {
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, captchaToken }),
      });

      const data = await response.json();

      if (response.ok) {
        logInfo('Email sign-up initiated', { email });
        setErrorMessage('Check your email for a verification link');
        setCaptchaToken('');
      } else {
        logError('Email sign-up failed', { email, error: data.error });
        setErrorMessage(data.error || 'Signup failed');
        setCaptchaToken('');
      }
    } catch (error) {
      logError('Email sign-up error', { email, error });
      setErrorMessage('An error occurred during sign up');
      setCaptchaToken('');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-neutral-50 px-6 py-12 dark:bg-neutral-950">
      <main
        className="w-full max-w-md rounded-3xl border border-neutral-200 bg-white p-10 shadow-xl dark:border-neutral-800 dark:bg-neutral-950"
        role="main"
        aria-labelledby="signin-heading"
      >
        <header className="mb-8 text-center">
          <h1
            id="signin-heading"
            className="text-3xl font-semibold text-neutral-900 dark:text-neutral-100"
          >
            Welcome to DevFortress
          </h1>
          <p className="mt-3 text-sm text-neutral-600 dark:text-neutral-400">
            Sign in with your email and password or GitHub account to access
            secure API generation, security hardening, and monitoring tools.
          </p>
        </header>

        {derivedMessage ? (
          <div
            className="mb-6 rounded-lg border border-warning-300 bg-warning-50 p-4 text-sm text-warning-900 dark:border-warning-700 dark:bg-amber-950 dark:text-warning-200"
            role="alert"
            aria-live="polite"
          >
            {derivedMessage}
          </div>
        ) : null}

        {errorMessage ? (
          <div
            className="mb-6 rounded-lg border border-error-300 bg-error-50 p-4 text-sm text-error-900 dark:border-error-700 dark:bg-red-950 dark:text-error-200"
            role="alert"
            aria-live="polite"
          >
            {errorMessage}
          </div>
        ) : null}

        <form
          onSubmit={
            useLocalAuth
              ? handleLocalAuthSignIn
              : isSignUp
                ? handleEmailSignUp
                : handleEmailSignIn
          }
          className="space-y-4 mb-6"
        >
          <div>
            <label
              htmlFor="email"
              className="block text-sm font-medium text-neutral-700 dark:text-neutral-300"
            >
              Email
            </label>
            <input
              id="email"
              name="email"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              className="mt-1 block w-full px-3 py-2 border border-neutral-300 rounded-md shadow-sm placeholder-neutral-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-neutral-800 dark:border-neutral-600 dark:text-neutral-100 dark:placeholder-neutral-500"
              placeholder="Enter your email"
            />
          </div>
          <div>
            <label
              htmlFor="password"
              className="block text-sm font-medium text-neutral-700 dark:text-neutral-300"
            >
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              className="mt-1 block w-full px-3 py-2 border border-neutral-300 rounded-md shadow-sm placeholder-neutral-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-neutral-800 dark:border-neutral-600 dark:text-neutral-100 dark:placeholder-neutral-500"
              placeholder="Enter your password"
            />
          </div>
          <div>
            <Turnstile
              ref={captchaRef}
              siteKey={process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || ''}
              onSuccess={token => setCaptchaToken(token)}
              onExpire={() => setCaptchaToken('')}
              onError={() => setCaptchaToken('')}
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {isLoading
              ? 'Processing...'
              : useLocalAuth
                ? `Local ${isSignUp ? 'Sign Up' : 'Sign In'}`
                : isSignUp
                  ? 'Sign Up'
                  : 'Sign In'}
          </button>
        </form>

        <div className="text-center mb-6">
          <button
            type="button"
            onClick={() => setIsSignUp(!isSignUp)}
            className="text-sm text-blue-600 hover:text-blue-500 dark:text-blue-400"
          >
            {isSignUp
              ? 'Already have an account? Sign In'
              : "Don't have an account? Sign Up"}
          </button>
          {!isSignUp && (
            <div className="mt-2">
              <a
                href="/auth/reset-password"
                className="text-sm text-blue-600 hover:text-blue-500 dark:text-blue-400"
              >
                Forgot your password?
              </a>
            </div>
          )}
        </div>

        <div className="relative mb-6">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-neutral-300 dark:border-neutral-600" />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white dark:bg-neutral-950 text-neutral-500">
              Or continue with
            </span>
          </div>
        </div>

        <nav className="flex flex-col gap-3" aria-label="Sign in options">
          <button
            type="button"
            onClick={handleGitHubSignIn}
            disabled={isLoading || !isGitHubConfigured}
            aria-disabled={!isGitHubConfigured}
            className={`flex w-full items-center justify-center gap-2 rounded-full px-5 py-3 text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 disabled:cursor-not-allowed disabled:opacity-70
              ${isGitHubConfigured ? 'bg-black text-white hover:bg-neutral-800 focus-visible:ring-black dark:bg-neutral-100 dark:text-black dark:hover:bg-neutral-200' : 'bg-neutral-200 text-neutral-500 focus-visible:ring-neutral-300 dark:bg-neutral-800 dark:text-neutral-500 dark:focus-visible:ring-neutral-700'}`}
            aria-label={
              isGitHubConfigured
                ? isLoading
                  ? 'Signing in with GitHub'
                  : 'Sign in with GitHub'
                : 'GitHub sign-in is currently unavailable'
            }
          >
            {isLoading
              ? 'Signing in…'
              : isGitHubConfigured
                ? 'Continue with GitHub'
                : 'GitHub sign-in unavailable'}
          </button>
          {(useLocalAuth || showDevLogin) && (
            <div className="mt-4 rounded-lg border border-amber-300 bg-amber-50 p-4 dark:border-amber-700 dark:bg-amber-950">
              <div className="mb-3 flex items-center gap-2">
                <svg
                  className="h-5 w-5 text-amber-600 dark:text-amber-400"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                  />
                </svg>
                <span className="text-sm font-medium text-amber-800 dark:text-amber-200">
                  Development Mode
                </span>
              </div>
              <p className="mb-3 text-xs text-amber-700 dark:text-amber-300">
                Quick login for local development. Select a role and click to
                sign in instantly.
              </p>
              <div className="mb-3">
                <label
                  htmlFor="dev-role"
                  className="mb-1 block text-xs font-medium text-amber-800 dark:text-amber-200"
                >
                  Login as:
                </label>
                <select
                  id="dev-role"
                  value={devLoginRole}
                  onChange={e =>
                    setDevLoginRole(e.target.value as DevLoginRole)
                  }
                  className="w-full rounded-md border border-amber-300 bg-white px-3 py-2 text-sm text-amber-900 focus:border-amber-500 focus:outline-none focus:ring-1 focus:ring-amber-500 dark:border-amber-600 dark:bg-amber-900 dark:text-amber-100"
                >
                  <option value="OWNER">👑 Owner (Full Access)</option>
                  <option value="ADMIN">🔧 Admin (Management Access)</option>
                  <option value="DEVELOPER">
                    💻 Developer (Development Access)
                  </option>
                </select>
              </div>
              <button
                type="button"
                onClick={handleDevSignIn}
                disabled={isLoading}
                className="flex w-full items-center justify-center gap-2 rounded-full bg-amber-600 px-5 py-3 text-sm font-medium text-white transition-colors hover:bg-amber-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-500 disabled:cursor-not-allowed disabled:opacity-70"
                aria-label={
                  isLoading
                    ? 'Signing in with dev login'
                    : `Sign in as ${devLoginRole}`
                }
              >
                {isLoading ? 'Signing in…' : `Quick Login as ${devLoginRole}`}
              </button>
            </div>
          )}
        </nav>

        <footer className="mt-6 text-center text-xs text-neutral-500 dark:text-neutral-500">
          By continuing you agree to the DevFortress{' '}
          <a
            href="/terms"
            className="underline"
            aria-label="Read Terms of Service"
          >
            Terms of Service
          </a>{' '}
          and{' '}
          <a
            href="/privacy"
            className="underline"
            aria-label="Read Privacy Policy"
          >
            Privacy Policy
          </a>
          .
        </footer>
      </main>
    </div>
  );
}
