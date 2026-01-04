import { cookies } from 'next/headers';
import { createServerClient } from '@supabase/ssr';
import { getEnv } from '@core/lib/env';
import type { Database } from '@/types/supabase';
import type { Session, User } from '@supabase/supabase-js';
import * as retry from 'retry';
import CircuitBreaker from 'opossum';
import { logInfo } from '@core/lib/logger';
import { getLocalAuthService } from '@core/lib/auth/local-auth';

const ensureSupabaseConfig = async () => {
  const env = getEnv();
  const supabaseUrl = env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseKey = env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey) {
    throw new Error(
      'Supabase configuration is missing. Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY.'
    );
  }

  // Check if we should use local auth instead of Supabase
  const shouldUseLocal = !supabaseUrl ||
                         !supabaseKey ||
                         supabaseUrl.includes('placeholder') ||
                         supabaseKey.includes('placeholder') ||
                         process.env.NODE_ENV === 'development' && process.env.USE_LOCAL_AUTH === 'true';

  if (shouldUseLocal) {
    logInfo('Using local authentication service for development');
    return null; // Signal to use local auth
  }

  return {
    supabaseUrl,
    supabaseKey,
  } as const;
};

// In-memory session cache with 5-minute TTL
const sessionCache = new Map<string, { session: Session; expires: number }>();

// Retry logic for authentication operations with exponential backoff
export async function retryAuth<T>(
  fn: () => Promise<T>,
  retries = 5,
  baseDelay = 1000
): Promise<T> {
  const operation = retry.operation({
    retries,
    factor: 2, // Exponential
    minTimeout: baseDelay,
    randomize: true, // Jitter
  });

  return new Promise((resolve, reject) => {
    operation.attempt(async (_currentAttempt) => {
      try {
        const result = await fn();
        resolve(result);
      } catch (error) {
        if (operation.retry(error as Error)) return;
        reject(error);
      }
    });
  });
}

// Circuit breaker for Supabase operations - aligned with session timeout
const breaker = new CircuitBreaker(async (fn: () => Promise<unknown>) => fn(), {
  timeout: 65000, // Increased to 65s to accommodate session timeout + buffer
  errorThresholdPercentage: 50,
  resetTimeout: 30000,
});

export const safeSupabaseCall = breaker.fire.bind(breaker);

// Query profiling utility for optimization
export async function profileQuery(query: string, params: unknown[] = []): Promise<unknown> {
  // Note: This is a simplified example. In production, use a proper PostgreSQL client.
  // For Supabase, you might need to use the REST API or direct connection.
  logInfo(`EXPLAIN ANALYZE ${query}`, { params });
  // Implement actual profiling logic here if needed
  return null;
}

// Get cached session or fetch new one
export async function getCachedSession(token: string): Promise<Session | null> {
  const cached = sessionCache.get(token);
  if (cached && cached.expires > Date.now()) {
    return cached.session;
  }
  return null;
}

// Cache a session
export function cacheSession(token: string, session: Session): void {
  sessionCache.set(token, {
    session,
    expires: Date.now() + 5 * 60 * 1000, // 5 minutes
  });
}

// Local auth client that mimics Supabase server client for local development
const createLocalAuthClient = async (cookieStore: Awaited<ReturnType<typeof cookies>>) => {
  const localAuth = getLocalAuthService();

  // Mock Supabase client interface
  return {
    auth: {
      getSession: async () => {
        try {
          // Check for local auth cookie
          const localSessionCookie = cookieStore.get('local-auth-session');
          if (!localSessionCookie) {
            return { data: { session: null }, error: null };
          }

          const sessionData = JSON.parse(localSessionCookie.value);
          const session = await localAuth.getSession(sessionData.access_token);

          if (!session) {
            return { data: { session: null }, error: null };
          }

          // Convert to Supabase session format
          const supabaseSession: Session = {
            access_token: session.access_token,
            refresh_token: session.refresh_token,
            expires_at: session.expires_at,
            expires_in: session.expires_at - Math.floor(Date.now() / 1000),
            token_type: 'bearer',
            // @ts-expect-error Local user object is partial
            user: {
              id: session.user.id,
              email: session.user.email,
              user_metadata: {
                name: session.user.name,
                full_name: session.user.name,
                role: session.user.role,
              },
            } as User,
          };

          return { data: { session: supabaseSession }, error: null };
        } catch (error) {
          logInfo('Local auth getSession error', { error });
          return { data: { session: null }, error: null };
        }
      },

      signInWithPassword: async (credentials: { email: string; password: string }) => {
        try {
          const result = await localAuth.signInWithPassword(credentials.email, credentials.password);

          if (result.error || !result.session) {
            return { data: { user: null, session: null }, error: { message: result.error } };
          }

          // Set cookie
          const sessionData = {
            access_token: result.session.access_token,
            refresh_token: result.session.refresh_token,
            expires_at: result.session.expires_at,
          };

          cookieStore.set('local-auth-session', JSON.stringify(sessionData), {
            httpOnly: true,
            secure: false, // Local dev
            sameSite: 'lax',
            maxAge: 60 * 60, // 1 hour
            path: '/',
          });

          // Convert to Supabase format
          const supabaseSession: Session = {
            access_token: result.session.access_token,
            refresh_token: result.session.refresh_token,
            expires_at: result.session.expires_at,
            expires_in: result.session.expires_at - Math.floor(Date.now() / 1000),
            token_type: 'bearer',
            user: {
              id: result.session.user.id,
              email: result.session.user.email,
              user_metadata: {
                name: result.session.user.name,
                full_name: result.session.user.name,
                role: result.session.user.role,
              },
            } as unknown as User,
          };

          return {
            data: {
              user: supabaseSession.user,
              session: supabaseSession
            },
            error: null
          };
        } catch (error) {
          logInfo('Local auth signInWithPassword error', { error });
          return { data: { user: null, session: null }, error: { message: 'Authentication failed' } };
        }
      },

      signUp: async (credentials: { email: string; password: string; options?: { emailRedirectTo?: string } }) => {
        try {
          // For local auth, signUp is the same as signInWithPassword
          const result = await localAuth.signInWithPassword(credentials.email, credentials.password);

          if (result.error || !result.session) {
            return { data: { user: null, session: null }, error: { message: result.error } };
          }

          // Set cookie
          const sessionData = {
            access_token: result.session.access_token,
            refresh_token: result.session.refresh_token,
            expires_at: result.session.expires_at,
          };

          cookieStore.set('local-auth-session', JSON.stringify(sessionData), {
            httpOnly: true,
            secure: false, // Local dev
            sameSite: 'lax',
            maxAge: 60 * 60, // 1 hour
            path: '/',
          });

          // Convert to Supabase format
          const supabaseSession: Session = {
            access_token: result.session.access_token,
            refresh_token: result.session.refresh_token,
            expires_at: result.session.expires_at,
            expires_in: result.session.expires_at - Math.floor(Date.now() / 1000),
            token_type: 'bearer',
            user: {
              id: result.session.user.id,
              email: result.session.user.email,
              user_metadata: {
                name: result.session.user.name,
                full_name: result.session.user.name,
                role: result.session.user.role,
              },
            } as unknown as User,
          };

          return {
            data: {
              user: supabaseSession.user,
              session: supabaseSession
            },
            error: null
          };
        } catch (error) {
          logInfo('Local auth signUp error', { error });
          return { data: { user: null, session: null }, error: { message: 'Signup failed' } };
        }
      },

      signOut: async () => {
        try {
          cookieStore.delete('local-auth-session');
          return { error: null };
        } catch (error) {
          logInfo('Local auth signOut error', { error });
          return { error: { message: 'Sign out failed' } };
        }
      },

      getUser: async () => {
        try {
          // Check for local auth cookie
          const localSessionCookie = cookieStore.get('local-auth-session');
          if (!localSessionCookie) {
            return { data: { user: null }, error: null };
          }

          const sessionData = JSON.parse(localSessionCookie.value);
          const session = await localAuth.getSession(sessionData.access_token);

          if (!session) {
            return { data: { user: null }, error: null };
          }

          // Convert to Supabase user format
          const user = {
            id: session.user.id,
            email: session.user.email,
            user_metadata: {
              name: session.user.name,
              full_name: session.user.name,
              role: session.user.role,
            },
          } as unknown as User;

          return { data: { user }, error: null };
        } catch (error) {
          logInfo('Local auth getUser error', { error });
          return { data: { user: null }, error: null };
        }
      },

      resetPasswordForEmail: async (_email: string, _options?: { redirectTo?: string }) => {
        // For local auth, simulate success
        return { error: null };
      },

      updateUser: async (_updates: { password?: string }) => {
        // For local auth, simulate success
        return { data: { user: { id: 'local-user', email: 'local@example.com' } as User }, error: null };
      },
    },

    // Mock other Supabase methods as needed
    from: () => ({
      select: (_columns?: string, options?: { count?: string }) => {
        const baseResult = {
          eq: () => ({
            eq: () => ({
              single: async (): Promise<{ data: null; error: { message: string } }> => ({ data: null, error: { message: 'Local auth mode - database operations not available' } }),
            }),
            single: async (): Promise<{ data: null; error: { message: string } }> => ({ data: null, error: { message: 'Local auth mode - database operations not available' } }),
          }),
          single: async (): Promise<{ data: null; error: { message: string } }> => ({ data: null, error: { message: 'Local auth mode - database operations not available' } }),
        };

        // If count is requested, return a result with count property
        if (options?.count === 'exact') {
          return {
            ...baseResult,
            count: 0,
          };
        }

        return baseResult;
      },
    }),
  };
};

const createClient = async () => {
  const cookieStore = await cookies();
  const config = await ensureSupabaseConfig();

  // If config is null, use local auth
  if (!config) {
    return createLocalAuthClient(cookieStore);
  }

  return createServerClient<Database>(config.supabaseUrl, config.supabaseKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) =>
            cookieStore.set(name, value, options)
          );
        } catch {
          // The `setAll` method was called from a Server Component.
          // This can be ignored if you have middleware refreshing
          // user sessions.
        }
      },
    },
    auth: {
      persistSession: true,
      autoRefreshToken: true,
    },
    global: {
      headers: {
        'X-Client-Info': 'apiforge',
      },
      // Increase timeout from default 60s to 60s for slower networks
      fetch: (url, options = {}) => {
        return fetch(url, {
          ...options,
          signal: AbortSignal.timeout(60000), // 60 seconds
        });
      },
    },
  });
};

// Use the same implementation for all server-side contexts
export const createSupabaseRouteClient = createClient;
export const createSupabaseServerActionClient = createClient;
export const createSupabaseServerComponentClient = createClient;

// Backwards compatible export for createClient
export { createClient };
