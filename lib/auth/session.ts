import { cookies } from 'next/headers';
import type {
  Session as SupabaseSession,
  User as SupabaseUser,
  SupabaseClient,
} from '@supabase/supabase-js';
import { UserRole } from '@prisma/client';
import type { User } from '@prisma/client';
import { prisma } from '@core/lib/prisma';
import { logError, logWarn, logInfo } from '@core/lib/logger';
import {
  createSupabaseServerComponentClient,
  createSupabaseRouteClient,
} from '@core/lib/supabase/server';
import type { Database } from '@/types/supabase';
import { getLocalAuthService } from '@core/lib/auth/local-auth';

export interface AuthenticatedUser {
  id: string;
  email: string;
  name: string | null;
  role: UserRole;
  hasGitHubAccount: boolean;
  supabaseUserId: string;
}

export interface DevFortressSession {
  user: AuthenticatedUser;
  supabase: SupabaseSession;
}

const isDatabaseConfigured = Boolean(process.env.DATABASE_URL);
// Increased timeout for slower/unreliable network connections to Supabase
const SESSION_FETCH_TIMEOUT_MS = 60000; // Increased to 60s for slower networks
const SESSION_RETRY_COUNT = 3; // Reduced to 3 for faster failure
const SESSION_RETRY_DELAY_MS = 1000; // Increased from 500ms to 1s

// Connection health check for Supabase
export async function checkSupabaseConnection(): Promise<boolean> {
  // If using local auth, consider it "connected"
  if (process.env.USE_LOCAL_AUTH === 'true') {
    return true;
  }

  try {
    const supabase = await createSupabaseServerComponentClient();

    // Check if this is a Supabase client (has 'from' method)
    if (!('from' in supabase) || typeof supabase.from !== 'function') {
      // Local auth mode - consider connected
      return true;
    }

    // At this point, we know supabase is a Supabase client
    const supabaseClient = supabase as any;  
    const { error } = await supabaseClient
      .from('profiles')
      .select('id')
      .limit(1);
    // Even if there's an error (e.g., table doesn't exist), we know the connection works
    // We just care that we can reach Supabase, not that the query succeeds
    return !error || error.message !== 'fetch failed';
  } catch (error) {
    logWarn('Supabase connection check failed', {
      error: error instanceof Error ? error.message : String(error),
    });
    return false;
  }
}
const SUPABASE_COOKIE_HINTS = [
  'sb-',
  'supabase-auth-token',
  'supabase-session',
  'supabase-access-token',
  'sb-access-token',
  'sb-refresh-token',
];

class SessionTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SessionTimeoutError';
  }
}

const hasSupabaseAuthCookies = async (): Promise<boolean> => {
  try {
    const cookieJar = await cookies();
    const allCookies = cookieJar.getAll();
    return allCookies.some(({ name }) =>
      SUPABASE_COOKIE_HINTS.some(hint =>
        hint.endsWith('-') ? name.startsWith(hint) : name === hint
      )
    );
  } catch (error) {
    // cookies() is only available during a request lifecycle. If we're outside
    // of that context (e.g., scripts), fall back to true so we don't block
    // session creation in legitimate scenarios.
    logWarn('Unable to inspect cookies for session detection', {
      error: error instanceof Error ? error.message : String(error),
    });
    return true;
  }
};

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

const withTimeout = async <T>(
  promise: Promise<T>,
  timeoutMs: number
): Promise<T> => {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new SessionTimeoutError(
          `Session retrieval exceeded ${timeoutMs}ms timeout`
        )
      );
    }, timeoutMs);

    promise
      .then(result => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch(error => {
        clearTimeout(timer);
        reject(error);
      });
  });
};

const withRetry = async <T>(
  fn: () => Promise<T>,
  retries: number = SESSION_RETRY_COUNT,
  delayMs: number = SESSION_RETRY_DELAY_MS
): Promise<T> => {
  let lastError: Error | undefined;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      // Only retry on network-related errors (fetch failed, timeout, etc.)
      const errorWithCause = lastError as Error & { cause?: { code?: string } };
      const isRetryable =
        lastError.message.includes('fetch failed') ||
        lastError.message.includes('ETIMEDOUT') ||
        lastError.message.includes('ECONNRESET') ||
        errorWithCause.cause?.code === 'ETIMEDOUT' ||
        (errorWithCause.cause instanceof AggregateError &&
          (errorWithCause.cause as AggregateError & { code?: string }).code ===
            'ETIMEDOUT') ||
        lastError instanceof SessionTimeoutError;

      if (!isRetryable || attempt === retries) {
        throw lastError;
      }

      logWarn(`Session fetch attempt ${attempt + 1} failed, retrying...`, {
        error: lastError.message,
        retriesRemaining: retries - attempt,
      });

      await delay(delayMs * (attempt + 1)); // Exponential backoff
    }
  }
  throw lastError;
};

type SupabaseDatabaseClient = SupabaseClient<Database>;

type SupabaseUserMetadata = Record<string, unknown> & {
  prisma_user_id?: string;
  role?: UserRole;
};

const getMetadataString = (
  metadata: SupabaseUserMetadata | undefined,
  key: string
) => {
  const value = metadata?.[key];
  return typeof value === 'string' && value.trim() !== ''
    ? value.trim()
    : undefined;
};

async function resolvePrismaUser(
  supabaseUser: SupabaseUser,
  metadata?: SupabaseUserMetadata
): Promise<User | null> {
  if (!isDatabaseConfigured) {
    return null;
  }

  try {
    if (metadata?.prisma_user_id) {
      const user = await prisma.user.findUnique({
        where: { id: metadata.prisma_user_id },
      });
      if (user) {
        return user;
      }
    }

    if (supabaseUser.email) {
      const existingByEmail = await prisma.user.findUnique({
        where: { email: supabaseUser.email },
      });

      if (existingByEmail) {
        return existingByEmail;
      }

      const inferredName =
        getMetadataString(metadata, 'full_name') ??
        getMetadataString(metadata, 'name') ??
        supabaseUser.email ??
        null;

      const created = await prisma.user.create({
        data: {
          id: supabaseUser.id,
          email: supabaseUser.email,
          name: inferredName,
          role: UserRole.VIEWER,
        },
      });

      return created;
    }
  } catch (error) {
    logError('Failed to resolve Prisma user for Supabase session.', {
      error: error instanceof Error ? error.message : String(error),
      supabaseUserId: supabaseUser.id,
    });
  }

  return null;
}

async function hasGithubToken(
  supabase: SupabaseDatabaseClient,
  supabaseUserId: string
): Promise<boolean> {
  try {
    const { data, error } = await supabase
      .from('user_tokens')
      .select('github_token')
      .eq('user_id', supabaseUserId)
      .maybeSingle();

    if (error) {
      logWarn('Unable to read GitHub token from Supabase user_tokens.', {
        message: error.message,
        supabaseUserId,
      });
      return false;
    }

    // @ts-expect-error Incomplete Supabase types for user_tokens table
    return Boolean(data?.github_token);
  } catch (error) {
    logWarn('Unexpected error when checking GitHub token state.', {
      error: error instanceof Error ? error.message : String(error),
      supabaseUserId,
    });
    return false;
  }
}

async function buildSession(
  supabase: SupabaseDatabaseClient
): Promise<DevFortressSession | null> {
  try {
    // Rely on Supabase client's timeout and outer retry logic
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser();

    if (error) {
      logError('Failed to retrieve Supabase user.', {
        message: error.message,
      });
      return null;
    }

    if (!supabaseUser) {
      return null;
    }

    const metadata = (supabaseUser.user_metadata || {}) as SupabaseUserMetadata;

    const prismaUser = await resolvePrismaUser(supabaseUser, metadata);

    const role = prismaUser?.role ?? metadata?.role ?? UserRole.VIEWER;
    const userId =
      prismaUser?.id ?? metadata?.prisma_user_id ?? supabaseUser.id;
    const resolvedEmail =
      prismaUser?.email ?? supabaseUser.email ?? 'unknown@supabase.local';
    const resolvedName =
      prismaUser?.name ??
      getMetadataString(metadata, 'full_name') ??
      getMetadataString(metadata, 'name') ??
      supabaseUser.email ??
      null;

    const hasGitHubAccount = await hasGithubToken(supabase, supabaseUser.id);

    // For backward compatibility, we need to create a minimal session object
    // since the DevFortressSession interface expects a supabase session
    const mockSession = {
      access_token: '', // Not exposed for security
      refresh_token: '', // Not exposed for security
      expires_at: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      expires_in: 3600, // 1 hour in seconds
      token_type: 'bearer' as const,
      user: supabaseUser,
    };

    return {
      user: {
        id: userId,
        email: resolvedEmail,
        name: resolvedName,
        role,
        hasGitHubAccount,
        supabaseUserId: supabaseUser.id,
      },
      supabase: mockSession,
    };
  } catch (error) {
    if (error instanceof SessionTimeoutError) {
      logWarn('Supabase session fetch timed out', {
        timeoutMs: SESSION_FETCH_TIMEOUT_MS,
      });
    } else {
      logError('Error building session', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
    return null;
  }
}

export async function getServerSession(): Promise<DevFortressSession | null> {
  try {
    // Check Supabase connection health first
    const isConnected = await checkSupabaseConnection();
    const shouldUseLocal =
      !isConnected || process.env.USE_LOCAL_AUTH === 'true';

    // Check for local auth session cookie first
    const cookieJar = await cookies();
    const localSessionCookie = cookieJar.get('local-auth-session');
    if (localSessionCookie && shouldUseLocal) {
      try {
        const sessionData = JSON.parse(localSessionCookie.value);
        const localAuth = getLocalAuthService();
        const session = await localAuth.getSession(sessionData.access_token);

        if (session) {
          // Fetch or create user in Prisma
          let user = await prisma.user.findUnique({
            where: { email: session.user.email },
            include: { accounts: true },
          });

          if (!user) {
            // Create user in Prisma for local auth
            user = await prisma.user.create({
              data: {
                id: session.user.id,
                email: session.user.email,
                name: session.user.name,
                role: session.user.role,
              },
              include: { accounts: true },
            });
          }

          const githubAccount = user.accounts.find(
            acc => acc.provider === 'github'
          );

          return {
            user: {
              id: user.id,
              email: user.email!,
              name: user.name,
              role: user.role,
              hasGitHubAccount: Boolean(githubAccount),
              supabaseUserId: user.id, // Use local user ID
            },
            supabase: {
              access_token: session.access_token,
              refresh_token: session.refresh_token,
              expires_at: session.expires_at,
              expires_in: session.expires_at - Math.floor(Date.now() / 1000),
              token_type: session.token_type,
              user: {
                id: user.id,
                email: user.email,
              } as SupabaseUser,
            } as SupabaseSession,
          };
        }
      } catch (parseError) {
        logWarn('Failed to parse local auth session cookie', {
          error: parseError,
        });
      }
    }

    // Check for dev session cookie first (local development) - doesn't require Supabase
    const devSessionCookie = cookieJar.get('dev-session');
    if (devSessionCookie) {
      try {
        const devSession = JSON.parse(devSessionCookie.value);
        if (devSession.user && new Date(devSession.expires) > new Date()) {
          // Fetch full user data from Prisma
          const user = await prisma.user.findUnique({
            where: { id: devSession.user.id },
            include: { accounts: true },
          });
          if (user) {
            const githubAccount = user.accounts.find(
              acc => acc.provider === 'github'
            );
            const supabaseAccount = user.accounts.find(
              acc => acc.provider === 'supabase'
            );
            return {
              user: {
                id: user.id,
                email: user.email!,
                name: user.name,
                role: user.role,
                hasGitHubAccount: Boolean(githubAccount),
                supabaseUserId: supabaseAccount?.providerAccountId || user.id,
              },
              supabase: {
                user: {
                  id: supabaseAccount?.providerAccountId || user.id,
                  email: user.email,
                } as SupabaseUser,
              } as SupabaseSession,
            };
          }
        }
      } catch (parseError) {
        logWarn('Failed to parse dev session cookie', { error: parseError });
      }
    }

    if (!isConnected) {
      logWarn('Supabase connection check failed, no session available');
      return null;
    }

    if (!(await hasSupabaseAuthCookies())) {
      return null;
    }

    // Use retry logic with connection health check
    return await withRetry(async () => {
      const supabase = await createSupabaseServerComponentClient();

      // Check if this is a Supabase client
      if (
        !('auth' in supabase) ||
        !supabase.auth ||
        typeof supabase.auth.getUser !== 'function'
      ) {
        // Local auth mode - should have been handled above
        logWarn('Unexpected local auth client in Supabase session path');
        return null;
      }

      // At this point, we know supabase is a Supabase client
      const supabaseClient = supabase as any;  
      return await withTimeout(
        buildSession(supabaseClient),
        SESSION_FETCH_TIMEOUT_MS
      );
    });
  } catch (error) {
    if (error instanceof SessionTimeoutError) {
      logWarn(
        'Server session lookup timed out after retries, continuing without session',
        {
          timeoutMs: SESSION_FETCH_TIMEOUT_MS,
          retries: SESSION_RETRY_COUNT,
        }
      );
      return null;
    }
    // For network errors (fetch failed), log warning instead of error and continue
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (
      errorMessage.includes('fetch failed') ||
      errorMessage.includes('ETIMEDOUT') ||
      errorMessage.includes('ECONNREFUSED') ||
      errorMessage.includes('ENOTFOUND')
    ) {
      logWarn('Network error retrieving session, continuing without session', {
        error: errorMessage,
      });
      return null;
    }
    logError('Failed to create Supabase client for server session.', {
      error: errorMessage,
    });
    return null;
  }
}

export async function getRouteSession(): Promise<DevFortressSession | null> {
  try {
    // Use retry logic to handle intermittent network issues with Supabase
    const session = await withRetry(async () => {
      const supabase = await createSupabaseRouteClient();

      // Check if this is a Supabase client
      if (
        !('auth' in supabase) ||
        !supabase.auth ||
        typeof supabase.auth.getUser !== 'function'
      ) {
        // Local auth mode - return null as routes should use local auth session handling
        return null;
      }

      // At this point, we know supabase is a Supabase client
      const supabaseClient = supabase as any;  
      return await withTimeout(
        buildSession(supabaseClient),
        SESSION_FETCH_TIMEOUT_MS
      );
    });

    // Audit logging for access attempts
    if (session) {
      logInfo('Successful authentication', {
        userId: session.user.id,
        email: session.user.email,
        role: session.user.role,
        endpoint: 'unknown', // This would be populated by middleware
        ipAddress: 'unknown', // This would be populated by middleware
        userAgent: 'unknown', // This would be populated by middleware
      });
    } else {
      logWarn('Failed authentication attempt', {
        endpoint: 'unknown', // This would be populated by middleware
        ipAddress: 'unknown', // This would be populated by middleware
        userAgent: 'unknown', // This would be populated by middleware
        reason: 'No valid session found',
      });
    }

    return session;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    // For network/timeout errors, log warning and continue gracefully
    if (
      error instanceof SessionTimeoutError ||
      errorMessage.includes('fetch failed') ||
      errorMessage.includes('ETIMEDOUT')
    ) {
      logWarn(
        'Network error retrieving route session, continuing without session',
        {
          error: errorMessage,
        }
      );
      return null;
    }

    logError('Failed to create Supabase client for route session.', {
      error: errorMessage,
    });

    // Audit logging for failed authentication
    logWarn('Authentication error', {
      error: errorMessage,
      endpoint: 'unknown', // This would be populated by middleware
      ipAddress: 'unknown', // This would be populated by middleware
      userAgent: 'unknown', // This would be populated by middleware
    });

    return null;
  }
}

export async function requireServerSession(): Promise<DevFortressSession> {
  const session = await getServerSession();
  if (!session) {
    throw new Error('Authentication required');
  }
  return session;
}

export async function requireRouteSession(): Promise<DevFortressSession> {
  const session = await getRouteSession();
  if (!session) {
    throw new Error('Authentication required');
  }
  return session;
}
