import type { Session, User, AuthChangeEvent } from '@supabase/supabase-js';
import { UserRole } from '@prisma/client';
import { logWarn } from '@core/lib/logger/client';

// Local auth session stored in localStorage
interface LocalAuthSession {
  access_token: string;
  refresh_token: string;
  expires_at: number;
  expires_in: number;
  token_type: string;
  user: {
    id: string;
    email: string;
    user_metadata?: {
      name?: string;
      full_name?: string;
      role?: UserRole;
    };
  };
}

// Local auth client that mimics Supabase auth API
class LocalAuthClient {
  private listeners: Array<
    (event: AuthChangeEvent, session: Session | null) => void
  > = [];
  private currentSession: LocalAuthSession | null = null;
  private initialized = false;

  constructor() {
    this.initialize();
  }

  private initialize() {
    if (typeof window === 'undefined') return;

    // Load session from localStorage
    const stored = localStorage.getItem('local-auth-session');
    if (stored) {
      try {
        const session = JSON.parse(stored) as LocalAuthSession;
        if (session.expires_at * 1000 > Date.now()) {
          this.currentSession = session;
        } else {
          localStorage.removeItem('local-auth-session');
        }
      } catch {
        localStorage.removeItem('local-auth-session');
      }
    }
    this.initialized = true;
    this.notifyListeners(
      'INITIAL_SESSION',
      this.currentSession ? this.toSupabaseSession(this.currentSession) : null
    );
  }

  private toSupabaseSession(localSession: LocalAuthSession): Session {
    return {
      access_token: localSession.access_token,
      refresh_token: localSession.refresh_token,
      expires_at: localSession.expires_at,
      expires_in: localSession.expires_in,
      token_type: 'bearer',
      user: {
        id: localSession.user.id,
        email: localSession.user.email,
        user_metadata: localSession.user.user_metadata || {},
      } as User,
    };
  }

  private notifyListeners(event: AuthChangeEvent, session: Session | null) {
    this.listeners.forEach(listener => {
      try {
        listener(event, session);
      } catch {
        // Ignore listener errors
      }
    });
  }

  // Auth methods
  async signInWithPassword(credentials: { email: string; password: string }) {
    // For local auth, accept any email/password combination for demo
    // In real implementation, this would validate against local database
    const userId = `local-${Date.now()}`;
    const session: LocalAuthSession = {
      access_token: `local-token-${userId}`,
      refresh_token: `local-refresh-${userId}`,
      expires_at: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      expires_in: 3600,
      token_type: 'bearer',
      user: {
        id: userId,
        email: credentials.email,
        user_metadata: {
          name: credentials.email.split('@')[0],
          full_name: credentials.email.split('@')[0],
          role: UserRole.OWNER,
        },
      },
    };

    this.currentSession = session;
    localStorage.setItem('local-auth-session', JSON.stringify(session));
    this.notifyListeners('SIGNED_IN', this.toSupabaseSession(session));

    return {
      data: {
        user: session.user as User,
        session: this.toSupabaseSession(session),
      },
      error: null,
    };
  }

  async signUp(credentials: {
    email: string;
    password: string;
    options?: { emailRedirectTo?: string };
  }) {
    // Same as sign in for local auth
    return this.signInWithPassword(credentials);
  }

  async signInWithOAuth(options: {
    provider: string;
    options?: { redirectTo?: string };
  }) {
    // For local auth, simulate OAuth success
    const userId = `oauth-${options.provider}-${Date.now()}`;
    const session: LocalAuthSession = {
      access_token: `oauth-token-${userId}`,
      refresh_token: `oauth-refresh-${userId}`,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      expires_in: 3600,
      token_type: 'bearer',
      user: {
        id: userId,
        email: `oauth-${options.provider}@local.dev`,
        user_metadata: {
          name: `OAuth ${options.provider}`,
          full_name: `OAuth ${options.provider} User`,
          role: UserRole.OWNER,
        },
      },
    };

    this.currentSession = session;
    localStorage.setItem('local-auth-session', JSON.stringify(session));
    this.notifyListeners('SIGNED_IN', this.toSupabaseSession(session));

    return {
      data: {
        user: session.user as User,
        session: this.toSupabaseSession(session),
      },
      error: null,
    };
  }

  async signOut() {
    this.currentSession = null;
    localStorage.removeItem('local-auth-session');
    this.notifyListeners('SIGNED_OUT', null);
    return { error: null };
  }

  async getSession() {
    if (!this.initialized) {
      this.initialize();
    }
    return {
      data: {
        session: this.currentSession
          ? this.toSupabaseSession(this.currentSession)
          : null,
      },
      error: null,
    };
  }

  async getUser() {
    if (!this.initialized) {
      this.initialize();
    }
    return {
      data: {
        user: this.currentSession ? (this.currentSession.user as User) : null,
      },
      error: null,
    };
  }

  async updateUser(_updates: { password?: string }) {
    if (!this.currentSession) {
      return { data: { user: null }, error: { message: 'No user logged in' } };
    }

    // For local auth, just update the session
    this.notifyListeners(
      'USER_UPDATED',
      this.toSupabaseSession(this.currentSession)
    );
    return { data: { user: this.currentSession.user as User }, error: null };
  }

  async resetPasswordForEmail(
    _email: string,
    _options?: { redirectTo?: string }
  ) {
    // For local auth, simulate success
    return { error: null };
  }

  async exchangeCodeForSession(_code: string) {
    // Local auth doesn't support OAuth, return error
    return {
      data: { session: null },
      error: { message: 'OAuth not supported in local auth' },
    };
  }

  // MFA methods (simplified)
  mfa = {
    async listFactors() {
      return { data: { factors: [] }, error: null };
    },
    async challenge(_options: { factorId: string }) {
      return { data: { challenge: { id: 'local-challenge' } }, error: null };
    },
    async verify(_options: { factorId: string; code: string }) {
      return { error: null };
    },
  };

  onAuthStateChange(
    callback: (event: AuthChangeEvent, session: Session | null) => void
  ) {
    this.listeners.push(callback);

    // Return unsubscribe function in Supabase format
    return {
      data: {
        subscription: {
          unsubscribe: () => {
            const index = this.listeners.indexOf(callback);
            if (index > -1) {
              this.listeners.splice(index, 1);
            }
          },
        },
      },
    };
  }
}

// Create a singleton local auth client
let localAuthClient: LocalAuthClient | null = null;

export const createLocalAuthClient = (): LocalAuthClient => {
  if (!localAuthClient) {
    localAuthClient = new LocalAuthClient();
  }
  return localAuthClient;
};

// For testing: create a new instance
export const createLocalAuthClientForTesting = (): LocalAuthClient => {
  return new LocalAuthClient();
};

// Helper to safely get env vars - NEXT_PUBLIC_* are inlined at build time by Next.js
// For client-side code, we MUST use direct access to process.env.NEXT_PUBLIC_*
// because Next.js replaces these at build time, not runtime
const getSupabaseConfig = (): { url?: string; key?: string } => {
  // CRITICAL: Next.js inlines NEXT_PUBLIC_* at build time
  // We must use direct string access, NOT dynamic property access
  // Dynamic access like process.env[varName] will NOT work on client

  // These will be replaced with actual values at build time by Next.js
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  return { url, key };
};

// Check if we should use local auth
export const shouldUseLocalAuth = async (): Promise<boolean> => {
  const { url: supabaseUrl, key: supabaseKey } = getSupabaseConfig();

  // Use local auth if Supabase is not configured or is using placeholder values
  if (
    !supabaseUrl ||
    !supabaseKey ||
    supabaseUrl.includes('placeholder') ||
    supabaseKey.includes('placeholder')
  ) {
    return true;
  }

  // Check runtime connectivity to Supabase
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 second timeout

    await fetch(`${supabaseUrl}/rest/v1/`, {
      method: 'HEAD',
      signal: controller.signal,
      headers: {
        apikey: supabaseKey,
        Authorization: `Bearer ${supabaseKey}`,
      },
    });

    clearTimeout(timeoutId);

    // Supabase is reachable, use Supabase auth
    return false;
  } catch (error) {
    // Network error, DNS failure, timeout, etc. - use local auth
    logWarn('Supabase connectivity check failed, falling back to local auth', {
      error: error instanceof Error ? error.message : String(error),
    });
    return true;
  }
};

// Create auth client that falls back to local auth
export const createAuthClient = async () => {
  if (await shouldUseLocalAuth()) {
    return createLocalAuthClient();
  }

  // Return a mock that throws errors for unavailable methods
  return {
    signInWithPassword: () =>
      Promise.reject(new Error('Supabase auth not available')),
    signUp: () => Promise.reject(new Error('Supabase auth not available')),
    signInWithOAuth: () =>
      Promise.reject(new Error('Supabase auth not available')),
    signOut: () => Promise.reject(new Error('Supabase auth not available')),
    getSession: () => Promise.reject(new Error('Supabase auth not available')),
    getUser: () => Promise.reject(new Error('Supabase auth not available')),
    updateUser: () => Promise.reject(new Error('Supabase auth not available')),
    resetPasswordForEmail: () =>
      Promise.reject(new Error('Supabase auth not available')),
    mfa: {
      listFactors: () =>
        Promise.reject(new Error('Supabase auth not available')),
      challenge: () => Promise.reject(new Error('Supabase auth not available')),
      verify: () => Promise.reject(new Error('Supabase auth not available')),
    },
    onAuthStateChange: () => ({
      data: {
        subscription: {
          unsubscribe: () => {},
        },
      },
    }),
  };
};

// Export a mock local auth service for server-side use
export const getLocalAuthService = () => {
  return {
    signInWithPassword: async (email: string, _password: string) => {
      // For server-side, just return a mock response
      // The actual auth logic is handled by the client-side LocalAuthClient
      return {
        user: {
          id: 'local-user',
          email,
          name: email.split('@')[0],
          role: 'DEVELOPER' as const,
          passwordHash: '',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        session: {
          user: {
            id: 'local-user',
            email,
            name: email.split('@')[0],
            role: 'DEVELOPER' as const,
          },
          access_token: 'local-token',
          refresh_token: 'local-refresh',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          token_type: 'bearer',
        },
        error: null,
      };
    },
    getSession: async (token: string) => {
      // Mock session retrieval
      return {
        user: {
          id: 'local-user',
          email: 'local@example.com',
          name: 'Local User',
          role: 'DEVELOPER' as const,
        },
        access_token: token,
        refresh_token: 'local-refresh',
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        token_type: 'bearer',
      };
    },
    signOut: async () => {},
  };
};
