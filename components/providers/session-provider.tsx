'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import type {
  AuthChangeEvent,
  Session,
  SupabaseClient,
} from '@supabase/supabase-js';
import { useRouter } from 'next/navigation';
import { createSupabaseClientComponentClient } from '@core/lib/supabase/client';
import {
  createLocalAuthClient,
  shouldUseLocalAuth,
} from '@core/lib/auth/local-auth';
import type { DevFortressSession } from '@core/lib/auth/session';
import { logInfo, logWarn, logError } from '@core/lib/logger/client';
import { UserRole } from '@prisma/client';

interface SessionProviderProps {
  children: React.ReactNode;
  session: DevFortressSession | null;
}

type SessionStatus = 'loading' | 'authenticated' | 'unauthenticated';

interface SessionContextValue {
  session: DevFortressSession | null;
  status: SessionStatus;
  isInitialized: boolean;
  signOut: (options?: { redirectTo?: string }) => Promise<void>;
}

const SessionContext = createContext<SessionContextValue | undefined>(
  undefined
);

export function SessionProvider({ children, session }: SessionProviderProps) {
  const router = useRouter();
  const [supabase, setSupabase] = useState<SupabaseClient | null>(null);
  const authClient = useMemo(() => createLocalAuthClient(), []);
  const [useLocalAuth, setUseLocalAuth] = useState<boolean | null>(null);

  // Determine auth mode asynchronously
  useEffect(() => {
    shouldUseLocalAuth()
      .then(setUseLocalAuth)
      .catch(() => setUseLocalAuth(true));
  }, []);

  // Create Supabase client once we know the auth mode
  useEffect(() => {
    if (useLocalAuth !== null) {
      createSupabaseClientComponentClient().then((client) => {
        setSupabase(client as unknown as SupabaseClient);
      });
    }
  }, [useLocalAuth]);
  const [currentSession, setCurrentSession] =
    useState<DevFortressSession | null>(session);
  const [status, setStatus] = useState<SessionStatus>(
    session ? 'authenticated' : 'loading'
  );
  const [isInitialized, setIsInitialized] = useState(false);

  // Listen for auth state changes
  useEffect(() => {
    // Don't initialize until we know which auth mode to use and supabase is ready
    if (useLocalAuth === null || (!useLocalAuth && !supabase)) return;

    let mounted = true;
    const timeoutId = setTimeout(() => {
      if (mounted && !isInitialized) {
        logWarn('Auth initialization timeout - forcing completion', {
          timeoutMs: 10000,
          useLocalAuth,
          hasExistingSession: !!session,
          currentStatus: status,
        });
        // Don't force unauthenticated if we have a server session - keep current status
        // This prevents showing signin button when user is actually logged in
        if (!session) {
          setStatus('unauthenticated');
        }
        setIsInitialized(true);
        clearTimeout(timeoutId);
      }
    }, 10000); // Increased to 10 seconds for development

    // Explicitly get current session on mount to handle existing sessions
    const initializeAuth = async () => {
      try {
        logInfo('Starting auth initialization', {
          useLocalAuth,
          hasServerSession: !!session,
        });
        if (useLocalAuth && !supabase) {
          // Wait for supabase to be initialized
          return;
        }
        const {
          data: { session: currentSession },
          error,
        } = await (useLocalAuth ? authClient : supabase!.auth).getSession();

        if (error) {
          logWarn('Error getting current session during initialization', {
            error: error.message,
            useLocalAuth,
            code: error.status,
          });
        }

        if (currentSession && mounted) {
          logInfo('Found existing session on initialization', {
            userId: currentSession.user.id,
            email: currentSession.user.email,
            useLocalAuth,
          });
          const vortexSession: DevFortressSession = {
            user: {
              id: currentSession.user.id,
              email: currentSession.user.email || 'unknown@supabase.local',
              name:
                currentSession.user.user_metadata?.full_name ||
                currentSession.user.user_metadata?.name ||
                currentSession.user.email ||
                null,
              role:
                (currentSession.user.user_metadata?.role as UserRole) ||
                UserRole.VIEWER,
              hasGitHubAccount: false, // Will be resolved later if needed
              supabaseUserId: currentSession.user.id,
            },
            supabase: currentSession,
          };
          setCurrentSession(vortexSession);
          setStatus('authenticated');
          setIsInitialized(true);
          clearTimeout(timeoutId);
          logInfo('Auth initialization completed successfully', {
            userId: currentSession.user.id,
          });
        } else if (session && mounted) {
          // Fall back to server session if client-side getSession fails
          logInfo('Using server session as fallback', {
            userId: session.user.id,
            email: session.user.email,
            useLocalAuth,
          });
          setCurrentSession(session);
          setStatus('authenticated');
          setIsInitialized(true);
          clearTimeout(timeoutId);
          logInfo(
            'Auth initialization completed with server session fallback',
            { userId: session.user.id }
          );
        } else {
          logInfo('No existing session found during initialization', {
            useLocalAuth,
          });
        }
      } catch (error) {
        logError('Failed to initialize auth session', {
          error: error instanceof Error ? error.message : String(error),
          useLocalAuth,
        });
      }
    };

    initializeAuth();

    const {
      data: { subscription },
    } = (useLocalAuth ? authClient : supabase!.auth).onAuthStateChange(
      async (event: AuthChangeEvent, session: Session | null) => {
        if (!mounted) return;

        logInfo('Auth state change', {
          event,
          hasSession: !!session,
          currentPath:
            typeof window !== 'undefined'
              ? window.location.pathname
              : 'unknown',
          useLocalAuth,
          userId: session?.user?.id,
          isInitialized,
        });

        // Handle different auth events
        if (event === 'SIGNED_IN' && session) {
          logInfo('Processing SIGNED_IN event', { userId: session.user.id });
          const vortexSession: DevFortressSession = {
            user: {
              id: session.user.id,
              email: session.user.email || 'unknown@supabase.local',
              name:
                session.user.user_metadata?.full_name ||
                session.user.user_metadata?.name ||
                session.user.email ||
                null,
              role:
                (session.user.user_metadata?.role as UserRole) ||
                UserRole.VIEWER,
              hasGitHubAccount: false, // Will be resolved later if needed
              supabaseUserId: session.user.id,
            },
            supabase: session,
          };

          setCurrentSession(vortexSession);
          setStatus('authenticated');
          setIsInitialized(true);
          clearTimeout(timeoutId);
        } else if (event === 'TOKEN_REFRESHED' && session) {
          // Silent token refresh - update session without redirect
          logInfo('Processing TOKEN_REFRESHED event', {
            userId: session.user.id,
          });
          const vortexSession: DevFortressSession = {
            user: {
              id: session.user.id,
              email: session.user.email || 'unknown@supabase.local',
              name:
                session.user.user_metadata?.full_name ||
                session.user.user_metadata?.name ||
                session.user.email ||
                null,
              role:
                (session.user.user_metadata?.role as UserRole) ||
                UserRole.VIEWER,
              hasGitHubAccount: false,
              supabaseUserId: session.user.id,
            },
            supabase: session,
          };

          setCurrentSession(vortexSession);
          setStatus('authenticated');
          setIsInitialized(true);
          clearTimeout(timeoutId);
        } else if (event === 'SIGNED_OUT' || !session) {
          logInfo('Processing sign out or no session event', {
            event,
            hasSession: !!session,
          });
          setCurrentSession(null);
          setStatus('unauthenticated');
          setIsInitialized(true);
          clearTimeout(timeoutId);
        } else {
          // Handle other events or initial load
          logInfo('Processing other auth event', {
            event,
            hasSession: !!session,
          });
          setStatus(session ? 'authenticated' : 'unauthenticated');
          setIsInitialized(true);
          clearTimeout(timeoutId);
        }
      }
    );

    return () => {
      mounted = false;
      clearTimeout(timeoutId);
      subscription.unsubscribe();
    };
  }, [supabase, authClient, router, useLocalAuth]); // eslint-disable-line react-hooks/exhaustive-deps

  const signOut = useCallback(
    async (options?: { redirectTo?: string }) => {
      if (useLocalAuth) {
        await authClient.signOut();
      } else if (supabase) {
        await supabase.auth.signOut();
      }
      setCurrentSession(null);
      router.push(options?.redirectTo ?? '/auth/signin');
    },
    [authClient, router, supabase, useLocalAuth]
  );

  const value = useMemo<SessionContextValue>(
    () => ({
      session: currentSession,
      status,
      isInitialized,
      signOut,
    }),
    [currentSession, signOut, status, isInitialized]
  );

  return (
    <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
  );
}

export function useAuthSession() {
  const context = useContext(SessionContext);
  if (!context) {
    throw new Error('useAuthSession must be used within a SessionProvider');
  }
  return context;
}
