import { createBrowserClient } from '@supabase/ssr';
import { getEnv } from '@core/lib/env';
import type { Database } from '@/types/supabase';
import * as retry from 'retry';
import CircuitBreaker from 'opossum';
import {
  createLocalAuthClient,
  shouldUseLocalAuth,
} from '@core/lib/auth/local-auth';

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
    operation.attempt(async _currentAttempt => {
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

// Circuit breaker for Supabase operations
const breaker = new CircuitBreaker(async (fn: () => Promise<unknown>) => fn(), {
  timeout: 3000,
  errorThresholdPercentage: 50,
  resetTimeout: 30000,
});

export const safeSupabaseCall = breaker.fire.bind(breaker);

export const createSupabaseClientComponentClient = async () => {
  const env = getEnv();
  // Access environment variables directly at runtime
  // Next.js will inline NEXT_PUBLIC_* variables at build time
  const url = env.NEXT_PUBLIC_SUPABASE_URL;
  const key = env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  // Override auth with local auth if needed
  if (await shouldUseLocalAuth()) {
    const client = createBrowserClient<Database>(url, key, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true, // Enable session detection from URL
      },
      global: {
        headers: {
          'X-Client-Info': 'apiforge',
        },
        // Increase timeout and add retry logic for better reliability
        fetch: async (url, options = {}) => {
          const maxRetries = 3;
          let lastError: Error | null = null;

          for (let attempt = 0; attempt < maxRetries; attempt++) {
            try {
              const controller = new AbortController();
              const timeoutId = setTimeout(() => controller.abort(), 60000); // 60 seconds

              const response = await fetch(url, {
                ...options,
                signal: controller.signal,
              });

              clearTimeout(timeoutId);
              return response;
            } catch (error) {
              lastError = error as Error;

              // Don't retry on abort or certain client errors
              if (
                error instanceof Error &&
                (error.name === 'AbortError' ||
                  error.message.includes('NetworkError') ||
                  error.message.includes('Failed to fetch'))
              ) {
                // Wait before retry (exponential backoff)
                if (attempt < maxRetries - 1) {
                  await new Promise(resolve =>
                    setTimeout(resolve, Math.pow(2, attempt) * 1000)
                  );
                  continue;
                }
              }

              // For other errors, fail immediately
              throw error;
            }
          }

          throw lastError || new Error('Max retries exceeded');
        },
      },
    });
    (client as { auth: unknown }).auth = createLocalAuthClient();
    return client;
  }

  return createBrowserClient<Database>(url, key, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true, // Enable session detection from URL
    },
    global: {
      headers: {
        'X-Client-Info': 'apiforge',
      },
      // Increase timeout and add retry logic for better reliability
      fetch: async (url, options = {}) => {
        const maxRetries = 3;
        let lastError: Error | null = null;

        for (let attempt = 0; attempt < maxRetries; attempt++) {
          try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 60000); // 60 seconds

            const response = await fetch(url, {
              ...options,
              signal: controller.signal,
            });

            clearTimeout(timeoutId);
            return response;
          } catch (error) {
            lastError = error as Error;

            // Don't retry on abort or certain client errors
            if (
              error instanceof Error &&
              (error.name === 'AbortError' ||
                error.message.includes('NetworkError') ||
                error.message.includes('Failed to fetch'))
            ) {
              // Wait before retry (exponential backoff)
              if (attempt < maxRetries - 1) {
                await new Promise(resolve =>
                  setTimeout(resolve, Math.pow(2, attempt) * 1000)
                );
                continue;
              }
            }

            // For other errors, fail immediately
            throw error;
          }
        }

        throw lastError || new Error('Max retries exceeded');
      },
    },
  });
};
