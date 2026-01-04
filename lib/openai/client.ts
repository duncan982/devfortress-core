import OpenAI from 'openai';
import { env } from '@core/lib/env';
import { logError, logInfo } from '@core/lib/logger';
import { getApiKey, markApiKeyInvalid, ApiKeyType } from '@core/lib/security/api-key-manager';

let cachedClient: OpenAI | null = null;

export const getOpenAIClient = (): OpenAI => {
  if (!env.OPENAI_API_KEY) {
    throw new Error('OpenAI API key is not configured');
  }

  if (!cachedClient) {
    cachedClient = new OpenAI({ apiKey: env.OPENAI_API_KEY });
  }

  return cachedClient;
};

/**
 * Gets an OpenAI client using the user's own API key (for free tier self-hosting).
 * Falls back to system key if user has an active subscription.
 *
 * @param userId - The user's ID
 * @param hasSubscription - Whether the user has an active paid subscription
 * @returns OpenAI client instance
 * @throws Error if no API key is available
 */
export const getOpenAIClientForUser = async (
  userId: string,
  hasSubscription: boolean = false
): Promise<OpenAI> => {
  // If user has a subscription, use system key
  if (hasSubscription && env.OPENAI_API_KEY) {
    logInfo('Using system OpenAI key for subscribed user', { userId });
    return getOpenAIClient();
  }

  // Try to get user's own API key
  const userApiKey = await getApiKey(userId, ApiKeyType.OPENAI);

  if (userApiKey) {
    logInfo('Using user-provided OpenAI key', { userId });
    return new OpenAI({ apiKey: userApiKey });
  }

  // Fallback to system key if available
  if (env.OPENAI_API_KEY) {
    logInfo('No user API key found, using system key', { userId });
    return getOpenAIClient();
  }

  throw new Error(
    'No OpenAI API key available. Please add your API key in Settings → API Keys, or upgrade to a paid plan.'
  );
};

/**
 * Handles OpenAI API errors and marks user keys as invalid if necessary.
 *
 * @param error - The error from OpenAI API
 * @param userId - The user's ID
 * @param usedUserKey - Whether a user-provided key was used
 */
export const handleOpenAIError = async (
  error: unknown,
  userId?: string,
  usedUserKey?: boolean
): Promise<void> => {
  if (error instanceof OpenAI.APIError) {
    // Authentication errors (401) indicate invalid API key
    if (error.status === 401 && userId && usedUserKey) {
      await markApiKeyInvalid(userId, ApiKeyType.OPENAI);
      logError('User OpenAI API key marked as invalid', {
        userId,
        errorCode: error.code,
      });
    }
  }
};

export const ensureOpenAIAvailability = () => {
  if (!env.OPENAI_API_KEY) {
    logError('OpenAI API key missing when attempting to use api-generator');
    throw new Error('OpenAI configuration missing');
  }
};
