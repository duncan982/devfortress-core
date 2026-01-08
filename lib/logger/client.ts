import type { LogLevel, LoggerLike } from './types';

// CRITICAL FIX: Do NOT use process.env at module level - it causes
// "process is not defined" errors in the browser.
// Instead, resolve the endpoint lazily inside the function.
const getLogEndpoint = (): string => {
  // In browser, check for globally injected config first
  if (typeof window !== 'undefined') {
    const win = window as typeof window & {
      __LOG_ENDPOINT__?: string;
    };
    if (win.__LOG_ENDPOINT__) {
      return win.__LOG_ENDPOINT__;
    }
  }
  // Default fallback - relative URL works in both environments
  return '/api/system/logs';
};

const resolveLogEndpoint = (): string | null => {
  const LOG_ENDPOINT = getLogEndpoint();
  if (
    LOG_ENDPOINT.startsWith('http://') ||
    LOG_ENDPOINT.startsWith('https://')
  ) {
    return LOG_ENDPOINT;
  }

  if (typeof window === 'undefined') {
    return null;
  }

  const origin = window.location?.origin;
  if (!origin) {
    return null;
  }

  return LOG_ENDPOINT.startsWith('/')
    ? `${origin}${LOG_ENDPOINT}`
    : `${origin}/${LOG_ENDPOINT}`;
};

type LogPayload = {
  level: LogLevel;
  message: string;
  data?: unknown;
  runtime: 'browser';
  timestamp: string;
};

const hasSupabaseSession = (): boolean => {
  if (typeof document === 'undefined') {
    return false;
  }

  // Supabase auth cookies follow the pattern sb-<project-ref>-auth-token
  return /sb-[^=]+-auth-token=/.test(document.cookie);
};

const enqueueLog = (level: LogLevel, message: string, data?: unknown) => {
  if (typeof window === 'undefined') {
    return;
  }

  const endpoint = resolveLogEndpoint();
  if (!endpoint) {
    return;
  }

  // Avoid spamming unauthenticated users with 401s when no session cookie exists
  if (!hasSupabaseSession() && endpoint.endsWith('/api/system/logs')) {
    return;
  }

  const payload: LogPayload = {
    level,
    message,
    data,
    runtime: 'browser',
    timestamp: new Date().toISOString(),
  };

  try {
    const body = JSON.stringify(payload);
    if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
      const blob = new Blob([body], { type: 'application/json' });
      navigator.sendBeacon(endpoint, blob);
      return;
    }

    void fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body,
      keepalive: true,
      credentials: 'include',
    });
  } catch {
    // Ignore client logging errors to avoid cascading failures
  }
};

const createClientLogger = (): LoggerLike => ({
  error: (message, data) => enqueueLog('error', message, data),
  warn: (message, data) => enqueueLog('warn', message, data),
  info: (message, data) => enqueueLog('info', message, data),
  debug: (message, data) => enqueueLog('debug', message, data),
  http: (message, data) => enqueueLog('http', message, data),
});

const logger = createClientLogger();

export default logger;

export const logError = (message: string, data?: unknown) =>
  logger.error(message, data);
export const logWarn = (message: string, data?: unknown) =>
  logger.warn(message, data);
export const logInfo = (message: string, data?: unknown) =>
  logger.info(message, data);
export const logDebug = (message: string, data?: unknown) =>
  logger.debug(message, data);
export const logHttp = (message: string, data?: unknown) =>
  logger.http(message, data);
