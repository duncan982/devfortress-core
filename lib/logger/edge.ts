/**
 * Edge Runtime Logger
 *
 * Provides logging for Edge Functions and Middleware.
 * Edge runtime requires absolute URLs for fetch requests.
 *
 * Configuration:
 * Set one of these environment variables to enable logging:
 * - LOG_ENDPOINT or NEXT_PUBLIC_LOG_ENDPOINT (absolute URL preferred)
 * - NEXT_PUBLIC_APP_URL (used to construct absolute URL)
 * - NEXTAUTH_URL (fallback)
 * - VERCEL_URL (auto-set on Vercel)
 *
 * Example: LOG_ENDPOINT=http://localhost:3000/api/system/logs
 *
 * If no valid absolute URL can be resolved, logging is silently disabled.
 */

import type { LogLevel, LoggerLike } from './types';

const DEFAULT_LOG_PATH = '/api/system/logs';

const isAbsoluteUrl = (value: string): boolean =>
  /^https?:\/\//i.test(value.trim());

const normalizeBaseUrl = (value: string): string | null => {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  if (isAbsoluteUrl(trimmed)) {
    return trimmed;
  }

  try {
    return `https://${trimmed.replace(/^https?:\/\//, '')}`;
  } catch {
    return null;
  }
};

const toAbsoluteUrl = (base: string, path: string): string | null => {
  try {
    const baseUrl = normalizeBaseUrl(base);
    if (!baseUrl) {
      return null;
    }

    const trimmedPath = path.trim();
    if (!trimmedPath) {
      return null;
    }

    if (isAbsoluteUrl(trimmedPath)) {
      return trimmedPath;
    }

    return new URL(trimmedPath, baseUrl).toString();
  } catch {
    return null;
  }
};

const resolveBaseUrl = (): string | null => {
  if (typeof process === 'undefined') {
    return null;
  }

  const candidates = [
    process.env.NEXT_PUBLIC_APP_URL,
    process.env.NEXTAUTH_URL,
    process.env.APP_URL,
    process.env.VERCEL_URL
      ? `https://${process.env.VERCEL_URL.replace(/^https?:\/\//, '')}`
      : undefined,
  ].filter(Boolean) as string[];

  if (process.env.NODE_ENV !== 'production') {
    candidates.push('http://localhost:3000');
  }

  for (const candidate of candidates) {
    const normalized = normalizeBaseUrl(candidate);
    if (normalized) {
      return normalized;
    }
  }

  return null;
};

const resolveEndpoint = () => {
  if (typeof process === 'undefined') {
    return null;
  }

  const explicitEndpoint =
    process.env.LOG_ENDPOINT ?? process.env.NEXT_PUBLIC_LOG_ENDPOINT ?? '';

  if (explicitEndpoint) {
    if (isAbsoluteUrl(explicitEndpoint)) {
      return explicitEndpoint.trim();
    }

    const baseForExplicit = resolveBaseUrl();
    if (baseForExplicit) {
      const explicitAbsolute = toAbsoluteUrl(baseForExplicit, explicitEndpoint);
      if (explicitAbsolute && isAbsoluteUrl(explicitAbsolute)) {
        return explicitAbsolute;
      }
    }
  }

  const baseUrl = resolveBaseUrl();
  if (!baseUrl) {
    return null;
  }

  const derivedEndpoint = toAbsoluteUrl(baseUrl, DEFAULT_LOG_PATH);
  if (derivedEndpoint && isAbsoluteUrl(derivedEndpoint)) {
    return derivedEndpoint;
  }

  return null;
};

const LOG_ENDPOINT = resolveEndpoint();

type LogPayload = {
  level: LogLevel;
  message: string;
  data?: unknown;
  runtime: 'edge';
  timestamp: string;
};

const resolveAuthHeader = () => {
  if (typeof process === 'undefined') {
    return null;
  }

  const token = process.env.LOG_INGESTION_TOKEN;
  if (!token) {
    return null;
  }

  return `Bearer ${token}`;
};

const AUTH_HEADER_VALUE = resolveAuthHeader();

const sendLog = (level: LogLevel, message: string, data?: unknown) => {
  // Check if we have a valid absolute URL endpoint
  if (!LOG_ENDPOINT || !isAbsoluteUrl(LOG_ENDPOINT)) {
    // Silently skip logging in edge runtime if endpoint is not properly configured
    // This prevents "malformed URL" errors in edge functions/middleware
    return;
  }

  const payload: LogPayload = {
    level,
    message,
    data,
    runtime: 'edge',
    timestamp: new Date().toISOString(),
  };

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (AUTH_HEADER_VALUE) {
      headers.Authorization = AUTH_HEADER_VALUE;
    }

    void fetch(LOG_ENDPOINT, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      cache: 'no-store',
    }).catch(() => {
      // Silently ignore fetch errors to prevent logging failures from breaking the app
    });
  } catch {
    // Avoid throwing from logging in edge runtime
  }
};

const logger: LoggerLike = {
  error: (message, data) => sendLog('error', message, data),
  warn: (message, data) => sendLog('warn', message, data),
  info: (message, data) => sendLog('info', message, data),
  debug: (message, data) => sendLog('debug', message, data),
  http: (message, data) => sendLog('http', message, data),
};

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
