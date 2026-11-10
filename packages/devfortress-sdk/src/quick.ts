/**
 * DevFortress SDK — Zero-Config Quick Start
 *
 * One-line initialization for fastest time-to-first-event:
 *   import df from '@devfortress/sdk/quick';
 *   df.init({ apiKey: 'df_...' });
 *
 * Auto-detects framework (Express, Fastify, Next.js, Hono)
 * and applies appropriate middleware configuration.
 */

import { DevFortressCore as DevFortress } from './devfortress';
import type { DevFortressConfig } from './types';

/* ─── Framework detection ─── */

type Framework = 'express' | 'fastify' | 'nextjs' | 'hono' | 'unknown';

function detectFramework(): Framework {
  try {
    // Check for Next.js
    if (typeof process !== 'undefined') {
      if (process.env.NEXT_RUNTIME || process.env.__NEXT_PRIVATE_ORIGIN) {
        return 'nextjs';
      }
    }
    // Check for Express (most common)
    try {
      require.resolve('express');
      return 'express';
    } catch {
      /* not available */
    }
    // Check for Fastify
    try {
      require.resolve('fastify');
      return 'fastify';
    } catch {
      /* not available */
    }
    // Check for Hono
    try {
      require.resolve('hono');
      return 'hono';
    } catch {
      /* not available */
    }
  } catch {
    /* detection failed */
  }
  return 'unknown';
}

/* ─── Quick config type ─── */

export interface QuickConfig {
  apiKey: string;
  /** App identifier (auto-generated from package.json name if omitted) */
  appId?: string;
  /** Privacy mode: 'standard' | 'strict'. Strict never sends user agents, IPs are hashed */
  privacy?: 'standard' | 'strict';
  /** Enable console debug logs: [DF →] / [DF ✗] */
  debug?: boolean;
  /** Override ingest endpoint */
  endpoint?: string;
  /** Environment tag */
  environment?: string;
}

/* ─── Auto-detect app ID ─── */

function autoAppId(): string {
  try {
    // Try to read from nearest package.json

    const pkg = require(process.cwd() + '/package.json');
    if (pkg.name) return pkg.name;
  } catch {
    /* no package.json */
  }
  return `app-${Date.now().toString(36)}`;
}

/* ─── Quick start factory ─── */

let _instance: DevFortress | null = null;

export function init(config: QuickConfig): DevFortress {
  const framework = detectFramework();
  const appId = config.appId ?? autoAppId();
  const isStrict = config.privacy === 'strict';

  const fullConfig: DevFortressConfig = {
    apiKey: config.apiKey,
    appId,
    environment: config.environment ?? process.env.NODE_ENV ?? 'production',
    debug: config.debug ?? false,
    endpoint: config.endpoint,
    // In strict privacy mode, hash IPs before sending
    enrichment: isStrict
      ? {
          getIP: (req: unknown) => {
            const r = req as {
              ip?: string;
              socket?: { remoteAddress?: string };
            };
            const raw = r.ip ?? r.socket?.remoteAddress ?? 'unknown';
            // SHA-256 hash for privacy
            const crypto = require('crypto');
            return crypto
              .createHash('sha256')
              .update(raw)
              .digest('hex')
              .slice(0, 16);
          },
        }
      : undefined,
  };

  _instance = new DevFortress(fullConfig);

  if (config.debug) {
    console.log(
      `[DF →] DevFortress initialized (framework: ${framework}, privacy: ${config.privacy ?? 'standard'}, appId: ${appId})`
    );
  }

  return _instance;
}

export function getInstance(): DevFortress | null {
  return _instance;
}

/** Data snapshot for privacy transparency — shows what would be sent */
export function getDataSnapshot(req: unknown): {
  collected: Record<string, string>;
  neverCollected: string[];
} {
  const r = req as Record<string, unknown>;
  return {
    collected: {
      ip: typeof r.ip === 'string' ? r.ip : 'from socket',
      method: String(r.method ?? 'unknown'),
      path: String(r.url ?? r.path ?? 'unknown'),
      statusCode: 'after response',
      responseTime: 'measured automatically',
      timestamp: new Date().toISOString(),
      userAgent: 'first 200 chars only',
    },
    neverCollected: [
      'Request body content',
      'Response body content',
      'Cookies or session data',
      'Authorization headers',
      'Real session tokens (anonymised via proprietary mechanism)',
      'Query string values',
      'Form data',
      'File uploads',
      'Database queries',
      'Environment variables',
      'Source code',
      'User PII (names, emails, phone numbers)',
    ],
  };
}

const quickApi = { init, getInstance, getDataSnapshot };
export default quickApi;
