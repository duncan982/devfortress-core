/**
 * Honeypot deployment automation
 * Handles GitHub repository creation and Vercel deployment
 */

import { Octokit } from '@octokit/rest';
import crypto from 'node:crypto';
import { logInfo, logError, logWarn } from '../logger';
import { updateHoneypotStatus } from './honeypot-service';
import { HoneypotStatus } from '@prisma/client';
import { prisma } from '../prisma';

/**
 * Delete a Vercel project by ID or name
 * Used when honeypots are deleted to clean up deployment resources
 * @param projectIdOrName - Vercel project ID or name to delete
 * @param vercelToken - Vercel API token (optional, uses env var if not provided)
 * @returns true if deleted successfully, false otherwise
 */
export async function deleteVercelProject(
  projectIdOrName: string,
  vercelToken?: string
): Promise<boolean> {
  const token = vercelToken || process.env.VERCEL_TOKEN;

  if (!token) {
    logWarn('Cannot delete Vercel project - VERCEL_TOKEN not set', {
      projectIdOrName,
    });
    return false;
  }

  if (!projectIdOrName) {
    logWarn('Cannot delete Vercel project - no project ID or name provided');
    return false;
  }

  try {
    logInfo('Deleting Vercel project', { projectIdOrName });

    // Vercel API v9 for deleting projects
    // https://vercel.com/docs/rest-api/endpoints/projects#delete-a-project
    const response = await fetch(
      `https://api.vercel.com/v9/projects/${encodeURIComponent(projectIdOrName)}`,
      {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    if (response.ok || response.status === 204) {
      logInfo('Vercel project deleted successfully', { projectIdOrName });
      return true;
    }

    // 404 means project doesn't exist - consider this a success
    if (response.status === 404) {
      logInfo('Vercel project not found (already deleted or never existed)', {
        projectIdOrName,
      });
      return true;
    }

    // Handle other errors
    const errorText = await response.text();
    logError('Failed to delete Vercel project', {
      projectIdOrName,
      status: response.status,
      statusText: response.statusText,
      error: errorText,
    });
    return false;
  } catch (error) {
    logError('Error deleting Vercel project', {
      error,
      projectIdOrName,
    });
    return false;
  }
}

/**
 * Disable Vercel deployment protection for a honeypot project
 * Honeypots need to be publicly accessible to attract attackers
 */
async function disableVercelDeploymentProtection(
  projectId: string,
  vercelToken: string
): Promise<boolean> {
  try {
    logInfo('Disabling Vercel deployment protection for honeypot', {
      projectId,
    });

    // Use Vercel API v9 to update project settings and disable SSO protection
    // This makes the honeypot publicly accessible (required for honeypots to work)
    // https://vercel.com/docs/rest-api/endpoints/projects#update-a-project
    const response = await fetch(
      `https://api.vercel.com/v9/projects/${projectId}`,
      {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${vercelToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          // Setting ssoProtection to null disables Vercel Authentication requirement
          ssoProtection: null,
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      logWarn('Failed to disable SSO protection on honeypot project', {
        projectId,
        status: response.status,
        error: errorText,
      });
      return false;
    }

    const result = await response.json();
    const protectionStatus = result.ssoProtection;

    logInfo('Deployment protection disabled for honeypot', {
      projectId,
      ssoProtection: protectionStatus,
      success: protectionStatus === null,
    });

    return protectionStatus === null;
  } catch (error) {
    logError('Error disabling deployment protection', {
      error,
      projectId,
    });
    return false;
  }
}

interface DeploymentConfig {
  honeypotId: string;
  apiProjectId: string;
  openApiSpec?: string;
  framework?: string;
  language?: string;
  apiProject?: {
    name?: string;
    description?: string | null;
  };
}

interface VercelDeploymentRequest {
  name: string;
  files?: Array<{
    file: string;
    data: string; // plain string for text files, base64 for binary
  }>;
  gitSource?: {
    type: 'github';
    repo: string;
    ref: string;
  };
  projectSettings?: {
    framework: string | null;
    buildCommand?: string;
    outputDirectory?: string;
  };
  target?: 'production' | 'preview';
  env?: Record<string, string>;
}

function normalizeWebhookBaseUrl(rawUrl: string): string {
  // Strip whitespace, newlines, carriage returns, and literal \n sequences
  const trimmed = rawUrl
    .trim()
    .replace(/\\n/g, '')
    .replace(/[\r\n]/g, '');

  if (trimmed.length === 0) {
    throw new Error('Webhook base URL cannot be empty');
  }

  const hasProtocol = /^https?:\/\//i.test(trimmed);
  const withProtocol = hasProtocol ? trimmed : `https://${trimmed}`;

  // Remove trailing slash to avoid double slashes when appending paths
  return withProtocol.replace(/\/$/, '');
}

function buildWebhookUrl(rawBaseUrl: string): string {
  const normalizedBase = normalizeWebhookBaseUrl(rawBaseUrl);

  try {
    const base = normalizedBase.endsWith('/')
      ? normalizedBase
      : `${normalizedBase}/`;
    // Use batch endpoint to reduce function invocations and avoid rate limits
    const constructed = new URL(
      '/api/webhooks/honeypot/batch',
      base
    ).toString();
    return constructed.replace(/\/$/, '');
  } catch {
    // Fallback to manual concatenation if URL parsing fails
    return `${normalizedBase}/api/webhooks/honeypot/batch`;
  }
}

/**
 * Generate obfuscated repository name for honeypot with API context awareness
 */
function generateObfuscatedRepoName(apiProject?: {
  name?: string;
  description?: string | null;
}): string {
  // Generic business term arrays for fallback
  const genericPrefixes = [
    'customer',
    'analytics',
    'dashboard',
    'commerce',
    'enterprise',
    'workflow',
    'integration',
    'management',
    'reporting',
    'collaboration',
    'payment',
    'transaction',
    'inventory',
    'logistics',
    'communication',
  ];
  const genericSuffixes = [
    'portal',
    'service',
    'hub',
    'platform',
    'gateway',
    'engine',
    'processor',
    'manager',
    'system',
    'network',
    'api',
    'web',
    'data',
    'cloud',
    'app',
  ];

  // Context-aware business terms based on API project metadata
  const contextPrefixes: string[] = [];
  const contextSuffixes: string[] = [];

  if (apiProject?.name || apiProject?.description) {
    const text =
      `${apiProject.name || ''} ${apiProject.description || ''}`.toLowerCase();

    // Extract meaningful keywords and map to business terms
    const keywordMappings: Record<string, string[]> = {
      // Inventory/Order Management
      inventory: ['inventory', 'stock', 'warehouse', 'supply'],
      order: ['order', 'purchase', 'transaction', 'commerce'],
      product: ['product', 'catalog', 'item', 'goods'],
      stock: ['inventory', 'stock', 'warehouse', 'supply'],

      // Customer/User Management
      customer: ['customer', 'client', 'user', 'account'],
      user: ['user', 'account', 'profile', 'member'],
      client: ['client', 'customer', 'partner', 'account'],

      // Analytics/Reporting
      analytics: ['analytics', 'reporting', 'insights', 'metrics'],
      report: ['reporting', 'analytics', 'dashboard', 'insights'],
      metric: ['metrics', 'analytics', 'performance', 'tracking'],
      dashboard: ['dashboard', 'analytics', 'reporting', 'insights'],

      // Payment/Financial
      payment: ['payment', 'billing', 'finance', 'transaction'],
      billing: ['billing', 'payment', 'invoice', 'finance'],
      finance: ['finance', 'payment', 'billing', 'accounting'],

      // Communication/Messaging
      message: ['communication', 'messaging', 'notification', 'chat'],
      notification: ['notification', 'alert', 'communication', 'messaging'],
      email: ['communication', 'messaging', 'notification', 'marketing'],

      // Content/Document Management
      content: ['content', 'document', 'media', 'publishing'],
      document: ['document', 'content', 'file', 'publishing'],
      file: ['document', 'content', 'storage', 'file'],

      // Project/Task Management
      project: ['project', 'task', 'workflow', 'management'],
      task: ['task', 'workflow', 'project', 'management'],
      workflow: ['workflow', 'process', 'automation', 'management'],

      // E-commerce/Retail
      shop: ['commerce', 'retail', 'store', 'marketplace'],
      store: ['commerce', 'retail', 'store', 'marketplace'],
      marketplace: ['marketplace', 'commerce', 'platform', 'trading'],

      // Healthcare/Medical
      patient: ['healthcare', 'medical', 'patient', 'clinic'],
      medical: ['healthcare', 'medical', 'clinic', 'patient'],
      health: ['healthcare', 'wellness', 'medical', 'fitness'],

      // Education/Learning
      course: ['education', 'learning', 'training', 'academy'],
      student: ['education', 'student', 'learning', 'academy'],
      learning: ['education', 'training', 'course', 'academy'],

      // Travel/Booking
      booking: ['travel', 'booking', 'reservation', 'tourism'],
      reservation: ['travel', 'booking', 'reservation', 'hospitality'],
      travel: ['travel', 'booking', 'tourism', 'hospitality'],

      // Logistics/Shipping
      shipping: ['logistics', 'shipping', 'delivery', 'transport'],
      delivery: ['logistics', 'delivery', 'shipping', 'transport'],
      logistics: ['logistics', 'shipping', 'supply', 'transport'],
    };

    // Check for keywords in the text
    for (const [keyword, terms] of Object.entries(keywordMappings)) {
      if (text.includes(keyword)) {
        contextPrefixes.push(...terms);
        contextSuffixes.push(...terms.map(term => term + 's')); // Add plural forms
        break; // Use first matching keyword for primary context
      }
    }

    // If no specific keywords found, try to extract common business terms
    const commonBusinessTerms = [
      'service',
      'system',
      'platform',
      'hub',
      'portal',
      'gateway',
      'manager',
      'engine',
      'processor',
      'tracker',
      'handler',
      'connector',
    ];

    for (const term of commonBusinessTerms) {
      if (text.includes(term)) {
        contextSuffixes.push(term);
      }
    }
  }

  // Use context-aware terms if available, otherwise fall back to generic
  const prefixes =
    contextPrefixes.length > 0
      ? [...new Set(contextPrefixes)]
      : genericPrefixes;
  const suffixes =
    contextSuffixes.length > 0
      ? [...new Set(contextSuffixes)]
      : genericSuffixes;

  // Generate name with context awareness
  const randomPrefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  const randomSuffix = suffixes[Math.floor(Math.random() * suffixes.length)];
  const randomId = crypto.randomBytes(3).toString('hex');

  // Ensure Vercel naming compliance: lowercase, alphanumeric, hyphens only
  const name = `${randomPrefix}-${randomSuffix}-${randomId}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '');

  return name;
}

/**
 * Generate honeypot API code based on OpenAPI specification
 */
export function generateHoneypotCode(params: {
  openApiSpec?: string;
  framework?: string;
  language?: string;
}): Record<string, string> {
  const { framework = 'Express', language = 'TypeScript' } = params;

  logInfo('Generating honeypot code', {
    framework,
    language,
  });

  // Generate Vercel serverless function code (works with all frameworks)
  const files: Record<string, string> = {};

  // Always generate Vercel-compatible serverless functions
  logInfo('Generating Vercel serverless function honeypot');

  files['package.json'] = JSON.stringify(
    {
      name: 'api-honeypot',
      version: '1.0.0',
      private: true,
    },
    null,
    2
  );

  // Vercel configuration for serverless functions
  // Setting framework to null and buildCommand to empty prevents Vercel from
  // looking for a dist directory or running a build process
  files['vercel.json'] = JSON.stringify(
    {
      version: 2,
      framework: null,
      buildCommand: '',
      outputDirectory: '',
      rewrites: [{ source: '/(.*)', destination: '/api/handler' }],
      functions: {
        'api/handler.js': {
          memory: 256,
          maxDuration: 10,
        },
      },
    },
    null,
    2
  );

  // Main catch-all handler as a Vercel serverless function
  files['api/handler.js'] = `const crypto = require('crypto');

/**
 * Lightweight logging helpers for serverless environment.
 * These mirror the DevFortress logger interface but just use console.*
 * since the deployed honeypot has no access to the parent project's logger.
 */
function logInfo(message, data) {
  console.log(JSON.stringify({ level: 'info', message, ...data, ts: new Date().toISOString() }));
}
function logWarn(message, data) {
  console.warn(JSON.stringify({ level: 'warn', message, ...data, ts: new Date().toISOString() }));
}
function logError(message, data) {
  console.error(JSON.stringify({ level: 'error', message, ...data, ts: new Date().toISOString() }));
}

/**
 * Parse error to a safe format
 */
function parseUnknownError(error) {
  if (error instanceof Error) {
    return { message: error.message, stack: error.stack, name: error.name };
  }
  if (typeof error === 'string') {
    return { message: error };
  }
  try {
    return { message: JSON.stringify(error) };
  } catch {
    return { message: '[unserializable error]' };
  }
}

/**
 * EventBuffer - Batches threat events before sending to webhook
 * Buffers events for FLUSH_INTERVAL_MS before sending as a batch
 * Implements exponential backoff for failed requests
 */
class EventBuffer {
  constructor() {
    this.buffer = [];
    this.flushTimer = null;
    this.isFlushing = false;
    this.FLUSH_INTERVAL_MS = 3000;  // 3 seconds buffer window
    this.MAX_BUFFER_SIZE = 50;       // Force flush at 50 events
    this.MAX_RETRIES = 5;            // Maximum retry attempts
    this.INITIAL_RETRY_DELAY_MS = 1000; // Start with 1s delay
  }

  /**
   * Add an event to the buffer
   */
  add(event) {
    this.buffer.push(event);
    logInfo('[EVENT-BUFFER] Event added', { 
      bufferSize: this.buffer.length,
      path: event.path,
      timestamp: new Date().toISOString()
    });

    // Force flush if buffer is full
    if (this.buffer.length >= this.MAX_BUFFER_SIZE) {
      logInfo('[EVENT-BUFFER] Buffer full, forcing flush');
      this.flush();
      return;
    }

    // Schedule flush if not already scheduled
    if (!this.flushTimer && !this.isFlushing) {
      this.flushTimer = setTimeout(() => {
        this.flush();
      }, this.FLUSH_INTERVAL_MS);
      logInfo('[EVENT-BUFFER] Flush scheduled in ' + this.FLUSH_INTERVAL_MS + 'ms');
    }
  }

  /**
   * Flush all buffered events to the webhook
   */
  async flush() {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    if (this.buffer.length === 0 || this.isFlushing) {
      return;
    }

    this.isFlushing = true;
    const events = [...this.buffer];
    this.buffer = [];

    logInfo('[EVENT-BUFFER] Flushing ' + events.length + ' events');

    try {
      await this.sendBatch(events);
    } catch (error) {
      console.error('[EVENT-BUFFER] Flush failed', { error: parseUnknownError(error).message });
      // Re-add failed events to buffer for retry
      this.buffer = [...events, ...this.buffer];
    } finally {
      this.isFlushing = false;
      // If there are still events in buffer, schedule another flush
      if (this.buffer.length > 0 && !this.flushTimer) {
        this.flushTimer = setTimeout(() => {
          this.flush();
        }, this.FLUSH_INTERVAL_MS);
      }
    }
  }

  /**
   * Send a single event to the legacy single-event endpoint
   */
  async sendSingleEvent(event) {
    const rawWebhookUrl = process.env.APIFORGE_WEBHOOK_URL;
    const webhookUrl = rawWebhookUrl ? rawWebhookUrl.trim().replace(/\\\\n/g, '').replace(/[\\r\\n]/g, '') : '';
    const webhookSecret = process.env.HONEYPOT_WEBHOOK_SECRET;
    const webhookAuthToken = process.env.HONEYPOT_WEBHOOK_AUTH_TOKEN || process.env.VERCEL_PROTECTION_BYPASS_TOKEN || null;

    // Convert batch URL to single event URL (remove /batch suffix)
    const singleEventUrl = webhookUrl.replace(/\\/batch$/, '');
    
    const payload = JSON.stringify(event);
    const signature = 'sha256=' + crypto.createHmac('sha256', webhookSecret).update(payload).digest('hex');

    const headers = {
      'Content-Type': 'application/json',
      'x-honeypot-signature': signature,
    };
    if (webhookAuthToken) {
      headers['Authorization'] = 'Bearer ' + webhookAuthToken;
    }

    const response = await fetch(singleEventUrl, {
      method: 'POST',
      headers,
      body: payload,
    });

    return response;
  }

  /**
   * Send events individually (fallback when batch endpoint returns 404)
   */
  async sendIndividually(events) {
    logInfo('[EVENT-BUFFER] Falling back to individual sends', { eventCount: events.length });
    
    let successCount = 0;
    let failCount = 0;

    for (const event of events) {
      try {
        const response = await this.sendSingleEvent(event);
        if (response.ok) {
          successCount++;
        } else {
          failCount++;
          console.warn('[EVENT-BUFFER] Individual send failed', { 
            status: response.status,
            path: event.path
          });
        }
        // Small delay between requests to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        failCount++;
        console.error('[EVENT-BUFFER] Individual send error', { 
          error: parseUnknownError(error).message,
          path: event.path
        });
      }
    }

    logInfo('[EVENT-BUFFER] Individual sends completed', { successCount, failCount });
    
    if (failCount > 0 && successCount === 0) {
      throw new Error('All individual sends failed');
    }
  }

  /**
   * Send a batch of events with exponential backoff retry
   * Falls back to individual sends if batch endpoint returns 404
   */
  async sendBatch(events, retryCount = 0) {
    // Sanitize webhook URL — strip stray newlines/whitespace from env vars
    const rawWebhookUrl = process.env.APIFORGE_WEBHOOK_URL;
    const webhookUrl = rawWebhookUrl ? rawWebhookUrl.trim().replace(/\\\\n/g, '').replace(/[\\r\\n]/g, '') : '';
    const webhookSecret = process.env.HONEYPOT_WEBHOOK_SECRET;
    const webhookAuthToken = process.env.HONEYPOT_WEBHOOK_AUTH_TOKEN || process.env.VERCEL_PROTECTION_BYPASS_TOKEN || null;

    if (!webhookUrl || !webhookSecret || !webhookUrl.startsWith('http')) {
      logWarn('[EVENT-BUFFER] Skipping batch send - missing config', {
        hasWebhookUrl: !!webhookUrl,
        hasWebhookSecret: !!webhookSecret,
        eventCount: events.length
      });
      return;
    }

    // Build batch payload
    const payload = JSON.stringify({ events });
    const signature = 'sha256=' + crypto.createHmac('sha256', webhookSecret).update(payload).digest('hex');

    const headers = {
      'Content-Type': 'application/json',
      'x-honeypot-signature': signature,
    };
    if (webhookAuthToken) {
      headers['Authorization'] = 'Bearer ' + webhookAuthToken;
    }

    logInfo('[EVENT-BUFFER] Sending batch request', {
      eventCount: events.length,
      retryCount,
      payloadLength: payload.length,
      timestamp: new Date().toISOString()
    });

    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers,
        body: payload,
      });

      if (response.ok) {
        const result = await response.json();
        logInfo('[EVENT-BUFFER] Batch sent successfully', {
          eventCount: events.length,
          successCount: result.successCount,
          failCount: result.failCount,
          timestamp: new Date().toISOString()
        });
        return;
      }

      // If batch endpoint returns 404, fall back to individual sends
      if (response.status === 404) {
        logWarn('[EVENT-BUFFER] Batch endpoint not found (404), falling back to individual sends');
        return this.sendIndividually(events);
      }

      // Handle rate limiting (429) and server errors (5xx) with retry
      if ((response.status === 429 || response.status >= 500) && retryCount < this.MAX_RETRIES) {
        const delay = this.INITIAL_RETRY_DELAY_MS * Math.pow(2, retryCount);
        logWarn('[EVENT-BUFFER] Batch request failed, retrying with exponential backoff', {
          status: response.status,
          retryCount: retryCount + 1,
          maxRetries: this.MAX_RETRIES,
          delayMs: delay
        });
        
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.sendBatch(events, retryCount + 1);
      }

      // Non-retryable error or max retries reached
      const errorText = await response.text();
      console.error('[EVENT-BUFFER] Batch request failed permanently', {
        status: response.status,
        error: errorText.substring(0, 200),
        eventCount: events.length,
        retryCount
      });
      
      // Throw to trigger re-buffering of events
      throw new Error('Batch request failed: ' + response.status);
    } catch (error) {
      if (error.message && error.message.startsWith('Batch request failed:')) {
        throw error;
      }
      if (error.message && error.message.startsWith('All individual sends failed')) {
        throw error;
      }

      // Network error - retry with exponential backoff
      if (retryCount < this.MAX_RETRIES) {
        const delay = this.INITIAL_RETRY_DELAY_MS * Math.pow(2, retryCount);
        logError('[EVENT-BUFFER] Network error, retrying with exponential backoff', {
          error: parseUnknownError(error).message,
          retryCount: retryCount + 1,
          maxRetries: this.MAX_RETRIES,
          delayMs: delay
        });
        
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.sendBatch(events, retryCount + 1);
      }

      console.error('[EVENT-BUFFER] Max retries reached', {
        error: parseUnknownError(error).message,
        eventCount: events.length,
        retryCount
      });
      throw error;
    }
  }
}

// Global event buffer instance
const eventBuffer = new EventBuffer();

/**
 * Log threat event to webhook (uses batching for efficiency)
 */
async function logThreatEvent(data) {
  const timestamp = new Date().toISOString();
  const honeypotId = process.env.HONEYPOT_ID || 'unknown';
  
  // Debug: Log environment config status
  logInfo('[THREAT] Processing threat event', {
    path: data.path,
    method: data.method,
    webhookUrl: process.env.APIFORGE_WEBHOOK_URL ? process.env.APIFORGE_WEBHOOK_URL.substring(0, 50) + '...' : 'NOT SET',
    hasWebhookSecret: !!process.env.HONEYPOT_WEBHOOK_SECRET,
    honeypotId,
    timestamp,
  });
  
  // Filter out Vercel internal bots
  const userAgent = data.headers['user-agent'] || data.headers['User-Agent'] || '';
  const isVercelBot = /vercel-(favicon|screenshot|thumbnail|preview|screenshot)/i.test(String(userAgent));
  const isVercelInternal = String(userAgent).includes('vercel-') && String(userAgent).includes('/1.0');
  
  if (isVercelBot || isVercelInternal) {
    logInfo('[THREAT] Skipping Vercel internal bot traffic', { userAgent, timestamp });
    return;
  }

  // Detect test requests
  const testMetadataHeader = data.headers['x-test-metadata'] || data.headers['X-Test-Metadata'];
  const isTestRequest = data.headers['x-test-request'] === 'true' || data.headers['X-Test-Request'] === 'true' || testMetadataHeader !== undefined;

  let testMetadata = null;
  if (testMetadataHeader) {
    try {
      testMetadata = JSON.parse(String(testMetadataHeader));
    } catch {
      testMetadata = { isTest: true, testUser: { id: data.headers['x-test-user-id'], email: data.headers['x-test-user-email'] } };
    }
  }

  // Build event object for batch sending
  const event = {
    honeypotId,
    timestamp,
    ip: data.ip,
    method: data.method,
    path: data.path,
    headers: data.headers,
    userAgent: data.headers['user-agent'] || data.headers['User-Agent'],
    ...(data.query && Object.keys(data.query).length > 0 ? { query: data.query } : {}),
    ...(data.body && Object.keys(data.body).length > 0 ? { body: data.body } : {}),
    severity: data.severity,
    ...(data.reason ? { reason: data.reason } : {}),
    ...(isTestRequest ? { isTest: true } : {}),
    ...(testMetadata ? { testMetadata } : {}),
  };

  const logPrefix = isTestRequest ? '[TEST-THREAT]' : '[THREAT]';
  logInfo(logPrefix, JSON.stringify({ ...data, timestamp, honeypotId, isTest: isTestRequest }));

  // Add to buffer for batch sending
  eventBuffer.add(event);
}

/**
 * Determine threat severity based on path and method
 */
function determineSeverity(path, method, headers, query, body) {
  const pathLower = path.toLowerCase();
  const bodyStr = JSON.stringify(body || {}).toLowerCase();
  const queryStr = JSON.stringify(query || {}).toLowerCase();
  const combined = pathLower + ' ' + bodyStr + ' ' + queryStr;
  
  // Critical patterns
  if (/(\\.\\.\\/|etc\\/passwd|cmd\\.exe|powershell)/i.test(combined)) return 'CRITICAL';
  if (/(\\/admin|\\/root|drop\\s+table|delete\\s+from)/i.test(combined)) return 'CRITICAL';
  
  // High severity patterns
  if (/(union.*select|insert\\s+into|exec\\s*\\()/i.test(combined)) return 'HIGH';
  if (/(<script|javascript:|onerror=|onload=)/i.test(combined)) return 'HIGH';
  if (/(\\.git|\\.env|\\.ssh|config\\.json|credentials)/i.test(pathLower)) return 'HIGH';
  
  // Medium severity
  if (method === 'POST' || method === 'PUT' || method === 'DELETE') return 'MEDIUM';
  if (pathLower.includes('/api/') && pathLower !== '/api/health') return 'MEDIUM';
  
  // Low severity for basic requests
  return 'LOW';
}

/**
 * Extract IP from Vercel headers
 */
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
    || req.headers['x-real-ip'] 
    || req.socket?.remoteAddress 
    || 'unknown';
}

/**
 * Parse request body
 */
async function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({ raw: body });
      }
    });
    req.on('error', () => resolve({}));
    // Timeout after 5 seconds
    setTimeout(() => resolve({}), 5000);
  });
}

/**
 * Parse URL query parameters
 */
function parseQuery(url) {
  try {
    const urlObj = new URL(url, 'http://localhost');
    const query = {};
    urlObj.searchParams.forEach((value, key) => { query[key] = value; });
    return query;
  } catch {
    return {};
  }
}

/**
 * Main handler - catches all requests
 */
module.exports = async function handler(req, res) {
  const path = req.url || '/';
  const method = req.method || 'GET';
  const ip = getClientIp(req);
  const headers = req.headers || {};
  const query = parseQuery(req.url);
  
  // Debug: Log every incoming request
  logInfo('[HONEYPOT] Request received', {
    path,
    method,
    ip,
    userAgent: headers['user-agent'] || 'none',
    timestamp: new Date().toISOString(),
    envCheck: {
      hasWebhookUrl: !!process.env.APIFORGE_WEBHOOK_URL,
      hasWebhookSecret: !!process.env.HONEYPOT_WEBHOOK_SECRET,
      hasHoneypotId: !!process.env.HONEYPOT_ID,
    }
  });
  
  // Parse body for POST/PUT/PATCH requests
  let body = {};
  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    body = await parseBody(req);
  }

  const severity = determineSeverity(path, method, headers, query, body);
  
  // Log the threat event
  await logThreatEvent({
    ip,
    method,
    path,
    headers,
    query,
    body,
    severity,
    reason: path === '/' ? 'Root access' : 'Endpoint accessed: ' + path,
  });

  // CRITICAL: Flush the event buffer BEFORE responding.
  // Serverless functions are frozen immediately after res.end(),
  // so the 3-second buffer timer will never fire.
  try {
    await eventBuffer.flush();
  } catch (flushErr) {
    console.error('[HONEYPOT] Failed to flush events', { error: parseUnknownError(flushErr).message });
  }

  // Return a fake successful response to keep attackers engaged
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Powered-By', 'Express'); // Fake header
  res.statusCode = 200;
  res.end(JSON.stringify({
    success: true,
    message: 'Request processed successfully',
    timestamp: new Date().toISOString(),
    requestId: crypto.randomUUID(),
  }));
};
`;

  files['.gitignore'] = `node_modules/
.env
.env.local
*.log
.DS_Store
.vercel
`;

  files['README.md'] = `# API Service

This is an automated API deployment.

**⚠️ WARNING:** This is a generated service. Do not use in production without review.

## Features

- Automatic request logging
- Generic API responses
- Request pattern detection

## Deployment

Automatically deployed via Vercel.
`;

  logInfo('Honeypot files generated successfully (Vercel serverless format)');

  return files;
}

/**
 * Create GitHub repository for honeypot
 */
export async function createHoneypotRepository(
  octokit: Octokit,
  ownerLogin: string,
  repoName?: string
): Promise<{ repoName: string; repoUrl: string }> {
  try {
    const finalRepoName = repoName || generateObfuscatedRepoName();

    logInfo('Creating GitHub repository for honeypot', {
      owner: ownerLogin,
      repo: finalRepoName,
    });

    const { data: repo } = await octokit.repos.createForAuthenticatedUser({
      name: finalRepoName,
      description: 'Automated API service deployment',
      private: true,
      auto_init: false,
    });

    logInfo('GitHub repository created', {
      repoName: repo.name,
      repoUrl: repo.html_url,
    });

    return {
      repoName: repo.name,
      repoUrl: repo.html_url,
    };
  } catch (error) {
    logError('Failed to create GitHub repository', {
      error,
      ownerLogin,
      repoName,
    });
    throw error;
  }
}

/**
 * Push honeypot code to GitHub repository
 */
export async function pushHoneypotCode(
  octokit: Octokit,
  ownerLogin: string,
  repoName: string,
  files: Record<string, string>
): Promise<void> {
  try {
    logInfo('Pushing honeypot code to GitHub', {
      owner: ownerLogin,
      repo: repoName,
    });

    // Get the default branch
    const { data: repo } = await octokit.repos.get({
      owner: ownerLogin,
      repo: repoName,
    });

    const defaultBranch = repo.default_branch || 'main';

    // Create initial commit with all files
    const fileBlobs = await Promise.all(
      Object.entries(files).map(async ([path, content]) => {
        const { data: blob } = await octokit.git.createBlob({
          owner: ownerLogin,
          repo: repoName,
          content: Buffer.from(content).toString('base64'),
          encoding: 'base64',
        });
        return { path, sha: blob.sha, mode: '100644' as const };
      })
    );

    // Create tree
    const { data: tree } = await octokit.git.createTree({
      owner: ownerLogin,
      repo: repoName,
      tree: fileBlobs,
    });

    // Create commit
    const { data: commit } = await octokit.git.createCommit({
      owner: ownerLogin,
      repo: repoName,
      message: 'Initial honeypot deployment',
      tree: tree.sha,
    });

    // Update reference
    await octokit.git.createRef({
      owner: ownerLogin,
      repo: repoName,
      ref: `refs/heads/${defaultBranch}`,
      sha: commit.sha,
    });

    logInfo('Honeypot code pushed to GitHub', {
      owner: ownerLogin,
      repo: repoName,
    });
  } catch (error) {
    logError('Failed to push honeypot code', { error, ownerLogin, repoName });
    throw error;
  }
}

/**
 * Poll Vercel deployment status until ready or failed
 */
async function pollDeploymentStatus(
  deploymentId: string,
  vercelToken: string
): Promise<'READY' | 'ERROR'> {
  const maxAttempts = 60; // 5 minutes max
  const interval = 5000; // 5 seconds

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      logInfo('Polling Vercel deployment status', {
        deploymentId,
        attempt: attempt + 1,
      });

      const response = await fetch(
        `https://api.vercel.com/v13/deployments/${deploymentId}`,
        {
          headers: {
            Authorization: `Bearer ${vercelToken}`,
          },
        }
      );

      if (!response.ok) {
        logWarn('Failed to get deployment status', {
          deploymentId,
          status: response.status,
        });
        continue;
      }

      const data = await response.json();
      const status = data.readyState;

      logInfo('Deployment status polled', {
        deploymentId,
        status,
        attempt: attempt + 1,
      });

      if (status === 'READY') {
        return 'READY';
      }

      if (status === 'ERROR' || status === 'CANCELED') {
        logError('Deployment failed', { deploymentId, status, data });
        return 'ERROR';
      }

      // Still building, wait
      await new Promise(resolve => setTimeout(resolve, interval));
    } catch (error) {
      logError('Error polling deployment status', {
        error,
        deploymentId,
        attempt: attempt + 1,
      });
      await new Promise(resolve => setTimeout(resolve, interval));
    }
  }

  logError('Deployment polling timed out', { deploymentId });
  return 'ERROR';
}

/**
 * Deploy honeypot to Vercel using direct file upload
 */
export async function deployToVercel(
  honeypotId: string,
  files: Record<string, string>,
  framework: string,
  webhookBaseUrl: string,
  apiProject?: {
    name?: string;
    description?: string | null;
  }
): Promise<{
  deploymentUrl: string;
  projectId: string;
  deploymentId: string;
  projectName: string;
}> {
  logInfo('Starting deployToVercel', {
    honeypotId,
    fileCount: Object.keys(files).length,
    framework,
    webhookBaseUrl,
  });

  const vercelToken = process.env.VERCEL_TOKEN;

  if (!vercelToken) {
    const errorMessage = [
      'VERCEL_TOKEN environment variable not set.',
      'To deploy honeypots, you need a Vercel access token with deployment permissions.',
      'Get your token from: https://vercel.com/account/tokens',
      'Set it in your production environment: VERCEL_TOKEN=your_token_here',
      'Or in Vercel Dashboard > Project > Settings > Environment Variables > Add VERCEL_TOKEN for All Environments',
      'Required scopes: Projects (Write), Deployments (Write)',
    ].join('\n');
    throw new Error(errorMessage);
  }

  logInfo('Vercel token present, length:', {
    length: vercelToken.length,
    mask:
      vercelToken.substring(0, 4) +
      '...' +
      vercelToken.substring(vercelToken.length - 4),
  });

  // Basic token validation
  if (vercelToken.length < 20) {
    const errorMessage = [
      'VERCEL_TOKEN appears to be invalid (too short).',
      'Vercel tokens are typically 24-32 characters long.',
      'Please check your token value at: https://vercel.com/account/tokens',
      'Regenerate the token if necessary.',
    ].join('\n');
    logError('VERCEL_TOKEN too short');
    throw new Error(errorMessage);
  }

  // Basic token presence check
  if (!vercelToken) {
    const errorMessage = [
      'VERCEL_TOKEN environment variable not set.',
      'To deploy honeypots, you need a Vercel access token with deployment permissions.',
      'Get your token from: https://vercel.com/account/tokens',
      'Set it in your Vercel project environment variables:',
      'Vercel Dashboard > Project > Settings > Environment Variables > Add VERCEL_TOKEN',
      'Make sure to set it for "All Environments" (Production, Preview, Development)',
      'Required scopes: Projects (Write), Deployments (Write)',
      'Make sure the token value is correct and has the right permissions.',
      'Redeploy after setting the variable.',
    ].join('\n');
    logError('VERCEL_TOKEN not set');
    throw new Error(errorMessage);
  }
  try {
    logInfo('Deploying honeypot to Vercel with direct file upload', {
      honeypotId,
      fileCount: Object.keys(files).length,
    });

    // Validate generated files
    if (!files['package.json']) {
      throw new Error('Missing package.json in generated files');
    }
    try {
      JSON.parse(files['package.json']);
    } catch (error) {
      logError('Invalid package.json in generated files', { error });
      throw new Error('Invalid package.json in generated files');
    }

    // Create Vercel project
    const projectName = generateObfuscatedRepoName(apiProject);

    // IMPORTANT: Always use serverless function settings
    // The generated code is a Vercel serverless function (api/handler.js)
    // NOT a traditional Express/Flask/etc app that needs building
    // The framework-specific code generation was removed - all honeypots
    // now use the same universal serverless handler for Vercel compatibility
    const vercelFramework: null = null;
    const buildCommand = '';
    const outputDirectory = '';

    const webhookUrl = buildWebhookUrl(webhookBaseUrl);
    const webhookAuthToken =
      process.env.HONEYPOT_WEBHOOK_AUTH_TOKEN ||
      process.env.VERCEL_PROTECTION_BYPASS_TOKEN;

    const deploymentRequest: VercelDeploymentRequest = {
      name: projectName,
      files: Object.entries(files).map(([filePath, content]) => ({
        file: filePath,
        data: content, // Send plain string content, not base64
      })),
      projectSettings: {
        framework: vercelFramework,
        buildCommand,
        outputDirectory,
      },
      target: 'production',
      env: {
        HONEYPOT_ID: honeypotId,
        APIFORGE_WEBHOOK_URL: webhookUrl,
        HONEYPOT_WEBHOOK_SECRET:
          process.env.HONEYPOT_WEBHOOK_SECRET || 'default-secret',
        ...(webhookAuthToken
          ? { HONEYPOT_WEBHOOK_AUTH_TOKEN: webhookAuthToken }
          : {}),
      },
    };

    logInfo('Vercel deployment request prepared', {
      name: projectName,
      fileCount: Object.keys(files).length,
      framework: deploymentRequest.projectSettings!.framework,
      envCount: Object.keys(deploymentRequest.env ?? {}).length,
      webhookUrl,
      hasWebhookAuthToken: !!webhookAuthToken,
    });

    logInfo('About to call Vercel API', {
      url: 'https://api.vercel.com/v13/deployments',
    });

    const response = await fetch('https://api.vercel.com/v13/deployments', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${vercelToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(deploymentRequest),
    });

    logInfo('Vercel API call completed', {
      status: response.status,
      statusText: response.statusText,
      ok: response.ok,
    });

    if (!response.ok) {
      let errorText: string;
      let errorDetails: unknown;
      try {
        errorText = await response.text();
        // Try to parse as JSON for better error details
        try {
          errorDetails = JSON.parse(errorText);
        } catch {
          // Not JSON, use as text
        }
      } catch {
        errorText = 'Failed to read error response';
      }
      logError('Vercel deployment failed', {
        status: response.status,
        statusText: response.statusText,
        error: errorText,
        errorDetails,
        requestBody: JSON.stringify(deploymentRequest, null, 2),
      });
      throw new Error(
        `Vercel deployment failed: ${response.status} ${response.statusText}${errorDetails ? ' - ' + JSON.stringify(errorDetails) : ''}`
      );
    }

    let deployment;
    try {
      deployment = await response.json();
    } catch (parseError) {
      logError('Failed to parse Vercel response JSON', {
        parseError,
        responseText: await response.text(),
      });
      throw new Error('Invalid response from Vercel API');
    }

    logInfo('Vercel deployment response parsed', {
      hasUrl: !!deployment.url,
      hasProjectId: !!deployment.projectId,
      hasId: !!deployment.id,
      deploymentKeys: Object.keys(deployment),
    });

    logInfo('Honeypot deployed to Vercel', {
      deploymentUrl: deployment.url,
      projectId: deployment.projectId,
      deploymentId: deployment.id,
      projectName,
    });

    // Disable deployment protection so honeypot is publicly accessible to attackers
    // This is critical - honeypots MUST be publicly accessible to serve their purpose
    if (deployment.projectId) {
      const protectionDisabled = await disableVercelDeploymentProtection(
        deployment.projectId,
        vercelToken
      );
      if (!protectionDisabled) {
        logWarn(
          'Could not disable deployment protection - honeypot may require manual configuration',
          {
            projectId: deployment.projectId,
            deploymentUrl: deployment.url,
          }
        );
      }
    }

    return {
      deploymentUrl: `https://${deployment.url}`,
      projectId: deployment.projectId,
      deploymentId: deployment.id,
      projectName,
    };
  } catch (error) {
    logError('Failed to deploy to Vercel', {
      error,
      honeypotId,
    });
    throw error;
  }
}

/**
 * Verify deployment health by checking the honeypot responds correctly
 */
async function verifyDeploymentHealth(deploymentUrl: string): Promise<boolean> {
  const maxRetries = 3;
  const baseDelay = 10000; // 10 seconds base delay

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logInfo('Checking deployment health', {
        deploymentUrl,
        attempt,
        maxRetries,
      });

      // Exponential backoff: attempt 1 = 60s, attempt 2 = 20s, attempt 3 = 40s
      const waitTime =
        attempt === 1 ? 60000 : baseDelay * Math.pow(2, attempt - 2);
      logInfo('Waiting before health check attempt', {
        deploymentUrl,
        attempt,
        waitTimeMs: waitTime,
      });
      await new Promise(resolve => setTimeout(resolve, waitTime));

      // Try /health endpoint first, fallback to root
      const healthUrls = [`${deploymentUrl}/health`, `${deploymentUrl}`];
      let response: Response | null = null;
      let usedUrl = '';

      for (const url of healthUrls) {
        try {
          logInfo('Attempting health check URL', {
            url,
            attempt,
          });

          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 15000);

          response = await fetch(url, {
            method: 'GET',
            signal: controller.signal,
            headers: {
              'User-Agent': 'APIForge-HealthCheck/1.0',
            },
          });

          clearTimeout(timeoutId);
          usedUrl = url;

          logInfo('Health check fetch completed', {
            url,
            status: response.status,
            statusText: response.statusText,
            attempt,
          });

          break; // Use first successful fetch
        } catch (fetchError) {
          logWarn('Health check URL failed', {
            url,
            error: fetchError,
            attempt,
          });
          // Continue to next URL
        }
      }

      if (!response) {
        logError('All health check URLs failed', {
          deploymentUrl,
          healthUrls,
          attempt,
        });
        continue;
      }

      if (response.ok) {
        const responseText = await response.text();
        logInfo('Health check response received', {
          usedUrl,
          status: response.status,
          responseLength: responseText.length,
          attempt,
        });

        try {
          const data = JSON.parse(responseText);
          if (data.success === true) {
            logInfo('Deployment health check successful', {
              usedUrl,
              data,
              attempt,
            });
            return true;
          } else {
            logWarn('Deployment health check failed - invalid response data', {
              usedUrl,
              data,
              attempt,
            });
          }
        } catch (parseError) {
          logWarn('Deployment health check failed - invalid JSON', {
            usedUrl,
            responseText: responseText.substring(0, 200),
            parseError,
            attempt,
          });
        }
      } else {
        logWarn('Deployment health check failed - bad response', {
          usedUrl,
          status: response.status,
          statusText: response.statusText,
          attempt,
        });
      }

      // If not last attempt, log retry
      if (attempt < maxRetries) {
        logInfo('Retrying health check', {
          deploymentUrl,
          attempt,
          nextAttempt: attempt + 1,
        });
      }
    } catch (error) {
      logError('Deployment health check error', {
        error,
        deploymentUrl,
        attempt,
      });
      if (attempt < maxRetries) {
        logInfo('Retrying health check after error', {
          deploymentUrl,
          attempt,
          nextAttempt: attempt + 1,
        });
      }
    }
  }

  logError('Deployment health check failed after all retries', {
    deploymentUrl,
    maxRetries,
  });
  return false;
}

/**
 * Complete honeypot deployment workflow (Direct Vercel deployment - No GitHub)
 */
export async function deployHoneypotWorkflow(
  config: DeploymentConfig
): Promise<{ deploymentUrl: string }> {
  const { honeypotId, apiProjectId, openApiSpec, framework, language } = config;

  try {
    logInfo('Starting honeypot deployment workflow (direct Vercel)', {
      honeypotId,
      apiProjectId,
      hasOpenApiSpec: !!openApiSpec,
      framework,
      language,
    });

    // Step 1: Update status to DEPLOYING
    logInfo('Updating honeypot status to DEPLOYING', { honeypotId });
    await updateHoneypotStatus(honeypotId, HoneypotStatus.DEPLOYING);
    logInfo('Honeypot status updated to DEPLOYING', { honeypotId });

    // Step 2: Generate honeypot code
    logInfo('Generating honeypot code', { honeypotId, framework, language });
    const files = generateHoneypotCode({ openApiSpec, framework, language });
    logInfo('Honeypot code generated', {
      honeypotId,
      fileCount: Object.keys(files).length,
    });

    // Step 3: Deploy directly to Vercel (no GitHub repo)
    logInfo('Starting Vercel deployment', { honeypotId });

    // Determine the webhook base URL dynamically
    // PRIORITY ORDER (most stable first):
    // 1. APIFORGE_BASE_URL - Explicit stable URL configured by admin
    // 2. NEXT_PUBLIC_APP_URL - Public app URL (usually production domain)
    // 3. VERCEL_URL - Current deployment URL (changes per deployment, use as fallback)
    //
    // For production reliability, prefer stable URLs over VERCEL_URL which changes
    // on every preview deployment and causes webhook delivery failures.
    const webhookBaseUrl = [
      process.env.APIFORGE_BASE_URL,
      process.env.NEXT_PUBLIC_APP_URL,
      process.env.VERCEL_URL,
    ]
      .map(v =>
        v
          ?.trim()
          .replace(/\\n/g, '')
          .replace(/[\r\n]/g, '')
      )
      .find(value => value && value.trim() !== '' && value !== '--value');

    if (!webhookBaseUrl) {
      throw new Error(
        'Unable to determine APIForge base URL for webhook. Please set APIFORGE_BASE_URL or NEXT_PUBLIC_APP_URL environment variable in Vercel for stable webhook delivery.'
      );
    }

    let normalizedWebhookBaseUrl: string;

    try {
      normalizedWebhookBaseUrl = normalizeWebhookBaseUrl(webhookBaseUrl);
    } catch (error) {
      logError('Failed to normalize webhook base URL', {
        honeypotId,
        webhookBaseUrl,
        error,
      });
      throw error;
    }

    logInfo('Using webhook base URL for honeypot deployment', {
      webhookBaseUrl: normalizedWebhookBaseUrl,
      honeypotId,
    });

    const { deploymentUrl, projectId, deploymentId, projectName } =
      await deployToVercel(
        honeypotId,
        files,
        config.framework || 'Express',
        normalizedWebhookBaseUrl,
        config.apiProject
      );
    logInfo('Vercel deployment initiated', {
      honeypotId,
      deploymentUrl,
      projectId,
      deploymentId,
      projectName,
    });

    // Step 4: Poll deployment status until ready
    logInfo('Polling deployment status', { honeypotId, deploymentId });
    const vercelToken = process.env.VERCEL_TOKEN!;
    const status = await pollDeploymentStatus(deploymentId, vercelToken);
    if (status === 'ERROR') {
      logError('Deployment failed on Vercel', { honeypotId, deploymentId });
      await updateHoneypotStatus(honeypotId, HoneypotStatus.ERROR);
      throw new Error(
        'Vercel deployment failed - check Vercel dashboard for details'
      );
    }
    logInfo('Deployment ready on Vercel', { honeypotId, deploymentId });

    // Step 5: Update status to DEPLOYED (Vercel deployment successful)
    logInfo('Updating honeypot status to DEPLOYED', { honeypotId });
    await updateHoneypotStatus(honeypotId, HoneypotStatus.DEPLOYED);
    logInfo('Honeypot status updated to DEPLOYED', { honeypotId });

    // Step 7: Update honeypot with deployment URL and set status to ACTIVE (Vercel deployment successful)
    logInfo('Updating honeypot with deployment URL', {
      honeypotId,
      deploymentUrl,
      projectName,
      projectId,
    });
    await prisma.honeypot.update({
      where: { id: honeypotId },
      data: {
        deploymentUrl,
        vercelProjectName: projectName,
        vercelProjectId: projectId,
        status: HoneypotStatus.ACTIVE, // Set to ACTIVE since Vercel deployment succeeded
        updatedAt: new Date(),
      },
    });
    logInfo(
      'Honeypot updated with deployment URL, Vercel project info and status set to ACTIVE',
      {
        honeypotId,
        deploymentUrl,
        projectName,
        projectId,
      }
    );

    // Step 8: Run health check in background (optional - don't fail deployment if it fails)
    logInfo('Running optional health check in background', {
      honeypotId,
      deploymentUrl,
    });
    verifyDeploymentHealth(deploymentUrl)
      .then(isHealthy => {
        if (!isHealthy) {
          logWarn(
            'Optional health check failed - honeypot may need manual verification',
            {
              honeypotId,
              deploymentUrl,
            }
          );
        } else {
          logInfo('Optional health check passed', {
            honeypotId,
            deploymentUrl,
          });
        }
      })
      .catch(error => {
        logWarn('Optional health check error', {
          error,
          honeypotId,
          deploymentUrl,
        });
      });

    logInfo('Honeypot deployment workflow completed (direct Vercel)', {
      honeypotId,
      deploymentUrl,
    });

    return { deploymentUrl };
  } catch (error) {
    logError('Honeypot deployment workflow error', { error });
    logError('Honeypot deployment workflow failed', { error, config });

    // Update status to ERROR only for actual deployment failures, not health check issues
    await updateHoneypotStatus(honeypotId, HoneypotStatus.ERROR);

    throw error;
  }
}
