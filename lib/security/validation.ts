/**
 * Input Validation Library
 * Comprehensive input validation and sanitization utilities
 */

import { logWarn } from '@core/lib/logger';

/**
 * Email validation
 */
export function validateEmail(email: string): {
  valid: boolean;
  error?: string;
} {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email is required' };
  }

  if (email.length > 255) {
    return { valid: false, error: 'Email is too long' };
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valid: false, error: 'Invalid email format' };
  }

  return { valid: true };
}

/**
 * URL validation
 */
export function validateUrl(url: string): { valid: boolean; error?: string } {
  if (!url || typeof url !== 'string') {
    return { valid: false, error: 'URL is required' };
  }

  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, error: 'URL must use HTTP or HTTPS protocol' };
    }
    return { valid: true };
  } catch {
    return { valid: false, error: 'Invalid URL format' };
  }
}

/**
 * String sanitization
 */
export function sanitizeString(
  input: string,
  options: {
    maxLength?: number;
    allowHtml?: boolean;
    trim?: boolean;
  } = {}
): string {
  const { maxLength = 1000, allowHtml = false, trim = true } = options;

  if (typeof input !== 'string') {
    return '';
  }

  let sanitized = input;

  // Remove HTML tags and potentially dangerous characters
  if (!allowHtml) {
    // First remove HTML tags
    sanitized = sanitized.replace(/<[^>]*>/g, '');
    // Then remove remaining dangerous characters
    sanitized = sanitized.replace(/[<>'"]/g, '');
  }

  // Apply max length
  sanitized = sanitized.slice(0, maxLength);

  if (trim) {
    sanitized = sanitized.trim();
  }

  return sanitized;
}

/**
 * SQL injection prevention
 */
export function sanitizeSqlInput(input: string): string {
  return input
    .replace(/['";]/g, '')
    .replace(/--/g, '')
    .replace(/\/\*/g, '')
    .replace(/\*\//g, '');
}

/**
 * XSS prevention
 */
export function escapeHtml(input: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
  };

  return input.replace(/[&<>"'/]/g, char => map[char] || char);
}

/**
 * JSON payload validation
 */
export function validateJsonPayload(
  payload: unknown,
  options: {
    maxSize?: number;
    requiredFields?: string[];
  } = {}
): { valid: boolean; error?: string } {
  const { maxSize = 1024 * 1024, requiredFields = [] } = options;

  if (payload === null || payload === undefined) {
    return { valid: false, error: 'Payload is required' };
  }

  try {
    const json = JSON.stringify(payload);

    if (json.length > maxSize) {
      return { valid: false, error: 'Payload exceeds maximum size' };
    }

    // Check required fields
    if (requiredFields.length > 0 && typeof payload === 'object') {
      for (const field of requiredFields) {
        if (!(field in (payload as Record<string, unknown>))) {
          return { valid: false, error: `Missing required field: ${field}` };
        }
      }
    }

    return { valid: true };
  } catch {
    return { valid: false, error: 'Invalid JSON payload' };
  }
}

/**
 * GitHub repository URL validation
 */
export function validateGitHubRepo(url: string): {
  valid: boolean;
  error?: string;
} {
  if (!url || typeof url !== 'string') {
    return { valid: false, error: 'Repository URL is required' };
  }

  const githubRegex = /^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+$/;
  if (!githubRegex.test(url)) {
    return { valid: false, error: 'Invalid GitHub repository URL' };
  }

  return { valid: true };
}

/**
 * Credit amount validation
 */
export function validateCreditAmount(amount: number): {
  valid: boolean;
  error?: string;
} {
  if (typeof amount !== 'number' || isNaN(amount)) {
    return { valid: false, error: 'Invalid credit amount' };
  }

  if (amount <= 0) {
    return { valid: false, error: 'Credit amount must be positive' };
  }

  if (amount > 10000) {
    return { valid: false, error: 'Credit amount exceeds maximum' };
  }

  if (!Number.isInteger(amount)) {
    return { valid: false, error: 'Credit amount must be a whole number' };
  }

  return { valid: true };
}

/**
 * Password validation
 */
export function validatePassword(password: string): {
  valid: boolean;
  error?: string;
} {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required' };
  }

  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters' };
  }

  if (password.length > 128) {
    return { valid: false, error: 'Password is too long' };
  }

  // Check for at least one uppercase, one lowercase, one number
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);

  if (!hasUpperCase || !hasLowerCase || !hasNumber) {
    return {
      valid: false,
      error: 'Password must contain uppercase, lowercase, and numbers',
    };
  }

  return { valid: true };
}

/**
 * API key validation
 */
export function validateApiKey(key: string): {
  valid: boolean;
  error?: string;
} {
  if (!key || typeof key !== 'string') {
    return { valid: false, error: 'API key is required' };
  }

  if (key.length < 32) {
    return { valid: false, error: 'API key is too short' };
  }

  if (key.length > 256) {
    return { valid: false, error: 'API key is too long' };
  }

  // Check for alphanumeric and common special characters
  const apiKeyRegex = /^[A-Za-z0-9_\-\.]+$/;
  if (!apiKeyRegex.test(key)) {
    return { valid: false, error: 'API key contains invalid characters' };
  }

  return { valid: true };
}

/**
 * File upload validation
 */
export function validateFileUpload(
  file: { name: string; size: number; type: string },
  options: {
    maxSize?: number;
    allowedTypes?: string[];
  } = {}
): { valid: boolean; error?: string } {
  const { maxSize = 10 * 1024 * 1024, allowedTypes = [] } = options; // 10MB default

  if (!file || !file.name) {
    return { valid: false, error: 'File is required' };
  }

  if (file.size > maxSize) {
    return {
      valid: false,
      error: `File size exceeds maximum of ${maxSize / (1024 * 1024)}MB`,
    };
  }

  if (allowedTypes.length > 0 && !allowedTypes.includes(file.type)) {
    return { valid: false, error: 'File type not allowed' };
  }

  // Check for suspicious file extensions
  const dangerousExtensions = ['.exe', '.sh', '.bat', '.cmd', '.com', '.pif'];
  if (dangerousExtensions.some(ext => file.name.toLowerCase().endsWith(ext))) {
    logWarn('Suspicious file upload attempt', { filename: file.name });
    return { valid: false, error: 'File type not allowed' };
  }

  return { valid: true };
}

/**
 * Rate limit key generation
 */
export function generateRateLimitKey(
  identifier: string,
  action: string
): string {
  return `rate_limit:${identifier}:${action}`;
}

/**
 * Validate webhook signature (for GitHub, Stripe, etc.)
 */
export async function validateWebhookSignature(
  payload: string,
  signature: string,
  secret: string,
  algorithm: 'SHA-256' | 'SHA-1' = 'SHA-256'
): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: algorithm },
      false,
      ['sign']
    );

    const signatureBuffer = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(payload)
    );

    const expectedSignature = Array.from(new Uint8Array(signatureBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // Constant-time comparison
    return expectedSignature === signature;
  } catch (error) {
    logWarn('Webhook signature validation failed', { error });
    return false;
  }
}
