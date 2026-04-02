/**
 * PII Sanitizer for Logger
 *
 * Masks or removes personally identifiable information (PII) from log data
 * before it is written to any transport (console, file, external service).
 *
 * Sensitive fields are masked to preserve log structure while preventing
 * exposure of real user data in log files, error messages, and API responses.
 */

/** Fields that should always be fully redacted (replaced with [REDACTED]) */
const REDACTED_FIELDS = new Set([
  'password',
  'passwd',
  'secret',
  'token',
  'sessiontoken',
  'accesstoken',
  'refreshtoken',
  'apikey',
  'api_key',
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-devfortress-key',
  'private_key',
  'privatekey',
  'credit_card',
  'creditcard',
  'cvv',
  'ssn',
  'social_security',
  'passport',
]);

/** Fields that should be partially masked (show first/last chars) */
const MASKED_FIELDS = new Set([
  'email',
  'phone',
  'phonenumber',
  'phone_number',
  'ip',
  'sourceip',
  'source_ip',
  'clientip',
  'client_ip',
  'x-forwarded-for',
  'x-real-ip',
  'userid',
  'user_id',
  'name',
  'firstname',
  'first_name',
  'lastname',
  'last_name',
  'fullname',
  'full_name',
  'address',
  'dob',
  'date_of_birth',
  'dateofbirth',
]);

/** Regex patterns to detect inline PII in string values */
const PII_PATTERNS: Array<{
  name: string;
  regex: RegExp;
  replacement: string;
}> = [
  {
    name: 'email',
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    replacement: '[EMAIL_REDACTED]',
  },
  {
    name: 'jwt',
    regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    replacement: '[JWT_REDACTED]',
  },
  {
    name: 'bearer_token',
    regex: /Bearer\s+[a-zA-Z0-9._~+/=-]+/gi,
    replacement: 'Bearer [TOKEN_REDACTED]',
  },
  {
    name: 'api_key_inline',
    regex:
      /(?:api[_-]?key|apikey|token|secret)[=:]\s*['"]?[a-zA-Z0-9._~+/=-]{16,}['"]?/gi,
    replacement: '[API_KEY_REDACTED]',
  },
  {
    name: 'credit_card',
    regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    replacement: '[CARD_REDACTED]',
  },
  {
    name: 'ssn',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    replacement: '[SSN_REDACTED]',
  },
];

/**
 * Mask an IP address: show first octet, mask the rest.
 * e.g. "192.168.1.100" → "192.***.***.***"
 */
function maskIP(ip: string): string {
  if (!ip || typeof ip !== 'string') return ip;
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.***.***.*${parts[3].slice(-1)}`;
  }
  // IPv6 or other format — show first segment only
  const segments = ip.split(':');
  if (segments.length > 1) {
    return `${segments[0]}:****:****`;
  }
  return ip.length > 4 ? `${ip.slice(0, 2)}***${ip.slice(-1)}` : '***';
}

/**
 * Mask an email: show first 2 chars and domain.
 * e.g. "john.doe@example.com" → "jo***@***.com"
 */
function maskEmail(email: string): string {
  if (!email || typeof email !== 'string') return email;
  const atIndex = email.indexOf('@');
  if (atIndex <= 0) return '***';
  const local = email.slice(0, atIndex);
  const domain = email.slice(atIndex + 1);
  const maskedLocal =
    local.length > 2 ? `${local.slice(0, 2)}***` : `${local[0]}***`;
  const domainParts = domain.split('.');
  const tld =
    domainParts.length > 1 ? domainParts[domainParts.length - 1] : domain;
  return `${maskedLocal}@***.${tld}`;
}

/**
 * Mask a generic string: show first 2 and last 1 character.
 * e.g. "usr_abc123" → "us*******3"
 */
function maskGenericString(value: string): string {
  if (!value || typeof value !== 'string') return value;
  if (value.length <= 4) return '***';
  return `${value.slice(0, 2)}${'*'.repeat(Math.min(value.length - 3, 7))}${value.slice(-1)}`;
}

/**
 * Sanitize a string value by replacing inline PII patterns.
 */
function sanitizeString(value: string): string {
  let sanitized = value;
  for (const pattern of PII_PATTERNS) {
    sanitized = sanitized.replace(pattern.regex, pattern.replacement);
  }
  return sanitized;
}

/**
 * Sanitize a value based on its field name.
 */
function sanitizeField(fieldName: string, value: unknown): unknown {
  const normalizedField = fieldName.toLowerCase().replace(/[-_\s]/g, '');

  // Fully redact sensitive fields
  if (REDACTED_FIELDS.has(normalizedField)) {
    return '[REDACTED]';
  }

  // Partially mask PII fields
  if (MASKED_FIELDS.has(normalizedField)) {
    if (typeof value !== 'string') return '[REDACTED]';
    if (normalizedField.includes('email')) return maskEmail(value);
    if (normalizedField.includes('ip') || normalizedField.includes('forwarded'))
      return maskIP(value);
    return maskGenericString(value);
  }

  return value;
}

/**
 * Deep-sanitize an object, masking or redacting PII fields
 * and scanning string values for inline PII patterns.
 *
 * @param data - The data object to sanitize
 * @param depth - Maximum recursion depth (default: 10)
 * @returns A new sanitized object (does not mutate input)
 */
export function sanitizeLogData(data: unknown, depth: number = 10): unknown {
  if (depth <= 0) return '[MAX_DEPTH]';

  if (data === null || data === undefined) return data;

  if (typeof data === 'string') {
    return sanitizeString(data);
  }

  if (typeof data === 'number' || typeof data === 'boolean') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizeLogData(item, depth - 1));
  }

  if (typeof data === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(
      data as Record<string, unknown>
    )) {
      const fieldSanitized = sanitizeField(key, value);
      if (fieldSanitized !== value) {
        // Field was sanitized by name — use the result
        sanitized[key] = fieldSanitized;
      } else if (typeof value === 'string') {
        // Not a known PII field, but scan string for inline PII
        sanitized[key] = sanitizeString(value);
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = sanitizeLogData(value, depth - 1);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  return data;
}

/**
 * Sanitize error messages to prevent leaking internal details.
 * Removes stack traces, file paths, and database error details.
 */
export function sanitizeErrorMessage(message: string): string {
  if (!message || typeof message !== 'string') return message;

  let sanitized = message;

  // Remove file paths
  sanitized = sanitized.replace(
    /(?:\/[\w.-]+)+\.\w+(?::\d+(?::\d+)?)?/g,
    '[PATH_REDACTED]'
  );

  // Remove SQL-like errors
  sanitized = sanitized.replace(
    /(?:relation|table|column|constraint|index)\s+"[^"]+"/gi,
    '[DB_DETAIL_REDACTED]'
  );

  // Remove connection strings
  sanitized = sanitized.replace(
    /(?:postgres|mysql|redis|mongodb):\/\/[^\s"']+/gi,
    '[CONNECTION_STRING_REDACTED]'
  );

  // Scan for inline PII
  sanitized = sanitizeString(sanitized);

  return sanitized;
}

/**
 * Sanitize API response data before sending to the client.
 * Removes internal error details while preserving the response structure.
 */
export function sanitizeApiResponse(
  data: Record<string, unknown>,
  includeInternalErrors: boolean = false
): Record<string, unknown> {
  const sanitized = { ...data };

  // Remove internal error details unless explicitly requested
  if (!includeInternalErrors) {
    delete sanitized.stack;
    delete sanitized.internalError;
    delete sanitized.sqlError;
    delete sanitized.prismaError;
    delete sanitized.query;
    delete sanitized.connectionString;
  }

  // Sanitize remaining fields
  return sanitizeLogData(sanitized) as Record<string, unknown>;
}
