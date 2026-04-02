/**
 * Tests for PII Sanitizer
 * Verifies that sensitive data is properly masked or redacted
 * in logs, error messages, and API responses.
 */

import {
  sanitizeLogData,
  sanitizeErrorMessage,
  sanitizeApiResponse,
} from '../../lib/logger/pii-sanitizer';

describe('PII Sanitizer', () => {
  describe('sanitizeLogData', () => {
    it('should redact password fields', () => {
      const data = { username: 'john', password: 'supersecret123' };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.password).toBe('[REDACTED]');
      expect(result.username).toBe('john');
    });

    it('should redact token and API key fields', () => {
      const data = {
        sessionToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test',
        apiKey: 'sk_live_abc123xyz',
        api_key: 'pk_test_123',
        authorization: 'Bearer eyJhbG...',
      };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.sessionToken).toBe('[REDACTED]');
      expect(result.apiKey).toBe('[REDACTED]');
      expect(result.api_key).toBe('[REDACTED]');
      expect(result.authorization).toBe('[REDACTED]');
    });

    it('should mask email fields', () => {
      const data = { email: 'john.doe@example.com' };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.email).toContain('jo***');
      expect(result.email).toContain('.com');
      expect(result.email).not.toBe('john.doe@example.com');
    });

    it('should mask IP address fields', () => {
      const data = { ip: '192.168.1.100', sourceIp: '10.0.0.50' };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.ip).not.toBe('192.168.1.100');
      expect((result.ip as string).startsWith('192')).toBe(true);
      expect(result.sourceIp).not.toBe('10.0.0.50');
    });

    it('should mask userId fields', () => {
      const data = { userId: 'usr_abc123def456' };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.userId).not.toBe('usr_abc123def456');
      expect((result.userId as string).startsWith('us')).toBe(true);
    });

    it('should detect and mask inline email in string values', () => {
      const data = { message: 'User john.doe@example.com logged in' };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.message).toContain('[EMAIL_REDACTED]');
      expect(result.message).not.toContain('john.doe@example.com');
    });

    it('should detect and mask inline JWT tokens', () => {
      const data = {
        message:
          'Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjMifQ.abc123',
      };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.message).toContain('[JWT_REDACTED]');
    });

    it('should detect and mask credit card numbers', () => {
      const data = { note: 'Card 4111-1111-1111-1111 was charged' };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.note).toContain('[CARD_REDACTED]');
      expect(result.note).not.toContain('4111');
    });

    it('should handle nested objects', () => {
      const data = {
        user: {
          email: 'test@example.com',
          password: 'secret',
          profile: {
            phone: '555-123-4567',
          },
        },
      };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      const user = result.user as Record<string, unknown>;
      expect(user.password).toBe('[REDACTED]');
      expect(user.email).toContain('***');
      const profile = user.profile as Record<string, unknown>;
      expect(profile.phone).not.toBe('555-123-4567');
    });

    it('should handle arrays', () => {
      const data = {
        users: [
          { email: 'a@b.com', password: 'p1' },
          { email: 'c@d.com', password: 'p2' },
        ],
      };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      const users = result.users as Array<Record<string, unknown>>;
      expect(users[0].password).toBe('[REDACTED]');
      expect(users[1].password).toBe('[REDACTED]');
    });

    it('should not modify non-PII fields', () => {
      const data = {
        status: 200,
        method: 'GET',
        path: '/api/health',
        count: 42,
      };
      const result = sanitizeLogData(data) as Record<string, unknown>;
      expect(result.status).toBe(200);
      expect(result.method).toBe('GET');
      expect(result.path).toBe('/api/health');
      expect(result.count).toBe(42);
    });

    it('should handle null and undefined gracefully', () => {
      expect(sanitizeLogData(null)).toBeNull();
      expect(sanitizeLogData(undefined)).toBeUndefined();
      expect(sanitizeLogData('')).toBe('');
    });

    it('should respect max depth to prevent infinite recursion', () => {
      // Create a deeply nested object
      let deep: Record<string, unknown> = { password: 'secret' };
      for (let i = 0; i < 15; i++) {
        deep = { nested: deep };
      }
      const result = sanitizeLogData(deep) as Record<string, unknown>;
      expect(result).toBeDefined();
    });
  });

  describe('sanitizeErrorMessage', () => {
    it('should remove file paths', () => {
      const msg = 'Error at /home/user/app/src/index.ts:42:10';
      const result = sanitizeErrorMessage(msg);
      expect(result).toContain('[PATH_REDACTED]');
      expect(result).not.toContain('/home/user/app');
    });

    it('should remove database details', () => {
      const msg = 'relation "users" does not exist';
      const result = sanitizeErrorMessage(msg);
      expect(result).toContain('[DB_DETAIL_REDACTED]');
    });

    it('should remove connection strings', () => {
      const msg = 'Cannot connect to postgres://user:pass@host:5432/db';
      const result = sanitizeErrorMessage(msg);
      expect(result).toContain('[CONNECTION_STRING_REDACTED]');
      expect(result).not.toContain('user:pass');
    });

    it('should mask inline emails in error messages', () => {
      const msg = 'Failed to send email to john@example.com';
      const result = sanitizeErrorMessage(msg);
      expect(result).toContain('[EMAIL_REDACTED]');
    });
  });

  describe('sanitizeApiResponse', () => {
    it('should remove internal error details', () => {
      const response = {
        error: 'Something went wrong',
        stack: 'Error: ...\n  at Object...',
        sqlError: 'relation "users" not found',
        prismaError: 'P2025',
        query: 'SELECT * FROM users',
        connectionString: 'postgres://...',
        status: 500,
      };
      const result = sanitizeApiResponse(response);
      expect(result.error).toBeDefined();
      expect(result.status).toBe(500);
      expect(result.stack).toBeUndefined();
      expect(result.sqlError).toBeUndefined();
      expect(result.prismaError).toBeUndefined();
      expect(result.query).toBeUndefined();
      expect(result.connectionString).toBeUndefined();
    });

    it('should keep internal errors when explicitly requested', () => {
      const response = {
        error: 'Something went wrong',
        stack: 'Error: ...',
        status: 500,
      };
      const result = sanitizeApiResponse(response, true);
      expect(result.stack).toBeDefined();
    });
  });
});
