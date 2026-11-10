/**
 *
 * TODO 36: this file previously had zero committed coverage — both claims
 * had only been verified via throwaway scripts (see commit 7ba1db0e).
 *
 * Coverage:
 *   Claim 7 — AES-256-GCM field encryption binds AAD to
 *     thirdPartyId|aliasId|fieldPath, so ciphertext cannot be swapped
 *     between fields or records without detection on decrypt.
 *   Claim 8 — INJECTION_PATTERNS response scanning (XSS, SQL-injection,
 *     SSRF, command-injection, path-traversal) flags known attack shapes
 *     without false-flagging ordinary payloads.
 */
import {
  PayloadProtectionService,
  type EncryptedFieldMeta,
} from '../src/payload-protection';

function makeService(): PayloadProtectionService {
  return new PayloadProtectionService({
    appSigningKey: 'test-signing-key-do-not-use-in-prod',
    appId: 'app-1',
  });
}

describe('PayloadProtectionService', () => {
  // ── Claim 7: AAD-bound field encryption ────────────────────

  describe('Claim 7 — AAD-bound field encryption', () => {
    it('round-trips sensitive fields and leaves non-sensitive fields untouched', () => {
      const service = makeService();
      const payload = {
        email: 'alice@example.com',
        profile: { password: 'hunter2', displayName: 'Alice' },
      };

      const { encryptedPayload, encryptedFields, fieldCount } =
        service.encryptSensitiveFields(payload, 'stripe', 'alias-1');

      expect(fieldCount).toBe(2);
      expect(encryptedPayload.email).not.toBe('alice@example.com');
      expect(
        (encryptedPayload.profile as Record<string, unknown>).password
      ).not.toBe('hunter2');
      expect(
        (encryptedPayload.profile as Record<string, unknown>).displayName
      ).toBe('Alice');

      const decrypted = service.decryptSensitiveFields(
        encryptedPayload,
        encryptedFields,
        'stripe',
        'alias-1'
      );
      expect(decrypted.email).toBe('alice@example.com');
      expect((decrypted.profile as Record<string, unknown>).password).toBe(
        'hunter2'
      );
    });

    it('detects a ciphertext swapped between two fields of the same record — the exact vulnerability the AAD binding closes', () => {
      // Field key derivation only depends on (thirdPartyId, aliasId), not on
      // fieldPath — so a valid (ciphertext, iv, authTag) tuple from one
      // field decrypts cleanly under another field's key. Before AAD was
      // bound to fieldPath (commit 7ba1db0e), moving "email"'s whole tuple
      // into the "ssn" slot would have silently succeeded, leaking email's
      // plaintext under the ssn key. With AAD bound to fieldPath, the same
      // swap must now fail closed.
      const service = makeService();
      const payload = { email: 'bob@example.com', ssn: '123-45-6789' };
      const { encryptedPayload, encryptedFields } =
        service.encryptSensitiveFields(payload, 'thirdparty-x', 'alias-x');

      const tamperedPayload = {
        ...encryptedPayload,
        ssn: encryptedPayload.email, // move email's ciphertext into ssn's slot
      };
      const tamperedFields = new Map<string, EncryptedFieldMeta>([
        ['ssn', encryptedFields.get('email')!], // move email's iv/authTag too
      ]);

      expect(() =>
        service.decryptSensitiveFields(
          tamperedPayload,
          tamperedFields,
          'thirdparty-x',
          'alias-x'
        )
      ).toThrow(
        /Field decryption failed for "ssn".*AAD\/auth tag verification failed/
      );

      // Fails closed: the tampered field is never overwritten with garbage.
      try {
        service.decryptSensitiveFields(
          tamperedPayload,
          tamperedFields,
          'thirdparty-x',
          'alias-x'
        );
      } catch {
        // expected
      }
      expect(tamperedPayload.ssn).toBe(encryptedPayload.email);
    });

    it('detects a ciphertext swapped between two different third-party records', () => {
      const service = makeService();
      const payloadA = { email: 'carol@example.com' };
      const payloadB = { email: 'dave@example.com' };
      const encA = service.encryptSensitiveFields(payloadA, 'service-a');
      service.encryptSensitiveFields(payloadB, 'service-b');

      // Attempt to decrypt service-a's ciphertext as if it belonged to
      // service-b's record.
      expect(() =>
        service.decryptSensitiveFields(
          encA.encryptedPayload,
          encA.encryptedFields,
          'service-b'
        )
      ).toThrow(/AAD\/auth tag verification failed/);
    });

    it('detects a ciphertext replayed under a different aliasId of the same third party', () => {
      const service = makeService();
      const payload = { email: 'erin@example.com' };
      const enc = service.encryptSensitiveFields(
        payload,
        'shared-service',
        'alias-1'
      );

      expect(() =>
        service.decryptSensitiveFields(
          enc.encryptedPayload,
          enc.encryptedFields,
          'shared-service',
          'alias-2'
        )
      ).toThrow(/AAD\/auth tag verification failed/);
    });

    it('detects a corrupted auth tag (bit-level ciphertext tampering)', () => {
      const service = makeService();
      const payload = { email: 'frank@example.com' };
      const { encryptedPayload, encryptedFields } =
        service.encryptSensitiveFields(payload, 'thirdparty-z');

      const meta = encryptedFields.get('email')!;
      const flippedLastByte =
        meta.authTag.slice(0, -2) +
        (meta.authTag.slice(-2) === '00' ? '11' : '00');
      const tamperedFields = new Map<string, EncryptedFieldMeta>([
        ['email', { ...meta, authTag: flippedLastByte }],
      ]);

      expect(() =>
        service.decryptSensitiveFields(
          encryptedPayload,
          tamperedFields,
          'thirdparty-z'
        )
      ).toThrow(
        /Field decryption failed for "email".*AAD\/auth tag verification failed/
      );
    });

    it('round-trips correctly when aliasId is omitted on both encrypt and decrypt', () => {
      const service = makeService();
      const payload = { email: 'grace@example.com' };
      const { encryptedPayload, encryptedFields } =
        service.encryptSensitiveFields(payload, 'no-alias-service');

      const decrypted = service.decryptSensitiveFields(
        encryptedPayload,
        encryptedFields,
        'no-alias-service'
      );
      expect(decrypted.email).toBe('grace@example.com');
    });
  });

  // ── Claim 8: injection-pattern detection ───────────────────

  describe('Claim 8 — injection-pattern detection (verifyInboundResponse)', () => {
    let service: PayloadProtectionService;

    beforeEach(() => {
      service = makeService();
    });

    describe('cross-site scripting', () => {
      it('flags a <script> tag', () => {
        const result = service.verifyInboundResponse(
          { comment: '<script>alert(1)</script>' },
          'svc-xss'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
        expect(result.valid).toBe(false);
      });

      it('flags an inline event-handler attribute', () => {
        const result = service.verifyInboundResponse(
          { html: '<img src=x onerror=alert(1)>' },
          'svc-xss'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });
    });

    describe('SQL injection', () => {
      it('flags a SELECT ... FROM statement', () => {
        const result = service.verifyInboundResponse(
          { q: 'SELECT * FROM users WHERE id=1' },
          'svc-sqli'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });

      it('flags a UNION SELECT statement', () => {
        const result = service.verifyInboundResponse(
          { q: '1 UNION SELECT username, password FROM accounts' },
          'svc-sqli'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });

      it('flags a DROP TABLE statement', () => {
        const result = service.verifyInboundResponse(
          { q: 'x; DROP TABLE users;' },
          'svc-sqli'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });
    });

    describe('SSRF', () => {
      it('flags a loopback URL', () => {
        const result = service.verifyInboundResponse(
          { callback: 'http://127.0.0.1/admin' },
          'svc-ssrf'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });

      it('flags a cloud-metadata endpoint URL', () => {
        const result = service.verifyInboundResponse(
          { callback: 'http://169.254.169.254/latest/meta-data' },
          'svc-ssrf'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });

      it('flags a file:// URI', () => {
        const result = service.verifyInboundResponse(
          { path: 'file:///etc/passwd' },
          'svc-ssrf'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });
    });

    describe('command injection (added commit 7ba1db0e)', () => {
      it('flags a chained "; rm -rf" command', () => {
        const result = service.verifyInboundResponse(
          { note: 'ok; rm -rf /' },
          'svc-cmdi'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });

      it('flags command substitution $(...)', () => {
        const result = service.verifyInboundResponse(
          { note: 'run $(whoami) now' },
          'svc-cmdi'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });

      it('flags piping output to a shell', () => {
        const result = service.verifyInboundResponse(
          { note: 'data | bash' },
          'svc-cmdi'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });
    });

    describe('path traversal (added commit 7ba1db0e)', () => {
      it('flags ../ sequences', () => {
        const result = service.verifyInboundResponse(
          { file: '../../etc/passwd' },
          'svc-traversal'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });

      it('flags URL-encoded traversal sequences', () => {
        const result = service.verifyInboundResponse(
          { file: '%2e%2e%2fetc%2fpasswd' },
          'svc-traversal'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });

      it('flags a direct /etc/passwd reference', () => {
        const result = service.verifyInboundResponse(
          { file: '/etc/passwd' },
          'svc-traversal'
        );
        expect(result.injectionIndicators.length).toBeGreaterThan(0);
      });
    });

    describe('legitimate payloads are not false-flagged', () => {
      it('does not flag an ordinary JSON API response', () => {
        const result = service.verifyInboundResponse(
          {
            id: 123,
            name: 'John Doe',
            email: 'john@example.com',
            createdAt: '2026-09-02T10:00:00Z',
            avatarUrl: 'https://cdn.example.com/avatars/123.png',
          },
          'svc-benign'
        );
        expect(result.injectionIndicators).toEqual([]);
        expect(result.valid).toBe(true);
      });

      it('does not flag prose that coincidentally contains SQL keywords', () => {
        const result = service.verifyInboundResponse(
          {
            bio: 'I select the best restaurants in town and always update my reviews.',
          },
          'svc-benign'
        );
        expect(result.injectionIndicators).toEqual([]);
      });

      it('does not flag an ordinary filesystem-style path', () => {
        const result = service.verifyInboundResponse(
          { path: '/home/user/documents/report.pdf' },
          'svc-benign'
        );
        expect(result.injectionIndicators).toEqual([]);
      });
    });
  });
});
