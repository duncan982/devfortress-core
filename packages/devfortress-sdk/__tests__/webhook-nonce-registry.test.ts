/**
 * Tests for WebhookNonceRegistry (Invention A4)
 *
 * Coverage: nonce format validation, replay detection, size cap eviction,
 * TTL expiry, metrics tracking, clock skew tolerance.
 */
import { WebhookNonceRegistry } from '../src/webhook-nonce-registry';

describe('WebhookNonceRegistry', () => {
  let registry: WebhookNonceRegistry;

  beforeEach(() => {
    registry = new WebhookNonceRegistry({
      maxEntries: 100,
      ttlMs: 5000, // 5 seconds for fast tests
      clockSkewToleranceMs: 1000,
      enableMetrics: true,
    });
  });

  afterEach(() => {
    registry.destroy();
  });

  // ── GAP-A4-3: Nonce Format Validation ─────────────────────

  describe('format validation', () => {
    it('should accept valid 32-char hex nonce', () => {
      const result = registry.validateAndRegister(
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
      );
      expect(result.valid).toBe(true);
    });

    it('should reject null nonce', () => {
      const result = registry.validateAndRegister(null);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe('missing');
      }
    });

    it('should reject undefined nonce', () => {
      const result = registry.validateAndRegister(undefined);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe('missing');
      }
    });

    it('should reject empty string', () => {
      const result = registry.validateAndRegister('');
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe('missing');
      }
    });

    it('should reject nonce shorter than 32 chars', () => {
      const result = registry.validateAndRegister('a1b2c3d4e5f6');
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe('format_invalid');
      }
    });

    it('should reject nonce longer than 32 chars', () => {
      const result = registry.validateAndRegister(
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6ff'
      );
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe('format_invalid');
      }
    });

    it('should reject nonce with uppercase hex', () => {
      const result = registry.validateAndRegister(
        'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6'
      );
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe('format_invalid');
      }
    });

    it('should reject nonce with non-hex characters', () => {
      const result = registry.validateAndRegister(
        'g1h2i3j4k5l6m7n8o9p0q1r2s3t4u5v6'
      );
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe('format_invalid');
      }
    });

    it('should correctly validate format via isValidFormat()', () => {
      expect(registry.isValidFormat('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')).toBe(
        true
      );
      expect(registry.isValidFormat('short')).toBe(false);
      expect(registry.isValidFormat(null)).toBe(false);
      expect(registry.isValidFormat(undefined)).toBe(false);
    });
  });

  // ── Replay Detection ──────────────────────────────────────

  describe('replay detection', () => {
    const validNonce = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';

    it('should accept a nonce on first use', () => {
      const result = registry.validateAndRegister(validNonce);
      expect(result.valid).toBe(true);
    });

    it('should reject a replayed nonce', () => {
      registry.validateAndRegister(validNonce);
      const result = registry.validateAndRegister(validNonce);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe('replay_detected');
      }
    });

    it('should accept different nonces', () => {
      const result1 = registry.validateAndRegister(
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
      );
      const result2 = registry.validateAndRegister(
        'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1'
      );
      expect(result1.valid).toBe(true);
      expect(result2.valid).toBe(true);
    });

    it('should track registry size', () => {
      expect(registry.size).toBe(0);
      registry.validateAndRegister('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6');
      expect(registry.size).toBe(1);
      registry.validateAndRegister('b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1');
      expect(registry.size).toBe(2);
    });
  });

  // ── GAP-A4-1: Size Cap with Eviction ──────────────────────

  describe('size cap eviction', () => {
    it('should evict oldest nonce when cap is reached', () => {
      const smallRegistry = new WebhookNonceRegistry({
        maxEntries: 3,
        ttlMs: 60000,
      });

      // Fill the registry
      smallRegistry.validateAndRegister('00000000000000000000000000000001');
      smallRegistry.validateAndRegister('00000000000000000000000000000002');
      smallRegistry.validateAndRegister('00000000000000000000000000000003');
      expect(smallRegistry.size).toBe(3);

      // Adding a 4th should evict the 1st
      smallRegistry.validateAndRegister('00000000000000000000000000000004');
      expect(smallRegistry.size).toBe(3);

      // The evicted nonce should now be accepted (not detected as replay)
      const result = smallRegistry.validateAndRegister(
        '00000000000000000000000000000001'
      );
      expect(result.valid).toBe(true);

      smallRegistry.destroy();
    });

    it('should track cap evictions in metrics', () => {
      const smallRegistry = new WebhookNonceRegistry({
        maxEntries: 2,
        ttlMs: 60000,
        enableMetrics: true,
      });

      smallRegistry.validateAndRegister('00000000000000000000000000000001');
      smallRegistry.validateAndRegister('00000000000000000000000000000002');
      smallRegistry.validateAndRegister('00000000000000000000000000000003');

      const metrics = smallRegistry.getMetrics();
      expect(metrics.capEvictions).toBe(1);
      expect(metrics.totalRegistered).toBe(3);

      smallRegistry.destroy();
    });
  });

  // ── GAP-A4-2: Clock Skew Tolerance ────────────────────────

  describe('clock skew tolerance', () => {
    it('should return effective max age with skew tolerance', () => {
      const baseMaxAge = 5 * 60 * 1000; // 5 minutes
      const effective = registry.getEffectiveMaxAge(baseMaxAge);
      expect(effective).toBe(baseMaxAge + 1000); // +1s skew tolerance
    });
  });

  // ── GAP-A4-4: Metrics ─────────────────────────────────────

  describe('metrics', () => {
    it('should track replay detections', () => {
      const nonce = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
      registry.validateAndRegister(nonce);
      registry.validateAndRegister(nonce); // replay
      registry.validateAndRegister(nonce); // replay again

      const metrics = registry.getMetrics();
      expect(metrics.replayDetections).toBe(2);
      expect(metrics.totalRegistered).toBe(1);
    });

    it('should track format rejections', () => {
      registry.validateAndRegister('bad');
      registry.validateAndRegister(null);
      registry.validateAndRegister('toolong1234567890123456789012345678');

      const metrics = registry.getMetrics();
      expect(metrics.formatRejections).toBe(3);
    });

    it('should report utilisation', () => {
      const smallRegistry = new WebhookNonceRegistry({
        maxEntries: 10,
        ttlMs: 60000,
      });

      smallRegistry.validateAndRegister('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6');
      smallRegistry.validateAndRegister('b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1');

      const metrics = smallRegistry.getMetrics();
      expect(metrics.utilisation).toBe(0.2); // 2/10
      expect(metrics.registrySize).toBe(2);

      smallRegistry.destroy();
    });

    it('should reset metrics', () => {
      registry.validateAndRegister('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6');
      registry.validateAndRegister('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'); // replay

      registry.resetMetrics();
      const metrics = registry.getMetrics();
      expect(metrics.replayDetections).toBe(0);
      expect(metrics.totalRegistered).toBe(0);
      // Size is still tracked (not a metric counter)
      expect(metrics.registrySize).toBe(1);
    });
  });

  // ── TTL Expiry ────────────────────────────────────────────

  describe('TTL expiry', () => {
    it('should allow re-registration of expired nonce', async () => {
      const fastRegistry = new WebhookNonceRegistry({
        maxEntries: 100,
        ttlMs: 100, // 100ms TTL for fast test
      });

      const nonce = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
      fastRegistry.validateAndRegister(nonce);

      // Wait for TTL to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      // Should now be accepted (TTL expired)
      const result = fastRegistry.validateAndRegister(nonce);
      expect(result.valid).toBe(true);

      fastRegistry.destroy();
    });
  });
});
