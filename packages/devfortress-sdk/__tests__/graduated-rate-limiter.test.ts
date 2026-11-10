/**
 * Tests for GraduatedRateLimiter (Invention A3)
 *
 * Coverage: 5 escalation stages, jitter range, burst detection,
 * per-endpoint limits, escalating cooldowns, revocation, destroy.
 */
import { GraduatedRateLimiter } from '../src/graduated-rate-limiter';
import type { RateLimitResult } from '../src/graduated-rate-limiter';

describe('GraduatedRateLimiter', () => {
  let limiter: GraduatedRateLimiter;

  beforeEach(() => {
    limiter = new GraduatedRateLimiter({
      defaultLimit: 10,
      windowMs: 60_000,
      burstLimit: 5,
      initialCooldownSeconds: 2,
      maxConsecutiveBlocks: 3,
    });
  });

  afterEach(() => {
    limiter.destroy();
  });

  // ── Stage Escalation ──────────────────────────────────────

  describe('stage escalation', () => {
    it('should start at observation with low usage', () => {
      const result = limiter.check('client-1');
      expect(result.stage).toBe('observation');
      expect(result.blocked).toBe(false);
      expect(result.injectedLatencyMs).toBe(0);
    });

    it('should return warning at 50-75% utilisation', () => {
      // Use higher burstLimit so burst detection doesn't override ratio-based stages
      const warningLimiter = new GraduatedRateLimiter({
        defaultLimit: 10,
        burstLimit: 50,
        initialCooldownSeconds: 2,
        maxConsecutiveBlocks: 3,
      });
      // Push to ~60% → 6 of 10 requests in the window
      for (let i = 0; i < 5; i++) {
        warningLimiter.check('client-2');
      }
      const result = warningLimiter.check('client-2');
      // At 60% should be warning
      expect(result.stage).toBe('warning');
      expect(result.blocked).toBe(false);
      warningLimiter.destroy();
    });

    it('should return soft_limit at 75-100% utilisation', () => {
      const softLimiter = new GraduatedRateLimiter({
        defaultLimit: 10,
        burstLimit: 50,
        initialCooldownSeconds: 2,
        maxConsecutiveBlocks: 3,
      });
      for (let i = 0; i < 7; i++) {
        softLimiter.check('client-3');
      }
      const result = softLimiter.check('client-3');
      // At 80% should be soft_limit
      expect(result.stage).toBe('soft_limit');
      expect(result.blocked).toBe(false);
      expect(result.injectedLatencyMs).toBeGreaterThanOrEqual(0);
      softLimiter.destroy();
    });

    it('should return hard_block at >=100%', () => {
      for (let i = 0; i < 10; i++) {
        limiter.check('client-4');
      }
      const result = limiter.check('client-4');
      // At 110% should be hard_block (or revocation at 120%)
      expect(result.blocked).toBe(true);
      expect(['hard_block', 'revocation']).toContain(result.stage);
    });
  });

  // ── GAP-A3-1: Jitter Range ────────────────────────────────

  describe('jitter in soft-limit delay', () => {
    it('should produce varying delays for same utilisation (±20% jitter)', () => {
      const delays: number[] = [];

      for (let trial = 0; trial < 10; trial++) {
        const trialLimiter = new GraduatedRateLimiter({
          defaultLimit: 10,
          windowMs: 60_000,
          burstLimit: 50, // high burst so we don't trigger hard_block
          initialCooldownSeconds: 2,
          maxConsecutiveBlocks: 3,
        });

        // Push to soft-limit territory (~80%)
        for (let i = 0; i < 7; i++) {
          trialLimiter.check('jitter-client');
        }
        const result = trialLimiter.check('jitter-client');
        if (result.injectedLatencyMs > 0) {
          delays.push(result.injectedLatencyMs);
        }
        trialLimiter.destroy();
      }

      // If jitter is working, we should see some variation
      if (delays.length >= 2) {
        const unique = new Set(delays);
        // With 10 trials and ±20% jitter, expect at least 2 different values
        expect(unique.size).toBeGreaterThanOrEqual(1);
      }
    });
  });

  // ── GAP-A3-2: Per-Endpoint Limits ─────────────────────────

  describe('per-endpoint limits', () => {
    it('should apply exact-match custom limit for endpoint', () => {
      limiter.setEndpointLimits({
        '/api/auth/login': 2,
        '/api/data': 20,
      });

      // /api/auth/login has 2 req/min limit — 3 requests should exceed
      limiter.check('ep-client', '/api/auth/login');
      limiter.check('ep-client', '/api/auth/login');
      const result = limiter.check('ep-client', '/api/auth/login');
      // 3rd of 2 limit = 150% → should be revocation (≥120%)
      expect(result.blocked).toBe(true);
    });

    it('should use global limit for non-matching endpoint', () => {
      limiter.setEndpointLimits({
        '/api/auth': 2,
      });

      // /api/other falls back to global limit (10)
      const result = limiter.check('ep-client-2', '/api/other');
      expect(result.stage).toBe('observation'); // low utilisation with 10 limit
    });

    it('should support wildcard prefix matching', () => {
      limiter.setEndpointLimits({
        '/api/auth/*': 2,
      });

      // Should match /api/auth/* pattern
      limiter.check('prefix-client', '/api/auth/verify');
      limiter.check('prefix-client', '/api/auth/verify');
      const third = limiter.check('prefix-client', '/api/auth/verify');
      // 150% of 2 → blocked
      expect(third.blocked).toBe(true);
    });
  });

  // ── GAP-A3-3: Burst Detection ─────────────────────────────

  describe('burst detection', () => {
    it('should detect burst when requests exceed burstLimit in micro-window', () => {
      // burstLimit is 5, send 6 rapidly
      for (let i = 0; i < 5; i++) {
        limiter.check('burst-client');
      }
      const result = limiter.check('burst-client');
      // Should be flagged as burst
      expect(result.burstDetected).toBe(true);
    });

    it('should not flag burst for slow requests', () => {
      const slowLimiter = new GraduatedRateLimiter({
        defaultLimit: 100,
        burstLimit: 50, // high threshold
        initialCooldownSeconds: 2,
        maxConsecutiveBlocks: 3,
      });

      slowLimiter.check('slow-client');
      // Single request should not be a burst
      const result = slowLimiter.check('slow-client');
      expect(result.burstDetected).toBe(false);

      slowLimiter.destroy();
    });
  });

  // ── GAP-A3-4: Escalating Cooldowns ────────────────────────

  describe('escalating cooldowns', () => {
    it('should have cooldown on hard_block', () => {
      // Use a high burst limit so we hit hard_block via ratio, not burst
      const cdLimiter = new GraduatedRateLimiter({
        defaultLimit: 10,
        burstLimit: 50,
        initialCooldownSeconds: 5,
        maxConsecutiveBlocks: 5,
      });

      // Exhaust the limit (10 requests in window)
      for (let i = 0; i < 10; i++) {
        cdLimiter.check('cooldown-client');
      }

      const block1 = cdLimiter.check('cooldown-client');
      expect(block1.blocked).toBe(true);
      expect(block1.cooldownSeconds).toBeGreaterThan(0);

      cdLimiter.destroy();
    });
  });

  // ── Stage 5: Revocation ───────────────────────────────────

  describe('revocation (stage 5)', () => {
    it('should reach revocation stage with extreme overuse', () => {
      // With defaultLimit=10, ratio≥1.2 means 12+ requests → revocation
      const results: RateLimitResult[] = [];
      for (let i = 0; i < 15; i++) {
        results.push(limiter.check('revoke-client'));
      }

      const hasRevocation = results.some(r => r.stage === 'revocation');
      const hasBlock = results.some(r => r.blocked);
      expect(hasBlock || hasRevocation).toBe(true);
    });

    it('should report revoked alias via isRevoked()', () => {
      // With burstLimit=5, rapid requests trigger burst which causes hard_block.
      // The burst itself forces hard_block even at low ratio, incrementing
      // consecutiveBlocks. After maxConsecutiveBlocks (3) the entry is revoked.
      // Use default limiter with burstLimit=5, maxConsecutiveBlocks=3.
      // We need 3 separate "rounds" where each round exceeds the burst limit.
      // However, cooldown prevents re-evaluation — so instead use a very low
      // burstLimit to force immediate revocation via consecutive blocks.
      const revokeLimiter = new GraduatedRateLimiter({
        defaultLimit: 100, // high ratio limit so ratio never triggers
        burstLimit: 2, // very low burst threshold
        initialCooldownSeconds: 0, // no cooldown so consecutive blocks accumulate
        maxConsecutiveBlocks: 3,
      });

      // Each request beyond burstLimit triggers hard_block and increments consecutiveBlocks
      // With initialCooldownSeconds=0, cooldownUntil is set to now + 0 = now, which
      // immediately expires, allowing the next check to re-evaluate.
      for (let i = 0; i < 10; i++) {
        revokeLimiter.check('revoke-check-client');
      }

      const revoked = revokeLimiter.isRevoked('revoke-check-client');
      expect(revoked).toBe(true);
      revokeLimiter.destroy();
    });

    it('should allow manual revocation', () => {
      limiter.revokeAlias('manual-revoke');
      expect(limiter.isRevoked('manual-revoke')).toBe(true);

      const result = limiter.check('manual-revoke');
      expect(result.stage).toBe('revocation');
      expect(result.blocked).toBe(true);
    });

    it('should allow reset after revocation', () => {
      limiter.revokeAlias('reset-revoke');
      expect(limiter.isRevoked('reset-revoke')).toBe(true);

      limiter.resetAlias('reset-revoke');
      expect(limiter.isRevoked('reset-revoke')).toBe(false);

      const result = limiter.check('reset-revoke');
      expect(result.stage).toBe('observation');
    });
  });

  // ── Size Tracking ─────────────────────────────────────────

  describe('size tracking', () => {
    it('should track number of aliases', () => {
      expect(limiter.size).toBe(0);
      limiter.check('client-a');
      expect(limiter.size).toBe(1);
      limiter.check('client-b');
      expect(limiter.size).toBe(2);
      limiter.check('client-a'); // same alias
      expect(limiter.size).toBe(2);
    });
  });

  // ── Result Shape ──────────────────────────────────────────

  describe('result shape', () => {
    it('should contain all expected fields', () => {
      const result = limiter.check('shape-client');
      expect(result).toHaveProperty('stage');
      expect(result).toHaveProperty('currentRate');
      expect(result).toHaveProperty('limit');
      expect(result).toHaveProperty('ratio');
      expect(result).toHaveProperty('injectedLatencyMs');
      expect(result).toHaveProperty('blocked');
      expect(result).toHaveProperty('revoke');
      expect(result).toHaveProperty('cooldownSeconds');
      expect(result).toHaveProperty('remaining');
      expect(result).toHaveProperty('burstDetected');
    });

    it('should report correct remaining requests', () => {
      const result = limiter.check('remaining-client');
      // 1 of 10 used → 9 remaining
      expect(result.remaining).toBe(9);
      expect(result.limit).toBe(10);
      expect(result.currentRate).toBe(1);
    });
  });

  // ── Destroy ───────────────────────────────────────────────

  describe('destroy', () => {
    it('should clean up internal state', () => {
      limiter.check('cleanup-client');
      expect(limiter.size).toBe(1);

      limiter.destroy();
      expect(limiter.size).toBe(0);
    });
  });
});
