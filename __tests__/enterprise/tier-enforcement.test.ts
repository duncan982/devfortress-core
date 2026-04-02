/**
 * Tests for Tier Enforcement Middleware — Closed-Loop Feature Gating
 *
 * Validates that CL features are correctly gated per tier:
 *   Starter: View-only; cannot block
 *   Pro: External CL blocking; hybrid CL as add-on; internal CL as backup only
 *   Enterprise: All modes available (default: hybrid)
 */

import {
  enforceTier,
  checkFeatureLimit,
  getTierFeatures,
  FEATURE_GATES,
} from '../../lib/enterprise/tier-enforcement';

describe('Tier Enforcement — Closed-Loop Gating', () => {
  // ── External CL Blocking ──────────────────────────────────

  describe('external_closed_loop_blocking', () => {
    it('should deny external CL blocking for free tier', () => {
      const result = enforceTier(
        'free',
        'pro',
        'external_closed_loop_blocking'
      );
      expect(result).not.toBeNull();
      expect(result?.status).toBe(403);
    });

    it('should deny external CL blocking for starter tier', () => {
      const result = enforceTier(
        'starter',
        'pro',
        'external_closed_loop_blocking'
      );
      expect(result).not.toBeNull();
      expect(result?.status).toBe(403);
    });

    it('should allow external CL blocking for pro tier', () => {
      const result = enforceTier('pro', 'pro', 'external_closed_loop_blocking');
      expect(result).toBeNull();
    });

    it('should allow external CL blocking for enterprise tier', () => {
      const result = enforceTier(
        'enterprise',
        'pro',
        'external_closed_loop_blocking'
      );
      expect(result).toBeNull();
    });
  });

  // ── Internal CL ───────────────────────────────────────────

  describe('internal_closed_loop', () => {
    it('should deny internal CL for starter tier', () => {
      const result = enforceTier('starter', 'pro', 'internal_closed_loop');
      expect(result).not.toBeNull();
    });

    it('should allow internal CL for pro (as backup, limit=0)', () => {
      const gate = FEATURE_GATES.find(
        g => g.feature === 'internal_closed_loop'
      );
      expect(gate).toBeDefined();
      expect(gate?.limits?.pro).toBe(0);
    });

    it('should allow unlimited internal CL for enterprise', () => {
      const gate = FEATURE_GATES.find(
        g => g.feature === 'internal_closed_loop'
      );
      expect(gate?.limits?.enterprise).toBe(-1);
    });
  });

  // ── Hybrid CL ────────────────────────────────────────────

  describe('hybrid_closed_loop', () => {
    it('should deny hybrid CL for starter tier', () => {
      const result = enforceTier('starter', 'pro', 'hybrid_closed_loop');
      expect(result).not.toBeNull();
    });

    it('should gate hybrid CL as add-on for pro (limit=1)', () => {
      const gate = FEATURE_GATES.find(g => g.feature === 'hybrid_closed_loop');
      expect(gate).toBeDefined();
      expect(gate?.minimumTier).toBe('pro');
      expect(gate?.limits?.pro).toBe(1);
    });

    it('should include hybrid CL unlimited for enterprise', () => {
      const gate = FEATURE_GATES.find(g => g.feature === 'hybrid_closed_loop');
      expect(gate?.limits?.enterprise).toBe(-1);
    });

    it('should allow hybrid CL for pro tier (with add-on)', () => {
      const limit = checkFeatureLimit('hybrid_closed_loop', 'pro', 0);
      expect(limit.allowed).toBe(true);
    });

    it('should deny hybrid CL for pro if at limit', () => {
      const limit = checkFeatureLimit('hybrid_closed_loop', 'pro', 1);
      expect(limit.allowed).toBe(false);
    });

    it('should always allow hybrid CL for enterprise', () => {
      const limit = checkFeatureLimit('hybrid_closed_loop', 'enterprise', 999);
      expect(limit.allowed).toBe(true);
    });
  });

  // ── Air-Gap Mode ──────────────────────────────────────────

  describe('air_gap_mode', () => {
    it('should deny air-gap mode for starter', () => {
      const result = enforceTier('starter', 'enterprise', 'air_gap_mode');
      expect(result).not.toBeNull();
    });

    it('should deny air-gap mode for pro', () => {
      const result = enforceTier('pro', 'enterprise', 'air_gap_mode');
      expect(result).not.toBeNull();
    });

    it('should allow air-gap mode for enterprise', () => {
      const result = enforceTier('enterprise', 'enterprise', 'air_gap_mode');
      expect(result).toBeNull();
    });
  });

  // ── Starter: View-Only (No Blocking) ──────────────────────

  describe('starter tier — view-only enforcement', () => {
    it('should deny automated_ip_blocking', () => {
      const result = enforceTier('starter', 'pro', 'automated_ip_blocking');
      expect(result).not.toBeNull();
    });

    it('should deny session_revocation', () => {
      const result = enforceTier('starter', 'pro', 'session_revocation');
      expect(result).not.toBeNull();
    });

    it('should deny account_lock', () => {
      const result = enforceTier('starter', 'pro', 'account_lock');
      expect(result).not.toBeNull();
    });

    it('should allow pre_auth_detection (limited)', () => {
      const result = enforceTier('starter', 'starter', 'pre_auth_detection');
      expect(result).toBeNull();
    });

    it('should enforce pre_auth_detection limit of 2', () => {
      const limit = checkFeatureLimit('pre_auth_detection', 'starter', 2);
      expect(limit.allowed).toBe(false);
    });
  });

  // ── getTierFeatures ───────────────────────────────────────

  describe('getTierFeatures', () => {
    it('should list CL features for starter as unavailable', () => {
      const features = getTierFeatures('starter');
      const externalCL = features.find(
        f => f.feature === 'external_closed_loop_blocking'
      );
      expect(externalCL?.available).toBe(false);
    });

    it('should list CL features for pro as available', () => {
      const features = getTierFeatures('pro');
      const externalCL = features.find(
        f => f.feature === 'external_closed_loop_blocking'
      );
      expect(externalCL?.available).toBe(true);
    });

    it('should list air_gap_mode for enterprise as available', () => {
      const features = getTierFeatures('enterprise');
      const airGap = features.find(f => f.feature === 'air_gap_mode');
      expect(airGap?.available).toBe(true);
    });

    it('should list air_gap_mode for pro as unavailable', () => {
      const features = getTierFeatures('pro');
      const airGap = features.find(f => f.feature === 'air_gap_mode');
      expect(airGap?.available).toBe(false);
    });
  });

  // ── FEATURE_GATES completeness ────────────────────────────

  describe('FEATURE_GATES CL completeness', () => {
    const clFeatures = [
      'external_closed_loop_blocking',
      'internal_closed_loop',
      'hybrid_closed_loop',
      'air_gap_mode',
    ];

    it.each(clFeatures)('should have feature gate for %s', feature => {
      const gate = FEATURE_GATES.find(g => g.feature === feature);
      expect(gate).toBeDefined();
    });
  });
});
