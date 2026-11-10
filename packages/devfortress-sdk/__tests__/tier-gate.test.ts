/**
 * Tests for TierGate — Feature Access Control
 *
 * Coverage: getEffectiveMode, canBlock, checkEventLimit, recordEvent,
 * validateBlockAction, validateMode, hasFeature, getCapabilities.
 */
import { TierGate, type SubscriptionTier } from '../src/tier-gate';

describe('TierGate', () => {
  // ── Starter Tier ──────────────────────────────────────────

  describe('starter tier', () => {
    let gate: TierGate;

    beforeEach(() => {
      gate = new TierGate('starter');
    });

    it('should default to external mode', () => {
      expect(gate.getEffectiveMode()).toBe('external');
    });

    it('should reject internal mode request', () => {
      expect(gate.getEffectiveMode('internal')).toBe('external');
    });

    it('should reject hybrid mode request', () => {
      expect(gate.getEffectiveMode('hybrid')).toBe('external');
    });

    it('should not allow blocking', () => {
      expect(gate.canBlock()).toBe(false);
    });

    it('should return error for block action', () => {
      const error = gate.validateBlockAction('block_ip');
      expect(error).toContain('not available on the starter tier');
    });

    it('should enforce 10K daily event limit', () => {
      const caps = gate.getCapabilities();
      expect(caps.maxEventsPerDay).toBe(10_000);
    });

    it('should not have audit access', () => {
      expect(gate.hasFeature('canAccessAudit')).toBe(false);
    });

    it('should not have webhook management', () => {
      expect(gate.hasFeature('canManageWebhooks')).toBe(false);
    });

    it('should not have custom rules', () => {
      expect(gate.hasFeature('canConfigureRules')).toBe(false);
    });

    it('should return correct tier name', () => {
      expect(gate.getTier()).toBe('starter');
    });

    it('should return error for internal mode validation', () => {
      const error = gate.validateMode('internal');
      expect(error).toContain('not available on the starter tier');
    });

    it('should return error for hybrid mode validation', () => {
      const error = gate.validateMode('hybrid');
      expect(error).toContain('not available on the starter tier');
    });

    it('should accept external mode validation', () => {
      expect(gate.validateMode('external')).toBeNull();
    });
  });

  // ── Pro Tier ──────────────────────────────────────────────

  describe('pro tier', () => {
    it('should default to external mode', () => {
      const gate = new TierGate('pro');
      expect(gate.getEffectiveMode()).toBe('external');
    });

    it('should allow external mode', () => {
      const gate = new TierGate('pro');
      expect(gate.getEffectiveMode('external')).toBe('external');
    });

    it('should reject hybrid without addon', () => {
      const gate = new TierGate('pro');
      expect(gate.getEffectiveMode('hybrid')).toBe('external');
    });

    it('should reject hybrid even with the (now-defunct) addon flag enabled', () => {
      // Package A (2026-08-28): Pro never gets ICL/hybrid at any point —
      // hybridAddonEnabled has no effect since hybrid isn't in Pro's allowedModes.
      const gate = new TierGate('pro', { hybridAddonEnabled: true });
      expect(gate.getEffectiveMode('hybrid')).toBe('external');
    });

    it('should have no ICL access', () => {
      const gate = new TierGate('pro');
      expect(gate.getMaxICLTier()).toBe(0);
    });

    it('should reject internal mode', () => {
      const gate = new TierGate('pro');
      expect(gate.getEffectiveMode('internal')).toBe('external');
    });

    it('should allow blocking', () => {
      const gate = new TierGate('pro');
      expect(gate.canBlock()).toBe(true);
    });

    it('should allow block action', () => {
      const gate = new TierGate('pro');
      expect(gate.validateBlockAction('block_ip')).toBeNull();
    });

    it('should enforce 100K daily event limit', () => {
      const gate = new TierGate('pro');
      expect(gate.getCapabilities().maxEventsPerDay).toBe(100_000);
    });

    it('should limit blocked IPs to 1000', () => {
      const gate = new TierGate('pro');
      expect(gate.getCapabilities().maxBlockedIPs).toBe(1_000);
    });

    it('should have audit access', () => {
      const gate = new TierGate('pro');
      expect(gate.hasFeature('canAccessAudit')).toBe(true);
    });

    it('should have webhook management', () => {
      const gate = new TierGate('pro');
      expect(gate.hasFeature('canManageWebhooks')).toBe(true);
    });

    it('should not have custom rules', () => {
      const gate = new TierGate('pro');
      expect(gate.hasFeature('canConfigureRules')).toBe(false);
    });
  });

  // ── Team Tier (TODO 189) ───────────────────────────────────

  describe('team tier', () => {
    it('should default to hybrid mode', () => {
      const gate = new TierGate('team');
      expect(gate.getEffectiveMode()).toBe('hybrid');
    });

    it('should allow external, internal, and hybrid modes', () => {
      const gate = new TierGate('team');
      expect(gate.getEffectiveMode('external')).toBe('external');
      expect(gate.getEffectiveMode('internal')).toBe('internal');
      expect(gate.getEffectiveMode('hybrid')).toBe('hybrid');
    });

    it('should allow blocking', () => {
      const gate = new TierGate('team');
      expect(gate.canBlock()).toBe(true);
    });

    it('should have ICL Tier 2 access', () => {
      const gate = new TierGate('team');
      expect(gate.getMaxICLTier()).toBe(2);
      expect(gate.isICLTierAvailable(2)).toBe(true);
      expect(gate.isICLTierAvailable(3)).toBe(false);
    });

    it('should not require a hybrid addon', () => {
      const gate = new TierGate('team');
      expect(gate.getCapabilities().hybridIsAddon).toBe(false);
    });

    it('should round-trip through a snapshot and retain mode/block permissions', () => {
      const gate = new TierGate('team');
      gate.recordEvent();
      gate.recordMonthlyEvent();
      const snapshot = gate.toSnapshot();
      expect(snapshot.tier).toBe('team');

      const restored = TierGate.fromSnapshot(snapshot);
      expect(restored.getTier()).toBe('team');
      expect(restored.getEffectiveMode()).toBe('hybrid');
      expect(restored.canBlock()).toBe(true);
      expect(restored.getEffectiveMode('internal')).toBe('internal');
    });
  });

  // ── Enterprise Tier ───────────────────────────────────────

  describe('enterprise tier', () => {
    let gate: TierGate;

    beforeEach(() => {
      gate = new TierGate('enterprise');
    });

    it('should default to hybrid mode', () => {
      expect(gate.getEffectiveMode()).toBe('hybrid');
    });

    it('should allow all three modes', () => {
      expect(gate.getEffectiveMode('external')).toBe('external');
      expect(gate.getEffectiveMode('internal')).toBe('internal');
      expect(gate.getEffectiveMode('hybrid')).toBe('hybrid');
    });

    it('should allow blocking', () => {
      expect(gate.canBlock()).toBe(true);
    });

    it('should have unlimited events (0 = unlimited)', () => {
      expect(gate.getCapabilities().maxEventsPerDay).toBe(0);
    });

    it('should have unlimited blocked IPs (0 = unlimited)', () => {
      expect(gate.getCapabilities().maxBlockedIPs).toBe(0);
    });

    it('should have custom rules', () => {
      expect(gate.hasFeature('canConfigureRules')).toBe(true);
    });

    it('should have audit access', () => {
      expect(gate.hasFeature('canAccessAudit')).toBe(true);
    });

    it('should have webhook management', () => {
      expect(gate.hasFeature('canManageWebhooks')).toBe(true);
    });

    it('should validate all modes', () => {
      expect(gate.validateMode('external')).toBeNull();
      expect(gate.validateMode('internal')).toBeNull();
      expect(gate.validateMode('hybrid')).toBeNull();
    });

    it('should not require hybrid addon', () => {
      expect(gate.getCapabilities().hybridIsAddon).toBe(false);
    });
  });

  // ── Event Limit Tracking ─────────────────────────────────

  describe('event limit tracking', () => {
    it('should allow events below the limit', () => {
      const gate = new TierGate('starter');
      const check = gate.checkEventLimit();
      expect(check.allowed).toBe(true);
      expect(check.remaining).toBe(10_000);
    });

    it('should decrement remaining on recordEvent', () => {
      const gate = new TierGate('starter');
      gate.recordEvent();
      gate.recordEvent();
      gate.recordEvent();

      const check = gate.checkEventLimit();
      expect(check.remaining).toBe(9_997);
    });

    it('should return unlimited for enterprise', () => {
      const gate = new TierGate('enterprise');
      const check = gate.checkEventLimit();
      expect(check.allowed).toBe(true);
      expect(check.remaining).toBe(Infinity);
    });

    it('should block events at the limit', () => {
      // Use a small custom max to test quickly
      const gate = new TierGate('starter');
      // Record 10,000 events
      for (let i = 0; i < 10_000; i++) {
        gate.recordEvent();
      }

      const check = gate.checkEventLimit();
      expect(check.allowed).toBe(false);
      expect(check.remaining).toBe(0);
    });
  });

  // ── getCapabilities ───────────────────────────────────────

  describe('getCapabilities', () => {
    it('should return readonly capabilities', () => {
      const gate = new TierGate('pro');
      const caps = gate.getCapabilities();

      expect(caps.canObserve).toBe(true);
      expect(caps.canBlock).toBe(true);
      expect(caps.allowedModes).toContain('external');
      expect(caps.allowedModes).not.toContain('hybrid');
      expect(caps.allowedModes).not.toContain('internal');
    });
  });

  // ── hasFeature ────────────────────────────────────────────

  describe('hasFeature', () => {
    it('should return true for boolean true features', () => {
      const gate = new TierGate('enterprise');
      expect(gate.hasFeature('canObserve')).toBe(true);
      expect(gate.hasFeature('canBlock')).toBe(true);
    });

    it('should return false for boolean false features', () => {
      const gate = new TierGate('starter');
      expect(gate.hasFeature('canBlock')).toBe(false);
    });

    it('should return true for array features with items', () => {
      const gate = new TierGate('enterprise');
      expect(gate.hasFeature('allowedModes')).toBe(true);
    });

    it('should return true for numeric features (including 0 = unlimited)', () => {
      const gate = new TierGate('enterprise');
      // maxEventsPerDay is 0 (unlimited), which should still return true
      expect(gate.hasFeature('maxEventsPerDay')).toBe(true);
    });
  });
});
