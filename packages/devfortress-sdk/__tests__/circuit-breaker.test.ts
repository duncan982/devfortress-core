/**
 * Tests for PlatformCircuitBreaker (CL-M2)
 *
 * Coverage: state transitions, shouldCallExternal, recovery timeout,
 * half-open test calls, getDiagnostics, reset.
 */
import {
  PlatformCircuitBreaker,
  type CircuitState,
} from '../src/circuit-breaker';

describe('PlatformCircuitBreaker', () => {
  let cb: PlatformCircuitBreaker;

  beforeEach(() => {
    cb = new PlatformCircuitBreaker({
      failureThreshold: 3,
      recoveryTimeMs: 1000, // 1s for fast tests
    });
  });

  // ── Initial State ─────────────────────────────────────────

  describe('initialization', () => {
    it('should start in closed state', () => {
      expect(cb.getState()).toBe('closed');
    });

    it('should allow external calls when closed', () => {
      expect(cb.shouldCallExternal()).toBe(true);
    });

    it('should report zero failures in diagnostics', () => {
      const diag = cb.getDiagnostics();
      expect(diag.state).toBe('closed');
      expect(diag.failureCount).toBe(0);
      expect(diag.lastFailureTime).toBe(0);
      expect(diag.msUntilRecoveryAttempt).toBe(0);
    });

    it('should use default config when none provided', () => {
      const defaultCb = new PlatformCircuitBreaker();
      expect(defaultCb.getState()).toBe('closed');
      expect(defaultCb.shouldCallExternal()).toBe(true);
    });
  });

  // ── Closed → Open Transition ──────────────────────────────

  describe('closed → open transition', () => {
    it('should remain closed after fewer failures than threshold', () => {
      cb.recordFailure();
      cb.recordFailure();
      expect(cb.getState()).toBe('closed');
      expect(cb.shouldCallExternal()).toBe(true);
    });

    it('should open after reaching failure threshold', () => {
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();
      expect(cb.getState()).toBe('open');
    });

    it('should block external calls when open', () => {
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();
      expect(cb.shouldCallExternal()).toBe(false);
    });

    it('should track failure count in diagnostics', () => {
      cb.recordFailure();
      cb.recordFailure();
      const diag = cb.getDiagnostics();
      expect(diag.failureCount).toBe(2);
      expect(diag.lastFailureTime).toBeGreaterThan(0);
    });
  });

  // ── Open → Half-Open Transition ───────────────────────────

  describe('open → half-open transition', () => {
    it('should transition to half-open after recovery timeout', async () => {
      // Open the circuit
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();
      expect(cb.getState()).toBe('open');

      // Wait for recovery
      await new Promise(resolve => setTimeout(resolve, 1100));

      // shouldCallExternal triggers the transition
      expect(cb.shouldCallExternal()).toBe(true);
      expect(cb.getState()).toBe('half-open');
    });

    it('should report msUntilRecoveryAttempt when open', () => {
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();

      const diag = cb.getDiagnostics();
      expect(diag.msUntilRecoveryAttempt).toBeGreaterThan(0);
      expect(diag.msUntilRecoveryAttempt).toBeLessThanOrEqual(1000);
    });
  });

  // ── Half-Open → Closed (recovery) ────────────────────────

  describe('half-open → closed (recovery)', () => {
    it('should return to closed on successful test call', async () => {
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();

      await new Promise(resolve => setTimeout(resolve, 1100));
      cb.shouldCallExternal(); // triggers half-open

      cb.recordSuccess();
      expect(cb.getState()).toBe('closed');
      expect(cb.shouldCallExternal()).toBe(true);
    });
  });

  // ── Half-Open → Open (test fail) ─────────────────────────

  describe('half-open → open (test failure)', () => {
    it('should re-open on failed test call', async () => {
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();

      await new Promise(resolve => setTimeout(resolve, 1100));
      cb.shouldCallExternal(); // triggers half-open

      cb.recordFailure();
      expect(cb.getState()).toBe('open');
    });
  });

  // ── Success Resets Failure Count ──────────────────────────

  describe('success handling', () => {
    it('should reset failure count on success while closed', () => {
      cb.recordFailure();
      cb.recordFailure();
      cb.recordSuccess();

      // Should take 3 more failures to open now
      cb.recordFailure();
      cb.recordFailure();
      expect(cb.getState()).toBe('closed');
    });
  });

  // ── Manual Reset ──────────────────────────────────────────

  describe('reset', () => {
    it('should force close the circuit', () => {
      cb.recordFailure();
      cb.recordFailure();
      cb.recordFailure();
      expect(cb.getState()).toBe('open');

      cb.reset();
      expect(cb.getState()).toBe('closed');
      expect(cb.getDiagnostics().failureCount).toBe(0);
      expect(cb.getDiagnostics().lastFailureTime).toBe(0);
    });
  });

  // ── State Change Callback ─────────────────────────────────

  describe('onStateChange callback', () => {
    it('should fire callback on state transitions', () => {
      const transitions: Array<{
        from: CircuitState;
        to: CircuitState;
        reason: string;
      }> = [];

      const tracked = new PlatformCircuitBreaker({
        failureThreshold: 2,
        recoveryTimeMs: 100,
        onStateChange: (from, to, reason) => {
          transitions.push({ from, to, reason });
        },
      });

      tracked.recordFailure();
      tracked.recordFailure();

      expect(transitions).toHaveLength(1);
      expect(transitions[0]).toEqual({
        from: 'closed',
        to: 'open',
        reason: '2_consecutive_failures',
      });
    });

    it('should survive callback errors without breaking circuit', () => {
      const errorCb = new PlatformCircuitBreaker({
        failureThreshold: 1,
        onStateChange: () => {
          throw new Error('callback error');
        },
      });

      // Should not throw
      expect(() => errorCb.recordFailure()).not.toThrow();
      expect(errorCb.getState()).toBe('open');
    });
  });
});
