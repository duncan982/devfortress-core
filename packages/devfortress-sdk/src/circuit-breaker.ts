/**
 * DevFortress SDK — Platform Circuit Breaker
 *
 * Monitors connectivity to the DevFortress platform and provides
 * automatic failover from external to internal closed-loop mode.
 *
 * Three states:
 *   - CLOSED:    Platform is reachable, external CL is active
 *   - OPEN:      Platform is unreachable, internal CL takes over
 *   - HALF-OPEN: Testing if platform has recovered
 *
 * Transition rules:
 *   CLOSED → OPEN:      After `failureThreshold` consecutive failures
 *   OPEN → HALF-OPEN:   After `recoveryTimeMs` elapsed
 *   HALF-OPEN → CLOSED: First successful call
 *   HALF-OPEN → OPEN:   First failed call
 *
 * @packageDocumentation
 */

export type CircuitState = 'closed' | 'open' | 'half-open';

export interface CircuitBreakerConfig {
  /** Number of consecutive failures before opening the circuit. Default: 3 */
  failureThreshold?: number;
  /** Time in ms to wait before testing recovery. Default: 60_000 (1 min) */
  recoveryTimeMs?: number;
  /** Callback when circuit state changes */
  onStateChange?: (
    from: CircuitState,
    to: CircuitState,
    reason: string
  ) => void;
}

export class PlatformCircuitBreaker {
  private state: CircuitState = 'closed';
  private failureCount = 0;
  private lastFailureTime = 0;
  private failureThreshold: number;
  private recoveryTimeMs: number;
  private onStateChange?: CircuitBreakerConfig['onStateChange'];

  // S27: Track when internal rules became stale (circuit opened)
  private staleSince: number | null = null;
  /** Rules older than 5 minutes without platform sync are considered stale */
  static readonly STALE_THRESHOLD_MS = 300_000; // 5 min

  constructor(config: CircuitBreakerConfig = {}) {
    this.failureThreshold = config.failureThreshold ?? 3;
    this.recoveryTimeMs = config.recoveryTimeMs ?? 60_000;
    this.onStateChange = config.onStateChange;
  }

  /**
   * Check if external platform calls should be attempted.
   * Returns true if the circuit allows external calls (CLOSED or HALF-OPEN).
   */
  shouldCallExternal(): boolean {
    if (this.state === 'closed') return true;

    if (this.state === 'open') {
      // Check if recovery time has elapsed
      if (Date.now() - this.lastFailureTime >= this.recoveryTimeMs) {
        this.transition('half-open', 'recovery_timeout_elapsed');
        return true; // Allow one test call
      }
      return false;
    }

    // half-open — allow the test call
    return true;
  }

  /**
   * Record a successful external call.
   */
  recordSuccess(): void {
    if (this.state === 'half-open') {
      this.transition('closed', 'test_call_succeeded');
    }
    this.failureCount = 0;
    // S27: Reset stale tracking — rules are now fresh
    this.staleSince = null;
  }

  /**
   * Record a failed external call.
   */
  recordFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === 'half-open') {
      this.transition('open', 'test_call_failed');
      return;
    }

    if (this.state === 'closed' && this.failureCount >= this.failureThreshold) {
      this.transition('open', `${this.failureCount}_consecutive_failures`);
    }
  }

  /**
   * Get current circuit state.
   */
  getState(): CircuitState {
    return this.state;
  }

  /**
   * Get diagnostics info.
   */
  getDiagnostics(): {
    state: CircuitState;
    failureCount: number;
    lastFailureTime: number;
    msUntilRecoveryAttempt: number;
    /** S27: Whether internal rules are potentially stale (no platform sync) */
    rulesStale: boolean;
    /** S27: How long rules have been stale (ms), 0 if not stale */
    staleDurationMs: number;
  } {
    const msUntilRecovery =
      this.state === 'open'
        ? Math.max(0, this.recoveryTimeMs - (Date.now() - this.lastFailureTime))
        : 0;

    const staleDurationMs = this.staleSince ? Date.now() - this.staleSince : 0;

    return {
      state: this.state,
      failureCount: this.failureCount,
      lastFailureTime: this.lastFailureTime,
      msUntilRecoveryAttempt: msUntilRecovery,
      rulesStale: staleDurationMs > PlatformCircuitBreaker.STALE_THRESHOLD_MS,
      staleDurationMs,
    };
  }

  /**
   * Force reset the circuit breaker to closed state.
   */
  reset(): void {
    this.transition('closed', 'manual_reset');
    this.failureCount = 0;
    this.lastFailureTime = 0;
    this.staleSince = null;
  }

  /**
   * S27: Check if internal rules are stale (no platform sync for >5 min).
   * Returns true when circuit has been OPEN for longer than STALE_THRESHOLD_MS.
   */
  isRulesStale(): boolean {
    return (
      this.staleSince !== null &&
      Date.now() - this.staleSince > PlatformCircuitBreaker.STALE_THRESHOLD_MS
    );
  }

  private transition(to: CircuitState, reason: string): void {
    const from = this.state;
    if (from === to) return;
    this.state = to;

    // S27: Track when rules became stale (circuit opened)
    if (to === 'open' && this.staleSince === null) {
      this.staleSince = Date.now();
    }

    if (this.onStateChange) {
      try {
        this.onStateChange(from, to, reason);
      } catch {
        // Callback errors should not break the circuit breaker
      }
    }
  }
}
