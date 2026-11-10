package devfortress

import (
	"sync"
	"time"
)

// ── PlatformCircuitBreaker ───────────────────────────────────────────────

// Mirrors the Node SDK's PlatformCircuitBreaker (circuit-breaker.ts).
// Monitors connectivity to the DevFortress platform and provides
// automatic failover from external to internal closed-loop mode.
//
// Three states:
//
//	Closed:   Platform is reachable, external CL is active.
//	Open:     Platform is unreachable, internal CL takes over.
//	HalfOpen: Testing if the platform has recovered.
//
// Transition rules:
//
//	Closed -> Open:     After FailureThreshold consecutive failures.
//	Open -> HalfOpen:   After RecoveryTime has elapsed.
//	HalfOpen -> Closed: First successful call.
//	HalfOpen -> Open:   First failed call.

// CircuitState is a PlatformCircuitBreaker's state.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half-open"
)

// CircuitBreakerConfig configures a PlatformCircuitBreaker. Mirrors the
// Node SDK's CircuitBreakerConfig.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before
	// opening the circuit. Default: 3.
	FailureThreshold int
	// RecoveryTime is how long to wait before testing recovery.
	// Default: 1 minute.
	RecoveryTime time.Duration
	// OnStateChange is called when the circuit's state changes.
	OnStateChange func(from, to CircuitState, reason string)
}

// CircuitBreakerDiagnostics is the result of
// PlatformCircuitBreaker.Diagnostics.
type CircuitBreakerDiagnostics struct {
	State                CircuitState
	FailureCount         int
	LastFailureTime      time.Time
	TimeUntilRecoveryAttempt time.Duration
	// RulesStale is whether internal rules are potentially stale (no
	// platform sync).
	RulesStale bool
	// StaleDuration is how long rules have been stale, zero if not
	// stale.
	StaleDuration time.Duration
}

// PlatformCircuitBreaker tracks platform connectivity and signals when
// external calls should be attempted vs. when internal closed-loop mode
// should take over. Mirrors the Node SDK's PlatformCircuitBreaker
// (circuit-breaker.ts). Safe for concurrent use.
type PlatformCircuitBreaker struct {
	mu               sync.Mutex
	state            CircuitState
	failureCount     int
	lastFailureTime  time.Time
	failureThreshold int
	recoveryTime     time.Duration
	onStateChange    func(from, to CircuitState, reason string)

	// staleSince tracks when internal rules became stale (circuit
	// opened). Rules older than StaleThreshold without a platform sync
	// are considered stale.
	staleSince *time.Time
}

// StaleThreshold is how long the circuit must stay open before internal
// rules are considered stale. Mirrors the Node SDK's
// STALE_THRESHOLD_MS (5 minutes).
const StaleThreshold = 5 * time.Minute

// NewPlatformCircuitBreaker creates a PlatformCircuitBreaker, starting
// in the closed state.
func NewPlatformCircuitBreaker(cfg CircuitBreakerConfig) *PlatformCircuitBreaker {
	if cfg.FailureThreshold == 0 {
		cfg.FailureThreshold = 3
	}
	if cfg.RecoveryTime == 0 {
		cfg.RecoveryTime = time.Minute
	}
	return &PlatformCircuitBreaker{
		state:            CircuitClosed,
		failureThreshold: cfg.FailureThreshold,
		recoveryTime:     cfg.RecoveryTime,
		onStateChange:    cfg.OnStateChange,
	}
}

// ShouldCallExternal reports whether external platform calls should be
// attempted. Returns true if the circuit allows external calls (closed
// or half-open).
func (b *PlatformCircuitBreaker) ShouldCallExternal() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == CircuitClosed {
		return true
	}

	if b.state == CircuitOpen {
		if time.Since(b.lastFailureTime) >= b.recoveryTime {
			b.transition(CircuitHalfOpen, "recovery_timeout_elapsed")
			return true // allow one test call
		}
		return false
	}

	// Half-open: allow the test call.
	return true
}

// RecordSuccess records a successful external call.
func (b *PlatformCircuitBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == CircuitHalfOpen {
		b.transition(CircuitClosed, "test_call_succeeded")
	}
	b.failureCount = 0
	// Reset stale tracking: rules are now fresh.
	b.staleSince = nil
}

// RecordFailure records a failed external call.
func (b *PlatformCircuitBreaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failureCount++
	b.lastFailureTime = time.Now()

	if b.state == CircuitHalfOpen {
		b.transition(CircuitOpen, "test_call_failed")
		return
	}

	if b.state == CircuitClosed && b.failureCount >= b.failureThreshold {
		b.transition(CircuitOpen, "consecutive_failures")
	}
}

// State returns the current circuit state.
func (b *PlatformCircuitBreaker) State() CircuitState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Diagnostics returns diagnostics info.
func (b *PlatformCircuitBreaker) Diagnostics() CircuitBreakerDiagnostics {
	b.mu.Lock()
	defer b.mu.Unlock()

	var timeUntilRecovery time.Duration
	if b.state == CircuitOpen {
		elapsed := time.Since(b.lastFailureTime)
		if elapsed < b.recoveryTime {
			timeUntilRecovery = b.recoveryTime - elapsed
		}
	}

	var staleDuration time.Duration
	if b.staleSince != nil {
		staleDuration = time.Since(*b.staleSince)
	}

	return CircuitBreakerDiagnostics{
		State:                    b.state,
		FailureCount:             b.failureCount,
		LastFailureTime:          b.lastFailureTime,
		TimeUntilRecoveryAttempt: timeUntilRecovery,
		RulesStale:               staleDuration > StaleThreshold,
		StaleDuration:            staleDuration,
	}
}

// Reset forces the circuit breaker back to the closed state.
func (b *PlatformCircuitBreaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.transition(CircuitClosed, "manual_reset")
	b.failureCount = 0
	b.lastFailureTime = time.Time{}
	b.staleSince = nil
}

// IsRulesStale reports whether internal rules are stale (no platform
// sync for longer than StaleThreshold).
func (b *PlatformCircuitBreaker) IsRulesStale() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.staleSince != nil && time.Since(*b.staleSince) > StaleThreshold
}

// transition changes state and fires OnStateChange. Caller must hold
// b.mu.
func (b *PlatformCircuitBreaker) transition(to CircuitState, reason string) {
	from := b.state
	if from == to {
		return
	}
	b.state = to

	if to == CircuitOpen && b.staleSince == nil {
		now := time.Now()
		b.staleSince = &now
	}

	if b.onStateChange != nil {
		// Callback panics should not break the circuit breaker, mirroring
		// the Node SDK's try/catch around onStateChange.
		func() {
			defer func() { recover() }()
			b.onStateChange(from, to, reason)
		}()
	}
}
