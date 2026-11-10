package devfortress

import (
	"testing"
	"time"
)

func TestPlatformCircuitBreaker_StartsClosedAndAllowsExternalCalls(t *testing.T) {
	b := NewPlatformCircuitBreaker(CircuitBreakerConfig{})
	if b.State() != CircuitClosed {
		t.Fatalf("expected initial state closed, got %s", b.State())
	}
	if !b.ShouldCallExternal() {
		t.Fatalf("expected closed circuit to allow external calls")
	}
}

func TestPlatformCircuitBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	var transitions []string
	b := NewPlatformCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		OnStateChange: func(from, to CircuitState, reason string) {
			transitions = append(transitions, string(from)+"->"+string(to))
		},
	})

	b.RecordFailure()
	b.RecordFailure()
	if b.State() != CircuitClosed {
		t.Fatalf("expected circuit to stay closed before threshold, got %s", b.State())
	}
	b.RecordFailure()
	if b.State() != CircuitOpen {
		t.Fatalf("expected circuit to open at failure threshold, got %s", b.State())
	}
	if len(transitions) != 1 || transitions[0] != "closed->open" {
		t.Fatalf("expected a single closed->open transition, got %v", transitions)
	}
	if b.ShouldCallExternal() {
		t.Fatalf("expected an open circuit within recovery time to block external calls")
	}
}

func TestPlatformCircuitBreaker_HalfOpenAfterRecoveryTimeElapsed(t *testing.T) {
	b := NewPlatformCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		RecoveryTime:     10 * time.Millisecond,
	})

	b.RecordFailure() // opens
	time.Sleep(15 * time.Millisecond)

	if !b.ShouldCallExternal() {
		t.Fatalf("expected a test call to be allowed once recovery time elapsed")
	}
	if b.State() != CircuitHalfOpen {
		t.Fatalf("expected half-open state after recovery timeout, got %s", b.State())
	}
}

func TestPlatformCircuitBreaker_HalfOpenSuccessClosesCircuit(t *testing.T) {
	b := NewPlatformCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		RecoveryTime:     10 * time.Millisecond,
	})

	b.RecordFailure()
	time.Sleep(15 * time.Millisecond)
	b.ShouldCallExternal() // transitions to half-open

	b.RecordSuccess()
	if b.State() != CircuitClosed {
		t.Fatalf("expected half-open success to close the circuit, got %s", b.State())
	}
}

func TestPlatformCircuitBreaker_HalfOpenFailureReopensCircuit(t *testing.T) {
	b := NewPlatformCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		RecoveryTime:     10 * time.Millisecond,
	})

	b.RecordFailure()
	time.Sleep(15 * time.Millisecond)
	b.ShouldCallExternal() // transitions to half-open

	b.RecordFailure()
	if b.State() != CircuitOpen {
		t.Fatalf("expected half-open failure to reopen the circuit, got %s", b.State())
	}
}

func TestPlatformCircuitBreaker_ResetForcesClosedAndClearsFailures(t *testing.T) {
	b := NewPlatformCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1})
	b.RecordFailure()
	if b.State() != CircuitOpen {
		t.Fatalf("expected circuit to open")
	}

	b.Reset()
	if b.State() != CircuitClosed {
		t.Fatalf("expected reset to force closed, got %s", b.State())
	}
	diag := b.Diagnostics()
	if diag.FailureCount != 0 {
		t.Fatalf("expected reset to clear failure count, got %d", diag.FailureCount)
	}
}

func TestPlatformCircuitBreaker_RulesBecomeStaleAfterThreshold(t *testing.T) {
	b := NewPlatformCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1})
	b.RecordFailure() // opens, staleSince set

	past := time.Now().Add(-StaleThreshold - time.Second)
	b.staleSince = &past

	if !b.IsRulesStale() {
		t.Fatalf("expected rules to be reported stale past the stale threshold")
	}
	diag := b.Diagnostics()
	if !diag.RulesStale {
		t.Fatalf("expected diagnostics to report rules stale")
	}
}

func TestPlatformCircuitBreaker_SuccessResetsStaleTracking(t *testing.T) {
	b := NewPlatformCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		RecoveryTime:     10 * time.Millisecond,
	})
	b.RecordFailure()
	time.Sleep(15 * time.Millisecond)
	b.ShouldCallExternal()
	b.RecordSuccess()

	if b.IsRulesStale() {
		t.Fatalf("expected a successful call to clear stale tracking")
	}
}
