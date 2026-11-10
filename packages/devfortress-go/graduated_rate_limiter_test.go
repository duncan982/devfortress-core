package devfortress

import (
	"testing"
	"time"
)

func TestGraduatedRateLimiter_ObservationStageBelowHalfLimit(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{DefaultLimit: 100})
	defer l.Destroy()

	result := l.Check("alias-1", "")
	if result.Stage != StageObservation {
		t.Fatalf("expected observation stage at 1/100, got %s", result.Stage)
	}
	if result.Blocked {
		t.Fatalf("observation stage must not block")
	}
}

func TestGraduatedRateLimiter_WarningStageAtHalfLimit(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{DefaultLimit: 10})
	defer l.Destroy()

	var result RateLimitResult
	for i := 0; i < 5; i++ {
		result = l.Check("alias-1", "")
	}
	if result.Stage != StageWarning {
		t.Fatalf("expected warning stage at 5/10, got %s", result.Stage)
	}
	if result.Blocked {
		t.Fatalf("warning stage must not block")
	}
}

func TestGraduatedRateLimiter_SoftLimitInjectsLatencyWithJitter(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{
		DefaultLimit:          10,
		SoftLimitBaseLatency:  2 * time.Second,
	})
	defer l.Destroy()

	var result RateLimitResult
	for i := 0; i < 8; i++ {
		result = l.Check("alias-1", "")
	}
	if result.Stage != StageSoftLimit {
		t.Fatalf("expected soft_limit stage at 8/10, got %s", result.Stage)
	}
	if result.Blocked {
		t.Fatalf("soft_limit stage must not block")
	}
	if result.InjectedLatency <= 0 {
		t.Fatalf("expected injected latency > 0 at soft_limit, got %s", result.InjectedLatency)
	}
}

func TestGraduatedRateLimiter_HardBlockAtLimit(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{DefaultLimit: 5})
	defer l.Destroy()

	var result RateLimitResult
	for i := 0; i < 5; i++ {
		result = l.Check("alias-1", "")
	}
	if result.Stage != StageHardBlock {
		t.Fatalf("expected hard_block stage at 5/5, got %s", result.Stage)
	}
	if !result.Blocked {
		t.Fatalf("hard_block stage must block")
	}
	if result.Cooldown != 60*time.Second {
		t.Fatalf("expected initial 60s cooldown, got %s", result.Cooldown)
	}
}

func TestGraduatedRateLimiter_EscalatingCooldownDoublesEachConsecutiveBlock(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{
		DefaultLimit:    1,
		InitialCooldown: 60 * time.Second,
	})
	defer l.Destroy()

	// First request: at limit (1/1), hard_block, cooldown 60s.
	first := l.Check("alias-1", "")
	if first.Stage != StageHardBlock || first.Cooldown != 60*time.Second {
		t.Fatalf("expected first hard_block with 60s cooldown, got stage=%s cooldown=%s", first.Stage, first.Cooldown)
	}

	// Force cooldown to have elapsed, and the prior request to have aged
	// out of the sliding window (as it would have by the time a real
	// 60s cooldown elapsed), so the next Check records a fresh,
	// second consecutive block rather than returning the in-cooldown
	// response or accumulating ratio from the still-windowed first
	// request.
	l.entries["alias-1"].cooldownUntil = time.Now().Add(-time.Millisecond)
	l.entries["alias-1"].timestamps = nil

	second := l.Check("alias-1", "")
	if second.Stage != StageHardBlock || second.Cooldown != 120*time.Second {
		t.Fatalf("expected second hard_block with 120s cooldown, got stage=%s cooldown=%s", second.Stage, second.Cooldown)
	}
}

func TestGraduatedRateLimiter_RevokesAfterMaxConsecutiveBlocks(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{
		DefaultLimit:         1,
		MaxConsecutiveBlocks: 3,
	})
	defer l.Destroy()

	for i := 0; i < 3; i++ {
		l.Check("alias-1", "")
		l.entries["alias-1"].cooldownUntil = time.Now().Add(-time.Millisecond)
	}

	result := l.Check("alias-1", "")
	if result.Stage != StageRevocation {
		t.Fatalf("expected revocation after 3 consecutive blocks, got %s", result.Stage)
	}
	if !l.IsRevoked("alias-1") {
		t.Fatalf("expected alias-1 to be revoked")
	}
}

func TestGraduatedRateLimiter_RevokedAliasStaysBlockedWithoutReRevoking(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{DefaultLimit: 100})
	defer l.Destroy()

	l.RevokeAlias("alias-1")
	result := l.Check("alias-1", "")
	if result.Stage != StageRevocation {
		t.Fatalf("expected revocation stage for pre-revoked alias, got %s", result.Stage)
	}
	if result.Revoke {
		t.Fatalf("Revoke must be false for an already-revoked alias (no re-revocation event)")
	}
}

func TestGraduatedRateLimiter_ResetAliasClearsState(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{DefaultLimit: 1})
	defer l.Destroy()

	// Escalate to a second, doubled cooldown (120s) via two consecutive
	// blocks, same technique as the escalation test.
	l.Check("alias-1", "")
	l.entries["alias-1"].cooldownUntil = time.Now().Add(-time.Millisecond)
	l.entries["alias-1"].timestamps = nil
	escalated := l.Check("alias-1", "")
	if escalated.Cooldown != 120*time.Second {
		t.Fatalf("expected escalated 120s cooldown before reset, got %s", escalated.Cooldown)
	}

	l.ResetAlias("alias-1")

	result := l.Check("alias-1", "")
	if result.Cooldown != 60*time.Second {
		t.Fatalf("expected reset to clear consecutive-block escalation back to the initial 60s cooldown, got %s", result.Cooldown)
	}
}

func TestGraduatedRateLimiter_PerEndpointLimitsOverrideDefault(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{
		DefaultLimit: 100,
		EndpointLimits: map[string]int{
			"/api/auth/*": 2,
		},
	})
	defer l.Destroy()

	l.Check("alias-1", "/api/auth/login")
	result := l.Check("alias-1", "/api/auth/login")
	if result.Limit != 2 {
		t.Fatalf("expected per-endpoint limit of 2 to apply, got limit=%d", result.Limit)
	}
	if result.Stage != StageHardBlock {
		t.Fatalf("expected hard_block at 2/2 for the matched endpoint, got %s", result.Stage)
	}
}

func TestGraduatedRateLimiter_BurstDetectionTriggersHardBlock(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{
		DefaultLimit: 1000,
		BurstLimit:   3,
	})
	defer l.Destroy()

	// The 4th call within the 1-second micro-window pushes
	// burstTimestamps past BurstLimit=3 and forces hard_block even
	// though currentRate/limit is tiny (4/1000). A 5th call would only
	// hit the "already in cooldown" early-return path (which, like
	// Node, reports BurstDetected: false unconditionally) rather than
	// re-evaluating burst state.
	var result RateLimitResult
	for i := 0; i < 4; i++ {
		result = l.Check("alias-1", "")
	}
	if !result.BurstDetected {
		t.Fatalf("expected burst detection after exceeding burst limit within 1s")
	}
	if result.Stage != StageHardBlock {
		t.Fatalf("expected a detected burst to force hard_block, got %s", result.Stage)
	}
}

func TestGraduatedRateLimiter_MaxEntriesEvictsOldestAlias(t *testing.T) {
	l := NewGraduatedRateLimiter(GraduatedRateLimiterConfig{
		DefaultLimit: 100,
		MaxEntries:   2,
	})
	defer l.Destroy()

	l.Check("alias-1", "")
	l.Check("alias-2", "")
	l.Check("alias-3", "") // should evict alias-1

	if l.Size() != 2 {
		t.Fatalf("expected size capped at 2, got %d", l.Size())
	}
	if _, ok := l.entries["alias-1"]; ok {
		t.Fatalf("expected alias-1 (oldest) to be evicted")
	}
}
