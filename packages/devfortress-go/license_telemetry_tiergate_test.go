package devfortress

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestLicenseManagerResolvesTierFromPlatform demonstrates CV-M1's
// successful path: a 2xx license-check response confirms the tier and
// (CV-M4) syncs the ML model, leaving the SDK fully enabled (not
// degraded).
func TestLicenseManagerResolvesTierFromPlatform(t *testing.T) {
	transport := &recordingTransport{script: []any{
		&TransportResponse{StatusCode: 200, Body: []byte(`{"tier":"team","modelVersion":"model-v3"}`)},
	}}

	lm, err := NewLicenseManager(LicenseManagerConfig{
		APIKey:    "test-key-0123456789",
		Endpoint:  "https://platform.example.com",
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}

	state := lm.CheckLicense(context.Background())
	if !state.Valid {
		t.Fatalf("expected a valid license state, got: %+v", state)
	}
	if state.Degraded {
		t.Fatalf("expected a non-degraded state on success, got: %+v", state)
	}
	if state.Tier != TierTeam {
		t.Fatalf("expected tier resolved from the platform response (team), got %v", state.Tier)
	}
	if state.ConsecutiveFailures != 0 {
		t.Fatalf("expected 0 consecutive failures after a successful check, got %d", state.ConsecutiveFailures)
	}

	model := lm.GetModelState()
	if model.ModelVersion != "model-v3" {
		t.Fatalf("expected ML model synced from the license-check response, got %+v", model)
	}
	if model.Expired {
		t.Fatalf("expected a freshly synced model to not be expired")
	}

	if transport.count() != 1 {
		t.Fatalf("expected exactly one license-check request, got %d", transport.count())
	}
	if !lm.CanPerformAction(LicenseActionBlock) {
		t.Fatalf("expected blocking to be allowed once the license is valid")
	}
}

// TestLicenseManagerDegradesAfterGracePeriodAndLogsVisibly demonstrates
// CV-M1's failure path — the exact bug class TODO 321 fixed on Node:
// a license-check failure must never fail silently. Once the grace
// period has elapsed since the last successful check, the SDK degrades
// to monitor-only (no blocking — Observe is always still allowed) and
// logs a visible warning, not a swallowed/silent failure.
func TestLicenseManagerDegradesAfterGracePeriodAndLogsVisibly(t *testing.T) {
	logger := &recordingLogger{}
	lm, err := NewLicenseManager(LicenseManagerConfig{
		APIKey:      "test-key-0123456789",
		Endpoint:    "https://platform.example.com",
		GracePeriod: 10 * time.Millisecond,
		Transport:   okTransport(),
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}

	// An initial successful check establishes a real LastCheckedAt
	// baseline to measure the grace period from.
	state := lm.CheckLicense(context.Background())
	if !state.Valid || state.Degraded {
		t.Fatalf("expected a clean initial check, got: %+v", state)
	}

	// White-box: there is no injectable clock, so simulate the grace
	// period having elapsed since the last successful check by moving the
	// recorded baseline into the past.
	lm.mu.Lock()
	lm.licenseState.LastCheckedAt = time.Now().Add(-time.Hour).UnixMilli()
	lm.mu.Unlock()
	lm.transport = &recordingTransport{script: []any{downError()}}

	state = lm.CheckLicense(context.Background())
	if !state.Degraded {
		t.Fatalf("expected the SDK to degrade to monitor-only after the grace period elapsed, got: %+v", state)
	}
	if state.DegradationReason == "" {
		t.Fatalf("expected a degradation reason to be recorded")
	}

	// Degraded = monitor-only: blocking/rate-limiting are denied, but
	// observe is always allowed.
	if lm.CanPerformAction(LicenseActionBlock) {
		t.Fatalf("expected blocking to be disallowed while degraded")
	}
	if lm.CanPerformAction(LicenseActionRateLimit) {
		t.Fatalf("expected rate limiting to be disallowed while degraded")
	}
	if !lm.CanPerformAction(LicenseActionObserve) {
		t.Fatalf("expected observe to remain allowed even while degraded")
	}
	if !lm.IsDegraded() {
		t.Fatalf("expected IsDegraded() to report true")
	}

	// The degradation must be visible in the log, not silently dropped.
	found := false
	for _, line := range logger.lines {
		if strings.HasPrefix(line, "warn ") && strings.Contains(line, "degraded to monitor-only") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a visible warn-level log line on degradation, got: %v", logger.lines)
	}
}

// TestTierGateBlocksIneligibleFeature demonstrates tier gating rejecting
// a feature the current tier isn't entitled to: the Starter tier cannot
// block, and cannot use hybrid closed-loop mode.
func TestTierGateBlocksIneligibleFeature(t *testing.T) {
	gate := NewTierGate(TierStarter, nil)

	if gate.CanBlock() {
		t.Fatalf("expected the starter tier to be unable to block")
	}
	allowed, reason := gate.ValidateBlockAction("block_ip")
	if allowed {
		t.Fatalf("expected starter blocking to be rejected")
	}
	if !strings.Contains(reason, "starter") {
		t.Fatalf("expected the rejection reason to name the tier, got: %q", reason)
	}

	modeAllowed, modeReason := gate.ValidateMode(ModeHybrid)
	if modeAllowed {
		t.Fatalf("expected starter hybrid mode to be rejected")
	}
	if modeReason == "" {
		t.Fatalf("expected a reason explaining the mode rejection")
	}

	if got := gate.GetEffectiveMode(ModeHybrid); got != ModeExternal {
		t.Fatalf("expected the disallowed request to fall back to the tier's default mode (external), got %v", got)
	}

	// Team, by contrast, is entitled to hybrid — a sanity check that the
	// gate isn't just always rejecting.
	team := NewTierGate(TierTeam, nil)
	if !team.CanBlock() {
		t.Fatalf("expected the team tier to be able to block")
	}
	if teamAllowed, _ := team.ValidateMode(ModeHybrid); !teamAllowed {
		t.Fatalf("expected the team tier to be allowed hybrid mode")
	}
}

// TestTelemetryManagerHeartbeatSendsSnapshotAndResetsCounters covers the
// TelemetryManager half of CV-M2: recorded counters are included in the
// heartbeat payload and reset after a successful send.
func TestTelemetryManagerHeartbeatSendsSnapshotAndResetsCounters(t *testing.T) {
	transport := okTransport()
	tm, err := NewTelemetryManager(TelemetryConfig{
		APIKey:    "test-key-0123456789",
		Endpoint:  "https://platform.example.com",
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewTelemetryManager failed: %v", err)
	}

	tm.RecordEvent()
	tm.RecordEvent()
	tm.RecordBlock()
	tm.RecordRateLimit()
	tm.RecordLatency(42)

	before := tm.GetState()
	if before.EventCount != 2 || before.BlockCount != 1 || before.RateLimitCount != 1 {
		t.Fatalf("expected counters to reflect recorded activity before a heartbeat, got: %+v", before)
	}

	tm.sendHeartbeat()

	if transport.count() != 1 {
		t.Fatalf("expected exactly one heartbeat request, got %d", transport.count())
	}
	after := tm.GetState()
	if after.EventCount != 0 || after.BlockCount != 0 || after.RateLimitCount != 0 {
		t.Fatalf("expected counters to reset after a successful heartbeat, got: %+v", after)
	}
}

// TestTelemetryRollupBufferBuffersAndFlushesInOneBatch covers the
// Anomaly-Gated Metering rollup buffer: several Add() contributions for
// the same key within the same hour collapse into one bucket, and Flush
// sends it as a single batched request (not one request per contribution).
func TestTelemetryRollupBufferBuffersAndFlushesInOneBatch(t *testing.T) {
	transport := okTransport()
	buf, err := NewTelemetryRollupBuffer(TelemetryRollupBufferConfig{
		APIKey:    "test-key-0123456789",
		Endpoint:  "https://platform.example.com",
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewTelemetryRollupBuffer failed: %v", err)
	}

	buf.Add(RollupContributionInput{AliasOrIPKey: "203.0.113.5", Endpoint: "/api/widgets", LatencyMs: 10})
	buf.Add(RollupContributionInput{AliasOrIPKey: "203.0.113.5", Endpoint: "/api/widgets", LatencyMs: 20, IsError: true})
	buf.Add(RollupContributionInput{AliasOrIPKey: "203.0.113.5", Endpoint: "/api/other", LatencyMs: 5})

	buf.mu.Lock()
	bucketCount := len(buf.buckets)
	buf.mu.Unlock()
	if bucketCount != 1 {
		t.Fatalf("expected the three same-key contributions to collapse into one bucket, got %d", bucketCount)
	}

	buf.Flush(context.Background())

	if transport.count() != 1 {
		t.Fatalf("expected exactly one batched flush request, got %d", transport.count())
	}

	buf.mu.Lock()
	remaining := len(buf.buckets)
	buf.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected buckets to be cleared after flush, got %d remaining", remaining)
	}
}

// TestHourlyPeriodKeyFormat pins HourlyPeriodKey's wire format, which must
// match AliasTelemetryRollup.periodKey on the platform.
func TestHourlyPeriodKeyFormat(t *testing.T) {
	ts := time.Date(2026, 8, 27, 14, 30, 0, 0, time.UTC)
	if got, want := HourlyPeriodKey(ts), "2026-08-27T14"; got != want {
		t.Fatalf("HourlyPeriodKey(%v) = %q, want %q", ts, got, want)
	}
}
