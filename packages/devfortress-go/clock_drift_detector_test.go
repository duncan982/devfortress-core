package devfortress

import (
	"testing"
	"time"
)

func nowMs() float64 {
	return float64(time.Now().UnixMilli())
}

func TestClockDriftDetector_WithinAcceptableThresholdIsAllowed(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	result := d.Check(nowMs(), "")
	if !result.Valid || result.Severity != ClockDriftSeverityLow || result.Action != ClockDriftActionAllow {
		t.Fatalf("expected LOW/allow, got %+v", result)
	}
}

func TestClockDriftDetector_SuspiciousDriftWarnsButStaysValid(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	result := d.Check(nowMs()-60_000, "")
	if !result.Valid || result.Severity != ClockDriftSeverityMedium || result.Action != ClockDriftActionWarn {
		t.Fatalf("expected MEDIUM/warn, got %+v", result)
	}
}

func TestClockDriftDetector_HighDriftEnforcesServerTime(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	result := d.Check(nowMs()-200_000, "")
	if !result.Valid || result.Severity != ClockDriftSeverityHigh || result.Action != ClockDriftActionUseServerTime {
		t.Fatalf("expected HIGH/use_server_time, got %+v", result)
	}
}

func TestClockDriftDetector_CriticalDriftIsRejected(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	result := d.Check(nowMs()-600_000, "")
	if result.Valid || result.Severity != ClockDriftSeverityCritical || result.Action != ClockDriftActionReject {
		t.Fatalf("expected CRITICAL/reject, got %+v", result)
	}
}

func TestClockDriftDetector_AheadOfServerTimeIsAlsoDetected(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	result := d.Check(nowMs()+600_000, "")
	if result.Valid {
		t.Fatalf("expected rejection for a client far ahead of server time, got %+v", result)
	}
}

func TestClockDriftDetector_CustomThresholdsAreRespected(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{
		AcceptableThresholdMs: 1_000,
		SuspiciousThresholdMs: 5_000,
		CriticalThresholdMs:   10_000,
	})
	if got := d.Check(nowMs()-2_000, "").Action; got != ClockDriftActionWarn {
		t.Fatalf("expected warn, got %s", got)
	}
	if got := d.Check(nowMs()-20_000, "").Action; got != ClockDriftActionReject {
		t.Fatalf("expected reject, got %s", got)
	}
}

func TestClockDriftDetector_DriftTrendRequiresAtLeastThreeSamples(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	d.Check(nowMs()-1_000, "c1")
	d.Check(nowMs()-2_000, "c1")
	if _, ok := d.GetDriftTrend("c1"); ok {
		t.Fatal("expected no trend with fewer than 3 samples")
	}

	d.Check(nowMs()-3_000, "c1")
	trend, ok := d.GetDriftTrend("c1")
	if !ok || trend.AvgDrift <= 0 {
		t.Fatalf("expected a trend with positive avg drift, got ok=%v trend=%+v", ok, trend)
	}
}

func TestClockDriftDetector_DriftTrendDetectsIncreasingDrift(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	for _, drift := range []float64{1_000, 1_000, 1_000, 5_000, 5_000, 5_000} {
		d.Check(nowMs()-drift, "growing")
	}
	trend, ok := d.GetDriftTrend("growing")
	if !ok || !trend.Increasing {
		t.Fatalf("expected increasing trend, got ok=%v trend=%+v", ok, trend)
	}
}

func TestClockDriftDetector_HistoryIsBoundedPerClient(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	for i := 0; i < 150; i++ {
		d.Check(nowMs(), "busy-client")
	}
	d.mu.Lock()
	n := len(d.history["busy-client"])
	d.mu.Unlock()
	if n != clockDriftMaxHistoryPerClient {
		t.Fatalf("expected history capped at %d, got %d", clockDriftMaxHistoryPerClient, n)
	}
}

func TestClockDriftDetector_GetStatsCountsTrackedClients(t *testing.T) {
	d := NewClockDriftDetector(ClockDriftConfig{})
	d.Check(nowMs(), "a")
	d.Check(nowMs(), "b")
	d.Check(nowMs(), "") // no clientID — not tracked
	if got := d.GetStats(); got != 2 {
		t.Fatalf("expected 2 tracked clients, got %d", got)
	}
}
