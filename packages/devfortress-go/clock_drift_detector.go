package devfortress

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// ── ClockDriftDetector (Invention A18) ───────────────────────────────────

// Mirrors the Node SDK's ClockDriftDetector (security-extensions.ts).
// TODO 419 — one of 17 Node-only claims identified by the 2026-11-02 patent
// audit; this is the first ported as a small, self-contained claim.
//
// Compares a client-supplied timestamp against server time and classifies
// the drift into an escalating action: allow, warn (audit with server
// time), use server time (enforce server-authoritative timestamps), or
// reject (possible timestamp manipulation).

// ClockDriftSeverity is the severity band of a ClockDriftResult.
type ClockDriftSeverity string

const (
	ClockDriftSeverityLow      ClockDriftSeverity = "LOW"
	ClockDriftSeverityMedium   ClockDriftSeverity = "MEDIUM"
	ClockDriftSeverityHigh     ClockDriftSeverity = "HIGH"
	ClockDriftSeverityCritical ClockDriftSeverity = "CRITICAL"
)

// ClockDriftAction is the action a ClockDriftResult recommends.
type ClockDriftAction string

const (
	ClockDriftActionAllow         ClockDriftAction = "allow"
	ClockDriftActionWarn          ClockDriftAction = "warn"
	ClockDriftActionUseServerTime ClockDriftAction = "use_server_time"
	ClockDriftActionReject        ClockDriftAction = "reject"
)

// ClockDriftConfig configures a ClockDriftDetector. Mirrors the Node SDK's
// ClockDriftConfig.
type ClockDriftConfig struct {
	// AcceptableThresholdMs is the drift below which a timestamp is
	// trusted outright. Default: 30_000 (30s).
	AcceptableThresholdMs float64
	// SuspiciousThresholdMs is the drift above which the request is
	// flagged for audit but still allowed. Default: 120_000 (2min).
	SuspiciousThresholdMs float64
	// CriticalThresholdMs is the drift above which the request is
	// rejected outright. Default: 300_000 (5min).
	CriticalThresholdMs float64
}

// ClockDriftResult is the outcome of one ClockDriftDetector.Check call.
type ClockDriftResult struct {
	Valid    bool
	DriftMs  float64
	Severity ClockDriftSeverity
	Action   ClockDriftAction
	Reason   string
}

// ClockDriftTrend is the drift trend for a client, from
// ClockDriftDetector.GetDriftTrend.
type ClockDriftTrend struct {
	AvgDrift   float64
	Increasing bool
}

const clockDriftMaxHistoryPerClient = 100

// ClockDriftDetector detects server-vs-client timestamp drift with
// per-client history. Safe for concurrent use.
type ClockDriftDetector struct {
	config ClockDriftConfig

	mu      sync.Mutex
	history map[string][]float64
}

// NewClockDriftDetector creates a ClockDriftDetector, applying defaults
// for any zero-valued config fields.
func NewClockDriftDetector(cfg ClockDriftConfig) *ClockDriftDetector {
	if cfg.AcceptableThresholdMs == 0 {
		cfg.AcceptableThresholdMs = 30_000
	}
	if cfg.SuspiciousThresholdMs == 0 {
		cfg.SuspiciousThresholdMs = 120_000
	}
	if cfg.CriticalThresholdMs == 0 {
		cfg.CriticalThresholdMs = 300_000
	}

	return &ClockDriftDetector{
		config:  cfg,
		history: make(map[string][]float64),
	}
}

// Check compares clientTimestampMs (epoch milliseconds) against server
// time. clientID, if non-empty, records the drift into that client's
// bounded history for GetDriftTrend.
func (d *ClockDriftDetector) Check(clientTimestampMs float64, clientID string) ClockDriftResult {
	serverTimeMs := float64(time.Now().UnixMilli())
	driftMs := math.Abs(clientTimestampMs - serverTimeMs)
	direction := "behind"
	if clientTimestampMs > serverTimeMs {
		direction = "ahead"
	}

	if clientID != "" {
		d.mu.Lock()
		hist := append(d.history[clientID], driftMs)
		if len(hist) > clockDriftMaxHistoryPerClient {
			hist = hist[len(hist)-clockDriftMaxHistoryPerClient:]
		}
		d.history[clientID] = hist
		d.mu.Unlock()
	}

	switch {
	case driftMs <= d.config.AcceptableThresholdMs:
		return ClockDriftResult{
			Valid:    true,
			DriftMs:  driftMs,
			Severity: ClockDriftSeverityLow,
			Action:   ClockDriftActionAllow,
			Reason:   fmt.Sprintf("Clock drift %.0fms (%s) within acceptable range", driftMs, direction),
		}
	case driftMs <= d.config.SuspiciousThresholdMs:
		return ClockDriftResult{
			Valid:    true,
			DriftMs:  driftMs,
			Severity: ClockDriftSeverityMedium,
			Action:   ClockDriftActionWarn,
			Reason:   fmt.Sprintf("Clock drift %.0fms (%s) — suspicious, using server time for audit", driftMs, direction),
		}
	case driftMs <= d.config.CriticalThresholdMs:
		return ClockDriftResult{
			Valid:    true,
			DriftMs:  driftMs,
			Severity: ClockDriftSeverityHigh,
			Action:   ClockDriftActionUseServerTime,
			Reason:   fmt.Sprintf("Clock drift %.0fms (%s) — enforcing server-authoritative timestamps", driftMs, direction),
		}
	default:
		return ClockDriftResult{
			Valid:    false,
			DriftMs:  driftMs,
			Severity: ClockDriftSeverityCritical,
			Action:   ClockDriftActionReject,
			Reason:   fmt.Sprintf("Clock drift %.0fms (%s) exceeds critical threshold — possible timestamp manipulation", driftMs, direction),
		}
	}
}

// GetDriftTrend returns the drift trend for clientID, or false if fewer
// than 3 samples have been recorded.
func (d *ClockDriftDetector) GetDriftTrend(clientID string) (ClockDriftTrend, bool) {
	d.mu.Lock()
	hist := d.history[clientID]
	d.mu.Unlock()

	if len(hist) < 3 {
		return ClockDriftTrend{}, false
	}

	sum := 0.0
	for _, v := range hist {
		sum += v
	}
	avgDrift := sum / float64(len(hist))

	recent := hist[len(hist)-3:]
	recentAvg := (recent[0] + recent[1] + recent[2]) / 3

	return ClockDriftTrend{AvgDrift: avgDrift, Increasing: recentAvg > avgDrift*1.2}, true
}

// GetStats returns the number of clients with tracked drift history.
func (d *ClockDriftDetector) GetStats() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.history)
}
