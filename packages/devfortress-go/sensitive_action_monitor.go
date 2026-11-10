package devfortress

import (
	"fmt"
	"sync"
	"time"
)

// ── SensitiveActionMonitor (Invention A6) ────────────────────────────────

// Mirrors the Node SDK's SensitiveActionMonitor (sensitive-action-monitor.ts).
// TODO 419/424 — one of the 20 Node-only claims identified by the
// 2026-11-02 patent audit.
//
// Monitors high-risk account operations (password change, email change,
// MFA enrollment/removal, role escalation, ...) with weighted behavioral
// deviation scoring over a sliding time window, and recommends an
// escalating response (allow, require MFA, delay, revoke session, block).

var sensitiveActionWeights = map[string]int{
	"password_change":       30,
	"email_change":          35,
	"mfa_enroll":            20,
	"mfa_remove":            40,
	"role_escalation":       45,
	"api_key_create":        15,
	"api_key_revoke":        25,
	"account_delete":        50,
	"payment_method_change": 30,
	"session_export":        20,
}

// SensitiveActionConfig configures a SensitiveActionMonitor.
type SensitiveActionConfig struct {
	// WindowMs is the window to track sensitive actions, in ms.
	// Default: 600_000 (10 min).
	WindowMs float64
	// MaxActionsPerWindow mirrors Node's own config field of the same
	// name, which Node's own implementation never actually reads —
	// carried here faithfully rather than silently dropped. Default: 3.
	MaxActionsPerWindow int
	// ScoreMultiplier scales the computed risk score. Default: 2.0.
	ScoreMultiplier float64
	// AutoRevoke selects revoke_session (true) vs. block (false) for a
	// CRITICAL result. Default: true.
	AutoRevoke *bool
	// MaxEntries caps the number of tracked users. Default: 50_000.
	MaxEntries int
}

// SensitiveActionEvent is one sensitive action to evaluate.
type SensitiveActionEvent struct {
	UserID     string
	ActionType string
	IP         string
	UserAgent  string
	SessionID  string
	// TimestampMs: epoch milliseconds. Zero means "now".
	TimestampMs float64
}

// SensitiveActionResult is the outcome of one
// SensitiveActionMonitor.Evaluate call.
type SensitiveActionResult struct {
	Allowed         bool
	RiskScore       int
	Severity        string // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
	Action          string // "allow" | "require_mfa" | "delay" | "revoke_session" | "block"
	Reason          string
	ActionsInWindow int
}

type sensitiveActionRecord struct {
	actions       []sensitiveActionEntry
	lastIP        string
	lastUserAgent string
}

type sensitiveActionEntry struct {
	actionType string
	timestamp  float64
	ip         string
}

// SensitiveActionMonitor tracks sensitive account actions per user over a
// sliding window. Safe for concurrent use.
type SensitiveActionMonitor struct {
	windowMs        float64
	scoreMultiplier float64
	autoRevoke      bool
	maxEntries      int

	mu          sync.Mutex
	userActions map[string]*sensitiveActionRecord
}

// NewSensitiveActionMonitor creates a SensitiveActionMonitor, applying
// defaults for any zero-valued config fields.
func NewSensitiveActionMonitor(cfg SensitiveActionConfig) *SensitiveActionMonitor {
	windowMs := cfg.WindowMs
	if windowMs == 0 {
		windowMs = 600_000
	}
	scoreMultiplier := cfg.ScoreMultiplier
	if scoreMultiplier == 0 {
		scoreMultiplier = 2.0
	}
	autoRevoke := true
	if cfg.AutoRevoke != nil {
		autoRevoke = *cfg.AutoRevoke
	}
	maxEntries := cfg.MaxEntries
	if maxEntries == 0 {
		maxEntries = 50_000
	}

	return &SensitiveActionMonitor{
		windowMs:        windowMs,
		scoreMultiplier: scoreMultiplier,
		autoRevoke:      autoRevoke,
		maxEntries:      maxEntries,
		userActions:     make(map[string]*sensitiveActionRecord),
	}
}

// Evaluate evaluates a sensitive action for risk.
func (m *SensitiveActionMonitor) Evaluate(event SensitiveActionEvent) SensitiveActionResult {
	now := event.TimestampMs
	if now == 0 {
		now = float64(time.Now().UnixMilli())
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.userActions) >= m.maxEntries {
		if _, exists := m.userActions[event.UserID]; !exists {
			// Node evicts the oldest-inserted key (Map preserves insertion
			// order); a Go map has no insertion order, so this evicts an
			// arbitrary entry instead — same eviction-when-full behavior,
			// not guaranteed to be the oldest one.
			for k := range m.userActions {
				delete(m.userActions, k)
				break
			}
		}
	}

	record, ok := m.userActions[event.UserID]
	if !ok {
		record = &sensitiveActionRecord{lastIP: event.IP, lastUserAgent: event.UserAgent}
		m.userActions[event.UserID] = record
	}

	fresh := record.actions[:0:0]
	for _, a := range record.actions {
		if now-a.timestamp <= m.windowMs {
			fresh = append(fresh, a)
		}
	}
	fresh = append(fresh, sensitiveActionEntry{actionType: event.ActionType, timestamp: now, ip: event.IP})
	record.actions = fresh

	actionsInWindow := len(record.actions)
	baseWeight, ok := sensitiveActionWeights[event.ActionType]
	if !ok {
		baseWeight = 20
	}

	riskScore := baseWeight
	if actionsInWindow > 1 {
		riskScore += (actionsInWindow - 1) * 15
	}

	uniqueIPs := map[string]bool{}
	actionTypes := map[string]bool{}
	for _, a := range record.actions {
		uniqueIPs[a.ip] = true
		actionTypes[a.actionType] = true
	}
	if len(uniqueIPs) > 1 {
		riskScore += 20
	}
	if actionTypes["mfa_remove"] && actionTypes["password_change"] {
		riskScore += 30
	}
	if actionTypes["email_change"] && actionTypes["password_change"] {
		riskScore += 25
	}
	if actionTypes["role_escalation"] && actionsInWindow > 1 {
		riskScore += 20
	}

	riskScore = int(float64(riskScore) * m.scoreMultiplier)
	if riskScore > 100 {
		riskScore = 100
	}

	var severity, action string
	allowed := true
	switch {
	case riskScore >= 85:
		severity = "CRITICAL"
		if m.autoRevoke {
			action = "revoke_session"
		} else {
			action = "block"
		}
		allowed = false
	case riskScore >= 65:
		severity = "HIGH"
		action = "require_mfa"
	case riskScore >= 40:
		severity = "MEDIUM"
		action = "delay"
	default:
		severity = "LOW"
		action = "allow"
	}

	record.lastIP = event.IP
	if event.UserAgent != "" {
		record.lastUserAgent = event.UserAgent
	}

	reason := fmt.Sprintf(
		"Sensitive action '%s' for user %s: %d actions in window, risk=%d, %d unique IPs",
		event.ActionType, event.UserID, actionsInWindow, riskScore, len(uniqueIPs),
	)
	if len(actionTypes) > 1 {
		reason += fmt.Sprintf(", %d action types", len(actionTypes))
	}

	return SensitiveActionResult{
		Allowed:         allowed,
		RiskScore:       riskScore,
		Severity:        severity,
		Action:          action,
		Reason:          reason,
		ActionsInWindow: actionsInWindow,
	}
}

// GetStats returns the number of tracked users.
func (m *SensitiveActionMonitor) GetStats() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.userActions)
}

// Cleanup purges expired actions and drops users with no remaining
// actions. nowMs of 0 means "now".
func (m *SensitiveActionMonitor) Cleanup(nowMs float64) {
	now := nowMs
	if now == 0 {
		now = float64(time.Now().UnixMilli())
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for userID, record := range m.userActions {
		fresh := record.actions[:0:0]
		for _, a := range record.actions {
			if now-a.timestamp <= m.windowMs {
				fresh = append(fresh, a)
			}
		}
		record.actions = fresh
		if len(record.actions) == 0 {
			delete(m.userActions, userID)
		}
	}
}
