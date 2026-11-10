package devfortress

import "testing"

func TestSensitiveActionMonitor_SingleLowWeightActionIsAllowed(t *testing.T) {
	m := NewSensitiveActionMonitor(SensitiveActionConfig{})
	result := m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "api_key_create", IP: "203.0.113.7"})
	if !result.Allowed || result.Severity != "LOW" || result.Action != "allow" {
		t.Fatalf("expected LOW/allow, got %+v", result)
	}
}

func TestSensitiveActionMonitor_AccountTakeoverComboIsCriticalAndRevokes(t *testing.T) {
	m := NewSensitiveActionMonitor(SensitiveActionConfig{})
	m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "mfa_remove", IP: "203.0.113.7", TimestampMs: 1_700_000_000_000})
	result := m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "password_change", IP: "203.0.113.7", TimestampMs: 1_700_000_000_500})
	if result.Severity != "CRITICAL" || result.Action != "revoke_session" || result.Allowed {
		t.Fatalf("expected CRITICAL/revoke_session, got %+v", result)
	}
}

func TestSensitiveActionMonitor_AutoRevokeDisabledBlocksInstead(t *testing.T) {
	autoRevoke := false
	m := NewSensitiveActionMonitor(SensitiveActionConfig{AutoRevoke: &autoRevoke})
	m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "mfa_remove", IP: "203.0.113.7", TimestampMs: 1_700_000_000_000})
	result := m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "password_change", IP: "203.0.113.7", TimestampMs: 1_700_000_000_500})
	if result.Action != "block" || result.Allowed {
		t.Fatalf("expected block, got %+v", result)
	}
}

func TestSensitiveActionMonitor_IPSwitchingRaisesRisk(t *testing.T) {
	m := NewSensitiveActionMonitor(SensitiveActionConfig{})
	m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "email_change", IP: "203.0.113.7", TimestampMs: 1_700_000_000_000})
	result := m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "email_change", IP: "198.51.100.1", TimestampMs: 1_700_000_000_500})
	if result.RiskScore <= 70 {
		t.Fatalf("expected risk score > 70, got %d", result.RiskScore)
	}
}

func TestSensitiveActionMonitor_ActionsOutsideWindowArePurged(t *testing.T) {
	m := NewSensitiveActionMonitor(SensitiveActionConfig{WindowMs: 1_000})
	m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "mfa_remove", IP: "203.0.113.7", TimestampMs: 1_000_000})
	result := m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "password_change", IP: "203.0.113.7", TimestampMs: 1_005_000})
	if result.ActionsInWindow != 1 {
		t.Fatalf("expected 1 action in window, got %d", result.ActionsInWindow)
	}
}

func TestSensitiveActionMonitor_GetStatsCountsTrackedUsers(t *testing.T) {
	m := NewSensitiveActionMonitor(SensitiveActionConfig{})
	m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "mfa_enroll", IP: "203.0.113.7"})
	m.Evaluate(SensitiveActionEvent{UserID: "u2", ActionType: "mfa_enroll", IP: "203.0.113.8"})
	if got := m.GetStats(); got != 2 {
		t.Fatalf("expected 2 tracked users, got %d", got)
	}
}

func TestSensitiveActionMonitor_CleanupDropsUsersWithNoRemainingActions(t *testing.T) {
	m := NewSensitiveActionMonitor(SensitiveActionConfig{WindowMs: 1_000})
	m.Evaluate(SensitiveActionEvent{UserID: "u1", ActionType: "mfa_enroll", IP: "203.0.113.7", TimestampMs: 1_000_000})
	m.Cleanup(1_005_000)
	if got := m.GetStats(); got != 0 {
		t.Fatalf("expected 0 tracked users after cleanup, got %d", got)
	}
}
