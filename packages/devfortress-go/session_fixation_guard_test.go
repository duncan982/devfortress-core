package devfortress

import "testing"

func TestSessionFixationGuard_RegistersAndValidatesMatchingSession(t *testing.T) {
	g := NewSessionFixationGuard(SessionFixationConfig{})
	sessionID := g.RegisterSession("203.0.113.7", "curl/8.0", "")
	result := g.ValidateSession(sessionID, "203.0.113.7", "curl/8.0")
	if !result.Valid || result.Regenerate || result.DriftScore != 0 {
		t.Fatalf("expected clean validation, got %+v", result)
	}
}

func TestSessionFixationGuard_UnknownSessionIsRejected(t *testing.T) {
	g := NewSessionFixationGuard(SessionFixationConfig{})
	result := g.ValidateSession("never-registered", "203.0.113.7", "curl/8.0")
	if result.Valid || !result.Regenerate || result.DriftScore != 100 {
		t.Fatalf("expected rejection, got %+v", result)
	}
}

func TestSessionFixationGuard_IPRangeChangeAloneIsMinorDrift(t *testing.T) {
	g := NewSessionFixationGuard(SessionFixationConfig{})
	sessionID := g.RegisterSession("203.0.113.7", "curl/8.0", "")
	result := g.ValidateSession(sessionID, "198.51.100.1", "curl/8.0")
	if !result.Valid || result.Regenerate || result.DriftScore != 40 {
		t.Fatalf("expected minor drift, got %+v", result)
	}
}

func TestSessionFixationGuard_IPAndUserAgentChangeIsFixationSuspected(t *testing.T) {
	g := NewSessionFixationGuard(SessionFixationConfig{})
	sessionID := g.RegisterSession("203.0.113.7", "curl/8.0", "")
	result := g.ValidateSession(sessionID, "198.51.100.1", "python-requests/2.0")
	if result.Valid || !result.Regenerate || result.DriftScore != 80 {
		t.Fatalf("expected fixation suspected, got %+v", result)
	}
}

func TestSessionFixationGuard_OldSessionRemovedOnReplacement(t *testing.T) {
	g := NewSessionFixationGuard(SessionFixationConfig{})
	oldID := g.RegisterSession("203.0.113.7", "curl/8.0", "")
	g.RegisterSession("203.0.113.7", "curl/8.0", oldID)
	result := g.ValidateSession(oldID, "203.0.113.7", "curl/8.0")
	if result.Valid {
		t.Fatalf("expected old session to be gone, got %+v", result)
	}
}

func TestSessionFixationGuard_RemoveSessionDropsIt(t *testing.T) {
	g := NewSessionFixationGuard(SessionFixationConfig{})
	sessionID := g.RegisterSession("203.0.113.7", "curl/8.0", "")
	g.RemoveSession(sessionID)
	result := g.ValidateSession(sessionID, "203.0.113.7", "curl/8.0")
	if result.Valid {
		t.Fatalf("expected removed session to be gone, got %+v", result)
	}
}

func TestSessionFixationGuard_GetStatsCountsActiveSessions(t *testing.T) {
	g := NewSessionFixationGuard(SessionFixationConfig{})
	g.RegisterSession("203.0.113.7", "curl/8.0", "")
	g.RegisterSession("203.0.113.8", "curl/8.0", "")
	if got := g.GetStats(); got != 2 {
		t.Fatalf("expected 2 active sessions, got %d", got)
	}
}

func TestSessionFixationGuard_DisablingIPBindingIgnoresIPChange(t *testing.T) {
	bindIP := false
	g := NewSessionFixationGuard(SessionFixationConfig{BindToIPRange: &bindIP})
	sessionID := g.RegisterSession("203.0.113.7", "curl/8.0", "")
	result := g.ValidateSession(sessionID, "198.51.100.1", "curl/8.0")
	if !result.Valid || result.DriftScore != 0 {
		t.Fatalf("expected IP change to be ignored, got %+v", result)
	}
}
