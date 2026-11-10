package devfortress

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ── SessionFixationGuard (Invention A13) ─────────────────────────────────

// Mirrors the Node SDK's SessionFixationGuard (security-extensions.ts).
// TODO 419/429 — one of the 20 Node-only claims identified by the
// 2026-11-02 patent audit.
//
// Binds a session to the IP range (first three octets) and user-agent it
// was created with, and flags drift when either changes mid-session — a
// classic session-fixation/hijack signal.

// SessionFixationConfig configures a SessionFixationGuard.
type SessionFixationConfig struct {
	// BindToIPRange binds the session to the IP's first three octets.
	// Default: true.
	BindToIPRange *bool
	// BindToUserAgent binds the session to the user-agent string.
	// Default: true.
	BindToUserAgent *bool
	// MaxFingerprintDrift mirrors Node's own config field of the same
	// name, which Node's own implementation never actually reads —
	// carried here faithfully rather than silently dropped.
	MaxFingerprintDrift int
}

// SessionFingerprint is the fingerprint recorded for one session at
// registration time.
type SessionFingerprint struct {
	SessionID    string
	IPPrefix     string
	UserAgent    string
	CreatedAt    int64
	LastVerified int64
}

// SessionValidationResult is the outcome of one
// SessionFixationGuard.ValidateSession call.
type SessionValidationResult struct {
	Valid      bool
	Regenerate bool
	Reason     string
	DriftScore int
}

func ipPrefix(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, ".")
}

// SessionFixationGuard tracks per-session IP/user-agent fingerprints and
// flags drift. Safe for concurrent use.
type SessionFixationGuard struct {
	bindToIPRange       bool
	bindToUserAgent     bool
	maxFingerprintDrift int

	mu       sync.Mutex
	sessions map[string]*SessionFingerprint
}

// NewSessionFixationGuard creates a SessionFixationGuard, applying
// defaults for any unset config fields.
func NewSessionFixationGuard(cfg SessionFixationConfig) *SessionFixationGuard {
	bindIP := true
	if cfg.BindToIPRange != nil {
		bindIP = *cfg.BindToIPRange
	}
	bindUA := true
	if cfg.BindToUserAgent != nil {
		bindUA = *cfg.BindToUserAgent
	}
	maxDrift := cfg.MaxFingerprintDrift
	if maxDrift == 0 {
		maxDrift = 2
	}

	return &SessionFixationGuard{
		bindToIPRange:       bindIP,
		bindToUserAgent:     bindUA,
		maxFingerprintDrift: maxDrift,
		sessions:            make(map[string]*SessionFingerprint),
	}
}

// RegisterSession registers a new session after authentication. Returns
// the new session ID; the caller must replace the old one. oldSessionID
// may be empty.
func (g *SessionFixationGuard) RegisterSession(ip, userAgent, oldSessionID string) string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	newSessionID := hex.EncodeToString(buf)
	now := time.Now().UnixMilli()

	g.mu.Lock()
	defer g.mu.Unlock()

	if oldSessionID != "" {
		delete(g.sessions, oldSessionID)
	}

	g.sessions[newSessionID] = &SessionFingerprint{
		SessionID:    newSessionID,
		IPPrefix:     ipPrefix(ip),
		UserAgent:    userAgent,
		CreatedAt:    now,
		LastVerified: now,
	}
	return newSessionID
}

// ValidateSession validates an ongoing session against its recorded
// fingerprint.
func (g *SessionFixationGuard) ValidateSession(sessionID, ip, userAgent string) SessionValidationResult {
	g.mu.Lock()
	fingerprint, ok := g.sessions[sessionID]
	g.mu.Unlock()

	if !ok {
		return SessionValidationResult{
			Valid: false, Regenerate: true, Reason: "Unknown session ID", DriftScore: 100,
		}
	}

	driftScore := 0
	var reasons []string

	if g.bindToIPRange {
		currentPrefix := ipPrefix(ip)
		if currentPrefix != fingerprint.IPPrefix {
			driftScore += 40
			reasons = append(reasons, fmt.Sprintf("IP range changed: %s.* -> %s.*", fingerprint.IPPrefix, currentPrefix))
		}
	}

	if g.bindToUserAgent && userAgent != fingerprint.UserAgent {
		driftScore += 40
		reasons = append(reasons, "User-agent changed mid-session")
	}

	g.mu.Lock()
	fingerprint.LastVerified = time.Now().UnixMilli()
	g.mu.Unlock()

	if driftScore > 50 {
		return SessionValidationResult{
			Valid: false, Regenerate: true,
			Reason:     fmt.Sprintf("Session fixation/hijack suspected: %s", strings.Join(reasons, "; ")),
			DriftScore: driftScore,
		}
	}

	if driftScore > 0 {
		return SessionValidationResult{
			Valid: true, Regenerate: false,
			Reason:     fmt.Sprintf("Minor session drift: %s", strings.Join(reasons, "; ")),
			DriftScore: driftScore,
		}
	}

	return SessionValidationResult{Valid: true, Regenerate: false, Reason: "Session fingerprint matches", DriftScore: 0}
}

// RemoveSession removes a session's fingerprint.
func (g *SessionFixationGuard) RemoveSession(sessionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.sessions, sessionID)
}

// GetStats returns the number of active sessions.
func (g *SessionFixationGuard) GetStats() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sessions)
}
