package devfortress

import (
	"sync"
	"time"
)

// ToolCallRiskLevel is a tool's risk classification within the sequence
// graph.
type ToolCallRiskLevel string

const (
	RiskLow      ToolCallRiskLevel = "low"
	RiskMedium   ToolCallRiskLevel = "medium"
	RiskHigh     ToolCallRiskLevel = "high"
	RiskCritical ToolCallRiskLevel = "critical"
)

// ToolCallGraphNode is one tool's entry in the authorized sequence graph.
type ToolCallGraphNode struct {
	// Requires lists tools that must have been called before this one.
	Requires []string
	// MaxCalls is the maximum calls to this tool per session (0 = unlimited).
	MaxCalls int
	RiskLevel ToolCallRiskLevel
}

// ToolCallGraph is the authorized tool-call DAG, keyed by tool name.
type ToolCallGraph map[string]ToolCallGraphNode

// ToolCallAction is the graduated response recommended for a tool call.
type ToolCallAction string

const (
	ActionAllow        ToolCallAction = "allow"
	ActionLog          ToolCallAction = "log"
	ActionRateLimit    ToolCallAction = "rate_limit"
	ActionBlock        ToolCallAction = "block"
	ActionRevokeSession ToolCallAction = "revoke_session"
)

// ToolCallSequenceConfig configures a ToolCallSequenceValidator.
type ToolCallSequenceConfig struct {
	Graph ToolCallGraph
	// MaxViolations is the violation count that triggers session
	// revocation. Default: 3.
	MaxViolations int
	// ViolationWindow is how long a violation counts toward MaxViolations.
	// Default: 5 minutes.
	ViolationWindow time.Duration
	// GraduatedResponse enables log -> rate_limit -> block -> revoke
	// escalation by violation count. When false, every violation is a
	// block. Default: true.
	GraduatedResponse *bool
}

// ToolCallValidationResult is the outcome of one ToolCallSequenceValidator.Validate call.
type ToolCallValidationResult struct {
	Allowed                bool
	Reason                 string
	Action                 ToolCallAction
	PromptInjectionLikely  bool
	ViolationCount         int
	CallHistory            []string
	MissingPrerequisites   []string
}

type sequenceViolation struct {
	timestamp time.Time
	tool      string
	reason    string
}

type sequenceSessionState struct {
	callHistory []string
	callCounts  map[string]int
	violations  []sequenceViolation
}

const maxSequenceSessions = 50_000

// ToolCallSequenceValidator validates AI agent tool calls against an
// authorized DAG (Invention A7), detecting out-of-sequence calls that
// indicate prompt injection, with a graduated response:
// log -> rate_limit -> block -> revoke_session. Safe for concurrent use.
type ToolCallSequenceValidator struct {
	mu              sync.Mutex
	config          ToolCallSequenceConfig
	sessions        map[string]*sequenceSessionState
	sessionOrder    []string
}

// NewToolCallSequenceValidator returns a validator for cfg.Graph.
func NewToolCallSequenceValidator(cfg ToolCallSequenceConfig) *ToolCallSequenceValidator {
	if cfg.MaxViolations <= 0 {
		cfg.MaxViolations = 3
	}
	if cfg.ViolationWindow <= 0 {
		cfg.ViolationWindow = 5 * time.Minute
	}
	if cfg.GraduatedResponse == nil {
		enabled := true
		cfg.GraduatedResponse = &enabled
	}
	return &ToolCallSequenceValidator{config: cfg, sessions: make(map[string]*sequenceSessionState)}
}

// Validate checks one tool call for sessionID against the authorized
// sequence graph, recording it if allowed.
func (v *ToolCallSequenceValidator) Validate(sessionID, toolName string) ToolCallValidationResult {
	v.mu.Lock()
	defer v.mu.Unlock()

	session := v.getOrCreateSessionLocked(sessionID)
	now := time.Now()

	pruned := session.violations[:0]
	for _, viol := range session.violations {
		if now.Sub(viol.timestamp) < v.config.ViolationWindow {
			pruned = append(pruned, viol)
		}
	}
	session.violations = pruned

	node, known := v.config.Graph[toolName]
	if !known {
		session.violations = append(session.violations, sequenceViolation{now, toolName, "unknown_tool"})
		return v.buildResult(session, false, "unknown_tool", toolName, nil)
	}

	var missing []string
	for _, req := range node.Requires {
		if !containsString(session.callHistory, req) {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		session.violations = append(session.violations, sequenceViolation{now, toolName, "missing_prerequisites"})
		return v.buildResult(session, false, "out_of_sequence", toolName, missing)
	}

	current := session.callCounts[toolName]
	if node.MaxCalls > 0 && current >= node.MaxCalls {
		session.violations = append(session.violations, sequenceViolation{now, toolName, "max_calls_exceeded"})
		return v.buildResult(session, false, "max_calls_exceeded", toolName, nil)
	}

	session.callHistory = append(session.callHistory, toolName)
	session.callCounts[toolName] = current + 1

	return ToolCallValidationResult{
		Allowed: true, Reason: "valid_sequence", Action: ActionAllow,
		ViolationCount: len(session.violations), CallHistory: cloneStrings(session.callHistory),
	}
}

// ResetSession clears a session's recorded state (e.g. after quarantine release).
func (v *ToolCallSequenceValidator) ResetSession(sessionID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.sessions, sessionID)
}

// History returns the recorded call history for sessionID.
func (v *ToolCallSequenceValidator) History(sessionID string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if s, ok := v.sessions[sessionID]; ok {
		return cloneStrings(s.callHistory)
	}
	return nil
}

// SessionStats returns monitoring stats for sessionID.
func (v *ToolCallSequenceValidator) SessionStats(sessionID string) (exists bool, callCount, violationCount int, history []string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.sessions[sessionID]
	if !ok {
		return false, 0, 0, nil
	}
	return true, len(s.callHistory), len(s.violations), cloneStrings(s.callHistory)
}

// Destroy clears all sessions.
func (v *ToolCallSequenceValidator) Destroy() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sessions = make(map[string]*sequenceSessionState)
	v.sessionOrder = nil
}

func (v *ToolCallSequenceValidator) getOrCreateSessionLocked(sessionID string) *sequenceSessionState {
	if s, ok := v.sessions[sessionID]; ok {
		return s
	}
	if len(v.sessions) >= maxSequenceSessions && len(v.sessionOrder) > 0 {
		oldest := v.sessionOrder[0]
		v.sessionOrder = v.sessionOrder[1:]
		delete(v.sessions, oldest)
	}
	s := &sequenceSessionState{callCounts: make(map[string]int)}
	v.sessions[sessionID] = s
	v.sessionOrder = append(v.sessionOrder, sessionID)
	return s
}

func (v *ToolCallSequenceValidator) buildResult(session *sequenceSessionState, allowed bool, reason, toolName string, missing []string) ToolCallValidationResult {
	violationCount := len(session.violations)

	action := ActionLog
	if v.config.GraduatedResponse != nil && *v.config.GraduatedResponse {
		switch {
		case violationCount >= v.config.MaxViolations:
			action = ActionRevokeSession
		case violationCount >= 2:
			action = ActionBlock
		case violationCount >= 1:
			action = ActionRateLimit
		}
	} else {
		action = ActionBlock
	}

	node := v.config.Graph[toolName]
	promptInjectionLikely := reason == "out_of_sequence" && (node.RiskLevel == RiskHigh || node.RiskLevel == RiskCritical)

	return ToolCallValidationResult{
		Allowed: allowed, Reason: reason, Action: action,
		PromptInjectionLikely: promptInjectionLikely, ViolationCount: violationCount,
		CallHistory: cloneStrings(session.callHistory), MissingPrerequisites: missing,
	}
}

func cloneStrings(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	return out
}
