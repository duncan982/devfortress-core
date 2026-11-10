package devfortress

import (
	"encoding/json"
	"hash/fnv"
	"sort"
	"strconv"
	"sync"
	"time"
)

// AgentLoopAction is the recommended response to a recorded cycle.
type AgentLoopAction string

const (
	LoopContinue   AgentLoopAction = "CONTINUE"
	LoopWarn       AgentLoopAction = "WARN"
	LoopPauseAgent AgentLoopAction = "PAUSE_AGENT"
	LoopTerminate  AgentLoopAction = "TERMINATE"
)

// AgentLoopProgressThreshold defines what counts as "making progress"
// within a sliding window of recent cycles.
type AgentLoopProgressThreshold struct {
	UniqueTools  int
	WindowCycles int
}

// AgentLoopConfig configures an AgentLoopDetector.
type AgentLoopConfig struct {
	// MaxCycles before circuit break. Default: 20.
	MaxCycles int
	// MaxDuration before circuit break. Default: 2 minutes.
	MaxDuration time.Duration
	// MaxTokens consumed per session before circuit break. Default: 100,000.
	MaxTokens int64
	// ProgressThreshold overrides the default (2 unique tools per 5 cycles).
	ProgressThreshold AgentLoopProgressThreshold
	// MaxSessions bounds tracked sessions. Default: 50,000.
	MaxSessions int
}

// LoopCycleContext is the data recorded for one agent execution cycle.
type LoopCycleContext struct {
	TokensUsed     int64
	ToolName       string
	ToolArgs       map[string]any
	ProgressMetric *float64
}

// LoopDetectionResult is the outcome of one AgentLoopDetector.RecordCycle call.
type LoopDetectionResult struct {
	Loop             bool
	Reason           string
	Action           AgentLoopAction
	Cycles           int
	TotalTokens      int64
	Elapsed          time.Duration
	MakingProgress   bool
	RepetitionScore  float64
}

type loopSession struct {
	agentID        string
	startedAt      time.Time
	cycles         int
	totalTokens    int64
	toolHistory    []string
	argHashes      []string
	progressMetrics []float64
	paused         bool
}

// AgentLoopDetector tracks agent execution cycles and token consumption,
// detecting infinite loops via cycle count, time budget and token budget
// thresholds, with an automatic circuit breaker (Invention A10). Safe for
// concurrent use.
type AgentLoopDetector struct {
	mu       sync.Mutex
	config   AgentLoopConfig
	sessions map[string]*loopSession
}

// NewAgentLoopDetector returns a detector with cfg's values, applying
// documented defaults for zero fields.
func NewAgentLoopDetector(cfg AgentLoopConfig) *AgentLoopDetector {
	if cfg.MaxCycles <= 0 {
		cfg.MaxCycles = 20
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = 2 * time.Minute
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 100_000
	}
	if cfg.ProgressThreshold.UniqueTools <= 0 {
		cfg.ProgressThreshold.UniqueTools = 2
	}
	if cfg.ProgressThreshold.WindowCycles <= 0 {
		cfg.ProgressThreshold.WindowCycles = 5
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 50_000
	}
	return &AgentLoopDetector{config: cfg, sessions: make(map[string]*loopSession)}
}

// RecordCycle records a new execution cycle for an agent session and
// returns the detection result.
func (d *AgentLoopDetector) RecordCycle(agentID, sessionID string, ctx LoopCycleContext) LoopDetectionResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	session := d.getOrCreateSessionLocked(agentID, sessionID)
	now := time.Now()

	if session.paused {
		return d.buildResult(session, now, true, "agent_paused", LoopTerminate)
	}

	session.cycles++
	session.totalTokens += ctx.TokensUsed
	if ctx.ToolName != "" {
		session.toolHistory = append(session.toolHistory, ctx.ToolName)
	}
	if ctx.ToolArgs != nil {
		session.argHashes = append(session.argHashes, hashArgs(ctx.ToolArgs))
	}
	if ctx.ProgressMetric != nil {
		session.progressMetrics = append(session.progressMetrics, *ctx.ProgressMetric)
	}

	elapsed := now.Sub(session.startedAt)
	makingProgress := d.checkProgress(session)
	repetitionScore := computeRepetitionScore(session)

	if session.cycles >= d.config.MaxCycles && !makingProgress {
		session.paused = true
		return d.buildResult(session, now, true, "max_cycles", LoopPauseAgent)
	}
	if elapsed >= d.config.MaxDuration {
		session.paused = true
		return d.buildResult(session, now, true, "max_duration", LoopPauseAgent)
	}
	if session.totalTokens >= d.config.MaxTokens {
		session.paused = true
		return d.buildResult(session, now, true, "max_tokens", LoopPauseAgent)
	}
	if repetitionScore > 0.8 && session.cycles > 5 && !makingProgress {
		session.paused = true
		return d.buildResult(session, now, true, "repetitive_pattern", LoopPauseAgent)
	}

	eightyPct := func(n int) int { return n * 8 / 10 }
	if session.cycles >= eightyPct(d.config.MaxCycles) ||
		elapsed >= d.config.MaxDuration*8/10 ||
		session.totalTokens >= d.config.MaxTokens*8/10 {
		return d.buildResult(session, now, false, "approaching_limit", LoopWarn)
	}

	return d.buildResult(session, now, false, "within_limits", LoopContinue)
}

// ClearSession removes a session's recorded state, keyed by agentID and
// sessionID together (matching RecordCycle's internal key).
func (d *AgentLoopDetector) ClearSession(agentID, sessionID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sessions, sessionKey(agentID, sessionID))
}

// ReleaseAgent resets a paused session back to a clean slate after human
// review. Returns false if the session doesn't exist.
func (d *AgentLoopDetector) ReleaseAgent(agentID, sessionID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[sessionKey(agentID, sessionID)]
	if !ok {
		return false
	}
	s.paused = false
	s.cycles = 0
	s.totalTokens = 0
	s.toolHistory = nil
	s.argHashes = nil
	return true
}

// IsPaused reports whether the session is currently paused.
func (d *AgentLoopDetector) IsPaused(agentID, sessionID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[sessionKey(agentID, sessionID)]
	return ok && s.paused
}

// Metrics returns monitoring metrics for a session.
func (d *AgentLoopDetector) Metrics(agentID, sessionID string) (exists bool, cycles int, tokens int64, elapsed time.Duration, paused bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[sessionKey(agentID, sessionID)]
	if !ok {
		return false, 0, 0, 0, false
	}
	return true, s.cycles, s.totalTokens, time.Since(s.startedAt), s.paused
}

// Destroy clears every tracked session.
func (d *AgentLoopDetector) Destroy() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions = make(map[string]*loopSession)
}

func sessionKey(agentID, sessionID string) string { return agentID + ":" + sessionID }

func (d *AgentLoopDetector) getOrCreateSessionLocked(agentID, sessionID string) *loopSession {
	key := sessionKey(agentID, sessionID)
	if s, ok := d.sessions[key]; ok {
		return s
	}
	if len(d.sessions) >= d.config.MaxSessions {
		for k := range d.sessions {
			delete(d.sessions, k)
			break
		}
	}
	s := &loopSession{agentID: agentID, startedAt: time.Now()}
	d.sessions[key] = s
	return s
}

func (d *AgentLoopDetector) checkProgress(session *loopSession) bool {
	uniqueTools, windowCycles := d.config.ProgressThreshold.UniqueTools, d.config.ProgressThreshold.WindowCycles
	recent := session.toolHistory
	if len(recent) > windowCycles {
		recent = recent[len(recent)-windowCycles:]
	}
	seen := make(map[string]bool)
	for _, t := range recent {
		seen[t] = true
	}
	if len(seen) >= uniqueTools {
		return true
	}

	if len(session.progressMetrics) >= 2 {
		recentMetrics := session.progressMetrics
		if len(recentMetrics) > 3 {
			recentMetrics = recentMetrics[len(recentMetrics)-3:]
		}
		increasing := true
		for i := 1; i < len(recentMetrics); i++ {
			if recentMetrics[i] <= recentMetrics[i-1] {
				increasing = false
				break
			}
		}
		if increasing {
			return true
		}
	}
	return false
}

func computeRepetitionScore(session *loopSession) float64 {
	if len(session.argHashes) < 3 {
		return 0
	}
	recent := session.argHashes
	if len(recent) > 10 {
		recent = recent[len(recent)-10:]
	}
	unique := make(map[string]bool)
	for _, h := range recent {
		unique[h] = true
	}
	return 1 - float64(len(unique))/float64(len(recent))
}

func hashArgs(args map[string]any) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]any, len(args))
	for _, k := range keys {
		ordered[k] = args[k]
	}
	raw, _ := json.Marshal(ordered)
	h := fnv.New64a()
	_, _ = h.Write(raw)
	return strconv.FormatUint(h.Sum64(), 36)
}

func (d *AgentLoopDetector) buildResult(session *loopSession, now time.Time, loop bool, reason string, action AgentLoopAction) LoopDetectionResult {
	return LoopDetectionResult{
		Loop: loop, Reason: reason, Action: action,
		Cycles: session.cycles, TotalTokens: session.totalTokens,
		Elapsed: now.Sub(session.startedAt), MakingProgress: d.checkProgress(session),
		RepetitionScore: computeRepetitionScore(session),
	}
}
