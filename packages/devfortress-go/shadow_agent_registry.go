package devfortress

import (
	"os"
	"strings"
	"sync"
	"time"
)

// ShadowAgentConfig configures a ShadowAgentRegistry.
type ShadowAgentConfig struct {
	// HeartbeatTimeout is the maximum time between agent heartbeats
	// before PruneInactive marks an agent inactive. Default: 5 minutes.
	HeartbeatTimeout time.Duration
	// AgentPatterns are behavioral patterns that indicate agent-like
	// activity. Empty uses DefaultAgentPatterns.
	AgentPatterns []string
	// AutoBlock enables recommending "block" (instead of "register") for
	// high-confidence shadow-agent detections.
	AutoBlock bool
}

// RegisteredAgent is one known, registered AI agent.
type RegisteredAgent struct {
	AgentID       string
	Name          string
	RegisteredAt  int64
	LastHeartbeat int64
	Owner         string
	Permissions   []string
	Active        bool
}

// ShadowAgentRecommendation is the action Detect recommends.
type ShadowAgentRecommendation string

const (
	ShadowRecommendRegister ShadowAgentRecommendation = "register"
	ShadowRecommendBlock    ShadowAgentRecommendation = "block"
	ShadowRecommendMonitor  ShadowAgentRecommendation = "monitor"
)

// ShadowAgentDetection is the outcome of Detect.
type ShadowAgentDetection struct {
	Detected         bool
	AgentFingerprint string
	Indicators       []string
	Confidence       float64
	Recommendation   ShadowAgentRecommendation
	MatchedPatterns  []string
}

// AgentRegistryStats summarizes registry/detection activity.
type AgentRegistryStats struct {
	RegisteredCount  int
	ActiveCount      int
	ShadowDetections int
	BlockedShadows   int
}

// DefaultAgentPatterns are the built-in behavioral indicators of
// agent-like (as opposed to human) activity.
var DefaultAgentPatterns = []string{
	"automated request pattern (>100 req/min)",
	"consistent timing between requests (<50ms variance)",
	"sequential resource enumeration",
	"user-agent indicates bot/automation",
	"no mouse/keyboard entropy in session",
	"API-only access (no page loads)",
}

// ShadowAgentRegistry detects and tracks unauthorized ("shadow") AI agents
// that operate without proper registration. Maintains a registry of known
// agents and flags unregistered agent-like behavior.
//
type ShadowAgentRegistry struct {
	heartbeatTimeout time.Duration
	agentPatterns    []string
	autoBlock        bool

	mu               sync.Mutex
	registry         map[string]*RegisteredAgent
	shadowDetections map[string]ShadowAgentDetection
	stats            AgentRegistryStats
}

// NewShadowAgentRegistry returns a registry configured by cfg.
func NewShadowAgentRegistry(cfg ShadowAgentConfig) *ShadowAgentRegistry {
	timeout := cfg.HeartbeatTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	patterns := cfg.AgentPatterns
	if len(patterns) == 0 {
		patterns = DefaultAgentPatterns
	}

	return &ShadowAgentRegistry{
		heartbeatTimeout: timeout,
		agentPatterns:    patterns,
		autoBlock:        cfg.AutoBlock,
		registry:         make(map[string]*RegisteredAgent),
		shadowDetections: make(map[string]ShadowAgentDetection),
	}
}

// Register adds agent to the registry as active, stamping RegisteredAt
// and LastHeartbeat with the current time (any values passed in those
// fields, and in Active, are overwritten). When FEATURE_PLATFORM_INTEL is
// "false", Register returns agent with both timestamps zeroed and
// Active=false, without registering it — matching the Node SDK's
// feature-flag short-circuit.
func (r *ShadowAgentRegistry) Register(agent RegisteredAgent) RegisteredAgent {
	if os.Getenv("FEATURE_PLATFORM_INTEL") == "false" {
		agent.RegisteredAt = 0
		agent.LastHeartbeat = 0
		agent.Active = false
		return agent
	}

	now := time.Now().UnixMilli()
	agent.RegisteredAt = now
	agent.LastHeartbeat = now
	agent.Active = true

	r.mu.Lock()
	stored := agent
	r.registry[agent.AgentID] = &stored
	r.stats.RegisteredCount++
	r.stats.ActiveCount++
	r.mu.Unlock()

	return agent
}

// Heartbeat records a heartbeat from a registered agent. Returns false if
// agentID isn't registered.
func (r *ShadowAgentRegistry) Heartbeat(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	agent, ok := r.registry[agentID]
	if !ok {
		return false
	}
	agent.LastHeartbeat = time.Now().UnixMilli()
	agent.Active = true
	return true
}

// Detect checks whether a request source is a registered agent (in which
// case it is never flagged) or looks like an unregistered shadow agent,
// based on how many of indicators match the registry's known agent
// behavioral patterns. When FEATURE_PLATFORM_INTEL is "false", Detect
// always reports "monitor" without inspecting indicators.
func (r *ShadowAgentRegistry) Detect(fingerprint string, indicators []string) ShadowAgentDetection {
	if os.Getenv("FEATURE_PLATFORM_INTEL") == "false" {
		return ShadowAgentDetection{AgentFingerprint: fingerprint, Recommendation: ShadowRecommendMonitor}
	}

	r.mu.Lock()
	for _, agent := range r.registry {
		if agent.AgentID == fingerprint && agent.Active {
			r.mu.Unlock()
			return ShadowAgentDetection{AgentFingerprint: fingerprint, Recommendation: ShadowRecommendMonitor}
		}
	}
	r.mu.Unlock()

	var matched []string
	for _, pattern := range r.agentPatterns {
		patternKey := strings.ToLower(strings.TrimSpace(strings.SplitN(pattern, "(", 2)[0]))
		for _, indicator := range indicators {
			if strings.Contains(strings.ToLower(indicator), patternKey) {
				matched = append(matched, pattern)
				break
			}
		}
	}

	confidence := float64(len(matched)) / 3
	if confidence > 1 {
		confidence = 1
	}
	detected := confidence > 0.3

	r.mu.Lock()
	if detected {
		r.stats.ShadowDetections++
		if r.autoBlock && confidence > 0.7 {
			r.stats.BlockedShadows++
		}
	}
	r.mu.Unlock()

	recommendation := ShadowRecommendMonitor
	if confidence > 0.7 {
		if r.autoBlock {
			recommendation = ShadowRecommendBlock
		} else {
			recommendation = ShadowRecommendRegister
		}
	}

	result := ShadowAgentDetection{
		Detected:         detected,
		AgentFingerprint: fingerprint,
		Indicators:       indicators,
		Confidence:       confidence,
		Recommendation:   recommendation,
		MatchedPatterns:  matched,
	}
	if detected {
		r.mu.Lock()
		r.shadowDetections[fingerprint] = result
		r.mu.Unlock()
	}
	return result
}

// PruneInactive marks inactive every registered agent whose last
// heartbeat is older than HeartbeatTimeout, and returns their IDs.
func (r *ShadowAgentRegistry) PruneInactive() []string {
	cutoff := time.Now().UnixMilli() - r.heartbeatTimeout.Milliseconds()

	r.mu.Lock()
	defer r.mu.Unlock()
	var pruned []string
	for id, agent := range r.registry {
		if agent.LastHeartbeat < cutoff {
			agent.Active = false
			r.stats.ActiveCount--
			pruned = append(pruned, id)
		}
	}
	return pruned
}

// GetStats returns current registry/detection stats.
func (r *ShadowAgentRegistry) GetStats() AgentRegistryStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

// GetRegistered returns every registered agent (active or not).
func (r *ShadowAgentRegistry) GetRegistered() []RegisteredAgent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RegisteredAgent, 0, len(r.registry))
	for _, agent := range r.registry {
		out = append(out, *agent)
	}
	return out
}
