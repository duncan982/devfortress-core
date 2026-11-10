package devfortress

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"sync"
	"time"
)

// AgentCredentialType is the kind of credential an agent alias protects.
type AgentCredentialType string

const (
	CredentialAgentAPIKey     AgentCredentialType = "agent_api_key"
	CredentialAgentOAuthToken AgentCredentialType = "agent_oauth_token"
	CredentialServiceAccount  AgentCredentialType = "service_account"
)

// AgentExecutionContext is an execution-context baseline captured at agent
// alias issuance (container/session identity, expected egress path,
// expected process signature). Recorded for later comparison; not
// compared against anything by this package yet.
type AgentExecutionContext struct {
	ContainerID             string
	ExpectedEgressPath      string
	ExpectedProcessSignature string
}

// AgentCredentialAliasData is one agent credential alias and its metadata.
type AgentCredentialAliasData struct {
	Alias             string
	AgentID           string
	CredentialType    AgentCredentialType
	CreatedAt         time.Time
	Quarantined       bool
	QuarantineReason  string
	QuarantinedAt     time.Time
	ExecutionContext  *AgentExecutionContext
}

// AgentBaselineMetrics is a behavioral baseline for one agent, built from
// its recorded sessions over a rolling window.
type AgentBaselineMetrics struct {
	AvgToolsPerSession   float64
	ToolDiversityEntropy float64
	AvgDataVolumeBytes   float64
	AvgSessionDurationMs float64
	TopTools             []string
	TotalSessions        int
	CreatedAt            time.Time
	LastUpdatedAt        time.Time
	TaskDefinition       string
}

// AgentToolCallRecord is one tool call within a session, for baseline
// building.
type AgentToolCallRecord struct {
	Tool       string
	DurationMs int64
	DataBytes  int64
}

// AgentSessionRecord is one completed (or in-progress) agent session.
type AgentSessionRecord struct {
	SessionID      string
	AgentID        string
	ToolCalls      []AgentToolCallRecord
	StartedAt      time.Time
	EndedAt        time.Time // zero value: not yet ended
	TotalDataBytes int64
}

// AgentAnomalyType identifies the kind of behavioral anomaly detected.
type AgentAnomalyType string

const (
	AnomalySequenceEntropy        AgentAnomalyType = "sequence_entropy_anomaly"
	AnomalyScopeDeviation         AgentAnomalyType = "scope_deviation"
	AnomalyDataVolume             AgentAnomalyType = "data_volume_anomaly"
	AnomalyCrossAgentSharing      AgentAnomalyType = "cross_agent_credential_sharing"
	AnomalyUnsanctionedTool       AgentAnomalyType = "unsanctioned_tool"
)

// AgentAnomalySeverity is the severity of a detected anomaly.
type AgentAnomalySeverity string

const (
	SeverityLow      AgentAnomalySeverity = "low"
	SeverityMedium   AgentAnomalySeverity = "medium"
	SeverityHigh     AgentAnomalySeverity = "high"
	SeverityCritical AgentAnomalySeverity = "critical"
)

// AgentAnomalySignal is one detected behavioral anomaly.
type AgentAnomalySignal struct {
	Type        AgentAnomalyType
	AgentID     string
	Severity    AgentAnomalySeverity
	Description string
	DetectedAt  time.Time
	Details     map[string]any
}

// AgentScopeDefinition is the sanctioned tool scope for one agent.
type AgentScopeDefinition struct {
	AgentID      string
	AllowedTools []string
	StrictMode   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func shannonEntropy(items []string) float64 {
	if len(items) == 0 {
		return 0
	}
	freq := make(map[string]int, len(items))
	for _, item := range items {
		freq[item]++
	}
	var entropy float64
	total := float64(len(items))
	for _, count := range freq {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func stdDev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	var sq float64
	for _, v := range values {
		sq += (v - mean) * (v - mean)
	}
	return math.Sqrt(sq / float64(len(values)))
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// is3SigmaDeviation reports whether newValue deviates more than 3 standard
// deviations from values.
func is3SigmaDeviation(values []float64, newValue float64) bool {
	if len(values) < 2 {
		return false
	}
	m := mean(values)
	sd := stdDev(values)
	if sd == 0 {
		return newValue != m
	}
	return math.Abs(newValue-m) > 3*sd
}

// AgentCredentialManager issues, quarantines, and revokes agent-scoped
// credential aliases (Invention IP-C2), delegating the underlying
// crypto to a CredentialIsolationManager.
type AgentCredentialManager struct {
	mu          sync.Mutex
	isolation   *CredentialIsolationManager
	credentials map[string][]*AgentCredentialAliasData // agentID -> aliases
	quarantines map[string]agentQuarantine
}

type agentQuarantine struct {
	reason string
	at     time.Time
}

// NewAgentCredentialManager returns a manager backed by isolation for the
// underlying credential-isolation crypto.
func NewAgentCredentialManager(isolation *CredentialIsolationManager) *AgentCredentialManager {
	return &AgentCredentialManager{
		isolation:   isolation,
		credentials: make(map[string][]*AgentCredentialAliasData),
		quarantines: make(map[string]agentQuarantine),
	}
}

// CreateAgentAlias creates an alias for an agent credential. The real
// credential never leaves the caller.
func (m *AgentCredentialManager) CreateAgentAlias(ctx context.Context, realCredential, agentID string, credentialType AgentCredentialType, ttl time.Duration, execCtx *AgentExecutionContext) (string, error) {
	if err := ValidateAgentID(agentID); err != nil {
		return "", err
	}
	alias, err := m.isolation.CreateAlias(ctx, realCredential, agentID, ttl)
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.credentials[agentID] = append(m.credentials[agentID], &AgentCredentialAliasData{
		Alias: alias, AgentID: agentID, CredentialType: credentialType,
		CreatedAt: time.Now(), ExecutionContext: execCtx,
	})
	return alias, nil
}

// RevokeAgentAccess revokes every credential for an agent (compromise or
// decommission). Returns the number of credentials revoked.
func (m *AgentCredentialManager) RevokeAgentAccess(ctx context.Context, agentID string, reason RevocationReason) int {
	m.mu.Lock()
	creds := m.credentials[agentID]
	delete(m.credentials, agentID)
	delete(m.quarantines, agentID)
	m.mu.Unlock()

	if reason == "" {
		reason = RevocationActiveThreat
	}
	revoked := 0
	for _, cred := range creds {
		if _, ok := m.isolation.RevokeByAlias(ctx, cred.Alias, reason, agentID); ok {
			revoked++
		}
	}
	return revoked
}

// QuarantineAgent suspends tool access for an agent while preserving its
// session data for forensics. Reversible, unlike revocation.
func (m *AgentCredentialManager) QuarantineAgent(agentID, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	at := time.Now()
	m.quarantines[agentID] = agentQuarantine{reason: reason, at: at}
	for _, cred := range m.credentials[agentID] {
		cred.Quarantined = true
		cred.QuarantineReason = reason
		cred.QuarantinedAt = at
	}
}

// UnquarantineAgent lifts quarantine, restoring normal tool access.
// Returns an error if the agent is not currently quarantined — reinstatement
// is only meaningful as the reverse of an active quarantine.
func (m *AgentCredentialManager) UnquarantineAgent(agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.quarantines[agentID]; !ok {
		return fmt.Errorf("devfortress: agent %q is not currently quarantined — nothing to reinstate", agentID)
	}
	delete(m.quarantines, agentID)
	for _, cred := range m.credentials[agentID] {
		cred.Quarantined = false
		cred.QuarantineReason = ""
		cred.QuarantinedAt = time.Time{}
	}
	return nil
}

// IsQuarantined reports whether agentID is currently quarantined.
func (m *AgentCredentialManager) IsQuarantined(agentID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.quarantines[agentID]
	return ok
}

// GetAgentCredentials returns every credential alias recorded for agentID.
func (m *AgentCredentialManager) GetAgentCredentials(agentID string) []AgentCredentialAliasData {
	m.mu.Lock()
	defer m.mu.Unlock()
	creds := m.credentials[agentID]
	out := make([]AgentCredentialAliasData, len(creds))
	for i, c := range creds {
		out[i] = *c
	}
	return out
}

const (
	baselineWindow        = 30 * 24 * time.Hour
	minSessionsForBaseline = 5
)

// AgentBaselineEngine builds and maintains a 30-day rolling behavioral
// baseline per agent (Invention IP-C3): average tools per session, tool
// diversity entropy, data volume, and session duration.
type AgentBaselineEngine struct {
	mu        sync.Mutex
	sessions  map[string][]AgentSessionRecord
	baselines map[string]*AgentBaselineMetrics
}

// NewAgentBaselineEngine returns an empty baseline engine.
func NewAgentBaselineEngine() *AgentBaselineEngine {
	return &AgentBaselineEngine{
		sessions:  make(map[string][]AgentSessionRecord),
		baselines: make(map[string]*AgentBaselineMetrics),
	}
}

// RecordSession records a completed session for baseline building,
// enforcing the 30-day rolling window and recalculating the baseline once
// enough sessions are present.
func (e *AgentBaselineEngine) RecordSession(record AgentSessionRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()

	windowStart := time.Now().Add(-baselineWindow)
	filtered := make([]AgentSessionRecord, 0, len(e.sessions[record.AgentID])+1)
	for _, s := range e.sessions[record.AgentID] {
		if s.StartedAt.After(windowStart) {
			filtered = append(filtered, s)
		}
	}
	filtered = append(filtered, record)
	e.sessions[record.AgentID] = filtered

	if len(filtered) >= minSessionsForBaseline {
		e.recalculateLocked(record.AgentID, "")
	}
}

// Baseline establishes (or returns the existing) baseline from a task
// definition. Returns nil until enough sessions have been recorded.
func (e *AgentBaselineEngine) Baseline(agentID, taskDefinition string) *AgentBaselineMetrics {
	e.mu.Lock()
	defer e.mu.Unlock()

	if existing, ok := e.baselines[agentID]; ok {
		existing.TaskDefinition = taskDefinition
		existing.LastUpdatedAt = time.Now()
		return existing
	}
	if len(e.sessions[agentID]) < minSessionsForBaseline {
		return nil
	}
	return e.recalculateLocked(agentID, taskDefinition)
}

// GetBaseline returns the current baseline for agentID, or nil.
func (e *AgentBaselineEngine) GetBaseline(agentID string) *AgentBaselineMetrics {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.baselines[agentID]
}

func (e *AgentBaselineEngine) recalculateLocked(agentID, taskDefinition string) *AgentBaselineMetrics {
	sessions := e.sessions[agentID]

	toolsPerSession := make([]float64, len(sessions))
	var allTools []string
	dataVolumes := make([]float64, len(sessions))
	var durations []float64
	toolFreq := make(map[string]int)

	for i, s := range sessions {
		toolsPerSession[i] = float64(len(s.ToolCalls))
		dataVolumes[i] = float64(s.TotalDataBytes)
		for _, tc := range s.ToolCalls {
			allTools = append(allTools, tc.Tool)
			toolFreq[tc.Tool]++
		}
		if !s.EndedAt.IsZero() {
			durations = append(durations, float64(s.EndedAt.Sub(s.StartedAt).Milliseconds()))
		}
	}

	type toolCount struct {
		tool  string
		count int
	}
	counts := make([]toolCount, 0, len(toolFreq))
	for t, c := range toolFreq {
		counts = append(counts, toolCount{t, c})
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].count > counts[j].count })
	topTools := make([]string, 0, 10)
	for i := 0; i < len(counts) && i < 10; i++ {
		topTools = append(topTools, counts[i].tool)
	}

	existing := e.baselines[agentID]
	createdAt := time.Now()
	if existing != nil {
		createdAt = existing.CreatedAt
		if taskDefinition == "" {
			taskDefinition = existing.TaskDefinition
		}
	}

	baseline := &AgentBaselineMetrics{
		AvgToolsPerSession:   mean(toolsPerSession),
		ToolDiversityEntropy: shannonEntropy(allTools),
		AvgDataVolumeBytes:   mean(dataVolumes),
		AvgSessionDurationMs: mean(durations),
		TopTools:             topTools,
		TotalSessions:        len(sessions),
		CreatedAt:            createdAt,
		LastUpdatedAt:        time.Now(),
		TaskDefinition:       taskDefinition,
	}
	e.baselines[agentID] = baseline
	return baseline
}

// AgentAnomalyHandler receives every detected anomaly signal.
type AgentAnomalyHandler func(AgentAnomalySignal)

// AgentAnomalyDetector flags behavioral anomalies against an agent's
// baseline (Invention IP-C4): scope deviation, 3-sigma data-volume
// deviation, cross-agent credential sharing, and sequence-entropy
// deviation — plus unsanctioned-tool enforcement (Invention IP-C5),
// integrated here for convenience.
type AgentAnomalyDetector struct {
	mu              sync.Mutex
	baselineEngine  *AgentBaselineEngine
	handlers        []AgentAnomalyHandler
	credentialUsage map[string]map[string]bool // credentialAlias -> set of agentID
	scopes          map[string]*AgentScopeDefinition
}

// NewAgentAnomalyDetector returns a detector driven by baselineEngine.
func NewAgentAnomalyDetector(baselineEngine *AgentBaselineEngine) *AgentAnomalyDetector {
	return &AgentAnomalyDetector{
		baselineEngine:  baselineEngine,
		credentialUsage: make(map[string]map[string]bool),
		scopes:          make(map[string]*AgentScopeDefinition),
	}
}

// OnAnomaly registers a handler invoked for every detected anomaly.
func (d *AgentAnomalyDetector) OnAnomaly(handler AgentAnomalyHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers = append(d.handlers, handler)
}

// DefineAgentScope registers the sanctioned tool scope for agentID
// (Invention IP-C5). In strict mode, any tool outside allowedTools fires a
// critical anomaly immediately.
func (d *AgentAnomalyDetector) DefineAgentScope(agentID string, allowedTools []string, strictMode bool) AgentScopeDefinition {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	createdAt := now
	if existing, ok := d.scopes[agentID]; ok {
		createdAt = existing.CreatedAt
	}
	scope := &AgentScopeDefinition{AgentID: agentID, AllowedTools: allowedTools, StrictMode: strictMode, CreatedAt: createdAt, UpdatedAt: now}
	d.scopes[agentID] = scope
	return *scope
}

// IsToolAllowed reports whether toolName is within agentID's defined
// scope. Allows by default when no scope is defined, or when the scope is
// not in strict mode.
func (d *AgentAnomalyDetector) IsToolAllowed(agentID, toolName string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	scope, ok := d.scopes[agentID]
	if !ok || !scope.StrictMode {
		return true
	}
	for _, t := range scope.AllowedTools {
		if t == toolName {
			return true
		}
	}
	return false
}

// AnalyzeToolCall checks one tool call against agentID's scope and
// baseline, returning every anomaly signal detected (each has already
// been dispatched to registered handlers).
func (d *AgentAnomalyDetector) AnalyzeToolCall(agentID, toolName string, dataBytes int64, credentialAlias string) []AgentAnomalySignal {
	d.mu.Lock()
	defer d.mu.Unlock()

	var signals []AgentAnomalySignal
	now := time.Now()

	if scope, ok := d.scopes[agentID]; ok && scope.StrictMode && !containsString(scope.AllowedTools, toolName) {
		signal := AgentAnomalySignal{
			Type: AnomalyUnsanctionedTool, AgentID: agentID, Severity: SeverityCritical,
			Description: fmt.Sprintf("Agent %s invoked unsanctioned tool %q. Allowed: %v", agentID, toolName, scope.AllowedTools),
			DetectedAt:  now, Details: map[string]any{"tool": toolName, "allowedTools": scope.AllowedTools},
		}
		signals = append(signals, signal)
		d.emitLocked(signal)
	}

	baseline := d.baselineEngine.GetBaseline(agentID)
	if baseline == nil {
		return signals
	}

	if len(baseline.TopTools) > 0 && !containsString(baseline.TopTools, toolName) {
		signal := AgentAnomalySignal{
			Type: AnomalyScopeDeviation, AgentID: agentID, Severity: SeverityMedium,
			Description: fmt.Sprintf("Agent %s invoked tool %q outside its baseline tool set", agentID, toolName),
			DetectedAt:  now, Details: map[string]any{"tool": toolName, "baselineTools": baseline.TopTools},
		}
		signals = append(signals, signal)
		d.emitLocked(signal)
	}

	if dataBytes > 0 {
		var volumes []float64
		for _, s := range d.baselineEngine.sessions[agentID] {
			volumes = append(volumes, float64(s.TotalDataBytes))
		}
		if is3SigmaDeviation(volumes, float64(dataBytes)) {
			signal := AgentAnomalySignal{
				Type: AnomalyDataVolume, AgentID: agentID, Severity: SeverityHigh,
				Description: fmt.Sprintf("Agent %s data volume %dB is 3-sigma deviation from baseline avg %.0fB", agentID, dataBytes, baseline.AvgDataVolumeBytes),
				DetectedAt:  now, Details: map[string]any{"dataBytes": dataBytes, "baselineAvg": baseline.AvgDataVolumeBytes},
			}
			signals = append(signals, signal)
			d.emitLocked(signal)
		}
	}

	if credentialAlias != "" {
		if d.credentialUsage[credentialAlias] == nil {
			d.credentialUsage[credentialAlias] = make(map[string]bool)
		}
		d.credentialUsage[credentialAlias][agentID] = true
		agents := d.credentialUsage[credentialAlias]
		if len(agents) > 1 {
			agentList := make([]string, 0, len(agents))
			for a := range agents {
				agentList = append(agentList, a)
			}
			truncated := credentialAlias
			if len(truncated) > 16 {
				truncated = truncated[:16]
			}
			signal := AgentAnomalySignal{
				Type: AnomalyCrossAgentSharing, AgentID: agentID, Severity: SeverityCritical,
				Description: fmt.Sprintf("Credential %s... shared across %d agents: %v", truncated, len(agents), agentList),
				DetectedAt:  now, Details: map[string]any{"credentialAlias": truncated + "...", "sharingAgents": agentList},
			}
			signals = append(signals, signal)
			d.emitLocked(signal)
		}
	}

	return signals
}

// AnalyzeSession checks a completed session's tool-call entropy against
// the agent's baseline, flagging a sequence-entropy anomaly when it
// deviates more than 50%.
func (d *AgentAnomalyDetector) AnalyzeSession(record AgentSessionRecord) []AgentAnomalySignal {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseline := d.baselineEngine.GetBaseline(record.AgentID)
	if baseline == nil || baseline.TotalSessions < 5 {
		return nil
	}

	tools := make([]string, len(record.ToolCalls))
	for i, tc := range record.ToolCalls {
		tools[i] = tc.Tool
	}
	sessionEntropy := shannonEntropy(tools)
	deviation := math.Abs(sessionEntropy - baseline.ToolDiversityEntropy)

	if baseline.ToolDiversityEntropy > 0 && deviation/baseline.ToolDiversityEntropy > 0.5 {
		signal := AgentAnomalySignal{
			Type: AnomalySequenceEntropy, AgentID: record.AgentID, Severity: SeverityHigh,
			Description: fmt.Sprintf("Agent %s session entropy %.2f deviates %.0f%% from baseline %.2f", record.AgentID, sessionEntropy, deviation/baseline.ToolDiversityEntropy*100, baseline.ToolDiversityEntropy),
			DetectedAt:  time.Now(),
			Details: map[string]any{
				"sessionEntropy": sessionEntropy, "baselineEntropy": baseline.ToolDiversityEntropy,
				"deviationPercent": deviation / baseline.ToolDiversityEntropy * 100,
			},
		}
		d.emitLocked(signal)
		return []AgentAnomalySignal{signal}
	}
	return nil
}

func (d *AgentAnomalyDetector) emitLocked(signal AgentAnomalySignal) {
	for _, h := range d.handlers {
		safeInvokeAnomalyHandler(h, signal)
	}
}

func safeInvokeAnomalyHandler(h AgentAnomalyHandler, signal AgentAnomalySignal) {
	defer func() { _ = recover() }() // a handler error must never block detection
	h(signal)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

const (
	agentIDMaxLength = 128
)

var agentIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-.:@]+$`)

// ValidateAgentID validates an agent ID to prevent injection and ensure
// safe use as a cache key and pseudo-URL path segment.
func ValidateAgentID(agentID string) error {
	if agentID == "" {
		return fmt.Errorf("devfortress: agentId is required and must be a non-empty string")
	}
	if len(agentID) > agentIDMaxLength {
		return fmt.Errorf("devfortress: agentId must be at most %d characters", agentIDMaxLength)
	}
	if !agentIDPattern.MatchString(agentID) {
		return fmt.Errorf("devfortress: agentId may only contain alphanumeric characters, hyphens, underscores, dots, colons, and @")
	}
	return nil
}
