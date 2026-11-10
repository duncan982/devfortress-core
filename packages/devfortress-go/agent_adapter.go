package devfortress

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// AgentToolCall is one AI agent tool invocation to observe.
type AgentToolCall struct {
	// Tool is the tool being invoked (e.g. "web_search", "sql_query").
	Tool string
	// Input is summarized (not stored raw) before being queued.
	Input map[string]any
	// DurationMs is how long the tool call took.
	DurationMs int64
	// Model is the LLM that triggered this tool call.
	Model string
	// Framework identifies the originating framework.
	Framework string // "langchain", "langgraph", "openai", "anthropic", "raw_http", "custom"
	// Meta is additional metadata merged into the queued event.
	Meta map[string]any
}

// AgentAdapterConfig configures an AgentAdapter.
type AgentAdapterConfig struct {
	// AgentID uniquely identifies this agent instance. Required.
	AgentID string
	// AgentName is a human-readable label. Defaults to AgentID.
	AgentName string
	// AgentIP is the IP of the agent host. Defaults to "127.0.0.1" for
	// server-side agents.
	AgentIP string
	// MaxInputSummaryLength bounds the serialized input summary. Default: 256.
	MaxInputSummaryLength int
	// SanitizeInputs redacts input fields whose key looks like a secret
	// (key/token/secret/password). Default: true. Pass a pointer to false
	// to disable explicitly.
	SanitizeInputs *bool
}

// AgentAdapter wraps Client.TrackEvent for AI agent tool invocations,
// extracting agent_id, tool_name and a sanitized input_summary — the real
// tool inputs stay local; only the summary is queued. Safe for concurrent
// use.
//
// Unlike the Node SDK's synchronous df.observe() (which can return a
// server-decided flag/action on the same call), this adapter's underlying
// Client queues events asynchronously (Client.TrackEvent) — there is no
// per-call server round trip here to carry a flagged verdict back, so
// AgentAdapter has no onFlagged callback. The event shape (agent_id,
// tool_name, input_summary, framework, session tracking) matches the Node
// SDK field-for-field.
type AgentAdapter struct {
	client                *Client
	agentID               string
	agentName             string
	agentIP               string
	maxInputSummaryLength int
	sanitizeInputs        bool

	mu               sync.Mutex
	sessionToolCount map[string]int
}

const maxTrackedAgentSessions = 10_000

// NewAgentAdapter returns an AgentAdapter bound to client. Returns an
// error if cfg.AgentID fails ValidateAgentID.
func NewAgentAdapter(client *Client, cfg AgentAdapterConfig) (*AgentAdapter, error) {
	if err := ValidateAgentID(cfg.AgentID); err != nil {
		return nil, err
	}
	name := cfg.AgentName
	if name == "" {
		name = cfg.AgentID
	}
	ip := cfg.AgentIP
	if ip == "" {
		ip = "127.0.0.1"
	}
	maxLen := cfg.MaxInputSummaryLength
	if maxLen <= 0 {
		maxLen = 256
	}
	sanitize := true
	if cfg.SanitizeInputs != nil {
		sanitize = *cfg.SanitizeInputs
	}
	return &AgentAdapter{
		client: client, agentID: cfg.AgentID, agentName: name, agentIP: ip,
		maxInputSummaryLength: maxLen, sanitizeInputs: sanitize,
		sessionToolCount: make(map[string]int),
	}, nil
}

// ObserveToolCall queues an observation of an AI agent tool invocation.
// sessionID may be empty ("default" is used for per-session tool counting).
func (a *AgentAdapter) ObserveToolCall(ctx context.Context, call AgentToolCall, sessionID string) {
	summary := summarizeInput(call.Input, a.maxInputSummaryLength, a.sanitizeInputs)

	sid := sessionID
	if sid == "" {
		sid = "default"
	}
	a.mu.Lock()
	a.sessionToolCount[sid]++
	count := a.sessionToolCount[sid]
	a.mu.Unlock()

	framework := call.Framework
	if framework == "" {
		framework = "custom"
	}

	meta := map[string]any{
		"agent_id":           a.agentID,
		"agent_name":         a.agentName,
		"tool_name":          call.Tool,
		"input_summary":      summary,
		"duration_ms":        call.DurationMs,
		"model":              call.Model,
		"framework":          framework,
		"session_tool_count": count,
		"session_id":         sessionID,
		"event_category":     "agent_tool_call",
	}
	for k, v := range call.Meta {
		meta[k] = v
	}

	a.client.TrackEvent(ctx, Event{
		"eventType": "custom",
		"method":    "TOOL_CALL",
		"path":      "/agent/" + a.agentID + "/tool/" + call.Tool,
		"ip":        a.agentIP,
		"userAgent": "DevFortress-Agent/" + a.agentName,
		"severity":  "LOW",
		"metadata":  meta,
	})
}

// ObserveLangChainTool is a convenience wrapper that extracts fields from
// the LangChain/LangGraph tool-call shape.
func (a *AgentAdapter) ObserveLangChainTool(ctx context.Context, toolName string, toolInput map[string]any, sessionID, model string, durationMs int64) {
	a.ObserveToolCall(ctx, AgentToolCall{
		Tool: toolName, Input: toolInput, Framework: "langchain", Model: model, DurationMs: durationMs,
	}, sessionID)
}

// ObserveOpenAIToolCall extracts from an OpenAI tool_calls entry
// (function name + JSON-encoded arguments).
func (a *AgentAdapter) ObserveOpenAIToolCall(ctx context.Context, functionName, argumentsJSON, sessionID, model string, durationMs int64) {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(argumentsJSON), &parsed); err != nil {
		parsed = map[string]any{"raw": argumentsJSON}
	}
	a.ObserveToolCall(ctx, AgentToolCall{
		Tool: functionName, Input: parsed, Framework: "openai", Model: model, DurationMs: durationMs,
	}, sessionID)
}

// ObserveHTTPToolCall observes a raw HTTP tool call (e.g. an agent calling
// an external API).
func (a *AgentAdapter) ObserveHTTPToolCall(ctx context.Context, url, method string, statusCode int, durationMs int64, sessionID string, meta map[string]any) {
	a.ObserveToolCall(ctx, AgentToolCall{
		Tool:       "http:" + strings.ToUpper(method),
		Input:      map[string]any{"url": url, "status_code": statusCode},
		Framework:  "raw_http",
		DurationMs: durationMs,
		Meta:       meta,
	}, sessionID)
}

// TrackSessionStart queues the start of an agent session (task/conversation).
func (a *AgentAdapter) TrackSessionStart(ctx context.Context, sessionID, taskDescription string) {
	a.mu.Lock()
	if len(a.sessionToolCount) >= maxTrackedAgentSessions {
		for k := range a.sessionToolCount {
			delete(a.sessionToolCount, k)
			break
		}
	}
	a.sessionToolCount[sessionID] = 0
	a.mu.Unlock()

	a.client.TrackEvent(ctx, Event{
		"eventType": "custom",
		"method":    "SESSION_START",
		"path":      "/agent/" + a.agentID + "/session/" + sessionID,
		"ip":        a.agentIP,
		"userAgent": "DevFortress-Agent/" + a.agentName,
		"severity":  "LOW",
		"metadata": map[string]any{
			"agent_id": a.agentID, "session_id": sessionID,
			"task_description": taskDescription, "event_category": "agent_session_start",
		},
	})
}

// TrackSessionEnd queues the end of an agent session with summary metrics.
func (a *AgentAdapter) TrackSessionEnd(ctx context.Context, sessionID string, totalDurationMs int64, success bool) {
	a.mu.Lock()
	toolCount := a.sessionToolCount[sessionID]
	delete(a.sessionToolCount, sessionID)
	a.mu.Unlock()

	a.client.TrackEvent(ctx, Event{
		"eventType": "custom",
		"method":    "SESSION_END",
		"path":      "/agent/" + a.agentID + "/session/" + sessionID,
		"ip":        a.agentIP,
		"userAgent": "DevFortress-Agent/" + a.agentName,
		"severity":  "LOW",
		"metadata": map[string]any{
			"agent_id": a.agentID, "session_id": sessionID,
			"total_tools": toolCount, "total_duration_ms": totalDurationMs,
			"success": success, "event_category": "agent_session_end",
		},
	})
}

// GetSessionToolCount returns the current tool-call count for sessionID.
func (a *AgentAdapter) GetSessionToolCount(sessionID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionToolCount[sessionID]
}

func summarizeInput(input map[string]any, maxLen int, sanitize bool) string {
	if input == nil {
		return "{}"
	}
	summary := make(map[string]string, len(input))
	for key, val := range input {
		switch v := val.(type) {
		case nil:
			summary[key] = "null"
		case string:
			lower := strings.ToLower(key)
			if sanitize && (strings.Contains(lower, "key") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password")) {
				summary[key] = "[REDACTED]"
			} else if len(v) > 64 {
				summary[key] = v[:61] + "..."
			} else {
				summary[key] = v
			}
		case bool:
			summary[key] = strconv.FormatBool(v)
		case []any:
			summary[key] = "Array(" + strconv.Itoa(len(v)) + ")"
		case int, int32, int64, float32, float64:
			summary[key] = fmt.Sprintf("%v", v)
		default:
			summary[key] = "{...}"
		}
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		return "{}"
	}
	str := string(raw)
	if len(str) > maxLen {
		return str[:maxLen-3] + "..."
	}
	return str
}
