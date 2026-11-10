package devfortress

import (
	"testing"
)

// TestAgentOutputExfiltrationDetectorIsOnThePublicSurface demonstrates
// Wave-4's B7 (AgentOutputExfiltrationDetector) is constructible and
// detects a known credential-leak pattern, redacting it on request.
func TestAgentOutputExfiltrationDetectorIsOnThePublicSurface(t *testing.T) {
	detector, err := NewAgentOutputExfiltrationDetector(ExfiltrationDetectorConfig{})
	if err != nil {
		t.Fatalf("NewAgentOutputExfiltrationDetector failed: %v", err)
	}

	result := detector.Analyze(AgentOutput{
		AgentID:         "agent-1",
		OutputContent:   "here is the key: AKIAABCDEFGHIJKLMNOP",
		OutputType:      OutputTypeText,
		DestinationType: DestinationUser,
	})

	if !result.Detected {
		t.Fatalf("expected an AWS-key-shaped output to be detected, got: %+v", result)
	}
	if result.ThreatType != ThreatCredentialLeak {
		t.Fatalf("expected a credential-leak classification, got %v", result.ThreatType)
	}
	if result.Recommendation != RecommendBlock {
		t.Fatalf("expected a block recommendation for a credential leak, got %v", result.Recommendation)
	}

	clean := detector.Analyze(AgentOutput{
		AgentID:       "agent-1",
		OutputContent: "the weather today is sunny",
		OutputType:    OutputTypeText,
	})
	if clean.Detected {
		t.Fatalf("expected ordinary text to not be flagged, got: %+v", clean)
	}
	if clean.Recommendation != RecommendAllow {
		t.Fatalf("expected an allow recommendation for clean output, got %v", clean.Recommendation)
	}
}

// TestShadowAgentRegistryIsOnThePublicSurface demonstrates Wave-4's B10
// (ShadowAgentRegistry) is constructible, that a registered agent is
// never flagged as a shadow, and that strong behavioral indicators for an
// unregistered source are.
func TestShadowAgentRegistryIsOnThePublicSurface(t *testing.T) {
	registry := NewShadowAgentRegistry(ShadowAgentConfig{AutoBlock: true})

	registered := registry.Register(RegisteredAgent{AgentID: "agent-known", Name: "Known Agent", Owner: "team-a"})
	if !registered.Active {
		t.Fatalf("expected a registered agent to be active")
	}

	knownCheck := registry.Detect("agent-known", nil)
	if knownCheck.Detected {
		t.Fatalf("expected a registered, active agent to never be flagged as a shadow, got: %+v", knownCheck)
	}

	shadowCheck := registry.Detect("unknown-fingerprint", []string{
		"automated request pattern seen at 400 req/min",
		"consistent timing between requests observed",
		"sequential resource enumeration detected",
	})
	if !shadowCheck.Detected {
		t.Fatalf("expected strong behavioral indicators to flag a shadow agent, got: %+v", shadowCheck)
	}
	if shadowCheck.Recommendation != ShadowRecommendBlock {
		t.Fatalf("expected autoBlock + high confidence to recommend block, got %v", shadowCheck.Recommendation)
	}

	stats := registry.GetStats()
	if stats.RegisteredCount != 1 || stats.ShadowDetections != 1 || stats.BlockedShadows != 1 {
		t.Fatalf("expected stats to reflect one registration and one blocked shadow detection, got: %+v", stats)
	}
}
