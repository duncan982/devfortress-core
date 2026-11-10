package devfortress

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
)

// AgentOutputType is the shape of an agent output.
type AgentOutputType string

const (
	OutputTypeText AgentOutputType = "text"
	OutputTypeJSON AgentOutputType = "json"
	OutputTypeCode AgentOutputType = "code"
	OutputTypeFile AgentOutputType = "file"
)

// AgentOutputDestination is where an agent output is headed.
type AgentOutputDestination string

const (
	DestinationUser AgentOutputDestination = "user"
	DestinationAPI  AgentOutputDestination = "api"
	DestinationFile AgentOutputDestination = "file"
	DestinationLog  AgentOutputDestination = "log"
)

// AgentOutput is one agent output to analyze.
type AgentOutput struct {
	AgentID         string
	OutputContent   string
	OutputType      AgentOutputType
	DestinationType AgentOutputDestination
	Timestamp       int64
}

// ExfiltrationThreatType classifies what Analyze detected.
type ExfiltrationThreatType string

const (
	ThreatPIILeak           ExfiltrationThreatType = "pii-leak"
	ThreatCredentialLeak    ExfiltrationThreatType = "credential-leak"
	ThreatSystemInfoLeak    ExfiltrationThreatType = "system-info-leak"
	ThreatHighEntropySecret ExfiltrationThreatType = "high-entropy-secret"
	ThreatOversizedOutput   ExfiltrationThreatType = "oversized-output"
	ThreatNone              ExfiltrationThreatType = "none"
)

// ExfiltrationRecommendation is the action Analyze recommends.
type ExfiltrationRecommendation string

const (
	RecommendBlock  ExfiltrationRecommendation = "block"
	RecommendRedact ExfiltrationRecommendation = "redact"
	RecommendWarn   ExfiltrationRecommendation = "warn"
	RecommendAllow  ExfiltrationRecommendation = "allow"
)

// ExfiltrationResult is the outcome of Analyze.
type ExfiltrationResult struct {
	Detected        bool
	ThreatType      ExfiltrationThreatType
	Confidence      float64
	MatchedPatterns []string
	Recommendation  ExfiltrationRecommendation
	// RedactedOutput is populated only when ThreatType is ThreatPIILeak,
	// ThreatCredentialLeak, or ThreatSystemInfoLeak.
	RedactedOutput string
}

// ExfiltrationDetectorConfig configures an AgentOutputExfiltrationDetector.
type ExfiltrationDetectorConfig struct {
	// SensitivePatterns are regex strings to detect, compiled
	// case-insensitively. Empty uses DefaultSensitivePatterns.
	SensitivePatterns []string
	// MaxOutputSizeBytes is the maximum allowed output size. Default:
	// 1_048_576 (1 MiB).
	MaxOutputSizeBytes int
	// EntropyDetection enables entropy-based secret detection for content
	// that matched no known pattern. Default: true (nil pointer = true;
	// set to a pointer to false to disable).
	EntropyDetection *bool
	// EntropyThreshold is the Shannon-entropy threshold (bits/char) above
	// which a candidate string is flagged. Default: 4.5.
	EntropyThreshold float64
}

// DefaultSensitivePatterns are the built-in regexes used when
// ExfiltrationDetectorConfig.SensitivePatterns is empty: credit cards,
// SSNs, email addresses, API keys/tokens, AWS keys, private key blocks,
// and internal (RFC 1918) IPs.
var DefaultSensitivePatterns = []string{
	// Credit cards
	`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`,
	// SSN
	`\b\d{3}-\d{2}-\d{4}\b`,
	// Email addresses in unexpected contexts
	`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b`,
	// API keys / tokens (high entropy strings)
	`(?:api[_-]?key|token|secret|password|credential)[\s:=]+["']?[A-Za-z0-9+/=_-]{20,}["']?`,
	// AWS keys
	`(?:AKIA|ASIA)[A-Z0-9]{16}`,
	// Private keys
	`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`,
	// Internal IPs
	`\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+\b`,
}

var highEntropyCandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)

// AgentOutputExfiltrationDetector monitors AI agent outputs for potential
// data exfiltration patterns. Detects when agent responses contain
// sensitive data that shouldn't be included in outputs (PII, credentials,
// internal system info).
//
type AgentOutputExfiltrationDetector struct {
	maxOutputSizeBytes int
	entropyDetection   bool
	entropyThreshold   float64
	patternSources     []string
	patterns           []*regexp.Regexp
}

// NewAgentOutputExfiltrationDetector returns a detector configured by cfg.
// An invalid regex in cfg.SensitivePatterns is the only construction
// error.
func NewAgentOutputExfiltrationDetector(cfg ExfiltrationDetectorConfig) (*AgentOutputExfiltrationDetector, error) {
	patterns := cfg.SensitivePatterns
	if len(patterns) == 0 {
		patterns = DefaultSensitivePatterns
	}
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("devfortress: invalid sensitive pattern %q: %w", p, err)
		}
		compiled[i] = re
	}

	maxSize := cfg.MaxOutputSizeBytes
	if maxSize <= 0 {
		maxSize = 1_048_576
	}
	entropyDetection := true
	if cfg.EntropyDetection != nil {
		entropyDetection = *cfg.EntropyDetection
	}
	threshold := cfg.EntropyThreshold
	if threshold <= 0 {
		threshold = 4.5
	}

	return &AgentOutputExfiltrationDetector{
		maxOutputSizeBytes: maxSize,
		entropyDetection:   entropyDetection,
		entropyThreshold:   threshold,
		patternSources:     patterns,
		patterns:           compiled,
	}, nil
}

// Analyze inspects output for exfiltration indicators: oversized payload,
// a known sensitive pattern, or (failing those) a high-entropy segment
// that looks like an unrecognized secret. When the FEATURE_PLATFORM_INTEL
// environment variable is "false", Analyze always reports "allow" without
// inspecting output — matching the Node SDK's feature-flag short-circuit.
func (d *AgentOutputExfiltrationDetector) Analyze(output AgentOutput) ExfiltrationResult {
	if os.Getenv("FEATURE_PLATFORM_INTEL") == "false" {
		return ExfiltrationResult{ThreatType: ThreatNone, Recommendation: RecommendAllow}
	}

	if len(output.OutputContent) > d.maxOutputSizeBytes {
		return ExfiltrationResult{
			Detected:       true,
			ThreatType:     ThreatOversizedOutput,
			Confidence:     0.7,
			Recommendation: RecommendWarn,
		}
	}

	var matched []string
	for i, re := range d.patterns {
		if re.MatchString(output.OutputContent) {
			matched = append(matched, d.patternSources[i])
		}
	}

	if len(matched) > 0 {
		isCredential := false
		isPII := false
		for _, p := range matched {
			if strings.Contains(p, "PRIVATE KEY") || strings.Contains(p, "AKIA") {
				isCredential = true
			}
			if strings.Contains(p, "SSN") || strings.Contains(p, "credit") {
				isPII = true
			}
		}
		threatType := ThreatSystemInfoLeak
		switch {
		case isCredential:
			threatType = ThreatCredentialLeak
		case isPII:
			threatType = ThreatPIILeak
		}

		confidence := 0.5 + float64(len(matched))*0.15
		if confidence > 1 {
			confidence = 1
		}
		recommendation := RecommendRedact
		if threatType == ThreatCredentialLeak {
			recommendation = RecommendBlock
		}

		return ExfiltrationResult{
			Detected:        true,
			ThreatType:      threatType,
			Confidence:      confidence,
			MatchedPatterns: matched,
			Recommendation:  recommendation,
			RedactedOutput:  d.redact(output.OutputContent),
		}
	}

	if d.entropyDetection {
		segments := d.findHighEntropySegments(output.OutputContent)
		if len(segments) > 0 {
			return ExfiltrationResult{
				Detected:        true,
				ThreatType:      ThreatHighEntropySecret,
				Confidence:      0.6,
				MatchedPatterns: segments,
				Recommendation:  RecommendWarn,
			}
		}
	}

	return ExfiltrationResult{ThreatType: ThreatNone, Recommendation: RecommendAllow}
}

func (d *AgentOutputExfiltrationDetector) redact(content string) string {
	redacted := content
	for _, re := range d.patterns {
		redacted = re.ReplaceAllString(redacted, "[REDACTED]")
	}
	return redacted
}

func (d *AgentOutputExfiltrationDetector) findHighEntropySegments(content string) []string {
	var segments []string
	for _, candidate := range highEntropyCandidatePattern.FindAllString(content, -1) {
		if charShannonEntropy(candidate) > d.entropyThreshold {
			truncated := candidate
			if len(truncated) > 20 {
				truncated = truncated[:20]
			}
			segments = append(segments, truncated+"...")
		}
	}
	return segments
}

// charShannonEntropy computes the Shannon entropy (bits/char) of s over
// its character frequencies. Named to avoid colliding with
// agent_security.go's shannonEntropy, which computes entropy over a set
// of distinct strings (tool names), not characters of one string.
func charShannonEntropy(s string) float64 {
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len(s))
	if length == 0 {
		return 0
	}
	var entropy float64
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
