package devfortress

import (
	"regexp"
	"strconv"
	"strings"
)

// PromptInjectionSensitivity scales the detection score.
type PromptInjectionSensitivity string

const (
	SensitivityLow    PromptInjectionSensitivity = "low"
	SensitivityMedium PromptInjectionSensitivity = "medium"
	SensitivityHigh   PromptInjectionSensitivity = "high"
)

// PromptInjectionConfig configures a PromptInjectionFilter.
type PromptInjectionConfig struct {
	// Sensitivity scales the weighted score: low=0.7x, medium=1.0x (default), high=1.5x.
	Sensitivity PromptInjectionSensitivity
	// CustomPatterns are additional regex patterns (RE2 syntax), each
	// weighted 30.
	CustomPatterns []string
	// MaxScanLength bounds how much of the input is scanned. Default: 100,000 bytes.
	MaxScanLength int
}

// PromptInjectionSeverity is the severity band of a scan result.
type PromptInjectionSeverity string

const (
	InjectionLow      PromptInjectionSeverity = "LOW"
	InjectionMedium   PromptInjectionSeverity = "MEDIUM"
	InjectionHigh     PromptInjectionSeverity = "HIGH"
	InjectionCritical PromptInjectionSeverity = "CRITICAL"
)

// PromptInjectionResult is the outcome of one PromptInjectionFilter.Scan call.
type PromptInjectionResult struct {
	Safe             bool
	Confidence       float64
	Severity         PromptInjectionSeverity
	DetectedPatterns []string
	Reason           string
}

type injectionPattern struct {
	regex  *regexp.Regexp
	name   string
	weight int
}

// knownInjectionPatterns are known indirect prompt-injection patterns,
// field-for-field matching the Node SDK's PromptInjectionFilter.
var knownInjectionPatterns = []struct {
	pattern string
	name    string
	weight  int
}{
	{`(?i)ignore\s+(previous|above|all|prior)\s+(instructions?|context|rules?)`, "instruction_override", 40},
	{`(?i)you\s+are\s+now\s+(a|an|the)`, "role_assignment", 35},
	{`(?i)system\s*:\s*|\[SYSTEM\]|<\|system\|>`, "system_prompt_injection", 45},
	{`(?i)forget\s+(everything|all|what)`, "memory_wipe", 40},
	{`(?i)do\s+not\s+(follow|obey|listen)`, "disobedience_injection", 35},
	{`(?i)act\s+as\s+(if|though)|pretend\s+(to\s+be|you)`, "persona_injection", 30},
	{`(?i)<script>|javascript:|onerror=|onload=`, "xss_in_data", 50},
	{`(?i)\bexec\s*\(|eval\s*\(|__import__`, "code_execution", 50},
	{`(?i)translate.*to.*base64|encode.*payload`, "encoding_evasion", 25},
	{`(?i)reveal\s+(your|the)\s+(system|secret|api|key|password)`, "secret_extraction", 45},
}

// PromptInjectionFilter detects indirect prompt-injection attempts in
// agent-observed text via a single weighted-scoring engine (Invention
// A16). Safe for concurrent use — Scan has no internal mutable state.
type PromptInjectionFilter struct {
	config        PromptInjectionConfig
	patterns      []injectionPattern
	maxScanLength int
}

// NewPromptInjectionFilter returns a filter with cfg's values, compiling
// every known pattern plus cfg.CustomPatterns. Returns an error if any
// custom pattern fails to compile as RE2.
func NewPromptInjectionFilter(cfg PromptInjectionConfig) (*PromptInjectionFilter, error) {
	if cfg.Sensitivity == "" {
		cfg.Sensitivity = SensitivityMedium
	}
	maxScan := cfg.MaxScanLength
	if maxScan <= 0 {
		maxScan = 100_000
	}

	patterns := make([]injectionPattern, 0, len(knownInjectionPatterns)+len(cfg.CustomPatterns))
	for _, p := range knownInjectionPatterns {
		patterns = append(patterns, injectionPattern{regex: regexp.MustCompile(p.pattern), name: p.name, weight: p.weight})
	}
	for i, p := range cfg.CustomPatterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, injectionPattern{regex: re, name: "custom_" + strconv.Itoa(i), weight: 30})
	}

	return &PromptInjectionFilter{config: cfg, patterns: patterns, maxScanLength: maxScan}, nil
}

// Scan scans content for known prompt-injection patterns, returning a
// weighted score (0-100), confidence, severity band, and the names of
// every pattern that matched.
func (f *PromptInjectionFilter) Scan(content string) PromptInjectionResult {
	text := content
	if len(text) > f.maxScanLength {
		text = text[:f.maxScanLength]
	}

	var detected []string
	totalWeight := 0
	for _, p := range f.patterns {
		if p.regex.MatchString(text) {
			detected = append(detected, p.name)
			totalWeight += p.weight
		}
	}

	multiplier := 1.0
	switch f.config.Sensitivity {
	case SensitivityHigh:
		multiplier = 1.5
	case SensitivityLow:
		multiplier = 0.7
	}

	score := int(float64(totalWeight)*multiplier + 0.5)
	if score > 100 {
		score = 100
	}

	confidence := 0.1
	if len(detected) > 0 {
		confidence = 0.5 + float64(len(detected))*0.15
		if confidence > 0.99 {
			confidence = 0.99
		}
	}

	var severity PromptInjectionSeverity
	switch {
	case score >= 70:
		severity = InjectionCritical
	case score >= 45:
		severity = InjectionHigh
	case score >= 20:
		severity = InjectionMedium
	default:
		severity = InjectionLow
	}

	reason := "Content appears safe"
	if len(detected) > 0 {
		reason = "Prompt injection detected: " + strings.Join(detected, ", ")
	}

	return PromptInjectionResult{
		Safe: score < 30, Confidence: confidence, Severity: severity,
		DetectedPatterns: detected, Reason: reason,
	}
}
