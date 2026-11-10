package devfortress

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var sqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bor\b.*=.*`),
	regexp.MustCompile(`(?i)\bunion\b.*\bselect\b`),
	regexp.MustCompile(`(?i)\bdrop\b.*\btable\b`),
	regexp.MustCompile(`(?i)'\s*or\s*'1'\s*=\s*'1`),
}

var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script>`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)onerror\s*=\s*`),
	regexp.MustCompile(`(?i)onload\s*=\s*`),
}

var traversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\.[/\\]`),
	regexp.MustCompile(`(?i)/etc/passwd`),
}

// DetectSuspicious returns the names of the suspicious patterns found in
// text: any of "sql_injection", "xss", "path_traversal". It matches the raw
// text and one percent-decoding pass (matching form-style "+" as space, like
// url.QueryUnescape); an invalid percent-sequence is skipped rather than
// treated as an error.
func DetectSuspicious(text string) []string {
	candidates := []string{text}
	if decoded, err := url.QueryUnescape(text); err == nil && decoded != text {
		candidates = append(candidates, decoded)
	}

	var found []string
	if hit(sqlPatterns, candidates) {
		found = append(found, "sql_injection")
	}
	if hit(xssPatterns, candidates) {
		found = append(found, "xss")
	}
	if hit(traversalPatterns, candidates) {
		found = append(found, "path_traversal")
	}
	return found
}

func hit(patterns []*regexp.Regexp, candidates []string) bool {
	for _, candidate := range candidates {
		for _, pattern := range patterns {
			if pattern.MatchString(candidate) {
				return true
			}
		}
	}
	return false
}

// ClassifyInput is the request/response shape DetectSuspicious and
// BuildEvent classify.
type ClassifyInput struct {
	IP         string
	Method     string
	Path       string
	StatusCode int
	LatencyMs  int
	UserAgent  string
	Query      string
	UserID     string
}

// BuildEvent maps an HTTP response to a security event, or returns nil when
// the request is not security-relevant.
func BuildEvent(in ClassifyInput) Event {
	var eventType, reason, action string
	severity := "LOW"

	switch {
	case in.StatusCode == 401 || in.StatusCode == 403:
		eventType = "auth_failure"
		severity = "MEDIUM"
		reason = "Authentication or authorization failed"
		action = "blocked"
	case in.StatusCode == 400 || in.StatusCode == 422:
		eventType = "validation_error"
		reason = "Request validation failed"
	case in.StatusCode == 429:
		eventType = "rate_limit_exceeded"
		severity = "MEDIUM"
		reason = "Rate limit exceeded"
		action = "rate_limited"
	case in.StatusCode >= 500:
		eventType = "5xx_error"
		severity = "HIGH"
		reason = "Server error: " + strconv.Itoa(in.StatusCode)
	case in.StatusCode >= 400:
		eventType = "4xx_error"
		reason = "Client error: " + strconv.Itoa(in.StatusCode)
	}
	if action == "" {
		action = "monitored"
	}

	suspicious := DetectSuspicious(in.Path + " " + in.Query)
	if len(suspicious) > 0 {
		eventType = "suspicious_pattern"
		severity = "HIGH"
		reason = "Suspicious patterns detected: " + strings.Join(suspicious, ", ")
		action = "flagged"
	}

	if eventType == "" {
		return nil
	}

	ip := in.IP
	if ip == "" {
		ip = "0.0.0.0"
	}
	authPhase := "pre_auth"
	if in.UserID != "" {
		authPhase = "post_auth"
	}

	var userAgent, userID any
	if in.UserAgent != "" {
		userAgent = in.UserAgent
	}
	if in.UserID != "" {
		userID = in.UserID
	}

	return Event{
		"eventType":         eventType,
		"ip":                ip,
		"method":            in.Method,
		"path":              in.Path,
		"userAgent":         userAgent,
		"statusCode":        in.StatusCode,
		"severity":          severity,
		"clMode":            "external",
		"authPhase":         authPhase,
		"actionTaken":       action,
		"responseLatencyMs": in.LatencyMs,
		"userId":            userID,
		"metadata":          map[string]any{"reason": reason},
	}
}
