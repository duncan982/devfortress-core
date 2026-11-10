package devfortress

import "testing"

func TestDetectSuspiciousFlagsEncodedPatterns(t *testing.T) {
	cases := map[string]string{
		"?id=1' or '1'='1":                       "sql_injection",
		"?x=<script>alert(1)</script>":           "xss",
		"?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E": "xss", // one decode pass reveals the tag
		"/../../etc/passwd":                      "path_traversal",
		"..%2Fetc%2Fpasswd":                      "path_traversal", // one decode pass reveals the slash
	}
	for input, want := range cases {
		got := DetectSuspicious(input)
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("DetectSuspicious(%q) = %v, want to include %q", input, got, want)
		}
	}
}

func TestDetectSuspiciousDoesNotDecodeTwice(t *testing.T) {
	// Double-encoded input ("%252F" -> "%2F" after one pass, not "/") is
	// not detected: only one decode pass runs.
	if got := DetectSuspicious("..%252Fetc%252Fpasswd"); len(got) != 0 {
		t.Errorf("expected no match for double-encoded input, got %v", got)
	}
}

func TestDetectSuspiciousLeavesALiteralPercentAlone(t *testing.T) {
	if got := DetectSuspicious("/discount?off=50%"); len(got) != 0 {
		t.Errorf("expected no match for a literal percent, got %v", got)
	}
}

func TestDetectSuspiciousDoesNotPanicOnInvalidEncoding(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DetectSuspicious panicked: %v", r)
		}
	}()
	DetectSuspicious("/x?bad=%zz%gg")
}

func TestBuildEventClassifiesByStatus(t *testing.T) {
	cases := []struct {
		status    int
		wantType  string
		wantSev   string
		wantEmpty bool
	}{
		{200, "", "", true},
		{401, "auth_failure", "MEDIUM", false},
		{403, "auth_failure", "MEDIUM", false},
		{400, "validation_error", "LOW", false},
		{422, "validation_error", "LOW", false},
		{429, "rate_limit_exceeded", "MEDIUM", false},
		{500, "5xx_error", "HIGH", false},
		{503, "5xx_error", "HIGH", false},
		{404, "4xx_error", "LOW", false},
	}
	for _, c := range cases {
		event := BuildEvent(ClassifyInput{IP: "203.0.113.7", Method: "GET", Path: "/x", StatusCode: c.status})
		if c.wantEmpty {
			if event != nil {
				t.Errorf("status %d: expected nil event, got %v", c.status, event)
			}
			continue
		}
		if event == nil {
			t.Fatalf("status %d: expected an event", c.status)
		}
		if event["eventType"] != c.wantType {
			t.Errorf("status %d: eventType = %v, want %v", c.status, event["eventType"], c.wantType)
		}
		if event["severity"] != c.wantSev {
			t.Errorf("status %d: severity = %v, want %v", c.status, event["severity"], c.wantSev)
		}
	}
}

func TestBuildEventSuspiciousPatternOverridesStatusClassification(t *testing.T) {
	event := BuildEvent(ClassifyInput{IP: "203.0.113.7", Method: "GET", Path: "/x", StatusCode: 200, Query: "id=1' or '1'='1"})
	if event == nil {
		t.Fatal("expected an event")
	}
	if event["eventType"] != "suspicious_pattern" || event["severity"] != "HIGH" || event["actionTaken"] != "flagged" {
		t.Errorf("got %v", event)
	}
}

func TestBuildEventDefaultsIPWhenEmpty(t *testing.T) {
	event := BuildEvent(ClassifyInput{Method: "GET", Path: "/x", StatusCode: 500})
	if event["ip"] != "0.0.0.0" {
		t.Errorf("ip = %v, want 0.0.0.0", event["ip"])
	}
}

func TestBuildEventAuthPhaseFollowsUserID(t *testing.T) {
	pre := BuildEvent(ClassifyInput{Method: "GET", Path: "/x", StatusCode: 500})
	if pre["authPhase"] != "pre_auth" {
		t.Errorf("authPhase = %v, want pre_auth", pre["authPhase"])
	}
	post := BuildEvent(ClassifyInput{Method: "GET", Path: "/x", StatusCode: 500, UserID: "u1"})
	if post["authPhase"] != "post_auth" {
		t.Errorf("authPhase = %v, want post_auth", post["authPhase"])
	}
}
