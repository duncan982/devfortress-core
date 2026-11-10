package devfortress

// InternalClosedLoopEngine (TODO 407 port): internal-mode decision engine,
// ported from internal-closed-loop-engine.ts. Mirrors the substance of the
// Python port's test_internal_closed_loop_engine.py (29 tests), adapted to
// Go idioms (table-driven Tier-1 rule tests) plus a concurrency test that
// has no Python equivalent (Python's engine is not called concurrently in
// this SDK's own usage; Go's is).

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func baseReq(mutate func(*InternalCLRequest)) InternalCLRequest {
	req := InternalCLRequest{IP: "203.0.113.5", Method: "GET", Path: "/"}
	if mutate != nil {
		mutate(&req)
	}
	return req
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

// ── Tier 1 rule matching (table-driven) ─────────────────────────────────

func TestTier1Rules_BlockOrFlagExpectedDecision(t *testing.T) {
	cases := []struct {
		name         string
		req          InternalCLRequest
		wantDecision InternalCLDecision
		wantRule     string
		wantTier     int
	}{
		{
			name:         "sql_injection/or-1-1",
			req:          baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "search=' OR 1=1 --" }),
			wantDecision: CLDecisionBlock,
			wantRule:     "sql_injection",
			wantTier:     1,
		},
		{
			name:         "sql_injection/drop-table",
			req:          baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "id=1; DROP TABLE users" }),
			wantDecision: CLDecisionBlock,
			wantRule:     "sql_injection",
			wantTier:     1,
		},
		{
			name:         "sql_injection/union-select",
			req:          baseReq(func(r *InternalCLRequest) { r.Path = "/search"; r.Query = "UNION SELECT password FROM users" }),
			wantDecision: CLDecisionBlock,
			wantRule:     "sql_injection",
			wantTier:     1,
		},
		{
			name:         "xss_attempt",
			req:          baseReq(func(r *InternalCLRequest) { r.Path = "/comment"; r.Query = "text=<script>alert(1)</script>" }),
			wantDecision: CLDecisionBlock,
			wantRule:     "xss_attempt",
			wantTier:     1,
		},
		{
			name:         "path_traversal",
			req:          baseReq(func(r *InternalCLRequest) { r.Path = "/files/../../etc/passwd" }),
			wantDecision: CLDecisionBlock,
			wantRule:     "path_traversal",
			wantTier:     1,
		},
		{
			name:         "scanner_detected",
			req:          baseReq(func(r *InternalCLRequest) { r.UserAgent = "sqlmap/1.7" }),
			wantDecision: CLDecisionBlock,
			wantRule:     "scanner_detected",
			wantTier:     1,
		},
		{
			name:         "sensitive_file_access",
			req:          baseReq(func(r *InternalCLRequest) { r.Path = "/.env" }),
			wantDecision: CLDecisionBlock,
			wantRule:     "sensitive_file_access",
			wantTier:     1,
		},
		{
			name:         "credential_stuffing_pattern",
			req:          baseReq(func(r *InternalCLRequest) { r.Method = "POST"; r.Path = "/api/login" }),
			wantDecision: CLDecisionRateLimit,
			wantRule:     "credential_stuffing_pattern",
			wantTier:     1,
		},
		{
			name:         "agent_unsanctioned_tool",
			req:          baseReq(func(r *InternalCLRequest) { r.AgentID = "agent-1"; r.ToolName = "shell_exec" }),
			wantDecision: CLDecisionQuarantine,
			wantRule:     "agent_unsanctioned_tool",
			wantTier:     1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewInternalClosedLoopEngine(InternalCLConfig{})
			result := engine.Evaluate(tc.req)
			if result.Decision != tc.wantDecision {
				t.Fatalf("decision = %s, want %s (matched: %v)", result.Decision, tc.wantDecision, result.MatchedRules)
			}
			if !contains(result.MatchedRules, tc.wantRule) {
				t.Fatalf("matchedRules = %v, want to contain %q", result.MatchedRules, tc.wantRule)
			}
			if result.Tier != tc.wantTier {
				t.Fatalf("tier = %d, want %d", result.Tier, tc.wantTier)
			}
		})
	}
}

func TestCleanRequestAllowed(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "search=laptop" }))
	if result.Decision != CLDecisionAllow {
		t.Fatalf("decision = %s, want allow", result.Decision)
	}
	if len(result.MatchedRules) != 0 {
		t.Fatalf("matchedRules = %v, want empty", result.MatchedRules)
	}
	if result.Score != 0 {
		t.Fatalf("score = %v, want 0", result.Score)
	}
}

func TestLiteralPercentNotFalsePositived(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "discount=50%" }))
	if result.Decision != CLDecisionAllow {
		t.Fatalf("decision = %s, want allow", result.Decision)
	}
}

func TestAgentUnsanctionedToolQuarantines(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.AgentID = "agent-1"; r.ToolName = "shell_exec" }))
	if result.Decision != CLDecisionQuarantine {
		t.Fatalf("decision = %s, want quarantine", result.Decision)
	}
	if !engine.IsAgentQuarantined("agent-1") {
		t.Fatalf("expected agent-1 to be quarantined")
	}
}

// ── Pre-check (already-blocked) short-circuit ────────────────────────────

func TestBlockedIPShortCircuitsBeforeRules(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{})
	engine.BlockIP("203.0.113.5", "manual_block", 0)
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/anything" }))
	if result.Decision != CLDecisionBlock {
		t.Fatalf("decision = %s, want block", result.Decision)
	}
	if len(result.MatchedRules) != 1 || result.MatchedRules[0] != "ip_blocked:manual_block" {
		t.Fatalf("matchedRules = %v, want [ip_blocked:manual_block]", result.MatchedRules)
	}
}

func TestUnblockIPAllowsAgain(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{})
	engine.BlockIP("203.0.113.5", "test", 0)
	engine.UnblockIP("203.0.113.5")
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products" }))
	if result.Decision != CLDecisionAllow {
		t.Fatalf("decision = %s, want allow", result.Decision)
	}
}

func TestBlockActionAlsoBlocksSessionAndAgent(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) {
		r.Path = "/.env"
		r.SessionID = "sess-1"
		r.AgentID = "agent-9"
	}))
	if result.Decision != CLDecisionBlock {
		t.Fatalf("decision = %s, want block", result.Decision)
	}
	types := map[string]bool{}
	for _, a := range result.Actions {
		types[a.Type] = true
	}
	for _, want := range []string{"block_ip", "block_session", "quarantine_agent"} {
		if !types[want] {
			t.Fatalf("actions = %v, want to include %q", result.Actions, want)
		}
	}
}

// ── Rate limiting ─────────────────────────────────────────────────────────

func TestRateLimitTriggersAfterMaxRequests(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{RateLimitMax: 3, RateLimitWindow: time.Minute})
	for i := 0; i < 3; i++ {
		result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "p=1" }))
		if result.Decision != CLDecisionAllow {
			t.Fatalf("request %d: decision = %s, want allow", i, result.Decision)
		}
	}
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "p=1" }))
	if result.Decision != CLDecisionRateLimit {
		t.Fatalf("decision = %s, want rate_limit", result.Decision)
	}
	if len(result.MatchedRules) != 1 || result.MatchedRules[0] != "rate_limit_exceeded" {
		t.Fatalf("matchedRules = %v, want [rate_limit_exceeded]", result.MatchedRules)
	}
}

// ── Tier 2: unimplemented/pass-through by default ─────────────────────────

func TestTier2ScorerUnsetByDefaultSkipsTier2(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "p=1" }))
	if result.Decision != CLDecisionAllow {
		t.Fatalf("decision = %s, want allow", result.Decision)
	}
	if result.Tier != 1 {
		t.Fatalf("tier = %d, want 1 (never reaches tier 2 scoring)", result.Tier)
	}
}

func TestTier2ScorerWhenSuppliedCanBlock(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{
		Tier2Scorer: func(req InternalCLRequest) (float64, error) { return 90, nil },
	})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "p=1" }))
	if result.Decision != CLDecisionBlock {
		t.Fatalf("decision = %s, want block", result.Decision)
	}
	if result.Tier != 2 {
		t.Fatalf("tier = %d, want 2", result.Tier)
	}
	if len(result.MatchedRules) != 1 || result.MatchedRules[0] != "tier2_ml_score" {
		t.Fatalf("matchedRules = %v, want [tier2_ml_score]", result.MatchedRules)
	}
}

func TestTier2ScorerElevatedRateLimits(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{
		Tier2Scorer: func(req InternalCLRequest) (float64, error) { return 70, nil },
	})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "p=1" }))
	if result.Decision != CLDecisionRateLimit {
		t.Fatalf("decision = %s, want rate_limit", result.Decision)
	}
	if result.Tier != 2 {
		t.Fatalf("tier = %d, want 2", result.Tier)
	}
}

// ── Tier 3: relay callback (hybrid mode only) ─────────────────────────────

func TestRelayNotCalledWhenExternalRelayDisabled(t *testing.T) {
	var calls []InternalCLResult
	engine := NewInternalClosedLoopEngine(InternalCLConfig{
		OnRelay: func(result InternalCLResult, req InternalCLRequest) { calls = append(calls, result) },
		// EnableExternalRelay defaults to false.
	})
	engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/.env" }))
	if len(calls) != 0 {
		t.Fatalf("calls = %v, want none", calls)
	}
}

func TestRelayCalledForFlaggedDecisionWhenEnabled(t *testing.T) {
	var calls []InternalCLResult
	engine := NewInternalClosedLoopEngine(InternalCLConfig{
		EnableExternalRelay: true,
		OnRelay:             func(result InternalCLResult, req InternalCLRequest) { calls = append(calls, result) },
	})
	// "/.env" matches BOTH path_traversal (score 90) and
	// sensitive_file_access (score 85) in Node's own pattern set —
	// independently confirmed against Node directly (see this file's
	// sibling internal_closed_loop_engine.go doc comment) — not a porting
	// bug, reproduced here deliberately.
	engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/.env" }))
	if len(calls) != 1 {
		t.Fatalf("calls = %v, want exactly 1", calls)
	}
	want := []string{"path_traversal", "sensitive_file_access"}
	got := calls[0].MatchedRules
	if len(got) != len(want) {
		t.Fatalf("matchedRules = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("matchedRules = %v, want %v", got, want)
		}
	}
}

func TestRelayNotCalledForAllowedDecision(t *testing.T) {
	var calls []InternalCLResult
	engine := NewInternalClosedLoopEngine(InternalCLConfig{
		EnableExternalRelay: true,
		OnRelay:             func(result InternalCLResult, req InternalCLRequest) { calls = append(calls, result) },
	})
	engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products" }))
	if len(calls) != 0 {
		t.Fatalf("calls = %v, want none", calls)
	}
}

// ── Fail mode ─────────────────────────────────────────────────────────────

func TestFailClosedSwallowsIndividualRuleError(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{FailMode: "closed"})
	engine.AddRule(InternalCLRule{
		Name: "broken", Description: "x", Severity: "low", Score: 1, Decision: CLDecisionAllow, Enabled: true,
		Match: func(req InternalCLRequest) bool { panic("boom") },
	})
	// Individual rule errors/panics are swallowed per-rule (matching
	// Node), not escalated to the top-level fail-mode handler — Evaluate
	// must not propagate the panic, and the decision should be allow
	// since no other rule matched.
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products" }))
	if result.Decision != CLDecisionAllow {
		t.Fatalf("decision = %s, want allow", result.Decision)
	}
}

func TestFailClosedOnTier2ScorerError(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{
		FailMode:    "closed",
		Tier2Scorer: func(req InternalCLRequest) (float64, error) { return 0, errors.New("scorer unavailable") },
	})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products" }))
	if result.Decision != CLDecisionBlock {
		t.Fatalf("decision = %s, want block (fail-closed)", result.Decision)
	}
	if result.Score != 100 {
		t.Fatalf("score = %v, want 100", result.Score)
	}
	if !contains(result.MatchedRules, "fail_closed_error") {
		t.Fatalf("matchedRules = %v, want fail_closed_error", result.MatchedRules)
	}
}

func TestFailOpenOnTier2ScorerError(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{
		FailMode:    "open",
		Tier2Scorer: func(req InternalCLRequest) (float64, error) { return 0, errors.New("scorer unavailable") },
	})
	result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products" }))
	if result.Decision != CLDecisionAllow {
		t.Fatalf("decision = %s, want allow (fail-open)", result.Decision)
	}
	if result.Score != 0 {
		t.Fatalf("score = %v, want 0", result.Score)
	}
	if !contains(result.MatchedRules, "fail_open_error") {
		t.Fatalf("matchedRules = %v, want fail_open_error", result.MatchedRules)
	}
}

// ── MatchesKnownAttackPattern (Option B content check) ────────────────────

func TestMatchesKnownAttackPatternDetectsSQLi(t *testing.T) {
	if MatchesKnownAttackPattern("/search", "") {
		t.Fatalf("expected clean path to not match")
	}
	if !MatchesKnownAttackPattern("/search?q=' OR 1=1 --", "") {
		t.Fatalf("expected SQLi path to match")
	}
}

func TestMatchesKnownAttackPatternDetectsScanner(t *testing.T) {
	if !MatchesKnownAttackPattern("/", "nikto/2.5") {
		t.Fatalf("expected scanner UA to match")
	}
}

// ── Client wiring: mode selection, Observe(), IsBlocked() ─────────────────

func TestClientExternalModeObserveIsNoop(t *testing.T) {
	client, err := NewClient("k", "", WithMode(ModeExternal))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.internalEngine != nil {
		t.Fatalf("expected no internal engine in external mode")
	}
	if client.Observe(baseReq(func(r *InternalCLRequest) { r.Path = "/.env" })) != nil {
		t.Fatalf("expected Observe to be a no-op in external mode")
	}
	if client.IsBlocked("203.0.113.5") {
		t.Fatalf("expected IsBlocked to be false in external mode")
	}
}

func TestClientInternalModeObserveBlocksAttack(t *testing.T) {
	client, err := NewClient("k", "", WithMode(ModeInternal))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.internalEngine == nil {
		t.Fatalf("expected an internal engine in internal mode")
	}
	result := client.Observe(baseReq(func(r *InternalCLRequest) { r.Path = "/.env" }))
	if result == nil || !result.Flagged {
		t.Fatalf("expected a flagged result, got %v", result)
	}
	if result.Decision != CLDecisionBlock {
		t.Fatalf("decision = %s, want block", result.Decision)
	}
	if !client.IsBlocked("203.0.113.5") {
		t.Fatalf("expected IsBlocked to be true after a block decision")
	}
}

func TestClientInternalModeObserveAllowsCleanRequest(t *testing.T) {
	client, err := NewClient("k", "", WithMode(ModeInternal))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.Observe(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "q=laptop" })) != nil {
		t.Fatalf("expected clean request to be allowed (nil result)")
	}
}

func TestClientHybridModeAllowsCleanRequestThenBlocksViaInternalFirst(t *testing.T) {
	// Clean request first, then the attack — blocking is sticky for the
	// rest of this client's lifetime (same IP), so the order matters; the
	// Python port hit exactly this ordering bug during its own live
	// end-to-end proof.
	client, err := NewClient("k", "", WithMode(ModeHybrid))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.circuitBreaker == nil {
		t.Fatalf("expected a circuit breaker in hybrid mode")
	}

	cleanResult := client.Observe(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "q=laptop" }))
	if cleanResult != nil {
		t.Fatalf("expected clean request to be allowed (nil result), got %v", cleanResult)
	}
	if client.circuitBreaker.State() != CircuitClosed {
		t.Fatalf("circuit state = %s, want closed", client.circuitBreaker.State())
	}

	blockResult := client.Observe(baseReq(func(r *InternalCLRequest) { r.Path = "/.env" }))
	if blockResult == nil || !blockResult.Flagged {
		t.Fatalf("expected a flagged result, got %v", blockResult)
	}
}

// ── Concurrency: Evaluate is safe for concurrent use ───────────────────────
//
// Run with `go test -race` to confirm no data races. Also asserts a real
// correctness property: the sliding-window rate limiter must not let more
// than RateLimitMax requests from the same IP through concurrently — a
// TOCTOU race between "check" and "record" would let it over-admit.

func TestEvaluateConcurrentSameIP_NoDataRace(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{RateLimitMax: 50, RateLimitWindow: time.Minute})

	const goroutines = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result := engine.Evaluate(baseReq(func(r *InternalCLRequest) { r.Path = "/products"; r.Query = "p=1" }))
			if result.Decision == CLDecisionAllow {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed > 50 {
		t.Fatalf("allowed = %d requests through the rate limiter, want <= 50 (RateLimitMax) — rate limiter is not atomic under concurrency", allowed)
	}
}

func TestEvaluateConcurrentDifferentIPs_NoDataRace(t *testing.T) {
	engine := NewInternalClosedLoopEngine(InternalCLConfig{})

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			ip := "10.0.0." + string(rune('0'+(i%10)))
			engine.Evaluate(InternalCLRequest{IP: ip, Method: "GET", Path: "/products", Query: "p=1"})
			engine.Evaluate(InternalCLRequest{IP: ip, Method: "GET", Path: "/.env"})
			engine.IsIPBlocked(ip)
			engine.GetStats()
			engine.GetAuditLog(10)
		}()
	}
	wg.Wait()
}
