package devfortress

// Internal Closed-Loop Protection Engine (TODO 407 port).
//
// Go port of the Node SDK's InternalClosedLoopEngine
// (internal-closed-loop-engine.ts), following the same structural pattern
// as the Python port (internal_closed_loop_engine.py) built earlier in the
// same session. Three tiers:
//
//	Tier 1: Deterministic rule engine (<1ms) — 7 regex/signature/heuristic
//	        rules, highest-scoring match wins. Pre-check short-circuits for
//	        an already-blocked IP/user/session or quarantined agent. A
//	        sliding-window rate limit runs between Tier 1 and Tier 2.
//	Tier 2: Optional custom scorer (Tier2Scorer) — unimplemented/pass-through
//	        by default. Evaluate skips Tier 2 entirely when the engine's
//	        config has no scorer configured, exactly like Node (tier2Scorer
//	        unset) and Python (tier2_scorer is None). This is deliberately
//	        not a Go port of Node's MLClassifier adapter, which is
//	        Node-specific and out of scope for this port.
//	Tier 3: Relay callback (OnRelay) — fired for every non-'allow' decision
//	        when EnableExternalRelay is true (hybrid mode only). This
//	        engine has no HTTP client or platform credentials of its own by
//	        design (stays air-gapped otherwise); the caller's callback does
//	        the actual platform call, same as Node's onRelay / Python's
//	        on_relay.
//
// Concurrency: unlike Node (single-threaded) and Python (typically
// single-threaded per request in this SDK's own usage), Go callers invoke
// Evaluate concurrently across goroutines handling different requests. All
// shared state (blocked IP/user/session maps, quarantined agents, the rate
// limiter, the audit log, and the rule set) is safe for concurrent use: the
// four block/quarantine/rate-limit stores reuse BoundedMap (already
// internally mutex-guarded per operation), and the rate limiter's
// check-then-record sequence — which BoundedMap's own per-call lock cannot
// make atomic by itself — is additionally guarded by this engine's own
// mutex so two concurrent requests from the same IP cannot both pass the
// rate-limit check before either is recorded. The rule set and audit log
// are likewise guarded by this engine's mutex.
//
// Fail mode: "closed" (block, score 100) or "open" (allow, score 0) on an
// evaluation error — default "closed". A panic anywhere inside Evaluate's
// guarded body (including a Tier2Scorer error) is recovered and routed
// through this fail-mode decision, matching Node's top-level try/catch and
// Python's top-level except. Individual Tier-1 rule panics are isolated
// per-rule (recovered inside safeMatch) and never escalate to the
// fail-mode handler — matching Node's per-rule try/catch exactly, not a
// top-level failure.
//
// Tier-3 relay dispatch — synchronous, not a goroutine (a deliberate
// choice, not an oversight): OnRelay is invoked synchronously within
// Evaluate, wrapped in its own recover(). Node's relay call is a
// fire-and-forget Promise (`.catch(() => {})`, not awaited by the caller),
// but because its onRelay callback body runs synchronously up to its own
// first await point before that Promise is even constructed, a
// synchronous-looking onRelay implementation (e.g. one that just appends
// to a list, as this port's own tests and Node's own test suite do)
// observably completes before Node's evaluate() returns control — Python's
// port makes this the same by awaiting the relay call directly. Firing
// OnRelay from a real goroutine in Go would break that observable
// synchrony: a caller (or a test) that inspects relay side effects
// immediately after Evaluate returns would race the goroutine. Dispatching
// synchronously keeps Evaluate's behavior deterministic and matches this
// engine's own design principle of staying zero-network in its own
// critical path — OnRelay's implementation (typically wired to something
// like Client.TrackEvent, which only enqueues in memory) is responsible
// for any real non-blocking background work, the same way this SDK's
// Observe/ObserveAndFlush already push actual network I/O into their own
// detached goroutine at the Client/middleware layer, not inside this
// engine.

import (
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── InternalCLDecision ──────────────────────────────────────────────────

// InternalCLDecision is a decision returned by
// InternalClosedLoopEngine.Evaluate.
type InternalCLDecision string

const (
	CLDecisionAllow      InternalCLDecision = "allow"
	CLDecisionBlock      InternalCLDecision = "block"
	CLDecisionRateLimit  InternalCLDecision = "rate_limit"
	CLDecisionChallenge  InternalCLDecision = "challenge"
	CLDecisionQuarantine InternalCLDecision = "quarantine"
)

// ── Default Tier-1 rule patterns ────────────────────────────────────────
//
// Byte-for-byte port of Node's 7 Tier-1 rule patterns, independently
// verified (not ported by analogy from the Python port) against both
// Node's actual regex objects (`node -e`) and Go's RE2 engine (`go run`,
// a throwaway harness) for every pattern, across representative
// true-positive, true-negative and edge-case inputs. Every one of these
// patterns compiles directly under RE2 and produced byte-for-byte
// identical true/false results to Node's V8 regex engine on every tested
// input — none needed rewriting for RE2 compatibility (RE2 lacks
// backreferences and lookahead/lookbehind, but none of Node's 7 rules use
// either construct). `/i` becomes the `(?i)` inline flag.
//
// Two deliberate, faithfully-reproduced quirks (confirmed against Node
// directly, matching what the Python port independently found and
// flagged, not introduced by this port):
//
//   - The strict SQL pattern `(?:^|\s)(?:UNION...)(?:\s|$)` requires a
//     string-start or whitespace boundary before the keyword, so
//     "q=UNION SELECT ..." (no space/start before UNION) does NOT match —
//     only a bare or space-preceded "UNION SELECT ..." does.
//   - "/.env" matches BOTH path_traversal (via its own
//     `(/\.env|/\.git|/\.ssh)` sub-pattern) and sensitive_file_access —
//     an overlap in Node's own pattern set, not a porting bug.
var iclSQLInjectionStrict = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:^|\s)(?:UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+[a-zA-Z0-9_]+\s+SET|DELETE\s+FROM)(?:\s|$)`),
	regexp.MustCompile(`(?i)(?:'|")\s*OR\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|"[^"]*"\s*=\s*"[^"]*")`),
	regexp.MustCompile(`(?:'|")\s*;\s*(?:--|/\*)`),
	regexp.MustCompile(`(?i)(\bxp_\w+)`),
}

var iclSQLInjectionModerate = []*regexp.Regexp{
	regexp.MustCompile(`(/\*.*\*/)`),
	regexp.MustCompile(`(?i)(\bEXEC\b|\bEXECUTE\b)\s*\(`),
}

var iclXSSPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[\s>]`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)on(load|error|click|mouseover|submit|focus|blur)\s*=`),
	regexp.MustCompile(`(?i)(<iframe|<object|<embed|<applet)`),
	regexp.MustCompile(`(?i)(document\.(cookie|write|location))`),
	regexp.MustCompile(`(?i)(window\.(location|open))`),
}

var iclPathTraversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\./`),
	regexp.MustCompile(`\.\.%2[fF]`),
	regexp.MustCompile(`\.\.\\$`),
	regexp.MustCompile(`(?i)%2e%2e[%/\\]`),
	regexp.MustCompile(`/etc/(passwd|shadow|hosts)`),
	regexp.MustCompile(`/proc/self`),
	regexp.MustCompile(`(/\.env|/\.git|/\.ssh)`),
}

var iclScannerSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)sqlmap`),
	regexp.MustCompile(`(?i)nikto`),
	regexp.MustCompile(`(?i)nmap`),
	regexp.MustCompile(`(?i)dirbuster`),
	regexp.MustCompile(`(?i)gobuster`),
	regexp.MustCompile(`(?i)wpscan`),
	regexp.MustCompile(`(?i)burp\s*suite`),
	regexp.MustCompile(`(?i)acunetix`),
	regexp.MustCompile(`(?i)nessus`),
	regexp.MustCompile(`(?i)masscan`),
	regexp.MustCompile(`(?i)zgrab`),
	regexp.MustCompile(`(?i)nuclei`),
}

var iclSensitiveFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`/\.env`),
	regexp.MustCompile(`/\.git`),
	regexp.MustCompile(`/\.ssh`),
	regexp.MustCompile(`/wp-admin`),
	regexp.MustCompile(`/wp-login`),
	regexp.MustCompile(`(?i)/phpmyadmin`),
	regexp.MustCompile(`/admin\.php`),
	regexp.MustCompile(`/\.htaccess`),
	regexp.MustCompile(`/\.htpasswd`),
	regexp.MustCompile(`/server-status`),
	regexp.MustCompile(`/actuator`),
	regexp.MustCompile(`/debug/`),
}

var iclAuthPaths = []string{"/login", "/signin", "/auth", "/api/auth", "/api/login", "/oauth/token"}

var iclDangerousTools = map[string]bool{
	"shell_exec": true,
	"eval":       true,
	"exec":       true,
	"rm":         true,
	"sudo":       true,
	"chmod":      true,
	"kill":       true,
}

func iclAnyMatch(patterns []*regexp.Regexp, s string) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

func iclNonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// MatchesKnownAttackPattern is a lightweight, synchronous, zero-network
// content check reusing the same Tier-1 patterns as
// InternalClosedLoopEngine's default rule set. Mirrors Node's
// matchesKnownAttackPattern / Python's matches_known_attack_pattern
// (Option B, 2026-08-27): external mode's own local behavioral preflight
// (cold-start / LSH campaign / rate limit) is purely statistical and
// cannot flag a single, first-ever malicious request from a fresh entity —
// there is no deviation/campaign/rate signal yet on request #1. This
// gives external mode a content check of its own for exactly that case.
func MatchesKnownAttackPattern(path, userAgent string) bool {
	if path != "" {
		if iclAnyMatch(iclSQLInjectionStrict, path) {
			return true
		}
		if iclAnyMatch(iclSQLInjectionModerate, path) {
			return true
		}
		if iclAnyMatch(iclXSSPatterns, path) {
			return true
		}
		if iclAnyMatch(iclPathTraversalPatterns, path) {
			return true
		}
	}
	if userAgent != "" && iclAnyMatch(iclScannerSignatures, userAgent) {
		return true
	}
	return false
}

// ── Request / Result / Action / Rule models ─────────────────────────────

// InternalCLRequest is one inbound request to evaluate.
type InternalCLRequest struct {
	IP        string
	Method    string
	Path      string
	UserAgent string
	UserID    string
	SessionID string
	// Body is the request body, for pattern matching. Optional.
	Body string
	// Query is the query string, for pattern matching. Optional.
	Query   string
	Headers map[string]string
	AgentID string
	// ToolName is the AI agent tool name, for agent tool-call monitoring.
	ToolName string
	// Timestamp overrides time.Now() for this evaluation. The zero value
	// means "now".
	Timestamp time.Time
}

// InternalCLAction is one side-effecting action taken as a result of a
// decision (block_ip, rate_limit, block_session, block_user,
// quarantine_agent, log).
type InternalCLAction struct {
	Type       string
	Target     string
	Reason     string
	TTLSeconds int
	Timestamp  time.Time
	EventID    string
}

// InternalCLResult is the outcome of InternalClosedLoopEngine.Evaluate.
type InternalCLResult struct {
	Decision         InternalCLDecision
	Score            float64
	Tier             int
	MatchedRules     []string
	EvaluationTimeUs int64
	Actions          []InternalCLAction
	EventID          string
}

// InternalCLAuditEntry is one entry in the engine's bounded audit log.
type InternalCLAuditEntry struct {
	EventID      string
	Timestamp    time.Time
	IP           string
	Decision     InternalCLDecision
	Score        float64
	Tier         int
	MatchedRules []string
	UserID       string
	AgentID      string
	Path         string
	Method       string
}

// InternalCLRule is one Tier-1 deterministic rule.
type InternalCLRule struct {
	Name        string
	Description string
	Severity    string
	Score       float64
	Decision    InternalCLDecision
	Match       func(req InternalCLRequest) bool
	Enabled     bool
}

// Tier2Scorer is an optional Tier-2 custom scorer callback, returning a
// 0-100 threat score. Unimplemented/pass-through by default: Evaluate
// skips Tier 2 entirely when the engine's config has no Tier2Scorer set,
// exactly as Node skips it when tier2Scorer is unset and Python skips it
// when tier2_scorer is None. This is deliberately not a Go port of Node's
// MLClassifier adapter, which is Node-specific and out of scope here
// (TODO 407).
type Tier2Scorer func(req InternalCLRequest) (float64, error)

// RelayCallback is the Tier-3 relay target, invoked for every non-'allow'
// decision when InternalCLConfig.EnableExternalRelay is true (hybrid mode
// only). See this file's top-level doc comment for why it is dispatched
// synchronously, not from a goroutine.
type RelayCallback func(result InternalCLResult, req InternalCLRequest)

// ActionCallback is invoked once per InternalCLAction a decision produces.
type ActionCallback func(action InternalCLAction)

// InternalCLConfig configures an InternalClosedLoopEngine. The zero value
// of every numeric/duration field below means "use the documented
// default" (mirroring Node's `config.x ?? default` / Python's dataclass
// defaults) — there is no supported way to set one of these fields to a
// literal zero.
type InternalCLConfig struct {
	// FailMode is "closed" (block, score 100, the default) or "open"
	// (allow, score 0) on an evaluation error.
	FailMode string
	// EnableExternalRelay enables Tier-3 relay (hybrid mode only).
	// Default: false (air-gap).
	EnableExternalRelay bool
	// MaxBlockedEntries bounds each of the four block/quarantine stores.
	// Default: 10,000.
	MaxBlockedEntries int
	// MaxRateLimitEntries bounds the rate limiter. Default: 50,000.
	MaxRateLimitEntries int
	// MaxAuditEntries bounds the audit log. Default: 100,000.
	MaxAuditEntries int
	// DefaultBlockTTL is how long an auto-block lasts. Default: 1 hour.
	DefaultBlockTTL time.Duration
	// Tier2Scorer is the optional custom Tier-2 scorer. Nil (the default)
	// skips Tier 2 entirely.
	Tier2Scorer Tier2Scorer
	// BlockThreshold is the Tier-2 score at/above which a request is
	// blocked. Default: 85.
	BlockThreshold float64
	// RateLimitThreshold is the Tier-2 score at/above which a request is
	// rate-limited (below BlockThreshold). Default: 60.
	RateLimitThreshold float64
	// RateLimitMax is the maximum requests per IP per RateLimitWindow.
	// Default: 100.
	RateLimitMax int
	// RateLimitWindow is the sliding window size. Default: 1 minute.
	RateLimitWindow time.Duration
	// Debug enables info/debug-level logging (error/warn always log).
	Debug bool
	// OnAction is invoked once per InternalCLAction a decision produces.
	OnAction ActionCallback
	// OnRelay is the Tier-3 relay target (hybrid mode).
	OnRelay RelayCallback
}

func (c InternalCLConfig) withDefaults() InternalCLConfig {
	if c.FailMode == "" {
		c.FailMode = "closed"
	}
	if c.MaxBlockedEntries == 0 {
		c.MaxBlockedEntries = 10_000
	}
	if c.MaxRateLimitEntries == 0 {
		c.MaxRateLimitEntries = 50_000
	}
	if c.MaxAuditEntries == 0 {
		c.MaxAuditEntries = 100_000
	}
	if c.DefaultBlockTTL == 0 {
		c.DefaultBlockTTL = time.Hour
	}
	if c.BlockThreshold == 0 {
		c.BlockThreshold = 85
	}
	if c.RateLimitThreshold == 0 {
		c.RateLimitThreshold = 60
	}
	if c.RateLimitMax == 0 {
		c.RateLimitMax = 100
	}
	if c.RateLimitWindow == 0 {
		c.RateLimitWindow = time.Minute
	}
	return c
}

// ── internal state entry types ──────────────────────────────────────────

type iclBlockEntry struct {
	expiresAt time.Time
	reason    string
}

type iclQuarantineEntry struct {
	reason    string
	timestamp time.Time
}

type iclRateLimitEntry struct {
	timestamps []time.Time
	blocked    bool
}

// ── InternalClosedLoopEngine ────────────────────────────────────────────

// InternalClosedLoopEngine is the Go port of Node's InternalClosedLoopEngine.
// Safe for concurrent use — see this file's top-level doc comment.
type InternalClosedLoopEngine struct {
	config InternalCLConfig

	blockedIPs        *BoundedMap[string, iclBlockEntry]
	blockedUsers      *BoundedMap[string, iclBlockEntry]
	blockedSessions   *BoundedMap[string, iclBlockEntry]
	quarantinedAgents *BoundedMap[string, iclQuarantineEntry]
	rateLimiter       *BoundedMap[string, iclRateLimitEntry]

	// mu guards the rule set, the audit log, and the rate limiter's
	// check-then-record critical section (see top-level doc comment).
	mu       sync.Mutex
	rules    []InternalCLRule
	auditLog []InternalCLAuditEntry

	eventCounter int64 // atomic
}

// NewInternalClosedLoopEngine returns a ready-to-use engine with the 7
// default Tier-1 rules registered.
func NewInternalClosedLoopEngine(config InternalCLConfig) *InternalClosedLoopEngine {
	config = config.withDefaults()

	e := &InternalClosedLoopEngine{
		config:            config,
		blockedIPs:        NewBoundedMap[string, iclBlockEntry](config.MaxBlockedEntries),
		blockedUsers:      NewBoundedMap[string, iclBlockEntry](config.MaxBlockedEntries),
		blockedSessions:   NewBoundedMap[string, iclBlockEntry](config.MaxBlockedEntries),
		quarantinedAgents: NewBoundedMap[string, iclQuarantineEntry](config.MaxBlockedEntries),
		rateLimiter:       NewBoundedMap[string, iclRateLimitEntry](config.MaxRateLimitEntries),
	}
	e.registerDefaultRules()
	e.log("info", fmt.Sprintf("Internal Closed-Loop Engine initialized (failMode=%s)", config.FailMode))
	return e
}

// ── Public API ───────────────────────────────────────────────────────────

// Evaluate evaluates req through the 3-tier engine. Call this for every
// inbound request, before it reaches the application — the defining
// behavior of internal mode is that this never needs a platform
// round-trip to produce a decision.
func (e *InternalClosedLoopEngine) Evaluate(req InternalCLRequest) InternalCLResult {
	start := time.Now()
	now := req.Timestamp
	if now.IsZero() {
		now = start
	}
	eventID := e.generateEventID()

	result, err := e.evaluateGuarded(req, now, eventID, start)
	if err != nil {
		elapsed := time.Since(start).Microseconds()
		e.log("error", fmt.Sprintf("Evaluation error: %v", err))
		if e.config.FailMode == "open" {
			return InternalCLResult{
				Decision:         CLDecisionAllow,
				Score:            0,
				Tier:             1,
				MatchedRules:     []string{"fail_open_error"},
				EvaluationTimeUs: elapsed,
				Actions:          []InternalCLAction{},
				EventID:          eventID,
			}
		}
		return InternalCLResult{
			Decision:         CLDecisionBlock,
			Score:            100,
			Tier:             1,
			MatchedRules:     []string{"fail_closed_error"},
			EvaluationTimeUs: elapsed,
			Actions:          []InternalCLAction{},
			EventID:          eventID,
		}
	}
	return result
}

// evaluateGuarded holds the real evaluation logic, with a recover() so a
// panic anywhere inside (including a misbehaving Tier2Scorer) is turned
// into an error for Evaluate's fail-mode handling, instead of crashing the
// caller. Individual Tier-1 rule panics are already isolated inside
// safeMatch and never reach here as an error.
func (e *InternalClosedLoopEngine) evaluateGuarded(req InternalCLRequest, now time.Time, eventID string, start time.Time) (result InternalCLResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	// ─── Pre-check: already-blocked IP/user/session or quarantined agent ───
	if decision, reason, blocked := e.checkBlocked(req, now); blocked {
		elapsed := time.Since(start).Microseconds()
		result = InternalCLResult{
			Decision:         decision,
			Score:            100,
			Tier:             1,
			MatchedRules:     []string{reason},
			EvaluationTimeUs: elapsed,
			Actions:          []InternalCLAction{},
			EventID:          eventID,
		}
		e.recordAudit(result, req, now)
		return result, nil
	}

	// ─── Tier 1: deterministic rules ───
	t1Decision, t1Score, t1Rules := e.evaluateTier1(req)
	if t1Decision != CLDecisionAllow {
		elapsed := time.Since(start).Microseconds()
		actions := e.executeActions(t1Decision, t1Rules, req, eventID, now)
		result = InternalCLResult{
			Decision:         t1Decision,
			Score:            t1Score,
			Tier:             1,
			MatchedRules:     t1Rules,
			EvaluationTimeUs: elapsed,
			Actions:          actions,
			EventID:          eventID,
		}
		e.recordAudit(result, req, now)
		if e.config.EnableExternalRelay {
			e.relayToExternal(result, req)
		}
		return result, nil
	}

	// ─── Rate limit: atomic check-and-record ───
	if e.checkAndRecordRateLimit(req.IP, now) {
		elapsed := time.Since(start).Microseconds()
		actions := e.executeActions(CLDecisionRateLimit, []string{"rate_limit_exceeded"}, req, eventID, now)
		result = InternalCLResult{
			Decision:         CLDecisionRateLimit,
			Score:            65,
			Tier:             1,
			MatchedRules:     []string{"rate_limit_exceeded"},
			EvaluationTimeUs: elapsed,
			Actions:          actions,
			EventID:          eventID,
		}
		e.recordAudit(result, req, now)
		return result, nil
	}

	// ─── Tier 2: optional custom scorer — unimplemented/pass-through by
	// default. Skipped entirely when no scorer is configured. ───
	if e.config.Tier2Scorer != nil {
		score, scoreErr := e.config.Tier2Scorer(req)
		if scoreErr != nil {
			return InternalCLResult{}, scoreErr
		}

		if score >= e.config.BlockThreshold {
			elapsed := time.Since(start).Microseconds()
			actions := e.executeActions(CLDecisionBlock, []string{"tier2_ml_score"}, req, eventID, now)
			result = InternalCLResult{
				Decision:         CLDecisionBlock,
				Score:            score,
				Tier:             2,
				MatchedRules:     []string{"tier2_ml_score"},
				EvaluationTimeUs: elapsed,
				Actions:          actions,
				EventID:          eventID,
			}
			e.recordAudit(result, req, now)
			if e.config.EnableExternalRelay {
				e.relayToExternal(result, req)
			}
			return result, nil
		} else if score >= e.config.RateLimitThreshold {
			elapsed := time.Since(start).Microseconds()
			result = InternalCLResult{
				Decision:         CLDecisionRateLimit,
				Score:            score,
				Tier:             2,
				MatchedRules:     []string{"tier2_ml_elevated"},
				EvaluationTimeUs: elapsed,
				Actions:          []InternalCLAction{},
				EventID:          eventID,
			}
			e.recordAudit(result, req, now)
			return result, nil
		}
	}

	// ─── Allow ───
	elapsed := time.Since(start).Microseconds()
	return InternalCLResult{
		Decision:         CLDecisionAllow,
		Score:            0,
		Tier:             1,
		MatchedRules:     []string{},
		EvaluationTimeUs: elapsed,
		Actions:          []InternalCLAction{},
		EventID:          eventID,
	}, nil
}

// BlockIP manually blocks ip. ttl <= 0 uses the engine's DefaultBlockTTL.
func (e *InternalClosedLoopEngine) BlockIP(ip, reason string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = e.config.DefaultBlockTTL
	}
	e.blockedIPs.Set(ip, iclBlockEntry{expiresAt: time.Now().Add(ttl), reason: reason})
	e.log("info", fmt.Sprintf("IP blocked: %s — %s (TTL: %s)", ip, reason, ttl))
}

// UnblockIP removes ip's block, if any, reporting whether it existed.
func (e *InternalClosedLoopEngine) UnblockIP(ip string) bool {
	existed := e.blockedIPs.Has(ip)
	e.blockedIPs.Delete(ip)
	if existed {
		e.log("info", fmt.Sprintf("IP unblocked: %s", ip))
	}
	return existed
}

// BlockUser manually blocks userID. ttl <= 0 uses DefaultBlockTTL.
func (e *InternalClosedLoopEngine) BlockUser(userID, reason string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = e.config.DefaultBlockTTL
	}
	e.blockedUsers.Set(userID, iclBlockEntry{expiresAt: time.Now().Add(ttl), reason: reason})
	e.log("info", fmt.Sprintf("User blocked: %s — %s", userID, reason))
}

// BlockSession manually blocks sessionID. ttl <= 0 uses DefaultBlockTTL.
func (e *InternalClosedLoopEngine) BlockSession(sessionID, reason string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = e.config.DefaultBlockTTL
	}
	e.blockedSessions.Set(sessionID, iclBlockEntry{expiresAt: time.Now().Add(ttl), reason: reason})
	e.log("info", fmt.Sprintf("Session blocked: %s — %s", sessionID, reason))
}

// QuarantineAgent quarantines agentID (permanent until UnquarantineAgent).
func (e *InternalClosedLoopEngine) QuarantineAgent(agentID, reason string) {
	e.quarantinedAgents.Set(agentID, iclQuarantineEntry{reason: reason, timestamp: time.Now()})
	e.log("info", fmt.Sprintf("Agent quarantined: %s — %s", agentID, reason))
}

// UnquarantineAgent removes agentID's quarantine, reporting whether it
// existed.
func (e *InternalClosedLoopEngine) UnquarantineAgent(agentID string) bool {
	existed := e.quarantinedAgents.Has(agentID)
	e.quarantinedAgents.Delete(agentID)
	if existed {
		e.log("info", fmt.Sprintf("Agent unquarantined: %s", agentID))
	}
	return existed
}

// IsIPBlocked reports whether ip is currently blocked, lazily evicting an
// expired block.
func (e *InternalClosedLoopEngine) IsIPBlocked(ip string) bool {
	entry, ok := e.blockedIPs.Get(ip)
	if !ok {
		return false
	}
	if time.Now().After(entry.expiresAt) {
		e.blockedIPs.Delete(ip)
		return false
	}
	return true
}

// IsAgentQuarantined reports whether agentID is quarantined.
func (e *InternalClosedLoopEngine) IsAgentQuarantined(agentID string) bool {
	return e.quarantinedAgents.Has(agentID)
}

// AddRule adds a custom Tier-1 rule.
func (e *InternalClosedLoopEngine) AddRule(rule InternalCLRule) {
	e.mu.Lock()
	e.rules = append(e.rules, rule)
	e.mu.Unlock()
	e.log("debug", fmt.Sprintf("Rule added: %s", rule.Name))
}

// RemoveRule removes the rule named name, reporting whether it existed.
func (e *InternalClosedLoopEngine) RemoveRule(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.Name == name {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			e.log("debug", fmt.Sprintf("Rule removed: %s", name))
			return true
		}
	}
	return false
}

// GetRules returns a snapshot of all registered rules.
func (e *InternalClosedLoopEngine) GetRules() []InternalCLRule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]InternalCLRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// GetAuditLog returns up to the last limit audit entries (all of them if
// limit <= 0).
func (e *InternalClosedLoopEngine) GetAuditLog(limit int) []InternalCLAuditEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 || limit > len(e.auditLog) {
		limit = len(e.auditLog)
	}
	start := len(e.auditLog) - limit
	out := make([]InternalCLAuditEntry, limit)
	copy(out, e.auditLog[start:])
	return out
}

// InternalCLStats is engine statistics, as returned by GetStats.
type InternalCLStats struct {
	BlockedIPs        int
	BlockedUsers      int
	BlockedSessions   int
	QuarantinedAgents int
	RateLimitEntries  int
	AuditLogSize      int
	RulesCount        int
	FailMode          string
}

// GetStats returns engine statistics.
func (e *InternalClosedLoopEngine) GetStats() InternalCLStats {
	e.mu.Lock()
	rulesCount := len(e.rules)
	auditLogSize := len(e.auditLog)
	e.mu.Unlock()
	return InternalCLStats{
		BlockedIPs:        e.blockedIPs.Size(),
		BlockedUsers:      e.blockedUsers.Size(),
		BlockedSessions:   e.blockedSessions.Size(),
		QuarantinedAgents: e.quarantinedAgents.Size(),
		RateLimitEntries:  e.rateLimiter.Size(),
		AuditLogSize:      auditLogSize,
		RulesCount:        rulesCount,
		FailMode:          e.config.FailMode,
	}
}

// ImportBlockedIPEntry is one entry for ImportBlockedIPs.
type ImportBlockedIPEntry struct {
	IP     string
	Reason string
	// TTL <= 0 uses the engine's DefaultBlockTTL.
	TTL time.Duration
}

// ImportBlockedIPs imports blocked IPs from an external source (e.g. an
// AbuseIPDB blacklist), returning how many were imported.
func (e *InternalClosedLoopEngine) ImportBlockedIPs(entries []ImportBlockedIPEntry) int {
	count := 0
	for _, entry := range entries {
		e.BlockIP(entry.IP, entry.Reason, entry.TTL)
		count++
	}
	return count
}

// reset clears all engine state. Unexported: for this package's own tests
// only, mirroring Node's `_reset()`/Python's `_reset()`.
func (e *InternalClosedLoopEngine) reset() {
	e.blockedIPs.Clear()
	e.blockedUsers.Clear()
	e.blockedSessions.Clear()
	e.quarantinedAgents.Clear()
	e.rateLimiter.Clear()
	e.mu.Lock()
	e.auditLog = nil
	e.mu.Unlock()
	atomic.StoreInt64(&e.eventCounter, 0)
}

// ── Private: pre-check / Tier 1 / rate limit / actions / audit / relay ──

func (e *InternalClosedLoopEngine) checkBlocked(req InternalCLRequest, now time.Time) (decision InternalCLDecision, reason string, blocked bool) {
	if entry, ok := e.blockedIPs.Get(req.IP); ok {
		if now.After(entry.expiresAt) {
			e.blockedIPs.Delete(req.IP)
		} else {
			return CLDecisionBlock, "ip_blocked:" + entry.reason, true
		}
	}

	if req.UserID != "" {
		if entry, ok := e.blockedUsers.Get(req.UserID); ok {
			if now.After(entry.expiresAt) {
				e.blockedUsers.Delete(req.UserID)
			} else {
				return CLDecisionBlock, "user_blocked:" + entry.reason, true
			}
		}
	}

	if req.SessionID != "" {
		if entry, ok := e.blockedSessions.Get(req.SessionID); ok {
			if now.After(entry.expiresAt) {
				e.blockedSessions.Delete(req.SessionID)
			} else {
				return CLDecisionBlock, "session_blocked:" + entry.reason, true
			}
		}
	}

	if req.AgentID != "" && e.quarantinedAgents.Has(req.AgentID) {
		return CLDecisionQuarantine, "agent_quarantined:" + req.AgentID, true
	}

	return "", "", false
}

// safeMatch isolates one rule's Match callback: a panicking rule is logged
// and treated as "did not match" — mirroring Node's per-rule try/catch, so
// one bad rule can never crash the whole engine or escalate to the
// top-level fail-mode handler.
func (e *InternalClosedLoopEngine) safeMatch(rule InternalCLRule, req InternalCLRequest) (matched bool) {
	defer func() {
		if r := recover(); r != nil {
			e.log("error", fmt.Sprintf("Rule %s panicked: %v", rule.Name, r))
			matched = false
		}
	}()
	return rule.Match(req)
}

func (e *InternalClosedLoopEngine) evaluateTier1(req InternalCLRequest) (InternalCLDecision, float64, []string) {
	e.mu.Lock()
	rules := make([]InternalCLRule, len(e.rules))
	copy(rules, e.rules)
	e.mu.Unlock()

	var matchedRules []string
	maxScore := 0.0
	decision := CLDecisionAllow

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if e.safeMatch(rule, req) {
			matchedRules = append(matchedRules, rule.Name)
			if rule.Score > maxScore {
				maxScore = rule.Score
				decision = rule.Decision
			}
		}
	}
	if matchedRules == nil {
		matchedRules = []string{}
	}
	return decision, maxScore, matchedRules
}

// checkAndRecordRateLimit atomically checks the sliding-window rate limit
// for ip and, if not exceeded, records this request's timestamp. The
// check and the record must happen under the same lock (not just
// BoundedMap's own per-call lock) so two concurrent requests from the same
// IP cannot both observe "under the limit" before either is recorded.
func (e *InternalClosedLoopEngine) checkAndRecordRateLimit(ip string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	entry, ok := e.rateLimiter.Get(ip)
	if !ok {
		e.rateLimiter.Set(ip, iclRateLimitEntry{timestamps: []time.Time{now}})
		return false
	}

	windowStart := now.Add(-e.config.RateLimitWindow)
	filtered := make([]time.Time, 0, len(entry.timestamps))
	for _, t := range entry.timestamps {
		if t.After(windowStart) {
			filtered = append(filtered, t)
		}
	}

	if len(filtered) >= e.config.RateLimitMax {
		entry.timestamps = filtered
		entry.blocked = true
		e.rateLimiter.Set(ip, entry)
		return true
	}

	filtered = append(filtered, now)
	entry.timestamps = filtered
	e.rateLimiter.Set(ip, entry)
	return false
}

func (e *InternalClosedLoopEngine) executeActions(decision InternalCLDecision, matchedRules []string, req InternalCLRequest, eventID string, now time.Time) []InternalCLAction {
	actions := []InternalCLAction{}
	ttl := e.config.DefaultBlockTTL
	reason := strings.Join(matchedRules, ", ")

	if decision == CLDecisionBlock || decision == CLDecisionQuarantine {
		e.blockedIPs.Set(req.IP, iclBlockEntry{expiresAt: now.Add(ttl), reason: reason})
		actions = append(actions, InternalCLAction{
			Type: "block_ip", Target: req.IP, Reason: reason,
			TTLSeconds: int(ttl.Seconds()), Timestamp: now, EventID: eventID,
		})

		if req.SessionID != "" {
			e.blockedSessions.Set(req.SessionID, iclBlockEntry{expiresAt: now.Add(ttl), reason: reason})
			actions = append(actions, InternalCLAction{
				Type: "block_session", Target: req.SessionID, Reason: reason,
				TTLSeconds: int(ttl.Seconds()), Timestamp: now, EventID: eventID,
			})
		}

		if req.AgentID != "" {
			e.quarantinedAgents.Set(req.AgentID, iclQuarantineEntry{reason: reason, timestamp: now})
			actions = append(actions, InternalCLAction{
				Type: "quarantine_agent", Target: req.AgentID, Reason: reason,
				TTLSeconds: 0, Timestamp: now, EventID: eventID,
			})
		}
	}

	if e.config.OnAction != nil {
		for _, action := range actions {
			e.safeOnAction(action)
		}
	}

	return actions
}

func (e *InternalClosedLoopEngine) safeOnAction(action InternalCLAction) {
	defer func() {
		if r := recover(); r != nil {
			e.log("error", fmt.Sprintf("OnAction callback error for %s: %v", action.Type, r))
		}
	}()
	e.config.OnAction(action)
}

func (e *InternalClosedLoopEngine) recordAudit(result InternalCLResult, req InternalCLRequest, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.auditLog) >= e.config.MaxAuditEntries {
		trim := e.config.MaxAuditEntries / 10
		if trim < 1 {
			trim = 1
		}
		if trim > len(e.auditLog) {
			trim = len(e.auditLog)
		}
		e.auditLog = e.auditLog[trim:]
	}

	e.auditLog = append(e.auditLog, InternalCLAuditEntry{
		EventID:      result.EventID,
		Timestamp:    now,
		IP:           req.IP,
		Decision:     result.Decision,
		Score:        result.Score,
		Tier:         result.Tier,
		MatchedRules: result.MatchedRules,
		UserID:       req.UserID,
		AgentID:      req.AgentID,
		Path:         req.Path,
		Method:       req.Method,
	})
}

// relayToExternal dispatches OnRelay synchronously. See this file's
// top-level doc comment for why this is not a goroutine.
func (e *InternalClosedLoopEngine) relayToExternal(result InternalCLResult, req InternalCLRequest) {
	e.log("debug", fmt.Sprintf("Tier 3 relay: %s -> external platform", result.EventID))
	if e.config.OnRelay == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			e.log("error", fmt.Sprintf("OnRelay callback error for %s: %v", result.EventID, r))
		}
	}()
	e.config.OnRelay(result, req)
}

func (e *InternalClosedLoopEngine) generateEventID() string {
	counter := atomic.AddInt64(&e.eventCounter, 1)
	ts := strconv.FormatInt(time.Now().UnixNano(), 36)
	c := strconv.FormatInt(counter, 36)
	for len(c) < 4 {
		c = "0" + c
	}
	r := strconv.FormatInt(rand.Int63n(0x10000), 36)
	return fmt.Sprintf("icl_%s_%s_%s", ts, c, r)
}

// ── Default Tier-1 rules ─────────────────────────────────────────────────

func (e *InternalClosedLoopEngine) registerDefaultRules() {
	e.rules = append(e.rules, InternalCLRule{
		Name:        "sql_injection",
		Description: "Detects SQL injection patterns context-aware (strict on path/query, moderate on body)",
		Severity:    "critical",
		Score:       95,
		Decision:    CLDecisionBlock,
		Enabled:     true,
		Match: func(req InternalCLRequest) bool {
			strictTargets := iclNonEmpty(req.Path, req.Query)
			for _, t := range strictTargets {
				if iclAnyMatch(iclSQLInjectionStrict, t) {
					return true
				}
			}
			for _, t := range strictTargets {
				if iclAnyMatch(iclSQLInjectionModerate, t) {
					return true
				}
			}

			bodyTargets := iclNonEmpty(req.Body)
			for _, v := range req.Headers {
				if v != "" {
					bodyTargets = append(bodyTargets, v)
				}
			}
			for _, t := range bodyTargets {
				if iclAnyMatch(iclSQLInjectionStrict, t) {
					return true
				}
			}
			return false
		},
	})

	e.rules = append(e.rules, InternalCLRule{
		Name:        "xss_attempt",
		Description: "Detects cross-site scripting patterns",
		Severity:    "high",
		Score:       90,
		Decision:    CLDecisionBlock,
		Enabled:     true,
		Match: func(req InternalCLRequest) bool {
			for _, t := range iclNonEmpty(req.Path, req.Query, req.Body) {
				if iclAnyMatch(iclXSSPatterns, t) {
					return true
				}
			}
			return false
		},
	})

	e.rules = append(e.rules, InternalCLRule{
		Name:        "path_traversal",
		Description: "Detects directory traversal attempts",
		Severity:    "high",
		Score:       90,
		Decision:    CLDecisionBlock,
		Enabled:     true,
		Match: func(req InternalCLRequest) bool {
			for _, t := range iclNonEmpty(req.Path, req.Query) {
				if iclAnyMatch(iclPathTraversalPatterns, t) {
					return true
				}
			}
			return false
		},
	})

	e.rules = append(e.rules, InternalCLRule{
		Name:        "scanner_detected",
		Description: "Detects known vulnerability scanner user agents",
		Severity:    "medium",
		Score:       75,
		Decision:    CLDecisionBlock,
		Enabled:     true,
		Match: func(req InternalCLRequest) bool {
			if req.UserAgent == "" {
				return false
			}
			return iclAnyMatch(iclScannerSignatures, req.UserAgent)
		},
	})

	e.rules = append(e.rules, InternalCLRule{
		Name:        "sensitive_file_access",
		Description: "Detects access to sensitive files (.env, .git, wp-admin, etc.)",
		Severity:    "high",
		Score:       85,
		Decision:    CLDecisionBlock,
		Enabled:     true,
		Match: func(req InternalCLRequest) bool {
			return iclAnyMatch(iclSensitiveFilePatterns, req.Path)
		},
	})

	e.rules = append(e.rules, InternalCLRule{
		Name:        "credential_stuffing_pattern",
		Description: "Detects credential stuffing via POST to auth endpoints",
		Severity:    "high",
		Score:       80,
		Decision:    CLDecisionRateLimit,
		Enabled:     true,
		Match: func(req InternalCLRequest) bool {
			if req.Method != "POST" {
				return false
			}
			lower := strings.ToLower(req.Path)
			for _, p := range iclAuthPaths {
				if strings.Contains(lower, p) {
					return true
				}
			}
			return false
		},
	})

	e.rules = append(e.rules, InternalCLRule{
		Name:        "agent_unsanctioned_tool",
		Description: "Detects agent attempting to use dangerous tools",
		Severity:    "critical",
		Score:       95,
		Decision:    CLDecisionQuarantine,
		Enabled:     true,
		Match: func(req InternalCLRequest) bool {
			if req.AgentID == "" || req.ToolName == "" {
				return false
			}
			return iclDangerousTools[strings.ToLower(req.ToolName)]
		},
	})
}

func (e *InternalClosedLoopEngine) log(level, message string) {
	if !e.config.Debug && level == "debug" {
		return
	}
	prefix := "[DevFortress ICL]"
	switch level {
	case "error", "warn":
		fmt.Fprintln(os.Stderr, prefix, message)
	default: // info, debug
		if e.config.Debug {
			fmt.Println(prefix, message)
		}
	}
}
