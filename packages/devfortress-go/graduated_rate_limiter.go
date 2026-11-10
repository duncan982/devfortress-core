package devfortress

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

// ── GraduatedRateLimiter (Invention A3) ──────────────────────────────────

// Mirrors the Node SDK's GraduatedRateLimiter
// (graduated-rate-limiter.ts). Implements alias-scoped graduated rate
// limiting with multi-stage response escalation. Addresses GAP-A3-1
// through GAP-A3-4:
//
//	GAP-A3-1: Latency jitter (±20%) in soft-limit injection
//	GAP-A3-2: Per-endpoint hierarchical rate limits (configurable)
//	GAP-A3-3: Burst detection (1-second micro-window)
//	GAP-A3-4: Escalating cooldowns (60s→120s→240s, revoke after 3)
//
// Four-stage graduated response:
//
//	Stage 1: Observation (< 50% of limit)
//	Stage 2: Warning (50%-75% of limit)
//	Stage 3: Soft-limit with latency injection (75%-100% of limit)
//	Stage 4: Hard-block with escalating cooldowns (>= 100% of limit)
//	Stage 5: Alias revocation (>= 120% of limit or 3 consecutive blocks)

// RateLimitStage is which graduated response stage a Check call
// triggered.
type RateLimitStage string

const (
	StageObservation RateLimitStage = "observation"
	StageWarning      RateLimitStage = "warning"
	StageSoftLimit    RateLimitStage = "soft_limit"
	StageHardBlock    RateLimitStage = "hard_block"
	StageRevocation   RateLimitStage = "revocation"
)

// GraduatedRateLimiterConfig configures a GraduatedRateLimiter. Mirrors
// the Node SDK's GraduatedRateLimiterConfig.
type GraduatedRateLimiterConfig struct {
	// DefaultLimit is the default rate limit (requests per window).
	// Default: 100.
	DefaultLimit int
	// Window is the sliding window size. Default: 1 minute.
	Window time.Duration
	// SoftLimitBaseLatency is the base latency for soft-limit injection.
	// Default: 2s.
	SoftLimitBaseLatency time.Duration
	// MaxEntries is the maximum number of tracked aliases. Default:
	// 50_000.
	MaxEntries int
	// EndpointLimits maps endpoint path patterns to max requests/window.
	EndpointLimits map[string]int
	// BurstLimit is the max requests per 1-second micro-window. Default:
	// 20.
	BurstLimit int
	// InitialCooldown is the initial cooldown duration. Default: 60s.
	InitialCooldown time.Duration
	// MaxConsecutiveBlocks is the max consecutive hard-blocks before
	// revocation. Default: 3.
	MaxConsecutiveBlocks int
}

// RateLimitResult is the outcome of one GraduatedRateLimiter.Check call.
type RateLimitResult struct {
	// Stage is which stage was triggered.
	Stage RateLimitStage
	// CurrentRate is the current request rate (requests in current
	// window).
	CurrentRate int
	// Limit is the effective limit for this alias.
	Limit int
	// Ratio is CurrentRate/Limit (0.0 - 1.5+).
	Ratio float64
	// InjectedLatency is the injected latency (zero for
	// observation/warning, >0 for soft_limit).
	InjectedLatency time.Duration
	// Blocked is whether the request should be blocked.
	Blocked bool
	// Revoke is whether the alias should be revoked.
	Revoke bool
	// Cooldown is the cooldown duration (zero if not in cooldown).
	Cooldown time.Duration
	// Remaining is the remaining requests before the next stage.
	Remaining int
	// BurstDetected is whether a burst was detected in the
	// micro-window.
	BurstDetected bool
}

type rateLimitEntry struct {
	timestamps        []time.Time
	cooldownUntil     time.Time
	consecutiveBlocks int
	revoked           bool
	burstTimestamps   []time.Time
}

// GraduatedRateLimiter implements alias-scoped graduated rate limiting
// with multi-stage response escalation. Mirrors the Node SDK's
// GraduatedRateLimiter (graduated-rate-limiter.ts), Invention A3. Safe
// for concurrent use.
type GraduatedRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
	// order tracks insertion order for oldest-first eviction, mirroring
	// the iteration order of Node's Map (a key's position is set once,
	// at first insertion, and unaffected by later Map.set calls on the
	// same key).
	order []string

	cfg GraduatedRateLimiterConfig

	stopCleanup chan struct{}
	stopped     bool
}

// NewGraduatedRateLimiter creates a GraduatedRateLimiter and starts its
// periodic cleanup, mirroring the Node SDK's 30-second cleanup interval.
// Call Destroy to stop it.
func NewGraduatedRateLimiter(cfg GraduatedRateLimiterConfig) *GraduatedRateLimiter {
	if cfg.DefaultLimit == 0 {
		cfg.DefaultLimit = 100
	}
	if cfg.Window == 0 {
		cfg.Window = time.Minute
	}
	if cfg.SoftLimitBaseLatency == 0 {
		cfg.SoftLimitBaseLatency = 2 * time.Second
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 50_000
	}
	if cfg.EndpointLimits == nil {
		cfg.EndpointLimits = map[string]int{}
	}
	if cfg.BurstLimit == 0 {
		cfg.BurstLimit = 20
	}
	if cfg.InitialCooldown == 0 {
		cfg.InitialCooldown = 60 * time.Second
	}
	if cfg.MaxConsecutiveBlocks == 0 {
		cfg.MaxConsecutiveBlocks = 3
	}

	l := &GraduatedRateLimiter{
		entries:     make(map[string]*rateLimitEntry),
		cfg:         cfg,
		stopCleanup: make(chan struct{}),
	}

	go l.runCleanupLoop()

	return l
}

func (l *GraduatedRateLimiter) runCleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.cleanup()
		case <-l.stopCleanup:
			return
		}
	}
}

// Check checks the rate limit for an alias (identified by key, typically
// an IP or session ID). It records the request and returns the graduated
// response. endpoint is optional and enables per-endpoint limits
// (GAP-A3-2).
func (l *GraduatedRateLimiter) Check(key string, endpoint string) RateLimitResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	entry, exists := l.entries[key]
	if !exists {
		entry = &rateLimitEntry{}
	}

	// Permanently revoked.
	if entry.revoked {
		return RateLimitResult{
			Stage:     StageRevocation,
			Ratio:     math.Inf(1),
			Blocked:   true,
			Revoke:    false, // already revoked
		}
	}

	// Currently in cooldown.
	if entry.cooldownUntil.After(now) {
		cooldownRemaining := entry.cooldownUntil.Sub(now)
		return RateLimitResult{
			Stage:        StageHardBlock,
			CurrentRate:  len(entry.timestamps),
			Limit:        l.getLimit(endpoint),
			Ratio:        1.0,
			Blocked:      true,
			Cooldown:     roundUpSeconds(cooldownRemaining),
			BurstDetected: false,
		}
	}

	// Clean old timestamps outside window.
	windowStart := now.Add(-l.cfg.Window)
	entry.timestamps = filterAfter(entry.timestamps, windowStart)

	// GAP-A3-3: clean burst micro-window (1 second).
	burstWindowStart := now.Add(-time.Second)
	entry.burstTimestamps = filterAfter(entry.burstTimestamps, burstWindowStart)

	// Record this request.
	entry.timestamps = append(entry.timestamps, now)
	entry.burstTimestamps = append(entry.burstTimestamps, now)

	// Enforce max entries.
	if !exists && len(l.entries) >= l.cfg.MaxEntries {
		l.evictOldest()
	}
	if !exists {
		l.order = append(l.order, key)
	}
	l.entries[key] = entry

	limit := l.getLimit(endpoint)
	currentRate := len(entry.timestamps)
	ratio := float64(currentRate) / float64(limit)

	// GAP-A3-3: burst detection.
	burstDetected := len(entry.burstTimestamps) > l.cfg.BurstLimit

	if ratio >= 1.2 || entry.consecutiveBlocks >= l.cfg.MaxConsecutiveBlocks {
		// Stage 5: revocation.
		entry.revoked = true
		return RateLimitResult{
			Stage:         StageRevocation,
			CurrentRate:   currentRate,
			Limit:         limit,
			Ratio:         ratio,
			Blocked:       true,
			Revoke:        true,
			BurstDetected: burstDetected,
		}
	}

	if ratio >= 1.0 || burstDetected {
		// Stage 4: hard-block with escalating cooldown (GAP-A3-4).
		entry.consecutiveBlocks++
		cooldownMultiplier := math.Pow(2, float64(entry.consecutiveBlocks-1))
		cooldown := time.Duration(float64(l.cfg.InitialCooldown) * cooldownMultiplier)
		entry.cooldownUntil = now.Add(cooldown)

		return RateLimitResult{
			Stage:         StageHardBlock,
			CurrentRate:   currentRate,
			Limit:         limit,
			Ratio:         ratio,
			Blocked:       true,
			Cooldown:      cooldown,
			BurstDetected: burstDetected,
		}
	}

	if ratio >= 0.75 {
		// Stage 3: soft-limit with latency injection + jitter
		// (GAP-A3-1). Reset consecutive blocks when in soft-limit (not
		// hitting hard block).
		entry.consecutiveBlocks = 0

		progress := (ratio - 0.75) / 0.25 // 0.0 at 75%, 1.0 at 100%
		baseLatencyMs := float64(l.cfg.SoftLimitBaseLatency.Milliseconds()) * math.Pow(progress, 2)
		// GAP-A3-1: add +/-20% random jitter.
		jitter := 0.8 + 0.4*rand.Float64()
		injectedLatencyMs := math.Round(baseLatencyMs * jitter)

		return RateLimitResult{
			Stage:           StageSoftLimit,
			CurrentRate:     currentRate,
			Limit:           limit,
			Ratio:           ratio,
			InjectedLatency: time.Duration(injectedLatencyMs) * time.Millisecond,
			Remaining:       max(0, limit-currentRate),
			BurstDetected:   burstDetected,
		}
	}

	if ratio >= 0.5 {
		// Stage 2: warning.
		entry.consecutiveBlocks = 0
		return RateLimitResult{
			Stage:       StageWarning,
			CurrentRate: currentRate,
			Limit:       limit,
			Ratio:       ratio,
			Remaining:   max(0, limit-currentRate),
		}
	}

	// Stage 1: observation.
	entry.consecutiveBlocks = 0
	return RateLimitResult{
		Stage:       StageObservation,
		CurrentRate: currentRate,
		Limit:       limit,
		Ratio:       ratio,
		Remaining:   max(0, limit-currentRate),
	}
}

// RevokeAlias manually revokes an alias (e.g. from an external security
// decision).
func (l *GraduatedRateLimiter) RevokeAlias(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.entries[key]
	if !exists {
		entry = &rateLimitEntry{revoked: true}
		l.order = append(l.order, key)
	} else {
		entry.revoked = true
	}
	l.entries[key] = entry
}

// ResetAlias resets an alias's rate limit state (e.g. after an admin
// override).
func (l *GraduatedRateLimiter) ResetAlias(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// IsRevoked reports whether an alias has been revoked.
func (l *GraduatedRateLimiter) IsRevoked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.entries[key]
	return exists && entry.revoked
}

// ── Per-Endpoint Limits (GAP-A3-2) ───────────────────────────────────────

// SetEndpointLimits sets per-endpoint rate limits (merged into any
// existing endpoint limits).
func (l *GraduatedRateLimiter) SetEndpointLimits(limits map[string]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for pattern, limit := range limits {
		l.cfg.EndpointLimits[pattern] = limit
	}
}

// getLimit returns the effective limit for an endpoint: the most
// specific matching endpoint limit, or the default. Caller must hold
// l.mu.
func (l *GraduatedRateLimiter) getLimit(endpoint string) int {
	if endpoint == "" || len(l.cfg.EndpointLimits) == 0 {
		return l.cfg.DefaultLimit
	}

	if limit, ok := l.cfg.EndpointLimits[endpoint]; ok {
		return limit
	}

	for pattern, limit := range l.cfg.EndpointLimits {
		if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
			prefix := pattern[:len(pattern)-1]
			if len(endpoint) >= len(prefix) && endpoint[:len(prefix)] == prefix {
				return limit
			}
		}
	}

	return l.cfg.DefaultLimit
}

// ── Internal ──────────────────────────────────────────────────────────

// evictOldest removes the oldest-inserted alias still present. Caller
// must hold l.mu.
func (l *GraduatedRateLimiter) evictOldest() {
	for len(l.order) > 0 {
		oldest := l.order[0]
		l.order = l.order[1:]
		if _, ok := l.entries[oldest]; ok {
			delete(l.entries, oldest)
			return
		}
	}
}

// cleanup removes entries with no recent activity that are not in
// cooldown and not revoked.
func (l *GraduatedRateLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-l.cfg.Window)

	for key, entry := range l.entries {
		hasRecentActivity := false
		for _, t := range entry.timestamps {
			if t.After(windowStart) {
				hasRecentActivity = true
				break
			}
		}
		inCooldown := entry.cooldownUntil.After(now)

		if !hasRecentActivity && !inCooldown && !entry.revoked {
			delete(l.entries, key)
		}
	}
}

// Destroy stops the limiter's cleanup goroutine and clears its state.
func (l *GraduatedRateLimiter) Destroy() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.stopped {
		l.stopped = true
		close(l.stopCleanup)
	}
	l.entries = make(map[string]*rateLimitEntry)
	l.order = nil
}

// Size returns the current number of tracked aliases.
func (l *GraduatedRateLimiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func filterAfter(timestamps []time.Time, after time.Time) []time.Time {
	kept := timestamps[:0]
	for _, t := range timestamps {
		if t.After(after) {
			kept = append(kept, t)
		}
	}
	return kept
}

func roundUpSeconds(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return ((d + time.Second - 1) / time.Second) * time.Second
}
