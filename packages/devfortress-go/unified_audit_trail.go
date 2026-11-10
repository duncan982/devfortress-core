package devfortress

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// ── UnifiedAuditTrail (CL-M3) ────────────────────────────────────────────

// Mirrors the Node SDK's UnifiedAuditTrail (unified-audit.ts). Merges
// internal and external closed-loop audit events into a single in-memory
// timeline with consistent fields regardless of source.
//
// NOTE on tamper-evidence: this is an in-memory log only — it is not
// cryptographically signed or hash-chained, and neither is Node's own
// UnifiedAuditTrail. The HMAC-signed, hash-chained tamper-evident audit
// trail (TODO 265/266/272) is a separate, server-side Next.js module
// (lib/audit-trail-signer.ts) operating directly on the LiveThreatEvent
// Postgres table. It has no SDK-side analog in any language, including
// Node, so this port does not and cannot provide tamper-evidence either.

// AuditSource is the source of an audit decision.
type AuditSource string

const (
	AuditSourceInternal AuditSource = "internal"
	AuditSourceExternal AuditSource = "external"
	AuditSourceHybrid   AuditSource = "hybrid"
)

const (
	auditDedupWindow       = 5 * time.Second
	auditDedupMapCap       = 10_000
	auditDefaultMaxEntries = 100_000
)

// UnifiedAuditEntry is one audit record, from any source.
type UnifiedAuditEntry struct {
	EventID      string
	Timestamp    time.Time
	Source       AuditSource
	Tier         int // 1, 2, 3 for internal; 0 for external
	Decision     string
	Score        float64
	Severity     string
	LatencyMs    float64
	IP           string
	Path         string
	Method       string
	MatchedRules []string
	UserID       *string
	AgentID      string
	SessionID    *string
	FallbackMode bool
	Meta         map[string]any
}

// UnifiedAuditStats is the result of UnifiedAuditTrail.Stats.
type UnifiedAuditStats struct {
	Total                int
	InternalDecisions    int
	ExternalDecisions    int
	HybridDecisions      int
	FallbackEvents       int
	TotalBlocks          int
	TotalAllows          int
	TotalRateLimits      int
	AvgInternalLatencyMs int
	AvgExternalLatencyMs int
}

// UnifiedAuditQuery filters UnifiedAuditTrail.Query. A nil/zero field is
// not applied.
type UnifiedAuditQuery struct {
	Source   AuditSource
	Decision string
	IP       string
	UserID   string
	AgentID  string
	MinScore *float64
	Since    *time.Time
	// Limit defaults to 100 when zero.
	Limit int
}

// UnifiedAuditConfig configures a UnifiedAuditTrail.
type UnifiedAuditConfig struct {
	// MaxEntries is the maximum number of entries to retain. Default: 100_000.
	MaxEntries int
	// OnEntry is invoked synchronously on each new audit entry, outside
	// the trail's internal lock. A panic in OnEntry is recovered so it
	// can never break Record, mirroring Node's try/catch around its
	// onEntry call.
	OnEntry func(UnifiedAuditEntry)
	Debug   bool
}

// UnifiedAuditTrail merges internal/external/hybrid closed-loop decisions
// into a single timeline. Mirrors the Node SDK's UnifiedAuditTrail
// (unified-audit.ts) feature-for-feature: bounded storage, the S27 dedup
// window for hybrid mode, aggregated stats, decision distribution,
// latency histogram, and JSON export. Safe for concurrent use.
type UnifiedAuditTrail struct {
	mu      sync.Mutex
	entries []UnifiedAuditEntry
	cfg     UnifiedAuditConfig

	recentEventIDs map[string]time.Time

	stats struct {
		internalDecisions, externalDecisions, hybridDecisions     int
		fallbackEvents, totalBlocks, totalAllows, totalRateLimits int
		internalLatencySum, externalLatencySum                    float64
	}
}

// NewUnifiedAuditTrail creates a UnifiedAuditTrail.
func NewUnifiedAuditTrail(cfg UnifiedAuditConfig) *UnifiedAuditTrail {
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = auditDefaultMaxEntries
	}
	return &UnifiedAuditTrail{
		cfg:            cfg,
		recentEventIDs: make(map[string]time.Time),
	}
}

// Record records an audit entry from any source. S27: the same EventID
// within the 5s dedup window is merged (external overrides internal), not
// duplicated.
func (t *UnifiedAuditTrail) Record(entry UnifiedAuditEntry) {
	t.mu.Lock()

	now := time.Now()
	if existing, ok := t.recentEventIDs[entry.EventID]; ok && now.Sub(existing) < auditDedupWindow {
		if entry.Source == AuditSourceExternal {
			for i, e := range t.entries {
				if e.EventID == entry.EventID && e.Source == AuditSourceInternal {
					merged := entry
					merged.Source = AuditSourceHybrid
					t.entries[i] = merged
					if t.cfg.Debug {
						log.Printf("[DF Audit] DEDUP: merged %s (external overrides internal)", entry.EventID)
					}
					break
				}
			}
		}
		t.mu.Unlock()
		return
	}

	t.recentEventIDs[entry.EventID] = now
	if len(t.recentEventIDs) > auditDedupMapCap {
		cutoff := now.Add(-auditDedupWindow)
		for id, ts := range t.recentEventIDs {
			if ts.Before(cutoff) {
				delete(t.recentEventIDs, id)
			}
		}
	}

	if len(t.entries) >= t.cfg.MaxEntries {
		t.entries = t.entries[int(float64(t.cfg.MaxEntries)*0.1):]
	}
	t.entries = append(t.entries, entry)
	t.updateStats(entry)

	debug := t.cfg.Debug
	onEntry := t.cfg.OnEntry
	t.mu.Unlock()

	if onEntry != nil {
		func() {
			defer func() { _ = recover() }() // callback errors must not break the audit trail
			onEntry(entry)
		}()
	}

	if debug {
		log.Printf("[DF Audit] %s:tier%d %s score=%v %s %s %s (%vms)",
			entry.Source, entry.Tier, entry.Decision, entry.Score, entry.IP, entry.Method, entry.Path, entry.LatencyMs)
	}
}

// Query returns audit entries matching the given filters, most recent
// last, capped at q.Limit (default 100).
func (t *UnifiedAuditTrail) Query(q UnifiedAuditQuery) []UnifiedAuditEntry {
	t.mu.Lock()
	result := make([]UnifiedAuditEntry, len(t.entries))
	copy(result, t.entries)
	t.mu.Unlock()

	if q.Source != "" {
		result = filterAuditEntries(result, func(e UnifiedAuditEntry) bool { return e.Source == q.Source })
	}
	if q.Decision != "" {
		result = filterAuditEntries(result, func(e UnifiedAuditEntry) bool { return e.Decision == q.Decision })
	}
	if q.IP != "" {
		result = filterAuditEntries(result, func(e UnifiedAuditEntry) bool { return e.IP == q.IP })
	}
	if q.UserID != "" {
		result = filterAuditEntries(result, func(e UnifiedAuditEntry) bool { return e.UserID != nil && *e.UserID == q.UserID })
	}
	if q.AgentID != "" {
		result = filterAuditEntries(result, func(e UnifiedAuditEntry) bool { return e.AgentID == q.AgentID })
	}
	if q.MinScore != nil {
		result = filterAuditEntries(result, func(e UnifiedAuditEntry) bool { return e.Score >= *q.MinScore })
	}
	if q.Since != nil {
		result = filterAuditEntries(result, func(e UnifiedAuditEntry) bool { return !e.Timestamp.Before(*q.Since) })
	}

	limit := q.Limit
	if limit == 0 {
		limit = 100
	}
	if len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

func filterAuditEntries(entries []UnifiedAuditEntry, keep func(UnifiedAuditEntry) bool) []UnifiedAuditEntry {
	out := entries[:0:0]
	for _, e := range entries {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

// Stats returns aggregated statistics.
func (t *UnifiedAuditTrail) Stats() UnifiedAuditStats {
	t.mu.Lock()
	defer t.mu.Unlock()

	avgInternal := 0
	if t.stats.internalDecisions > 0 {
		avgInternal = int(math.Round(t.stats.internalLatencySum / float64(t.stats.internalDecisions)))
	}
	avgExternal := 0
	if t.stats.externalDecisions > 0 {
		avgExternal = int(math.Round(t.stats.externalLatencySum / float64(t.stats.externalDecisions)))
	}

	return UnifiedAuditStats{
		Total:                len(t.entries),
		InternalDecisions:    t.stats.internalDecisions,
		ExternalDecisions:    t.stats.externalDecisions,
		HybridDecisions:      t.stats.hybridDecisions,
		FallbackEvents:       t.stats.fallbackEvents,
		TotalBlocks:          t.stats.totalBlocks,
		TotalAllows:          t.stats.totalAllows,
		TotalRateLimits:      t.stats.totalRateLimits,
		AvgInternalLatencyMs: avgInternal,
		AvgExternalLatencyMs: avgExternal,
	}
}

// DecisionDistribution returns source:decision counts, for dashboard
// visualization.
func (t *UnifiedAuditTrail) DecisionDistribution() map[string]int {
	t.mu.Lock()
	entries := make([]UnifiedAuditEntry, len(t.entries))
	copy(entries, t.entries)
	t.mu.Unlock()

	dist := make(map[string]int)
	for _, e := range entries {
		key := fmt.Sprintf("%s:%s", e.Source, e.Decision)
		dist[key]++
	}
	return dist
}

// LatencyHistogram is the result of UnifiedAuditTrail.LatencyHistogram.
type LatencyHistogram struct {
	Under1ms, Under5ms, Under50ms, Under200ms, Under1s, Over1s int
}

// LatencyHistogram returns latency histogram buckets.
func (t *UnifiedAuditTrail) LatencyHistogram() LatencyHistogram {
	t.mu.Lock()
	entries := make([]UnifiedAuditEntry, len(t.entries))
	copy(entries, t.entries)
	t.mu.Unlock()

	var hist LatencyHistogram
	for _, e := range entries {
		switch {
		case e.LatencyMs < 1:
			hist.Under1ms++
		case e.LatencyMs < 5:
			hist.Under5ms++
		case e.LatencyMs < 50:
			hist.Under50ms++
		case e.LatencyMs < 200:
			hist.Under200ms++
		case e.LatencyMs < 1000:
			hist.Under1s++
		default:
			hist.Over1s++
		}
	}
	return hist
}

// ExportJSON exports entries as JSON (for compliance/archival), optionally
// filtered to those at or after since.
func (t *UnifiedAuditTrail) ExportJSON(since *time.Time) ([]byte, error) {
	t.mu.Lock()
	entries := make([]UnifiedAuditEntry, len(t.entries))
	copy(entries, t.entries)
	t.mu.Unlock()

	if since != nil {
		entries = filterAuditEntries(entries, func(e UnifiedAuditEntry) bool { return !e.Timestamp.Before(*since) })
	}
	return json.MarshalIndent(entries, "", "  ")
}

// Reset clears the audit trail (for testing).
func (t *UnifiedAuditTrail) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = nil
	t.recentEventIDs = make(map[string]time.Time)
	t.stats = struct {
		internalDecisions, externalDecisions, hybridDecisions     int
		fallbackEvents, totalBlocks, totalAllows, totalRateLimits int
		internalLatencySum, externalLatencySum                    float64
	}{}
}

// updateStats must be called with t.mu held.
func (t *UnifiedAuditTrail) updateStats(entry UnifiedAuditEntry) {
	switch entry.Source {
	case AuditSourceInternal:
		t.stats.internalDecisions++
		t.stats.internalLatencySum += entry.LatencyMs
	case AuditSourceExternal:
		t.stats.externalDecisions++
		t.stats.externalLatencySum += entry.LatencyMs
	default:
		t.stats.hybridDecisions++
		if entry.Tier > 0 {
			t.stats.internalLatencySum += entry.LatencyMs
		} else {
			t.stats.externalLatencySum += entry.LatencyMs
		}
	}

	if entry.FallbackMode {
		t.stats.fallbackEvents++
	}

	switch entry.Decision {
	case "block":
		t.stats.totalBlocks++
	case "allow":
		t.stats.totalAllows++
	case "rate_limit":
		t.stats.totalRateLimits++
	}
}
