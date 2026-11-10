package devfortress

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func makeAuditEntry(mutate func(*UnifiedAuditEntry)) UnifiedAuditEntry {
	e := UnifiedAuditEntry{
		EventID:      fmt.Sprintf("evt_%d", rand.Int63()),
		Timestamp:    time.Now(),
		Source:       AuditSourceInternal,
		Tier:         1,
		Decision:     "allow",
		Score:        10,
		Severity:     "low",
		LatencyMs:    0.5,
		IP:           "192.168.1.1",
		Path:         "/api/test",
		Method:       "GET",
		MatchedRules: []string{},
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

func TestUnifiedAuditTrail_RecordAndQuery(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.IP = "10.0.0.1" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.IP = "10.0.0.2" }))

	if got := len(audit.Query(UnifiedAuditQuery{})); got != 2 {
		t.Fatalf("expected 2 entries, got %d", got)
	}
}

func TestUnifiedAuditTrail_FilterBySource(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source = AuditSourceInternal }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source = AuditSourceExternal }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source = AuditSourceHybrid }))

	if got := len(audit.Query(UnifiedAuditQuery{Source: AuditSourceInternal})); got != 1 {
		t.Fatalf("expected 1 internal entry, got %d", got)
	}
	if got := len(audit.Query(UnifiedAuditQuery{Source: AuditSourceExternal})); got != 1 {
		t.Fatalf("expected 1 external entry, got %d", got)
	}
	if got := len(audit.Query(UnifiedAuditQuery{Source: AuditSourceHybrid})); got != 1 {
		t.Fatalf("expected 1 hybrid entry, got %d", got)
	}
}

func TestUnifiedAuditTrail_FilterByDecision(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Decision = "allow" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Decision = "block" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Decision = "rate_limit" }))

	if got := len(audit.Query(UnifiedAuditQuery{Decision: "block"})); got != 1 {
		t.Fatalf("expected 1 block entry, got %d", got)
	}
}

func TestUnifiedAuditTrail_FilterByMinScore(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Score = 20 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Score = 60 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Score = 90 }))

	min := 50.0
	if got := len(audit.Query(UnifiedAuditQuery{MinScore: &min})); got != 2 {
		t.Fatalf("expected 2 entries with score >= 50, got %d", got)
	}
}

func TestUnifiedAuditTrail_FilterBySince(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	now := time.Now()
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Timestamp = now.Add(-10 * time.Second) }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Timestamp = now.Add(-5 * time.Second) }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Timestamp = now }))

	since := now.Add(-7 * time.Second)
	if got := len(audit.Query(UnifiedAuditQuery{Since: &since})); got != 2 {
		t.Fatalf("expected 2 entries since -7s, got %d", got)
	}
}

func TestUnifiedAuditTrail_LimitResults(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	for i := 0; i < 50; i++ {
		audit.Record(makeAuditEntry(nil))
	}
	if got := len(audit.Query(UnifiedAuditQuery{Limit: 10})); got != 10 {
		t.Fatalf("expected 10 entries with limit, got %d", got)
	}
}

func TestUnifiedAuditTrail_CombineFilters(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) {
		e.Source, e.Decision, e.Score = AuditSourceInternal, "block", 85
	}))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) {
		e.Source, e.Decision, e.Score = AuditSourceInternal, "allow", 10
	}))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) {
		e.Source, e.Decision, e.Score = AuditSourceExternal, "block", 90
	}))

	min := 80.0
	results := audit.Query(UnifiedAuditQuery{Source: AuditSourceInternal, Decision: "block", MinScore: &min})
	if len(results) != 1 || results[0].Score != 85 {
		t.Fatalf("expected single combined-filter match with score 85, got %+v", results)
	}
}

func TestUnifiedAuditTrail_Stats(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source = AuditSourceInternal }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source = AuditSourceInternal }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source = AuditSourceExternal }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source = AuditSourceHybrid }))

	stats := audit.Stats()
	if stats.Total != 4 || stats.InternalDecisions != 2 || stats.ExternalDecisions != 1 || stats.HybridDecisions != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestUnifiedAuditTrail_StatsCountsDecisions(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Decision = "block" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Decision = "allow" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Decision = "allow" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Decision = "rate_limit" }))

	stats := audit.Stats()
	if stats.TotalBlocks != 1 || stats.TotalAllows != 2 || stats.TotalRateLimits != 1 {
		t.Fatalf("unexpected decision counts: %+v", stats)
	}
}

func TestUnifiedAuditTrail_AverageLatencies(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source, e.LatencyMs = AuditSourceInternal, 0.5 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source, e.LatencyMs = AuditSourceInternal, 1.5 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source, e.LatencyMs = AuditSourceExternal, 100 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source, e.LatencyMs = AuditSourceExternal, 200 }))

	stats := audit.Stats()
	if stats.AvgInternalLatencyMs != 1 {
		t.Fatalf("expected avg internal latency 1, got %d", stats.AvgInternalLatencyMs)
	}
	if stats.AvgExternalLatencyMs != 150 {
		t.Fatalf("expected avg external latency 150, got %d", stats.AvgExternalLatencyMs)
	}
}

func TestUnifiedAuditTrail_DecisionDistribution(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source, e.Decision = AuditSourceInternal, "allow" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source, e.Decision = AuditSourceInternal, "allow" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source, e.Decision = AuditSourceInternal, "block" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Source, e.Decision = AuditSourceExternal, "allow" }))

	dist := audit.DecisionDistribution()
	if dist["internal:allow"] != 2 || dist["internal:block"] != 1 || dist["external:allow"] != 1 {
		t.Fatalf("unexpected distribution: %+v", dist)
	}
}

func TestUnifiedAuditTrail_LatencyHistogram(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.LatencyMs = 0.3 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.LatencyMs = 2 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.LatencyMs = 30 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.LatencyMs = 100 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.LatencyMs = 500 }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.LatencyMs = 2000 }))

	hist := audit.LatencyHistogram()
	want := LatencyHistogram{Under1ms: 1, Under5ms: 1, Under50ms: 1, Under200ms: 1, Under1s: 1, Over1s: 1}
	if hist != want {
		t.Fatalf("unexpected histogram: %+v, want %+v", hist, want)
	}
}

func TestUnifiedAuditTrail_ExportJSON(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.IP = "1.1.1.1" }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.IP = "2.2.2.2" }))

	raw, err := audit.ExportJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed []UnifiedAuditEntry
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("exported JSON did not parse: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 exported entries, got %d", len(parsed))
	}
}

func TestUnifiedAuditTrail_ExportJSONSince(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	now := time.Now()
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Timestamp = now.Add(-10 * time.Second) }))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.Timestamp = now }))

	since := now.Add(-5 * time.Second)
	raw, err := audit.ExportJSON(&since)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed []UnifiedAuditEntry
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("exported JSON did not parse: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 exported entry since cutoff, got %d", len(parsed))
	}
}

func TestUnifiedAuditTrail_BoundedStorageEvictsOldest10Percent(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{MaxEntries: 100})
	for i := 0; i < 110; i++ {
		audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) { e.EventID = fmt.Sprintf("evt_%d", i) }))
	}

	stats := audit.Stats()
	if stats.Total > 110 || stats.Total <= 90 {
		t.Fatalf("expected bounded total between 90 and 110, got %d", stats.Total)
	}
}

func TestUnifiedAuditTrail_Reset(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(nil))
	audit.Record(makeAuditEntry(nil))
	if audit.Stats().Total != 2 {
		t.Fatalf("expected 2 entries before reset")
	}

	audit.Reset()
	stats := audit.Stats()
	if stats.Total != 0 || stats.InternalDecisions != 0 {
		t.Fatalf("expected empty stats after reset, got %+v", stats)
	}
}

func TestUnifiedAuditTrail_OnEntryCallback(t *testing.T) {
	var received []UnifiedAuditEntry
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{
		OnEntry: func(e UnifiedAuditEntry) { received = append(received, e) },
	})
	audit.Record(makeAuditEntry(nil))
	audit.Record(makeAuditEntry(nil))

	if len(received) != 2 {
		t.Fatalf("expected callback fired twice, got %d", len(received))
	}
}

func TestUnifiedAuditTrail_OnEntrySurvivesPanic(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{
		OnEntry: func(UnifiedAuditEntry) { panic("callback error") },
	})

	audit.Record(makeAuditEntry(nil)) // must not panic out of Record
	if audit.Stats().Total != 1 {
		t.Fatalf("expected entry still recorded despite callback panic")
	}
}

func TestUnifiedAuditTrail_DedupMergesExternalOverInternal(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) {
		e.EventID, e.Source, e.Decision = "evt_dup", AuditSourceInternal, "allow"
	}))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) {
		e.EventID, e.Source, e.Decision = "evt_dup", AuditSourceExternal, "block"
	}))

	results := audit.Query(UnifiedAuditQuery{})
	if len(results) != 1 {
		t.Fatalf("expected dedup to merge into 1 entry, got %d", len(results))
	}
	if results[0].Source != AuditSourceHybrid || results[0].Decision != "block" {
		t.Fatalf("expected merged hybrid/block entry, got %+v", results[0])
	}
}

func TestUnifiedAuditTrail_DedupSkipsDuplicateInternal(t *testing.T) {
	audit := NewUnifiedAuditTrail(UnifiedAuditConfig{})
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) {
		e.EventID, e.Source, e.Decision = "evt_dup2", AuditSourceInternal, "allow"
	}))
	audit.Record(makeAuditEntry(func(e *UnifiedAuditEntry) {
		e.EventID, e.Source, e.Decision = "evt_dup2", AuditSourceInternal, "block"
	}))

	results := audit.Query(UnifiedAuditQuery{})
	if len(results) != 1 || results[0].Decision != "allow" {
		t.Fatalf("expected the first internal entry to survive unmerged, got %+v", results)
	}
}
