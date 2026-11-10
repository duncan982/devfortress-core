package devfortress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── TelemetryManager (CV-M2) ─────────────────────────────────────────────

// Defaults and timeouts for TelemetryManager, matching the Node SDK
// (telemetry.ts).
const (
	// DefaultHeartbeatInterval is how often a heartbeat is sent once Start
	// is called. CV-M2.
	DefaultHeartbeatInterval = 5 * time.Minute
	// HeartbeatTimeout bounds a single heartbeat HTTP attempt.
	HeartbeatTimeout = 5 * time.Second

	maxLatencySamples = 100
)

// TelemetrySnapshot is one heartbeat's payload. CLMode, Tier, and
// SDKVersion default to ModeExternal, TierStarter, and Version
// respectively when left as their zero value by a TelemetrySnapshotProvider
// (mirroring the Node SDK's `enriched.clMode ?? 'external'` etc. — these
// three fields are the only ones with a non-zero-looking default).
type TelemetrySnapshot struct {
	// EventCount is total events observed since the last heartbeat.
	EventCount int
	// BlockCount is total events blocked since the last heartbeat.
	BlockCount int
	// RateLimitCount is total events rate-limited since the last
	// heartbeat.
	RateLimitCount int
	// CLMode is the current closed-loop mode.
	CLMode CLMode
	// Tier is the subscription tier.
	Tier SubscriptionTier
	// SDKVersion is the SDK version string.
	SDKVersion string
	// ModelExpired is whether the ML model is expired.
	ModelExpired bool
	// LicenseDegraded is whether the license is degraded.
	LicenseDegraded bool
	// IntegrityHash is the anti-tampering integrity hash.
	IntegrityHash string
	// UptimeSeconds is seconds since SDK/TelemetryManager init.
	UptimeSeconds int64
	// P99LatencyMs is the sampled p99 observe latency, in milliseconds.
	P99LatencyMs float64
}

// TelemetrySnapshotProvider enriches a heartbeat with live SDK state
// (closed-loop mode, tier, integrity hash, ...) not tracked by
// TelemetryManager itself. A nil return, or a panicking provider, is
// treated as "no enrichment" — it never reaches the host application.
type TelemetrySnapshotProvider func() TelemetrySnapshot

// TelemetryDiagnostics is TelemetryManager's own-state snapshot, for
// diagnostics (as opposed to TelemetrySnapshot, which is what's actually
// sent to the platform).
type TelemetryDiagnostics struct {
	EventCount     int
	BlockCount     int
	RateLimitCount int
	UptimeSeconds  int64
}

// TelemetryConfig configures a TelemetryManager.
type TelemetryConfig struct {
	// APIKey authenticates heartbeat requests. Required.
	APIKey string
	// Endpoint is the platform base URL (no /api/sdk/... suffix).
	// Required.
	Endpoint string
	// HeartbeatInterval is how often a heartbeat is sent once Start is
	// called. Default: DefaultHeartbeatInterval (5 minutes).
	HeartbeatInterval time.Duration
	// Debug enables debug-level logging.
	Debug bool
	// Transport replaces the HTTP transport, e.g. with a recording
	// transport in tests. Defaults to NewHTTPTransport().
	Transport Transport
	// Logger receives debug-level delivery detail. Heartbeat delivery is
	// fire-and-forget by design (CV-M2: a dropped heartbeat just means
	// the platform dashboard shows "SDK offline" until the next one
	// succeeds), so failures are logged at debug level only, not warn.
	Logger Logger
}

// TelemetryManager sends anonymised usage telemetry to the platform on a
// fixed interval (CV-M2: a 5-minute heartbeat by default). No PII is
// transmitted — only aggregate counts and operational metadata.
//
// If the heartbeat stops, the platform dashboard shows: "SDK offline —
// upgrade to Hybrid for guaranteed visibility."
type TelemetryManager struct {
	endpoint          string
	heartbeatInterval time.Duration
	debug             bool
	signer            *Signer
	transport         Transport
	logger            Logger

	mu               sync.Mutex
	eventCount       int
	blockCount       int
	rateLimitCount   int
	latencies        []float64
	startedAt        time.Time
	snapshotProvider TelemetrySnapshotProvider
	started          bool

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewTelemetryManager returns a TelemetryManager for cfg. An empty APIKey
// or Endpoint is the only construction error.
func NewTelemetryManager(cfg TelemetryConfig) (*TelemetryManager, error) {
	signer, err := NewSigner(cfg.APIKey)
	if err != nil {
		return nil, err
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("devfortress: a platform endpoint is required")
	}

	interval := cfg.HeartbeatInterval
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	transport := cfg.Transport
	if transport == nil {
		transport = NewHTTPTransport()
	}

	return &TelemetryManager{
		endpoint:          strings.TrimRight(cfg.Endpoint, "/"),
		heartbeatInterval: interval,
		debug:             cfg.Debug,
		signer:            signer,
		transport:         transport,
		logger:            cfg.Logger,
		startedAt:         time.Now(),
		stopCh:            make(chan struct{}),
	}, nil
}

// Start begins sending periodic heartbeats: a first heartbeat after a
// short delay (so Start never blocks SDK init), then one every
// HeartbeatInterval, until Stop is called. provider may be nil. Calling
// Start more than once is a no-op.
func (t *TelemetryManager) Start(provider TelemetrySnapshotProvider) {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return
	}
	t.started = true
	t.snapshotProvider = provider
	t.startedAt = time.Now()
	t.mu.Unlock()

	t.doneCh = make(chan struct{})
	go t.run()

	t.log("info", fmt.Sprintf("Telemetry heartbeat started (interval: %.0fs)", t.heartbeatInterval.Seconds()))
}

func (t *TelemetryManager) run() {
	defer close(t.doneCh)

	initial := time.NewTimer(5 * time.Second)
	defer initial.Stop()
	select {
	case <-initial.C:
		t.sendHeartbeat()
	case <-t.stopCh:
		return
	}

	ticker := time.NewTicker(t.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.sendHeartbeat()
		case <-t.stopCh:
			return
		}
	}
}

// RecordEvent records one observed event.
func (t *TelemetryManager) RecordEvent() {
	t.mu.Lock()
	t.eventCount++
	t.mu.Unlock()
}

// RecordBlock records one blocked event.
func (t *TelemetryManager) RecordBlock() {
	t.mu.Lock()
	t.blockCount++
	t.mu.Unlock()
}

// RecordRateLimit records one rate-limited event.
func (t *TelemetryManager) RecordRateLimit() {
	t.mu.Lock()
	t.rateLimitCount++
	t.mu.Unlock()
}

// RecordLatency records one observe-latency sample (ms) for p99
// calculation, using reservoir sampling once maxLatencySamples (100) is
// reached.
func (t *TelemetryManager) RecordLatency(ms float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.latencies) >= maxLatencySamples {
		idx := rand.Intn(len(t.latencies))
		t.latencies[idx] = ms
	} else {
		t.latencies = append(t.latencies, ms)
	}
}

// GetState returns TelemetryManager's own counters, for diagnostics.
func (t *TelemetryManager) GetState() TelemetryDiagnostics {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TelemetryDiagnostics{
		EventCount:     t.eventCount,
		BlockCount:     t.blockCount,
		RateLimitCount: t.rateLimitCount,
		UptimeSeconds:  int64(time.Since(t.startedAt).Seconds()),
	}
}

// Stop stops sending heartbeats. Safe to call more than once, and safe to
// call even if Start was never called.
func (t *TelemetryManager) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopCh)
	})
	if t.doneCh != nil {
		<-t.doneCh
	}
}

// sendHeartbeat sends one heartbeat to the platform. Fire-and-forget:
// failures are logged at debug level, never panicked or surfaced to the
// caller — the background goroutine just tries again next interval.
func (t *TelemetryManager) sendHeartbeat() {
	enriched := t.callProvider()

	t.mu.Lock()
	snapshot := TelemetrySnapshot{
		EventCount:      t.eventCount,
		BlockCount:      t.blockCount,
		RateLimitCount:  t.rateLimitCount,
		CLMode:          enriched.CLMode,
		Tier:            enriched.Tier,
		SDKVersion:      enriched.SDKVersion,
		ModelExpired:    enriched.ModelExpired,
		LicenseDegraded: enriched.LicenseDegraded,
		IntegrityHash:   enriched.IntegrityHash,
		UptimeSeconds:   int64(time.Since(t.startedAt).Seconds()),
		P99LatencyMs:    computeP99(t.latencies),
	}
	t.mu.Unlock()

	if snapshot.CLMode == "" {
		snapshot.CLMode = ModeExternal
	}
	if snapshot.Tier == "" {
		snapshot.Tier = TierStarter
	}
	if snapshot.SDKVersion == "" {
		snapshot.SDKVersion = Version
	}

	body, err := json.Marshal(map[string]any{
		"timestamp":       time.Now().UnixMilli(),
		"eventCount":      snapshot.EventCount,
		"blockCount":      snapshot.BlockCount,
		"rateLimitCount":  snapshot.RateLimitCount,
		"clMode":          string(snapshot.CLMode),
		"tier":            string(snapshot.Tier),
		"sdkVersion":      snapshot.SDKVersion,
		"modelExpired":    snapshot.ModelExpired,
		"licenseDegraded": snapshot.LicenseDegraded,
		"integrityHash":   snapshot.IntegrityHash,
		"uptimeSeconds":   snapshot.UptimeSeconds,
		"p99LatencyMs":    snapshot.P99LatencyMs,
	})
	if err != nil {
		t.log("debug", fmt.Sprintf("Heartbeat failed: %v", err))
		return
	}

	url := t.endpoint + "/api/sdk/heartbeat"
	headers, err := t.sign(url, body)
	if err != nil {
		t.log("debug", fmt.Sprintf("Heartbeat failed: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), HeartbeatTimeout)
	defer cancel()
	if _, err := t.safeSend(ctx, url, headers, body); err != nil {
		t.log("debug", fmt.Sprintf("Heartbeat failed: %v", err))
		return
	}

	t.log("debug", fmt.Sprintf(
		"Heartbeat sent: events=%d, blocks=%d, uptime=%ds",
		snapshot.EventCount, snapshot.BlockCount, snapshot.UptimeSeconds,
	))

	t.mu.Lock()
	t.eventCount = 0
	t.blockCount = 0
	t.rateLimitCount = 0
	t.latencies = nil
	t.mu.Unlock()
}

// callProvider invokes the snapshot provider, recovering a panic (and
// treating it as "no enrichment") so a host-supplied provider can never
// reach into the background goroutine and crash the process.
func (t *TelemetryManager) callProvider() (snapshot TelemetrySnapshot) {
	t.mu.Lock()
	provider := t.snapshotProvider
	t.mu.Unlock()
	if provider == nil {
		return TelemetrySnapshot{}
	}
	defer func() { _ = recover() }()
	return provider()
}

func computeP99(latencies []float64) float64 {
	if len(latencies) == 0 {
		return 0
	}
	sorted := append([]float64(nil), latencies...)
	sort.Float64s(sorted)
	idx := int(float64(len(sorted)) * 0.99)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func (t *TelemetryManager) sign(url string, body []byte) (map[string]string, error) {
	headers, err := t.signer.Sign("POST", RequestTargetFromURL(url), string(body), "", "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		out[k] = v
	}
	out["Content-Type"] = "application/json"
	return out, nil
}

func (t *TelemetryManager) safeSend(ctx context.Context, url string, headers map[string]string, body []byte) (resp *TransportResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp, err = nil, fmt.Errorf("transport panicked: %v", r)
		}
	}()
	return t.transport.Send(ctx, "POST", url, headers, body, 0)
}

func (t *TelemetryManager) log(level, message string) {
	if t.logger == nil {
		return
	}
	if level == "debug" && !t.debug {
		return
	}
	defer func() { _ = recover() }()
	t.logger.Log(level, "[DevFortress:Telemetry] "+message, nil)
}

// ── TelemetryRollupBuffer (Anomaly-Gated Metering) ──────────────────────
//
// Option B (2026-08-27): clean/unflagged traffic no longer gets a full,
// billed event row per request. Instead, this buffer accumulates
// lightweight per-alias/IP-per-hour counters in memory (request count,
// unique endpoints seen, error count, latency sum) and flushes them as a
// small number of upsert-increment rows to /api/events/telemetry-rollup
// on a short interval — not per request. This is what feeds population-
// level baseline needs without counting toward the customer's billed
// event quota.

// MaxEndpointsTrackedPerBucket bounds per-bucket endpoint tracking —
// uniqueEndpoints is an approximation (this is non-billing, best-effort
// aggregate telemetry, not an exact count).
const MaxEndpointsTrackedPerBucket = 50

// Defaults for TelemetryRollupBuffer.
const (
	// DefaultRollupFlushInterval matches TelemetryManager's
	// DefaultHeartbeatInterval: this is aggregate, non-billing telemetry,
	// not real-time-critical, so a wider batching window means fewer
	// platform requests (aligned with Option B's goal) and keeps this
	// interval consistent with the SDK's other background timer.
	DefaultRollupFlushInterval = 5 * time.Minute
	// DefaultMaxBufferedKeys bounds total buffered (aliasOrIpKey,
	// periodKey) buckets before a forced flush.
	DefaultMaxBufferedKeys = 500
)

// RollupContributionInput is one clean (non-flagged) request's
// contribution to the rollup buffer.
type RollupContributionInput struct {
	// AliasOrIPKey is the IP (or, in future, resolved alias) this
	// contribution is keyed on.
	AliasOrIPKey string
	// Endpoint is the request path/endpoint observed.
	Endpoint string
	// IsError is whether this request was an error.
	IsError bool
	// LatencyMs is the response latency, in milliseconds.
	LatencyMs float64
}

// rollupBucketKey is the composite (aliasOrIpKey, periodKey) bucket key.
// Go idiom: a comparable struct used directly as a map key, rather than
// the Node SDK's NUL-byte string-concatenation trick
// (`${aliasOrIpKey}\x00${periodKey}`) — same collision-free bucketing
// semantics (a NUL byte can't appear in either component in Go either,
// but a struct key sidesteps the question entirely).
type rollupBucketKey struct {
	aliasOrIPKey string
	periodKey    string
}

// rollupBucket is one bucket's accumulated counters.
type rollupBucket struct {
	aliasOrIPKey string
	periodKey    string
	requestCount int
	endpoints    map[string]struct{}
	errorCount   int
	latencySumMs float64
	windowStart  int64
	windowEnd    int64
}

// HourlyPeriodKey returns the hour-bucket period key for t (converted to
// UTC), e.g. "2026-08-27T14" — matches AliasTelemetryRollup.periodKey.
func HourlyPeriodKey(t time.Time) string {
	return t.UTC().Format("2006-01-02T15")
}

// TelemetryRollupBufferConfig configures a TelemetryRollupBuffer.
type TelemetryRollupBufferConfig struct {
	// APIKey authenticates flush requests. Required.
	APIKey string
	// Endpoint is the platform base URL (no /api/events/... suffix) —
	// flushes POST to {Endpoint}/api/events/telemetry-rollup. Required.
	Endpoint string
	// FlushInterval is how often buffered buckets are flushed. Default:
	// DefaultRollupFlushInterval (5 minutes).
	FlushInterval time.Duration
	// MaxBufferedKeys bounds total buffered buckets before Add forces an
	// early flush. Default: DefaultMaxBufferedKeys (500).
	MaxBufferedKeys int
	// Debug enables logging of flush failures (best-effort — a failed
	// flush is otherwise dropped silently, since this is non-billing
	// aggregate telemetry, unlike the full event relay path).
	Debug bool
	// Transport replaces the HTTP transport, e.g. with a recording
	// transport in tests. Defaults to NewHTTPTransport().
	Transport Transport
	// Logger receives flush-failure detail when Debug is set.
	Logger Logger
}

// TelemetryRollupBuffer accumulates per-(aliasOrIpKey, hour) counters in
// memory and flushes them to the platform in one batch request per
// FlushInterval, rather than one request per contribution.
type TelemetryRollupBuffer struct {
	endpoint        string
	flushInterval   time.Duration
	maxBufferedKeys int
	debug           bool
	signer          *Signer
	transport       Transport
	logger          Logger

	mu      sync.Mutex
	buckets map[rollupBucketKey]*rollupBucket
	started bool

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewTelemetryRollupBuffer returns a TelemetryRollupBuffer for cfg. An
// empty APIKey or Endpoint is the only construction error.
func NewTelemetryRollupBuffer(cfg TelemetryRollupBufferConfig) (*TelemetryRollupBuffer, error) {
	signer, err := NewSigner(cfg.APIKey)
	if err != nil {
		return nil, err
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("devfortress: a platform endpoint is required")
	}

	flushInterval := cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = DefaultRollupFlushInterval
	}
	maxKeys := cfg.MaxBufferedKeys
	if maxKeys <= 0 {
		maxKeys = DefaultMaxBufferedKeys
	}
	transport := cfg.Transport
	if transport == nil {
		transport = NewHTTPTransport()
	}

	return &TelemetryRollupBuffer{
		endpoint:        strings.TrimRight(cfg.Endpoint, "/"),
		flushInterval:   flushInterval,
		maxBufferedKeys: maxKeys,
		debug:           cfg.Debug,
		signer:          signer,
		transport:       transport,
		logger:          cfg.Logger,
		buckets:         make(map[rollupBucketKey]*rollupBucket),
		stopCh:          make(chan struct{}),
	}, nil
}

// Start starts the periodic flush timer. Safe to call multiple times
// (a no-op if already started).
func (b *TelemetryRollupBuffer) Start() {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return
	}
	b.started = true
	b.mu.Unlock()

	b.doneCh = make(chan struct{})
	go b.run()
}

func (b *TelemetryRollupBuffer) run() {
	defer close(b.doneCh)
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.Flush(context.Background())
		case <-b.stopCh:
			return
		}
	}
}

// Add buffers one clean (non-flagged) request's contribution.
// Synchronous, no network call — actual delivery happens on the next
// Flush, except when the buffer is full (see MaxBufferedKeys), in which
// case Add forces an immediate Flush and drops this one contribution.
func (b *TelemetryRollupBuffer) Add(input RollupContributionInput) {
	periodKey := HourlyPeriodKey(time.Now())
	key := rollupBucketKey{aliasOrIPKey: input.AliasOrIPKey, periodKey: periodKey}
	now := time.Now().UnixMilli()

	b.mu.Lock()
	bucket, ok := b.buckets[key]
	if !ok && len(b.buckets) >= b.maxBufferedKeys {
		b.mu.Unlock()
		// Bound total buffered keys so a burst of unique IPs can't grow
		// memory unbounded — force an early flush and drop this one
		// contribution. Acceptable: this is approximate, non-billing
		// aggregate telemetry.
		b.Flush(context.Background())
		return
	}
	if !ok {
		bucket = &rollupBucket{
			aliasOrIPKey: input.AliasOrIPKey,
			periodKey:    periodKey,
			endpoints:    make(map[string]struct{}),
			windowStart:  now,
			windowEnd:    now,
		}
		b.buckets[key] = bucket
	}

	bucket.requestCount++
	if len(bucket.endpoints) < MaxEndpointsTrackedPerBucket {
		bucket.endpoints[input.Endpoint] = struct{}{}
	}
	if input.IsError {
		bucket.errorCount++
	}
	bucket.latencySumMs += input.LatencyMs
	bucket.windowEnd = now
	b.mu.Unlock()
}

// Flush sends all buffered buckets to the platform in one batch request.
// Best-effort: a failed flush is dropped (logged only when Debug is set)
// rather than retried — unlike the full event relay path, aggregate
// telemetry is not billing-relevant.
func (b *TelemetryRollupBuffer) Flush(ctx context.Context) {
	b.mu.Lock()
	if len(b.buckets) == 0 {
		b.mu.Unlock()
		return
	}
	contributions := make([]map[string]any, 0, len(b.buckets))
	for _, bucket := range b.buckets {
		contributions = append(contributions, map[string]any{
			"aliasOrIpKey":           bucket.aliasOrIPKey,
			"periodKey":              bucket.periodKey,
			"requestCount":           bucket.requestCount,
			"uniqueEndpointsInBatch": len(bucket.endpoints),
			"errorCount":             bucket.errorCount,
			"latencySumMs":           bucket.latencySumMs,
			"windowStart":            bucket.windowStart,
			"windowEnd":              bucket.windowEnd,
		})
	}
	b.buckets = make(map[rollupBucketKey]*rollupBucket)
	b.mu.Unlock()

	body, err := json.Marshal(map[string]any{"contributions": contributions})
	if err != nil {
		b.log(fmt.Sprintf("telemetry rollup flush failed: %v", err))
		return
	}

	url := b.endpoint + "/api/events/telemetry-rollup"
	headers, err := b.sign(url, body)
	if err != nil {
		b.log(fmt.Sprintf("telemetry rollup flush failed: %v", err))
		return
	}

	if _, err := b.safeSend(ctx, url, headers, body); err != nil {
		b.log(fmt.Sprintf("telemetry rollup flush failed: %v", err))
	}
}

// Stop stops the flush timer and drops any unflushed buckets. Safe to
// call more than once, and safe to call even if Start was never called.
func (b *TelemetryRollupBuffer) Stop() {
	b.stopOnce.Do(func() {
		close(b.stopCh)
	})
	if b.doneCh != nil {
		<-b.doneCh
	}
	b.mu.Lock()
	b.buckets = make(map[rollupBucketKey]*rollupBucket)
	b.mu.Unlock()
}

func (b *TelemetryRollupBuffer) sign(url string, body []byte) (map[string]string, error) {
	headers, err := b.signer.Sign("POST", RequestTargetFromURL(url), string(body), "", "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		out[k] = v
	}
	out["Content-Type"] = "application/json"
	return out, nil
}

func (b *TelemetryRollupBuffer) safeSend(ctx context.Context, url string, headers map[string]string, body []byte) (resp *TransportResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp, err = nil, fmt.Errorf("transport panicked: %v", r)
		}
	}()
	return b.transport.Send(ctx, "POST", url, headers, body, 0)
}

func (b *TelemetryRollupBuffer) log(message string) {
	if !b.debug || b.logger == nil {
		return
	}
	defer func() { _ = recover() }()
	b.logger.Log("debug", "[DevFortress] "+message, nil)
}
