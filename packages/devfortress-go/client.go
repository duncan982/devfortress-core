package devfortress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// Version is this SDK's version.
const Version = "0.1.0"

// Defaults, matching the Node, Python and PHP SDKs.
const (
	DefaultEndpoint  = "https://www.devfortress.net/api/events/ingest"
	DefaultTimeout   = 15 * time.Second
	DefaultRetries   = 3
	DefaultBatchSize = 25
	// MaxServerBatch is the largest number of events the platform accepts
	// in one ingest request; Flush splits the queue into chunks this size.
	MaxServerBatch = 100
)

// Client is a DevFortress event client (external mode).
//
// Events are queued in memory (TrackEvent, TrackEvents) and delivered in
// batches ({"events": [...]}, server maximum MaxServerBatch) by Flush. Every
// request is signed with the request signature contract (see Signer): the
// API key never goes on the wire, only a key ID does.
//
// Retry: up to Retries attempts, exponential backoff, only on 5xx responses
// and network errors. 3xx and 4xx responses are never retried. Every attempt
// is signed again with a fresh nonce and timestamp.
//
// Delivery never panics or returns an error into the host application: a
// failed delivery comes back as a DeliveryResult and is logged. Only a
// missing API key fails construction. The queue is safe for concurrent use.
type Client struct {
	signer        *Signer
	endpoint      string
	requestTarget string
	timeout       time.Duration
	retries       int
	batchSize     int
	backoffBase   time.Duration
	defaults      map[string]any
	privacy       string
	logger        Logger
	transport     Transport
	sleeper       func(time.Duration)

	mu    sync.Mutex
	queue []Event

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}

	// ── Closed-loop mode (TODO 407) ──────────────────────────────────────
	// Mirrors Node's DevFortressCore and the Python port's DevFortressClient:
	// internal/hybrid mode gets its own InternalClosedLoopEngine instance;
	// hybrid additionally gets a PlatformCircuitBreaker guarding the
	// external-enrichment leg. Default mode is "external" — no behavior
	// change for existing callers that don't pass WithMode.
	mode           CLMode
	internalEngine *InternalClosedLoopEngine
	circuitBreaker *PlatformCircuitBreaker
}

// Option configures a Client. See With* functions.
type Option func(*clientConfig)

type clientConfig struct {
	timeout       time.Duration
	retries       int
	batchSize     int
	backoffBase   time.Duration
	defaults      map[string]any
	privacy       string
	logger        Logger
	transport     Transport
	sleeper       func(time.Duration)
	flushInterval time.Duration

	mode                           CLMode
	internalCLConfig               *InternalCLConfig
	circuitBreakerFailureThreshold int
	circuitBreakerRecoveryTime     time.Duration
}

// WithTimeout sets the per-attempt HTTP timeout (default 15s).
func WithTimeout(d time.Duration) Option { return func(c *clientConfig) { c.timeout = d } }

// WithRetries sets the maximum delivery attempts per batch (default 3).
func WithRetries(n int) Option { return func(c *clientConfig) { c.retries = n } }

// WithBatchSize sets how many queued events trigger an automatic flush
// (default 25).
func WithBatchSize(n int) Option { return func(c *clientConfig) { c.batchSize = n } }

// WithBackoffBase sets the base of the exponential retry backoff (default
// 1s: 1s, 2s, 4s, ...).
func WithBackoffBase(d time.Duration) Option { return func(c *clientConfig) { c.backoffBase = d } }

// WithDefaults sets fields merged under every queued event (appId,
// environment, ...).
func WithDefaults(defaults map[string]any) Option {
	return func(c *clientConfig) { c.defaults = defaults }
}

// WithPrivacy sets "standard" (default) or "strict" (no user agents,
// 16-hex-character hashed IPs).
func WithPrivacy(privacy string) Option { return func(c *clientConfig) { c.privacy = privacy } }

// WithLogger sets the logger used for delivery failures. Nil (the default)
// disables logging.
func WithLogger(logger Logger) Option { return func(c *clientConfig) { c.logger = logger } }

// WithTransport replaces the HTTP transport, e.g. with a recording
// transport in tests.
func WithTransport(transport Transport) Option {
	return func(c *clientConfig) { c.transport = transport }
}

// WithSleeper replaces the retry backoff sleep, e.g. to make tests
// deterministic.
func WithSleeper(sleeper func(time.Duration)) Option {
	return func(c *clientConfig) { c.sleeper = sleeper }
}

// WithFlushInterval starts a background goroutine that flushes the queue on
// this interval, stopped by Close. Zero (the default) disables it; callers
// then flush explicitly (Flush, Close, or the batch-size auto-flush).
func WithFlushInterval(d time.Duration) Option {
	return func(c *clientConfig) { c.flushInterval = d }
}

// WithMode sets the closed-loop delivery mode: ModeExternal (the default,
// no behavior change for existing callers), ModeInternal, or ModeHybrid.
// Internal and hybrid construct this client's own InternalClosedLoopEngine
// (see Observe/IsBlocked); hybrid additionally constructs a
// PlatformCircuitBreaker guarding the external-enrichment leg.
func WithMode(mode CLMode) Option {
	return func(c *clientConfig) { c.mode = mode }
}

// WithInternalCLConfig supplies the InternalCLConfig used to construct this
// client's InternalClosedLoopEngine when mode is internal or hybrid.
// Ignored in external mode. When mode is hybrid and cfg.OnRelay is nil,
// the client wires its own relay (see Observe) as OnRelay, same as the
// Python port's default wiring.
func WithInternalCLConfig(cfg InternalCLConfig) Option {
	return func(c *clientConfig) { c.internalCLConfig = &cfg }
}

// WithCircuitBreaker sets the PlatformCircuitBreaker's failure threshold
// and recovery time, used only in hybrid mode. Zero values use
// PlatformCircuitBreaker's own defaults (3 failures, 1 minute).
func WithCircuitBreaker(failureThreshold int, recoveryTime time.Duration) Option {
	return func(c *clientConfig) {
		c.circuitBreakerFailureThreshold = failureThreshold
		c.circuitBreakerRecoveryTime = recoveryTime
	}
}

// NewClient returns a Client for apiKey, delivering to endpoint (an empty
// string uses DefaultEndpoint). An empty apiKey is the only construction
// error.
func NewClient(apiKey, endpoint string, opts ...Option) (*Client, error) {
	signer, err := NewSigner(apiKey)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	cfg := clientConfig{
		timeout:     DefaultTimeout,
		retries:     DefaultRetries,
		batchSize:   DefaultBatchSize,
		backoffBase: time.Second,
		privacy:     "standard",
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.retries < 1 {
		cfg.retries = 1
	}
	if cfg.batchSize < 1 {
		cfg.batchSize = 1
	}
	transport := cfg.transport
	if transport == nil {
		transport = NewHTTPTransport()
	}
	sleeper := cfg.sleeper
	if sleeper == nil {
		sleeper = func(d time.Duration) {
			if d > 0 {
				time.Sleep(d)
			}
		}
	}

	mode := cfg.mode
	if mode == "" {
		mode = ModeExternal
	}

	c := &Client{
		signer:        signer,
		endpoint:      endpoint,
		requestTarget: RequestTargetFromURL(endpoint),
		timeout:       cfg.timeout,
		retries:       cfg.retries,
		batchSize:     cfg.batchSize,
		backoffBase:   cfg.backoffBase,
		defaults:      cfg.defaults,
		privacy:       cfg.privacy,
		logger:        cfg.logger,
		transport:     transport,
		sleeper:       sleeper,
		stopCh:        make(chan struct{}),
		mode:          mode,
	}

	if cfg.flushInterval > 0 {
		c.doneCh = make(chan struct{})
		go c.backgroundFlush(cfg.flushInterval)
	}

	// ── Mode / internal closed-loop engine ──────────────────────────────
	// Mirrors Node's DevFortressCore and the Python port: internal/hybrid
	// mode gets its own InternalClosedLoopEngine; hybrid additionally gets
	// a PlatformCircuitBreaker guarding the external-enrichment leg.
	if mode == ModeInternal || mode == ModeHybrid {
		var iclConfig InternalCLConfig
		if cfg.internalCLConfig != nil {
			iclConfig = *cfg.internalCLConfig
		}
		iclConfig.EnableExternalRelay = mode == ModeHybrid
		if iclConfig.OnRelay == nil && mode == ModeHybrid {
			iclConfig.OnRelay = c.relayInternalDecisionToPlatform
		}
		c.internalEngine = NewInternalClosedLoopEngine(iclConfig)
	}
	if mode == ModeHybrid {
		c.circuitBreaker = NewPlatformCircuitBreaker(CircuitBreakerConfig{
			FailureThreshold: cfg.circuitBreakerFailureThreshold,
			RecoveryTime:     cfg.circuitBreakerRecoveryTime,
		})
	}

	return c, nil
}

// TrackEvent queues one event. The queue is sent (synchronously, like
// Flush) once it reaches the batch size; it is also sent when Flush is
// called, or at Close. A caller that must not block on delivery — such as
// Middleware — calls TrackEvent from its own goroutine.
func (c *Client) TrackEvent(ctx context.Context, event Event) {
	c.enqueue(ctx, []Event{event})
}

// TrackEvents queues several events.
func (c *Client) TrackEvents(ctx context.Context, events []Event) {
	c.enqueue(ctx, events)
}

// Flush sends everything queued, in chunks of at most MaxServerBatch
// events, and returns one DeliveryResult per chunk. Flush never panics or
// returns a Go error; failures are reported through the returned results.
func (c *Client) Flush(ctx context.Context) []DeliveryResult {
	c.mu.Lock()
	events := c.queue
	c.queue = nil
	c.mu.Unlock()

	if len(events) == 0 {
		return nil
	}

	var results []DeliveryResult
	for i := 0; i < len(events); i += MaxServerBatch {
		end := i + MaxServerBatch
		if end > len(events) {
			end = len(events)
		}
		chunk := events[i:end]
		results = append(results, c.post(ctx, map[string]any{"events": chunk}))
	}
	return results
}

// PendingEvents is the number of events waiting to be flushed.
func (c *Client) PendingEvents() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queue)
}

// TestConnection reports whether the platform accepts a signed test event
// with this key. It never panics or returns a Go error; an unreachable
// platform or a rejected key both report false.
func (c *Client) TestConnection(ctx context.Context) bool {
	event := c.prepare(Event{
		"eventType":         "custom",
		"ip":                "127.0.0.1",
		"method":            "GET",
		"path":              "/__devfortress/test",
		"severity":          "LOW",
		"authPhase":         "pre_auth",
		"actionTaken":       "monitored",
		"responseLatencyMs": 0,
		"clMode":            "external",
		"metadata":          map[string]any{"test": true, "sdk": "go"},
	})
	return c.post(ctx, event).OK
}

// Close stops the background flush goroutine (if any) and flushes whatever
// is still queued. It is safe to call more than once.
func (c *Client) Close(ctx context.Context) {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	if c.doneCh != nil {
		<-c.doneCh
	}
	c.Flush(ctx)
}

// ── Internal / hybrid closed-loop mode (TODO 407) ───────────────────────
// Mirrors Node's DevFortressCore.observeInternal()/observeHybrid()/
// isIPBlocked() and the Python port's observe()/is_blocked(): a
// pre-response gate the caller invokes (typically from middleware) before
// the request reaches the application. Mode is set at construction time
// (WithMode); external mode has no Observe behavior here — external-mode
// reporting stays on the existing after-response Observe/ObserveAndFlush
// path (middleware.go), unchanged.

// Mode returns this client's closed-loop delivery mode.
func (c *Client) Mode() CLMode { return c.mode }

// InternalCLObserveResult is Observe's non-nil return value: the request
// should be blocked/rate-limited/challenged/quarantined. A nil return
// means allowed (or external mode, a no-op).
type InternalCLObserveResult struct {
	Flagged      bool
	EventID      string
	Confidence   float64
	Decision     InternalCLDecision
	MatchedRules []string
}

// Observe evaluates req through internal/hybrid closed-loop mode. Returns
// nil in external mode, or when the request is allowed.
func (c *Client) Observe(req InternalCLRequest) *InternalCLObserveResult {
	switch c.mode {
	case ModeInternal:
		return c.observeInternal(req)
	case ModeHybrid:
		return c.observeHybrid(req)
	default:
		return nil
	}
}

func (c *Client) observeInternal(req InternalCLRequest) *InternalCLObserveResult {
	if c.internalEngine == nil {
		return nil
	}
	result := c.internalEngine.Evaluate(req)
	if result.Decision != CLDecisionAllow {
		return &InternalCLObserveResult{
			Flagged:      true,
			EventID:      result.EventID,
			Confidence:   result.Score / 100,
			Decision:     result.Decision,
			MatchedRules: result.MatchedRules,
		}
	}
	return nil
}

func (c *Client) observeHybrid(req InternalCLRequest) *InternalCLObserveResult {
	// Step 1: internal evaluation (immediate, sub-ms, no round-trip).
	internalResult := c.observeInternal(req)
	if internalResult != nil {
		// The internal engine's own OnRelay callback (wired in NewClient)
		// already handles the Tier-3 relay for this decision — no second
		// relay call here, matching Node's TODO-210 double-billing fix.
		return internalResult
	}

	// Step 2: external enrichment, circuit-breaker gated.
	//
	// KNOWN LIMITATION (flagged explicitly, not silently claimed as full
	// parity): Node's observeHybrid() calls observeExternal() here to
	// fetch a real platform-side enrichment verdict. This port, like the
	// Python port before it, does not yet make that platform call — it
	// only exercises the circuit breaker's success/failure bookkeeping
	// around a no-op enrichment step, so clean traffic is allowed and the
	// circuit stays closed, but a request that internal mode missed and
	// only the platform's own cross-customer intelligence would have
	// caught is not enriched here.
	if c.circuitBreaker != nil && c.circuitBreaker.ShouldCallExternal() {
		c.circuitBreaker.RecordSuccess()
	}
	return nil
}

// IsBlocked reports whether ip is currently blocked by the internal
// engine's in-memory cache. Always false in external mode (no internal
// engine exists).
func (c *Client) IsBlocked(ip string) bool {
	if c.internalEngine == nil {
		return false
	}
	return c.internalEngine.IsIPBlocked(ip)
}

// relayInternalDecisionToPlatform is the Tier-3 relay target for hybrid
// mode, wired as the internal engine's OnRelay callback in NewClient. It
// reuses the existing TrackEvent/Flush path, same as every other outbound
// event from this client, rather than opening a second HTTP path. It is
// invoked synchronously by the engine (see
// internal_closed_loop_engine.go's relayToExternal); TrackEvent itself
// only enqueues in memory, so this does not block on network I/O.
// relayInternalDecisionToPlatform is wired as the internal engine's OnRelay
// callback, invoked synchronously within Evaluate (see
// InternalClosedLoopEngine's own doc comment on why: Evaluate itself must
// stay zero-network and deterministic). It enqueues via TrackEvent — fast,
// in-memory only, safe to call synchronously here — then flushes in its
// own detached goroutine, mirroring ObserveAndFlush's exact pattern, so a
// single hybrid-mode relay (sparse traffic — the common case, one flagged
// request at a time) is actually delivered promptly instead of sitting
// queued until this Client's batch size or flush interval is reached.
// Found live, via this port's own end-to-end demo proof against a real
// platform (not the dummy unreachable endpoint sdk-validation-v4.sh's own
// ICL phase deliberately uses): without this, a relayed event could sit
// queued for up to FlushInterval (often 30s) or indefinitely with no
// interval configured, even though the request itself was already
// blocked and responded to.
func (c *Client) relayInternalDecisionToPlatform(result InternalCLResult, req InternalCLRequest) {
	eventType := fmt.Sprintf("icl_%s", result.Decision)
	if len(result.MatchedRules) > 0 {
		eventType = result.MatchedRules[0]
	}

	var severity string
	switch {
	case result.Score >= 85:
		severity = "CRITICAL"
	case result.Score >= 60:
		severity = "HIGH"
	case result.Score >= 35:
		severity = "MEDIUM"
	default:
		severity = "LOW"
	}

	actionMap := map[InternalCLDecision]string{
		CLDecisionAllow:      "allowed",
		CLDecisionBlock:      "blocked",
		CLDecisionRateLimit:  "rate_limited",
		CLDecisionChallenge:  "challenge_required",
		CLDecisionQuarantine: "flagged",
	}
	actionTaken, ok := actionMap[result.Decision]
	if !ok {
		actionTaken = "flagged"
	}

	authPhase := "pre_auth"
	if req.UserID != "" {
		authPhase = "post_auth"
	}

	c.TrackEvent(context.Background(), Event{
		"eventType":         eventType,
		"ip":                req.IP,
		"severity":          severity,
		"method":            req.Method,
		"path":              req.Path,
		"userAgent":         req.UserAgent,
		"authPhase":         authPhase,
		"actionTaken":       actionTaken,
		"responseLatencyMs": result.EvaluationTimeUs / 1000,
		"clMode":            "hybrid",
		"metadata": map[string]any{
			"source":          "internal-closed-loop-engine",
			"tier":            result.Tier,
			"matchedRules":    result.MatchedRules,
			"internalEventId": result.EventID,
			"sessionId":       req.SessionID,
			"agentId":         req.AgentID,
		},
	})
	go c.Flush(context.Background())
}

func (c *Client) backgroundFlush(interval time.Duration) {
	defer close(c.doneCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.Flush(context.Background())
		case <-c.stopCh:
			return
		}
	}
}

func (c *Client) enqueue(ctx context.Context, events []Event) {
	c.mu.Lock()
	for _, event := range events {
		c.queue = append(c.queue, c.prepare(event))
	}
	shouldFlush := len(c.queue) >= c.batchSize
	c.mu.Unlock()

	if shouldFlush {
		c.Flush(ctx)
	}
}

// maxPreparedEventFields caps the map-size hint computed in prepare() below.
const maxPreparedEventFields = 1_000_000

// preparedEventSize returns a safe make() size hint for merging defaults
// and event, clamped to maxPreparedEventFields. Checked against the cap
// before adding (not `a + b + 1` directly), so two huge inputs can't wrap
// int into a negative size and reach make() unexamined — make() panics on
// a negative size rather than failing safely.
func preparedEventSize(defaults, event int) int {
	if defaults < 0 || event < 0 {
		return 0
	}
	if defaults >= maxPreparedEventFields || event >= maxPreparedEventFields-1 {
		return maxPreparedEventFields
	}
	return defaults + event + 1
}

func (c *Client) prepare(event Event) Event {
	item := make(Event, preparedEventSize(len(c.defaults), len(event)))
	for k, v := range c.defaults {
		item[k] = v
	}
	for k, v := range event {
		item[k] = v
	}
	if _, ok := item["timestamp"]; !ok {
		item["timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if c.privacy == "strict" {
		delete(item, "userAgent")
		if ip, ok := item["ip"].(string); ok {
			sum := sha256.Sum256([]byte(ip))
			item["ip"] = hex.EncodeToString(sum[:])[:16]
		}
	}
	if meta, ok := item["metadata"]; ok && meta == nil {
		item["metadata"] = map[string]any{}
	}
	return item
}

func (c *Client) post(ctx context.Context, payload any) DeliveryResult {
	raw, err := json.Marshal(payload)
	if err != nil {
		return c.fail(DeliveryResult{Err: fmt.Errorf("could not encode payload: %w", err)})
	}

	last := DeliveryResult{Err: errors.New("no delivery attempt was made")}
	for attempt := 1; attempt <= c.retries; attempt++ {
		// A fresh nonce and timestamp on every attempt, so a retry is not a replay.
		headers, signErr := c.sign(raw)
		if signErr != nil {
			return c.fail(DeliveryResult{Err: signErr, Attempts: attempt})
		}
		headers["Content-Type"] = "application/json"
		headers["Accept"] = "application/json"
		headers["User-Agent"] = "devfortress-sdk-go/" + Version

		resp, sendErr := c.safeSend(ctx, headers, raw)
		if sendErr != nil {
			last = DeliveryResult{Err: fmt.Errorf("request failed: %w", sendErr), Attempts: attempt}
		} else {
			body := decodeBody(resp.Body)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return DeliveryResult{OK: true, StatusCode: resp.StatusCode, Body: body, Attempts: attempt}
			}
			last = DeliveryResult{
				StatusCode: resp.StatusCode,
				Body:       body,
				Err:        fmt.Errorf("HTTP %d", resp.StatusCode),
				Attempts:   attempt,
			}
			if resp.StatusCode < 500 {
				return c.fail(last) // 3xx and 4xx: never retried
			}
		}

		if err := ctx.Err(); err != nil {
			return c.fail(DeliveryResult{Err: err, Attempts: attempt})
		}
		if attempt < c.retries {
			c.sleeper(time.Duration(float64(c.backoffBase) * math.Pow(2, float64(attempt-1))))
		}
	}

	return c.fail(last)
}

func (c *Client) sign(body []byte) (map[string]string, error) {
	headers, err := c.signer.Sign("POST", c.requestTarget, string(body), "", "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(headers)+3)
	for k, v := range headers {
		out[k] = v
	}
	return out, nil
}

// safeSend recovers a panicking Transport so it can never reach the host
// application.
func (c *Client) safeSend(ctx context.Context, headers map[string]string, body []byte) (resp *TransportResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp, err = nil, fmt.Errorf("transport panicked: %v", r)
		}
	}()
	return c.transport.Send(ctx, "POST", c.endpoint, headers, body, c.timeout)
}

func (c *Client) fail(result DeliveryResult) DeliveryResult {
	message := "unknown error"
	if result.Err != nil {
		message = result.Err.Error()
	}
	c.log("warning", "devfortress: delivery failed: "+message, map[string]any{
		"status":   result.StatusCode,
		"attempts": result.Attempts,
	})
	return result
}

// log recovers a panicking Logger so it can never reach the host
// application either.
func (c *Client) log(level, message string, fields map[string]any) {
	if c.logger == nil {
		return
	}
	defer func() { _ = recover() }()
	c.logger.Log(level, message, fields)
}

func decodeBody(raw []byte) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	return v
}
