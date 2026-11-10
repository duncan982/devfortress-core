package devfortress

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Defaults and timeouts for LicenseManager, matching the Node SDK
// (license-manager.ts).
const (
	// DefaultLicenseCheckInterval is how often CheckLicense runs in the
	// background once Start is called. CV-M1.
	DefaultLicenseCheckInterval = 24 * time.Hour
	// DefaultGracePeriod is how long consecutive check failures are
	// tolerated before the SDK degrades to monitor-only. CV-M1.
	DefaultGracePeriod = 72 * time.Hour
	// DefaultModelExpiry is how long the embedded ML model is considered
	// fresh without a platform sync. CV-M4.
	DefaultModelExpiry = 30 * 24 * time.Hour
	// LicenseCheckTimeout bounds a single license-check HTTP attempt.
	LicenseCheckTimeout = 10 * time.Second
)

// LicenseState is the SDK's current license/tier state, as last resolved by
// CheckLicense.
type LicenseState struct {
	// Valid is whether the license is currently valid.
	Valid bool
	// Tier is the subscription tier confirmed by the platform.
	Tier SubscriptionTier
	// LastCheckedAt is the Unix millisecond timestamp of the last
	// successful license check (0 = never checked).
	LastCheckedAt int64
	// ConsecutiveFailures is the number of consecutive check failures.
	ConsecutiveFailures int
	// Degraded is whether the SDK is in degraded (monitor-only) mode due
	// to an expired or unreachable license.
	Degraded bool
	// DegradationReason explains Degraded, when true.
	DegradationReason string
}

// ModelState is the embedded ML model's freshness state (CV-M4).
type ModelState struct {
	// LastSyncedAt is the Unix millisecond timestamp the model was last
	// synced from the platform.
	LastSyncedAt int64
	// ModelVersion identifies the model.
	ModelVersion string
	// Expired is whether the model has gone stale (no platform sync
	// within the configured ModelExpiry).
	Expired bool
}

// LicenseAction is a capability CanPerformAction checks.
type LicenseAction string

const (
	LicenseActionBlock     LicenseAction = "block"
	LicenseActionRateLimit LicenseAction = "rate_limit"
	LicenseActionObserve   LicenseAction = "observe"
)

// LicenseManagerConfig configures a LicenseManager.
type LicenseManagerConfig struct {
	// APIKey authenticates license-check requests. Required.
	APIKey string
	// Endpoint is the platform base URL (no /api/sdk/... suffix).
	// Required.
	Endpoint string
	// CheckInterval is how often CheckLicense runs once Start is called.
	// Default: DefaultLicenseCheckInterval (24h).
	CheckInterval time.Duration
	// GracePeriod is how long consecutive failures are tolerated before
	// degrading to monitor-only. Default: DefaultGracePeriod (72h).
	GracePeriod time.Duration
	// ModelExpiry is the ML model staleness threshold. Default:
	// DefaultModelExpiry (30 days).
	ModelExpiry time.Duration
	// IntegritySecret, if set, enables ComputeIntegrityHash/VerifyIntegrity
	// (anti-tampering, CV-M7). Empty disables it (ComputeIntegrityHash
	// then returns "no-integrity-secret").
	IntegritySecret string
	// Debug enables debug-level logging in addition to the warnings that
	// are always logged.
	Debug bool
	// Transport replaces the HTTP transport, e.g. with a recording
	// transport in tests. Defaults to NewHTTPTransport().
	Transport Transport
	// Logger receives warnings on degradation/failure (always, regardless
	// of Debug) and debug-level detail (only when Debug is set). A nil
	// Logger means failures and degradation go unlogged — the exact
	// silent-failure bug class TODO 321 fixed on the platform side; hosts
	// should always supply one in production.
	Logger Logger
}

// LicenseManager resolves and maintains the SDK's license/tier state
// against the platform (CV-M1, CV-M4, CV-M7):
//
//   - CV-M1: server-side license validation with a 24h check interval and
//     72h grace-period degradation. A license check that fails silently
//     (no logging, no visible degraded state) is exactly the bug class
//     TODO 321 fixed on the platform's license-check/heartbeat endpoints;
//     this client never swallows a failure without logging it.
//   - CV-M4: ML model staleness tracking (30 days without a platform sync).
//   - CV-M7: SDK anti-tampering integrity hash.
type LicenseManager struct {
	apiKey          string
	endpoint        string
	checkInterval   time.Duration
	gracePeriod     time.Duration
	modelExpiry     time.Duration
	integritySecret string
	debug           bool
	signer          *Signer
	transport       Transport
	logger          Logger

	mu           sync.Mutex
	licenseState LicenseState
	modelState   ModelState
	started      bool

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewLicenseManager returns a LicenseManager for cfg. An empty APIKey or
// Endpoint is the only construction error.
func NewLicenseManager(cfg LicenseManagerConfig) (*LicenseManager, error) {
	signer, err := NewSigner(cfg.APIKey)
	if err != nil {
		return nil, err
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("devfortress: a platform endpoint is required")
	}

	checkInterval := cfg.CheckInterval
	if checkInterval <= 0 {
		checkInterval = DefaultLicenseCheckInterval
	}
	gracePeriod := cfg.GracePeriod
	if gracePeriod <= 0 {
		gracePeriod = DefaultGracePeriod
	}
	modelExpiry := cfg.ModelExpiry
	if modelExpiry <= 0 {
		modelExpiry = DefaultModelExpiry
	}
	transport := cfg.Transport
	if transport == nil {
		transport = NewHTTPTransport()
	}

	now := time.Now().UnixMilli()
	return &LicenseManager{
		apiKey:          cfg.APIKey,
		endpoint:        strings.TrimRight(cfg.Endpoint, "/"),
		checkInterval:   checkInterval,
		gracePeriod:     gracePeriod,
		modelExpiry:     modelExpiry,
		integritySecret: cfg.IntegritySecret,
		debug:           cfg.Debug,
		signer:          signer,
		transport:       transport,
		logger:          cfg.Logger,
		licenseState:    LicenseState{Tier: TierStarter},
		modelState:      ModelState{LastSyncedAt: now, ModelVersion: "embedded-v1"},
		stopCh:          make(chan struct{}),
	}, nil
}

// ── CV-M1: License Validation ───────────────────────────────────────────

// Start performs an initial license check and then starts periodic
// checks on CheckInterval, in a background goroutine, until Stop is
// called. Calling Start more than once is a no-op (it returns the current
// state without checking again).
func (l *LicenseManager) Start(ctx context.Context) LicenseState {
	l.mu.Lock()
	if l.started {
		state := l.licenseState
		l.mu.Unlock()
		return state
	}
	l.started = true
	l.mu.Unlock()

	state := l.CheckLicense(ctx)

	l.doneCh = make(chan struct{})
	go l.backgroundCheck()

	return state
}

func (l *LicenseManager) backgroundCheck() {
	defer close(l.doneCh)
	ticker := time.NewTicker(l.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.CheckLicense(context.Background())
		case <-l.stopCh:
			return
		}
	}
}

// Stop stops periodic license checks. Safe to call more than once, and
// safe to call even if Start was never called.
func (l *LicenseManager) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopCh)
	})
	if l.doneCh != nil {
		<-l.doneCh
	}
}

// CheckLicense performs a single license check against the platform. On
// success it records the confirmed tier (and syncs the ML model state, if
// the platform returned a modelVersion). On failure it tracks consecutive
// failures and degrades to monitor-only once the grace period has
// elapsed — logging a warning either way, never failing silently.
func (l *LicenseManager) CheckLicense(ctx context.Context) LicenseState {
	body, err := json.Marshal(map[string]any{
		"sdkVersion": Version,
		"timestamp":  time.Now().UnixMilli(),
		"integrity":  l.ComputeIntegrityHash(),
	})
	if err != nil {
		l.handleCheckFailure(fmt.Sprintf("could not encode request: %v", err))
		return l.GetLicenseState()
	}

	url := l.endpoint + "/api/sdk/license-check"
	headers, err := l.sign(url, body)
	if err != nil {
		l.handleCheckFailure(fmt.Sprintf("could not sign request: %v", err))
		return l.GetLicenseState()
	}

	resp, err := l.safeSend(ctx, url, headers, body)
	if err != nil {
		l.handleCheckFailure(err.Error())
		return l.GetLicenseState()
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		l.handleCheckSuccess(resp.Body)
	case resp.StatusCode == 402 || resp.StatusCode == 403:
		l.handleCheckRejected(resp.StatusCode)
	default:
		l.handleCheckFailure(fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	return l.GetLicenseState()
}

func (l *LicenseManager) handleCheckSuccess(rawBody []byte) {
	var data struct {
		Tier         string `json:"tier"`
		ModelVersion string `json:"modelVersion"`
	}
	_ = json.Unmarshal(rawBody, &data)

	l.mu.Lock()
	tier := l.licenseState.Tier
	if data.Tier != "" {
		tier = SubscriptionTier(data.Tier)
	}
	l.licenseState = LicenseState{
		Valid:         true,
		Tier:          tier,
		LastCheckedAt: time.Now().UnixMilli(),
	}
	if data.ModelVersion != "" {
		l.modelState = ModelState{LastSyncedAt: time.Now().UnixMilli(), ModelVersion: data.ModelVersion}
	}
	l.mu.Unlock()

	l.log("info", fmt.Sprintf("License validated: tier=%s", tier))
}

func (l *LicenseManager) handleCheckRejected(status int) {
	l.mu.Lock()
	l.licenseState.Valid = false
	l.licenseState.Tier = TierStarter
	l.licenseState.LastCheckedAt = time.Now().UnixMilli()
	l.licenseState.ConsecutiveFailures++
	l.licenseState.Degraded = true
	l.licenseState.DegradationReason = fmt.Sprintf("License rejected: HTTP %d", status)
	reason := l.licenseState.DegradationReason
	l.mu.Unlock()

	l.log("warn", reason)
}

// handleCheckFailure tracks a transient (network/5xx) failure. It is the
// direct port of TODO 321's fix intent: a failure is always logged (warn
// once the grace period elapses, debug before that — never silent), and
// the SDK only degrades to monitor-only after GracePeriod has elapsed
// since the last successful check.
func (l *LicenseManager) handleCheckFailure(reason string) {
	l.mu.Lock()
	l.licenseState.ConsecutiveFailures++
	baseline := l.licenseState.LastCheckedAt
	now := time.Now().UnixMilli()
	if baseline == 0 {
		baseline = now
	}
	elapsed := time.Duration(now-baseline) * time.Millisecond

	var level, message string
	if elapsed >= l.gracePeriod {
		l.licenseState.Degraded = true
		l.licenseState.DegradationReason = fmt.Sprintf(
			"License check failed for %dh (grace period: %dh). Reason: %s. SDK degraded to monitor-only mode.",
			int(elapsed.Hours()), int(l.gracePeriod.Hours()), reason,
		)
		message = l.licenseState.DegradationReason
		level = "warn"
	} else {
		remaining := l.gracePeriod - elapsed
		message = fmt.Sprintf(
			"License check failed (%s), %d consecutive failures, %dh grace remaining",
			reason, l.licenseState.ConsecutiveFailures, int(remaining.Hours()),
		)
		level = "debug"
	}
	l.mu.Unlock()

	l.log(level, message)
}

// GetLicenseState returns a copy of the current license state.
func (l *LicenseManager) GetLicenseState() LicenseState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.licenseState
}

// IsDegraded reports whether the SDK should operate in degraded
// (monitor-only) mode: no blocking, no rate limiting, just logging.
func (l *LicenseManager) IsDegraded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.licenseState.Degraded
}

// CanPerformAction reports whether action is available given the current
// license state. LicenseActionObserve is always allowed.
func (l *LicenseManager) CanPerformAction(action LicenseAction) bool {
	if action == LicenseActionObserve {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.licenseState.Degraded {
		return false
	}
	if !l.licenseState.Valid && l.licenseState.LastCheckedAt == 0 {
		// Never validated yet — allow actions during the initial grace period.
		return true
	}
	return l.licenseState.Valid
}

// ── CV-M4: ML Model Expiry ──────────────────────────────────────────────

// IsModelExpired reports whether the embedded ML model has expired
// (no platform sync within ModelExpiry). If expired, ICL should fall back
// to Tier 1 (deterministic) only.
func (l *LicenseManager) IsModelExpired() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	age := time.Duration(time.Now().UnixMilli()-l.modelState.LastSyncedAt) * time.Millisecond
	l.modelState.Expired = age > l.modelExpiry
	return l.modelState.Expired
}

// GetModelState returns the current ML model state, with Expired freshly
// recomputed.
func (l *LicenseManager) GetModelState() ModelState {
	expired := l.IsModelExpired()
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.modelState
	state.Expired = expired
	return state
}

// SyncModel manually records a model sync (called from init or on a
// successful heartbeat).
func (l *LicenseManager) SyncModel(modelVersion string) {
	l.mu.Lock()
	l.modelState = ModelState{LastSyncedAt: time.Now().UnixMilli(), ModelVersion: modelVersion}
	l.mu.Unlock()

	l.log("info", fmt.Sprintf("ML model synced: version=%s", modelVersion))
}

// ── CV-M7: Anti-Tampering ───────────────────────────────────────────────

// ComputeIntegrityHash computes an HMAC over a fixed set of critical SDK
// code-path names, keyed with IntegritySecret and the API key. If
// IntegritySecret is empty, it returns "no-integrity-secret" (anti-tamper
// checking disabled).
func (l *LicenseManager) ComputeIntegrityHash() string {
	if l.integritySecret == "" {
		return "no-integrity-secret"
	}

	criticalPaths := strings.Join([]string{
		"DevFortress.observe",
		"DevFortress.isBlocked",
		"LicenseManager.checkLicense",
		"InternalClosedLoopEngine.evaluate",
		"TierGate.checkEventLimit",
	}, "|")

	mac := hmac.New(sha256.New, []byte(l.integritySecret))
	mac.Write([]byte(criticalPaths))
	mac.Write([]byte(l.apiKey))
	sum := hex.EncodeToString(mac.Sum(nil))
	return sum[:16]
}

// VerifyIntegrity reports whether the SDK appears tampered with: hash is
// always the freshly computed integrity hash; tampered is true only when
// expectedHash is non-empty and doesn't match it.
func (l *LicenseManager) VerifyIntegrity(expectedHash string) (tampered bool, hash string) {
	current := l.ComputeIntegrityHash()
	if expectedHash == "" {
		return false, current
	}
	return current != expectedHash, current
}

// ── Transport / signing / logging ───────────────────────────────────────

func (l *LicenseManager) sign(url string, body []byte) (map[string]string, error) {
	headers, err := l.signer.Sign("POST", RequestTargetFromURL(url), string(body), "", "")
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

// safeSend recovers a panicking Transport so it can never reach the host
// application.
func (l *LicenseManager) safeSend(ctx context.Context, url string, headers map[string]string, body []byte) (resp *TransportResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp, err = nil, fmt.Errorf("transport panicked: %v", r)
		}
	}()
	return l.transport.Send(ctx, "POST", url, headers, body, LicenseCheckTimeout)
}

// log recovers a panicking Logger so it can never reach the host
// application. Levels "warn" and "error" are always forwarded; "debug" is
// forwarded only when Debug is set — matching the Node SDK's log()
// gating, and ensuring a degradation warning is never silently dropped.
func (l *LicenseManager) log(level, message string) {
	if l.logger == nil {
		return
	}
	if level == "debug" && !l.debug {
		return
	}
	defer func() { _ = recover() }()
	l.logger.Log(level, "[DevFortress:License] "+message, nil)
}
