package devfortress

import (
	"reflect"
	"sync"
	"time"
)

// SubscriptionTier is a DevFortress subscription tier.
type SubscriptionTier string

const (
	TierStarter    SubscriptionTier = "starter"
	TierPro        SubscriptionTier = "pro"
	TierTeam       SubscriptionTier = "team"
	TierEnterprise SubscriptionTier = "enterprise"
)

// CLMode is a closed-loop delivery mode.
type CLMode string

const (
	ModeExternal CLMode = "external"
	ModeInternal CLMode = "internal"
	ModeHybrid   CLMode = "hybrid"
)

// TierCapabilities is the full feature-access profile for one
// SubscriptionTier.
//
//	Starter:    Observe events; response is webhook-dispatched and
//	            self-executed by the customer (no platform-side blocking).
//	Pro:        View + block via external CL only — no internal/hybrid,
//	            not even as an add-on (Package A, 2026-08-28).
//	Team:       External, internal, and hybrid all available as
//	            first-class capabilities (default: hybrid) — the entry
//	            point for internal/hybrid CL under Package A.
//	Enterprise: Can select internal, external, or hybrid (default: hybrid
//	            with internal backup, external primary).
type TierCapabilities struct {
	// CanObserve is whether events can be observed/collected.
	CanObserve bool
	// CanBlock is whether blocking actions can be executed.
	CanBlock bool
	// AllowedModes lists the closed-loop modes permitted for this tier.
	AllowedModes []CLMode
	// DefaultMode is the mode used when none is requested, or the
	// requested mode isn't allowed.
	DefaultMode CLMode
	// HybridIsAddon is whether hybrid mode requires extra payment on top
	// of this tier.
	HybridIsAddon bool
	// InternalAsBackupOnly is whether internal CL acts only as a backup
	// (legacy Pro behavior).
	InternalAsBackupOnly bool
	// CanConfigureRules is whether custom rules can be configured.
	CanConfigureRules bool
	// CanAccessAudit is whether the audit trail is available.
	CanAccessAudit bool
	// CanManageWebhooks is whether webhook secrets can be managed.
	CanManageWebhooks bool
	// MaxEventsPerDay is the daily ingestion ceiling (0 = unlimited).
	MaxEventsPerDay int
	// MaxBlockedIPs is the maximum blocked-IP count (0 = unlimited).
	MaxBlockedIPs int
	// ICLMaxTier is the highest ICL tier available: 0=none,
	// 1=deterministic, 2=+ML, 3=full (CV-S2).
	ICLMaxTier int
	// AirGapEnabled is whether offline (air-gap) mode is available.
	AirGapEnabled bool
	// CustomRulesEnabled is whether custom ICL rules are available.
	CustomRulesEnabled bool
	// MaxEventsPerMonth is the monthly billed-event quota (0 = unlimited,
	// CV-S3).
	MaxEventsPerMonth int
	// PlatformAlerts is whether platform alert channels (email/Slack/
	// PagerDuty) are available (CV-S4).
	PlatformAlerts bool
	// SharedState is whether cross-instance shared state (IP blocklists,
	// baselines) via the platform is available (CV-S5).
	SharedState bool
	// ComplianceEvidence is whether compliance evidence generation (PDF
	// reports, audit exports) is available (CV-S6).
	ComplianceEvidence bool
}

// tierCapabilities is the tier capability matrix. Values mirror
// tier-gate.ts's TIER_CAPABILITIES exactly (including the per-tier
// comments there about Package A's 2026-08-28 pricing changes).
var tierCapabilities = map[SubscriptionTier]TierCapabilities{
	TierStarter: {
		CanObserve:        true,
		CanBlock:          false,
		AllowedModes:      []CLMode{ModeExternal},
		DefaultMode:       ModeExternal,
		MaxEventsPerDay:   10_000,
		ICLMaxTier:        1,
		MaxEventsPerMonth: 50_000,
	},
	TierPro: {
		CanObserve:        true,
		CanBlock:          true,
		AllowedModes:      []CLMode{ModeExternal},
		DefaultMode:       ModeExternal,
		CanAccessAudit:    true,
		CanManageWebhooks: true,
		MaxEventsPerDay:   100_000,
		MaxBlockedIPs:     1_000,
		ICLMaxTier:        0,
		MaxEventsPerMonth: 75_000,
		PlatformAlerts:    true,
		SharedState:       true,
	},
	TierTeam: {
		CanObserve:         true,
		CanBlock:           true,
		AllowedModes:       []CLMode{ModeExternal, ModeInternal, ModeHybrid},
		DefaultMode:        ModeHybrid,
		CanAccessAudit:     true,
		CanManageWebhooks:  true,
		MaxEventsPerDay:    0, // Unlimited ingestion; monthly billing quota below still caps flagged events.
		MaxBlockedIPs:      5_000,
		ICLMaxTier:         2,
		MaxEventsPerMonth:  100_000,
		PlatformAlerts:     true,
		SharedState:        true,
		ComplianceEvidence: true,
	},
	TierEnterprise: {
		CanObserve:         true,
		CanBlock:           true,
		AllowedModes:       []CLMode{ModeExternal, ModeInternal, ModeHybrid},
		DefaultMode:        ModeHybrid,
		CanConfigureRules:  true,
		CanAccessAudit:     true,
		CanManageWebhooks:  true,
		MaxEventsPerDay:    0,
		MaxBlockedIPs:      0,
		ICLMaxTier:         3,
		AirGapEnabled:      true,
		CustomRulesEnabled: true,
		MaxEventsPerMonth:  0,
		PlatformAlerts:     true,
		SharedState:        true,
		ComplianceEvidence: true,
	},
}

// EventLimitStatus is the outcome of CheckEventLimit or CheckMonthlyQuota.
type EventLimitStatus struct {
	Allowed bool
	// Remaining is meaningful only when Unlimited is false.
	Remaining int
	// Limit is the configured ceiling (0 when Unlimited).
	Limit     int
	Unlimited bool
}

// MonthlyUsage is telemetry-heartbeat-friendly monthly quota usage.
type MonthlyUsage struct {
	Used        int
	Limit       int
	PercentUsed int
	Unlimited   bool
}

// TierGateOptions configures a TierGate at construction.
type TierGateOptions struct {
	// HybridAddonEnabled enables hybrid mode on the Pro tier when its
	// capabilities mark hybrid as an add-on. Ignored on tiers where
	// hybrid isn't an add-on.
	HybridAddonEnabled bool
}

// TierGateSnapshot is a serializable snapshot of a TierGate's mutable
// state (S15: usage metering persistence). Callers serialize this to
// JSON and store it in a DB/file across restarts.
type TierGateSnapshot struct {
	Tier               SubscriptionTier
	HybridAddonEnabled bool
	DailyEventCount    int
	DailyResetTime     int64
	MonthlyEventCount  int
	MonthlyResetTime   int64
	SnapshotTimestamp  int64
}

// TierGate enforces feature access based on subscription tier. It depends
// on nothing but the tier name itself — callers resolve the active tier
// (typically via LicenseManager.GetLicenseState().Tier) and construct or
// refresh a TierGate from it.
type TierGate struct {
	mu                 sync.Mutex
	tier               SubscriptionTier
	capabilities       TierCapabilities
	hybridAddonEnabled bool
	dailyEventCount    int
	dailyResetTime     int64
	monthlyEventCount  int
	monthlyResetTime   int64
}

// NewTierGate returns a TierGate for tier. opts may be nil. An unknown
// tier gets the zero-value TierCapabilities (default-deny: no observe, no
// block, no modes) rather than silently falling back to another tier.
func NewTierGate(tier SubscriptionTier, opts *TierGateOptions) *TierGate {
	caps := tierCapabilities[tier] // zero value if tier is unknown

	hybridAddonEnabled := false
	if opts != nil {
		hybridAddonEnabled = opts.HybridAddonEnabled
	}

	now := time.Now()
	return &TierGate{
		tier:               tier,
		capabilities:       caps,
		hybridAddonEnabled: hybridAddonEnabled,
		dailyResetTime:     startOfDay(now),
		monthlyResetTime:   startOfMonth(now),
	}
}

// GetEffectiveMode validates requestedMode against tier permissions and
// returns it, or the tier's default mode if requestedMode is empty, not
// allowed, or (Pro + hybrid-as-addon, addon not enabled) gated.
func (g *TierGate) GetEffectiveMode(requestedMode CLMode) CLMode {
	g.mu.Lock()
	defer g.mu.Unlock()

	if requestedMode == "" {
		return g.capabilities.DefaultMode
	}
	if !containsMode(g.capabilities.AllowedModes, requestedMode) {
		return g.capabilities.DefaultMode
	}
	if g.tier == TierPro && requestedMode == ModeHybrid && g.capabilities.HybridIsAddon && !g.hybridAddonEnabled {
		return ModeExternal
	}
	return requestedMode
}

// CanBlock reports whether blocking is allowed for this tier.
func (g *TierGate) CanBlock() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities.CanBlock
}

// CheckEventLimit reports whether the daily event limit has been reached,
// resetting the daily counter first if a new day has started.
func (g *TierGate) CheckEventLimit() EventLimitStatus {
	g.mu.Lock()
	defer g.mu.Unlock()

	dayStart := startOfDay(time.Now())
	if g.dailyResetTime < dayStart {
		g.dailyEventCount = 0
		g.dailyResetTime = dayStart
	}

	if g.capabilities.MaxEventsPerDay == 0 {
		return EventLimitStatus{Allowed: true, Unlimited: true}
	}

	remaining := g.capabilities.MaxEventsPerDay - g.dailyEventCount
	if remaining < 0 {
		remaining = 0
	}
	return EventLimitStatus{Allowed: remaining > 0, Remaining: remaining, Limit: g.capabilities.MaxEventsPerDay}
}

// RecordEvent records one event against the daily limit.
func (g *TierGate) RecordEvent() {
	g.mu.Lock()
	g.dailyEventCount++
	g.mu.Unlock()
}

// HasFeature reports whether the named TierCapabilities field is "on":
// true for a true bool, true for any numeric field (mirroring the Node
// SDK's `value > 0 || value === 0`, which is true for every non-negative
// number — every capability value here is non-negative), and true for a
// non-empty slice. feature is the exported Go field name (e.g.
// "CanConfigureRules", "MaxBlockedIPs").
func (g *TierGate) HasFeature(feature string) bool {
	g.mu.Lock()
	caps := g.capabilities
	g.mu.Unlock()

	f := reflect.ValueOf(caps).FieldByName(feature)
	if !f.IsValid() {
		return false
	}
	switch f.Kind() {
	case reflect.Bool:
		return f.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	case reflect.Slice:
		return f.Len() > 0
	default:
		return false
	}
}

// GetCapabilities returns the full capability set for this tier.
func (g *TierGate) GetCapabilities() TierCapabilities {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities
}

// GetTier returns the current tier name.
func (g *TierGate) GetTier() SubscriptionTier {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tier
}

// ValidateBlockAction validates a blocking action against tier
// permissions. allowed is false only when the tier cannot block at all;
// reason explains why when allowed is false.
func (g *TierGate) ValidateBlockAction(action string) (allowed bool, reason string) {
	g.mu.Lock()
	canBlock := g.capabilities.CanBlock
	tier := g.tier
	g.mu.Unlock()

	if !canBlock {
		return false, "Blocking is not available on the " + string(tier) + " tier. Upgrade to Pro or Enterprise to enable blocking."
	}
	return true, ""
}

// ValidateMode validates a mode selection against tier permissions.
// allowed is false when mode isn't in AllowedModes, or (Pro + hybrid
// add-on, not enabled) gated; reason explains why in that case.
func (g *TierGate) ValidateMode(mode CLMode) (allowed bool, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !containsMode(g.capabilities.AllowedModes, mode) {
		allowedList := ""
		for i, m := range g.capabilities.AllowedModes {
			if i > 0 {
				allowedList += ", "
			}
			allowedList += string(m)
		}
		return false, "The '" + string(mode) + "' mode is not available on the " + string(g.tier) + " tier. Allowed modes: " + allowedList + "."
	}

	if g.tier == TierPro && mode == ModeHybrid && g.capabilities.HybridIsAddon && !g.hybridAddonEnabled {
		return false, "Hybrid mode requires the hybrid add-on on the Pro tier. Enable it in your subscription settings."
	}

	return true, ""
}

// ── CV-S2: Tiered ICL Capabilities ──────────────────────────────────────

// GetMaxICLTier returns the maximum ICL tier available for this
// subscription (0=none, 1=deterministic, 2=+ML, 3=full).
func (g *TierGate) GetMaxICLTier() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities.ICLMaxTier
}

// IsICLTierAvailable reports whether the given ICL tier (1, 2, or 3) is
// available.
func (g *TierGate) IsICLTierAvailable(tier int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities.ICLMaxTier >= tier
}

// IsAirGapEnabled reports whether air-gap (offline) mode is available.
func (g *TierGate) IsAirGapEnabled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities.AirGapEnabled
}

// CanConfigureCustomRules reports whether custom ICL rules can be
// configured.
func (g *TierGate) CanConfigureCustomRules() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities.CustomRulesEnabled
}

// ── CV-S3: Monthly Event Quotas ──────────────────────────────────────────

// CheckMonthlyQuota reports whether the monthly event quota has been
// reached, resetting the monthly counter first if a new month has
// started.
func (g *TierGate) CheckMonthlyQuota() EventLimitStatus {
	g.mu.Lock()
	defer g.mu.Unlock()

	monthStart := startOfMonth(time.Now())
	if g.monthlyResetTime < monthStart {
		g.monthlyEventCount = 0
		g.monthlyResetTime = monthStart
	}

	limit := g.capabilities.MaxEventsPerMonth
	if limit == 0 {
		return EventLimitStatus{Allowed: true, Unlimited: true}
	}

	remaining := limit - g.monthlyEventCount
	if remaining < 0 {
		remaining = 0
	}
	return EventLimitStatus{Allowed: remaining > 0, Remaining: remaining, Limit: limit}
}

// RecordMonthlyEvent records one event against the monthly quota.
func (g *TierGate) RecordMonthlyEvent() {
	g.mu.Lock()
	g.monthlyEventCount++
	g.mu.Unlock()
}

// GetMonthlyUsage returns monthly usage stats for a telemetry heartbeat.
func (g *TierGate) GetMonthlyUsage() MonthlyUsage {
	g.mu.Lock()
	defer g.mu.Unlock()

	limit := g.capabilities.MaxEventsPerMonth
	if limit == 0 {
		return MonthlyUsage{Used: g.monthlyEventCount, Unlimited: true}
	}
	return MonthlyUsage{
		Used:        g.monthlyEventCount,
		Limit:       limit,
		PercentUsed: int(float64(g.monthlyEventCount) / float64(limit) * 100),
	}
}

// ── CV-S4/S5/S6: Platform Feature Checks ────────────────────────────────

// HasPlatformAlerts reports whether platform alert channels are
// available. CV-S4: ICL mode can only log to console/filesystem.
func (g *TierGate) HasPlatformAlerts() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities.PlatformAlerts
}

// HasSharedState reports whether cross-instance shared state is
// available. CV-S5: ICL maintains per-instance state only.
func (g *TierGate) HasSharedState() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities.SharedState
}

// HasComplianceEvidence reports whether compliance evidence generation is
// available. CV-S6: ICL provides raw logs but no compliance formatting.
func (g *TierGate) HasComplianceEvidence() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.capabilities.ComplianceEvidence
}

// ── S15: Usage Metering Persistence ─────────────────────────────────────

// ToSnapshot captures mutable state for persistence across restarts.
// Callers serialize the result to JSON and store it in a DB/file.
func (g *TierGate) ToSnapshot() TierGateSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	return TierGateSnapshot{
		Tier:               g.tier,
		HybridAddonEnabled: g.hybridAddonEnabled,
		DailyEventCount:    g.dailyEventCount,
		DailyResetTime:     g.dailyResetTime,
		MonthlyEventCount:  g.monthlyEventCount,
		MonthlyResetTime:   g.monthlyResetTime,
		SnapshotTimestamp:  time.Now().UnixMilli(),
	}
}

// TierGateFromSnapshot restores a TierGate from a previously saved
// snapshot. Daily/monthly counters are restored only if the snapshot's
// reset time is still within the current day/month — a stale snapshot is
// treated like a fresh TierGate for that counter.
//
// opts is accepted for signature parity with the Node SDK's
// fromSnapshot(snapshot, options), where options.hybridAddonEnabled is a
// fallback used only if snapshot.hybridAddonEnabled is nullish — which
// never happens, since it's a required field there. snapshot's value is
// therefore always what's used here too; opts is otherwise ignored.
func TierGateFromSnapshot(snapshot TierGateSnapshot, opts *TierGateOptions) *TierGate {
	_ = opts
	gate := NewTierGate(snapshot.Tier, &TierGateOptions{HybridAddonEnabled: snapshot.HybridAddonEnabled})

	now := time.Now()
	todayStart := startOfDay(now)
	monthStart := startOfMonth(now)

	gate.mu.Lock()
	if snapshot.DailyResetTime >= todayStart {
		gate.dailyEventCount = snapshot.DailyEventCount
		gate.dailyResetTime = snapshot.DailyResetTime
	}
	if snapshot.MonthlyResetTime >= monthStart {
		gate.monthlyEventCount = snapshot.MonthlyEventCount
		gate.monthlyResetTime = snapshot.MonthlyResetTime
	}
	gate.mu.Unlock()

	return gate
}

func containsMode(modes []CLMode, mode CLMode) bool {
	for _, m := range modes {
		if m == mode {
			return true
		}
	}
	return false
}

func startOfDay(t time.Time) int64 {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location()).UnixMilli()
}

func startOfMonth(t time.Time) int64 {
	y, m, _ := t.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, t.Location()).UnixMilli()
}
