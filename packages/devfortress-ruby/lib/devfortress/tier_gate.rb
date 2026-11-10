# frozen_string_literal: true

module DevFortress
  # Tier Gating & Feature Access Control.
  #
  # Enforces feature access based on subscription tier:
  #
  #   Starter:    Observe events; response is webhook-dispatched and
  #               self-executed by the customer (no platform-side blocking)
  #   Pro:        View + block via external CL only — no internal/hybrid,
  #               not even as an add-on (Package A, 2026-08-28)
  #   Team:       External, internal, and hybrid all available as first-class
  #               capabilities (default: hybrid) — the entry point for
  #               internal/hybrid CL under Package A
  #   Enterprise: Can select internal, external, or hybrid
  #               (default: hybrid with internal backup, external primary)
  #
  # Mirrors packages/devfortress-sdk/src/tier-gate.ts. Depends on
  # LicenseManager resolving the active subscription tier from the
  # platform (see LicenseManager#license_state.tier).
  class TierGate
    TierGateSnapshot = Struct.new(
      :tier, :hybrid_addon_enabled, :daily_event_count, :daily_reset_time,
      :monthly_event_count, :monthly_reset_time, :snapshot_timestamp,
      keyword_init: true
    )

    TIER_CAPABILITIES = {
      "starter" => {
        can_observe: true, can_block: false, allowed_modes: %w[external], default_mode: "external",
        hybrid_is_addon: false, internal_as_backup_only: false, can_configure_rules: false,
        can_access_audit: false, can_manage_webhooks: false, max_events_per_day: 10_000, max_blocked_ips: 0,
        # CV-S2: Starter gets Tier 1 deterministic rules only
        icl_max_tier: 1, air_gap_enabled: false, custom_rules_enabled: false,
        # CV-S3: 50K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
        max_events_per_month: 50_000,
        # CV-S4/S5/S6
        platform_alerts: false, shared_state: false, compliance_evidence: false,
      }.freeze,
      "pro" => {
        can_observe: true, can_block: true,
        # Package A (2026-08-28): Pro gets External CL only, at no point in
        # time does it get ICL/hybrid — differentiation comes from
        # platform-executed response, post-auth detection, alias
        # isolation, and AI insights, never from CL mode depth.
        # Internal/Hybrid access starts at Team.
        allowed_modes: %w[external], default_mode: "external", hybrid_is_addon: false,
        internal_as_backup_only: false, can_configure_rules: false, can_access_audit: true,
        can_manage_webhooks: true, max_events_per_day: 100_000, max_blocked_ips: 1_000,
        # CV-S2: Pro has no ICL access — External CL only (Package A)
        icl_max_tier: 0, air_gap_enabled: false, custom_rules_enabled: false,
        # CV-S3: 75K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
        max_events_per_month: 75_000,
        # CV-S4/S5/S6: platform alerts + shared state, no compliance evidence (Enterprise only)
        platform_alerts: true, shared_state: true, compliance_evidence: false,
      }.freeze,
      "team" => {
        can_observe: true, can_block: true,
        # Package A (2026-08-28): Team is the new entry point for
        # Internal/Hybrid CL — takes on the capability profile Pro used to
        # have, but as a first-class capability (no add-on gate, no
        # backup-only limit).
        allowed_modes: %w[external internal hybrid], default_mode: "hybrid", hybrid_is_addon: false,
        internal_as_backup_only: false, can_configure_rules: false, can_access_audit: true,
        can_manage_webhooks: true, max_events_per_day: 0, max_blocked_ips: 5_000,
        # CV-S2: Team gets Tier 1 + Tier 2 ML (same ceiling Pro used to have)
        icl_max_tier: 2, air_gap_enabled: false, custom_rules_enabled: false,
        # CV-S3: 100K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
        max_events_per_month: 100_000,
        # CV-S4/S5/S6: platform alerts + shared state + compliance evidence
        # (matches Team's advertised compliance PDF reports)
        platform_alerts: true, shared_state: true, compliance_evidence: true,
      }.freeze,
      "enterprise" => {
        can_observe: true, can_block: true, allowed_modes: %w[external internal hybrid],
        default_mode: "hybrid", hybrid_is_addon: false, internal_as_backup_only: false,
        can_configure_rules: true, can_access_audit: true, can_manage_webhooks: true,
        max_events_per_day: 0, max_blocked_ips: 0,
        # CV-S2: Enterprise gets all tiers + air-gap + custom rules
        icl_max_tier: 3, air_gap_enabled: true, custom_rules_enabled: true,
        # CV-S3: Unlimited events/month
        max_events_per_month: 0,
        # CV-S4/S5/S6: full alert channels, full shared state, compliance evidence
        platform_alerts: true, shared_state: true, compliance_evidence: true,
      }.freeze,
    }.freeze

    attr_reader :tier, :capabilities

    def initialize(tier, hybrid_addon_enabled: false)
      raise ArgumentError, "DevFortress: unknown subscription tier #{tier.inspect}" unless TIER_CAPABILITIES.key?(tier)

      @tier = tier
      @capabilities = TIER_CAPABILITIES.fetch(tier).dup
      @hybrid_addon_enabled = hybrid_addon_enabled
      @daily_event_count = 0
      @daily_reset_time = self.class.day_start_ms
      @monthly_event_count = 0
      @monthly_reset_time = self.class.month_start_ms
    end

    # Gets the effective closed-loop mode for this tier. Validates the
    # requested mode against tier permissions.
    def effective_mode(requested_mode = nil)
      return @capabilities[:default_mode] unless requested_mode
      return @capabilities[:default_mode] unless @capabilities[:allowed_modes].include?(requested_mode)

      # Pro tier: hybrid requires add-on
      if @tier == "pro" && requested_mode == "hybrid" && @capabilities[:hybrid_is_addon] && !@hybrid_addon_enabled
        return "external"
      end

      requested_mode
    end

    def can_block?
      @capabilities[:can_block]
    end

    # Checks whether the daily event limit has been reached.
    def check_event_limit
      day_start = self.class.day_start_ms
      if @daily_reset_time < day_start
        @daily_event_count = 0
        @daily_reset_time = day_start
      end

      return { allowed: true, remaining: Float::INFINITY } if (@capabilities[:max_events_per_day]).zero?

      remaining = @capabilities[:max_events_per_day] - @daily_event_count
      { allowed: remaining.positive?, remaining: [0, remaining].max }
    end

    # Records an event (for limit tracking).
    def record_event
      @daily_event_count += 1
    end

    # Checks whether a specific feature is available for this tier.
    def has_feature?(feature)
      value = @capabilities[feature.to_sym]
      case value
      when true, false then value
      when Numeric then true
      when Array then !value.empty?
      else false
      end
    end

    # Validates a blocking action against tier permissions. Returns an
    # error message if not allowed, nil if allowed.
    def validate_block_action(_action)
      return nil if @capabilities[:can_block]

      "Blocking is not available on the #{@tier} tier. Upgrade to Pro or Enterprise to enable blocking."
    end

    # Validates a mode selection against tier permissions. Returns an
    # error message if not allowed, nil if allowed.
    def validate_mode(mode)
      unless @capabilities[:allowed_modes].include?(mode)
        return "The '#{mode}' mode is not available on the #{@tier} tier. " \
               "Allowed modes: #{@capabilities[:allowed_modes].join(', ')}."
      end

      if @tier == "pro" && mode == "hybrid" && @capabilities[:hybrid_is_addon] && !@hybrid_addon_enabled
        return "Hybrid mode requires the hybrid add-on on the Pro tier. Enable it in your subscription settings."
      end

      nil
    end

    # Resets daily/monthly counters — test-only, mirrors the Node source's
    # _reset() (also documented there as @internal/test-only).
    def reset_for_testing!
      @daily_event_count = 0
      @daily_reset_time = 0
      @monthly_event_count = 0
      @monthly_reset_time = 0
    end

    # ── CV-S2: Tiered ICL Capabilities ──────────────────────────

    # Gets the maximum ICL tier available for this subscription.
    # - 0: No ICL (monitor-only)
    # - 1: Tier 1 deterministic rules only
    # - 2: Tier 1 + Tier 2 ML scoring
    # - 3: All tiers + air-gap + custom rules
    def max_icl_tier
      @capabilities[:icl_max_tier]
    end

    def icl_tier_available?(tier)
      @capabilities[:icl_max_tier] >= tier
    end

    def air_gap_enabled?
      @capabilities[:air_gap_enabled]
    end

    def custom_rules_configurable?
      @capabilities[:custom_rules_enabled]
    end

    # ── CV-S3: Monthly Event Quotas ──────────────────────────────

    def check_monthly_quota
      month_start = self.class.month_start_ms
      if @monthly_reset_time < month_start
        @monthly_event_count = 0
        @monthly_reset_time = month_start
      end

      limit = @capabilities[:max_events_per_month]
      return { allowed: true, remaining: Float::INFINITY, limit: 0 } if limit.zero?

      remaining = limit - @monthly_event_count
      { allowed: remaining.positive?, remaining: [0, remaining].max, limit: limit }
    end

    def record_monthly_event
      @monthly_event_count += 1
    end

    # Gets monthly usage stats for the telemetry heartbeat.
    def monthly_usage
      limit = @capabilities[:max_events_per_month]
      {
        used: @monthly_event_count,
        limit: limit,
        percent_used: limit.positive? ? ((@monthly_event_count.to_f / limit) * 100).round : 0,
      }
    end

    # ── CV-S4/S5/S6: Platform Feature Checks ────────────────────

    # CV-S4: ICL mode can only log to console/filesystem.
    def platform_alerts?
      @capabilities[:platform_alerts]
    end

    # CV-S5: ICL maintains per-instance state only.
    def shared_state?
      @capabilities[:shared_state]
    end

    # CV-S6: ICL provides raw logs but no compliance formatting.
    def compliance_evidence?
      @capabilities[:compliance_evidence]
    end

    # ── S15: Usage Metering Persistence ─────────────────────────

    # Snapshots mutable state for persistence across restarts. Caller
    # should serialize to JSON and store in DB/file.
    def to_snapshot
      TierGateSnapshot.new(
        tier: @tier, hybrid_addon_enabled: @hybrid_addon_enabled, daily_event_count: @daily_event_count,
        daily_reset_time: @daily_reset_time, monthly_event_count: @monthly_event_count,
        monthly_reset_time: @monthly_reset_time, snapshot_timestamp: (Time.now.to_f * 1000).to_i
      )
    end

    # Restores state from a previously saved snapshot. Ignores the
    # snapshot's counters if the tier has changed or if they are stale
    # (past their reset boundary).
    def self.from_snapshot(snapshot, hybrid_addon_enabled: nil)
      gate = new(
        snapshot.tier,
        hybrid_addon_enabled: snapshot.hybrid_addon_enabled.nil? ? hybrid_addon_enabled : snapshot.hybrid_addon_enabled
      )

      if snapshot.daily_reset_time >= day_start_ms
        gate.instance_variable_set(:@daily_event_count, snapshot.daily_event_count)
        gate.instance_variable_set(:@daily_reset_time, snapshot.daily_reset_time)
      end

      if snapshot.monthly_reset_time >= month_start_ms
        gate.instance_variable_set(:@monthly_event_count, snapshot.monthly_event_count)
        gate.instance_variable_set(:@monthly_reset_time, snapshot.monthly_reset_time)
      end

      gate
    end

    def self.day_start_ms(time = Time.now)
      Time.new(time.year, time.month, time.day, 0, 0, 0, time.utc_offset).to_i * 1000
    end

    def self.month_start_ms(time = Time.now)
      Time.new(time.year, time.month, 1, 0, 0, 0, time.utc_offset).to_i * 1000
    end
  end
end
