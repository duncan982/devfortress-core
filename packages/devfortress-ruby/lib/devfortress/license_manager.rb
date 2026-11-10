# frozen_string_literal: true

require "openssl"
require "json"
require "thread"

require_relative "signer"
require_relative "transport"
require_relative "version"

module DevFortress
  # License Manager — CV-M1, CV-M4, CV-M7.
  #
  # Implements:
  # - CV-M1: Server-side license validation with a 24h check interval and
  #   a 72h grace period before degrading to monitor-only mode.
  # - CV-M4: ML model staleness detection (30 days without a platform sync).
  # - CV-M7: SDK anti-tampering HMAC integrity hash.
  #
  # This is the client-side half of the fix for the bug class TODO 321
  # already fixed on the platform: license-check/heartbeat calls silently
  # 404ing and causing silent monitor-only degradation. The platform's
  # /api/sdk/license-check and /api/sdk/heartbeat endpoints already exist
  # (TODO 321); this class only talks to them — no new platform route.
  # Mirrors packages/devfortress-sdk/src/license-manager.ts.
  #
  # Every check is logged visibly (info/warn to $stderr, debug to $stdout
  # when debug: true) — never silent — matching TODO 321's fix intent: a
  # failing license check must be loud, not invisible.
  #
  # A background periodic-check thread is only started if
  # check_interval_seconds is given and positive (mirrors Client's own
  # opt-in flush_interval convention) — #check_license is always callable
  # directly, which is what the test suite uses.
  class LicenseManager
    DEFAULT_CHECK_INTERVAL_SECONDS = 24 * 60 * 60       # 24 hours
    DEFAULT_GRACE_PERIOD_SECONDS = 72 * 60 * 60         # 72 hours
    DEFAULT_MODEL_EXPIRY_SECONDS = 30 * 24 * 60 * 60    # 30 days
    DEFAULT_TIMEOUT_SECONDS = 10

    CRITICAL_PATHS = %w[
      DevFortress.observe
      DevFortress.isBlocked
      LicenseManager.checkLicense
      InternalClosedLoopEngine.evaluate
      TierGate.checkEventLimit
    ].join("|").freeze

    LicenseState = Struct.new(
      :valid, :tier, :last_checked_at, :consecutive_failures, :degraded, :degradation_reason,
      keyword_init: true
    )

    ModelState = Struct.new(:last_synced_at, :model_version, :expired, keyword_init: true)

    def initialize(
      api_key:,
      endpoint:,
      check_interval_seconds: nil,
      grace_period_seconds: DEFAULT_GRACE_PERIOD_SECONDS,
      model_expiry_seconds: DEFAULT_MODEL_EXPIRY_SECONDS,
      integrity_secret: nil,
      debug: false,
      timeout: DEFAULT_TIMEOUT_SECONDS,
      transport: nil
    )
      @api_key = api_key
      @endpoint = endpoint
      @signer = Signer.new(api_key)
      @check_interval_seconds = check_interval_seconds
      @grace_period_seconds = grace_period_seconds || DEFAULT_GRACE_PERIOD_SECONDS
      @model_expiry_seconds = model_expiry_seconds || DEFAULT_MODEL_EXPIRY_SECONDS
      @integrity_secret = integrity_secret
      @debug = debug
      @timeout = timeout
      @transport = transport || Transport.new

      @mutex = Mutex.new
      @license_state = LicenseState.new(
        valid: false, tier: "starter", last_checked_at: 0, consecutive_failures: 0,
        degraded: false, degradation_reason: nil
      )
      @model_state = ModelState.new(last_synced_at: now_ms, model_version: "embedded-v1", expired: false)

      @check_thread = nil
      @stop = false
      @stop_cv = ConditionVariable.new
      @initialized = false
    end

    # ── CV-M1: License Validation ──────────────────────────────

    # Performs an initial license check and, if check_interval_seconds was
    # given and positive, starts a background thread for periodic checks.
    # Safe to call more than once (a no-op after the first call).
    def init
      return license_state if @initialized

      check_license

      @check_thread = Thread.new { periodic_check } if @check_interval_seconds && @check_interval_seconds.positive?

      @initialized = true
      license_state
    end

    # Performs one license check against the platform. On failure, tracks
    # consecutive failures and degrades to monitor-only once the grace
    # period has elapsed since the last success.
    def check_license
      url = "#{@endpoint}/api/sdk/license-check"
      body = JSON.generate({ "sdkVersion" => VERSION, "timestamp" => now_ms, "integrity" => compute_integrity_hash })
      headers = sign_headers(url, body)

      begin
        response = @transport.send_request("POST", url, headers, body, @timeout)

        if response.status_code >= 200 && response.status_code < 300
          data = JSON.parse(response.body.to_s)
          @mutex.synchronize do
            @license_state = LicenseState.new(
              valid: true,
              tier: data["tier"] || @license_state.tier,
              last_checked_at: now_ms,
              consecutive_failures: 0,
              degraded: false,
              degradation_reason: nil
            )
            if data["modelVersion"]
              @model_state = ModelState.new(last_synced_at: now_ms, model_version: data["modelVersion"],
                                             expired: false)
            end
          end
          log(:info, "License validated: tier=#{@license_state.tier}")
        elsif [402, 403].include?(response.status_code)
          @mutex.synchronize do
            @license_state = LicenseState.new(
              valid: false, tier: "starter", last_checked_at: now_ms,
              consecutive_failures: @license_state.consecutive_failures + 1,
              degraded: true, degradation_reason: "License rejected: HTTP #{response.status_code}"
            )
          end
          log(:warn, "License rejected: HTTP #{response.status_code}")
        else
          handle_check_failure("HTTP #{response.status_code}")
        end
      rescue StandardError => e
        handle_check_failure(e.message)
      end

      license_state
    end

    def license_state
      @mutex.synchronize { @license_state.dup }
    end

    def degraded?
      @mutex.synchronize { @license_state.degraded }
    end

    # Checks whether a specific capability is available given current
    # license state. action: "block", "rate_limit" or "observe".
    def can_perform_action?(action)
      return true if action.to_s == "observe"

      state = @mutex.synchronize { @license_state }
      return false if state.degraded
      return true if !state.valid && state.last_checked_at.zero?

      state.valid
    end

    # ── CV-M4: ML Model Expiry ─────────────────────────────────

    # Checks whether the embedded ML model has expired. If expired (>30
    # days without platform sync), ICL falls back to Tier 1 only.
    def model_expired?
      @mutex.synchronize do
        age_seconds = (now_ms - @model_state.last_synced_at) / 1000.0
        @model_state.expired = age_seconds > @model_expiry_seconds
        @model_state.expired
      end
    end

    def model_state
      expired = model_expired?
      @mutex.synchronize do
        state = @model_state.dup
        state.expired = expired
        state
      end
    end

    # Manually trigger a model sync (called from DevFortress.init or a
    # license-check response that carries a modelVersion).
    def sync_model(model_version)
      @mutex.synchronize do
        @model_state = ModelState.new(last_synced_at: now_ms, model_version: model_version, expired: false)
      end
      log(:info, "ML model synced: version=#{model_version}")
    end

    # ── CV-M7: Anti-Tampering ──────────────────────────────────

    # Computes an HMAC signature over critical SDK code paths. If the SDK
    # distribution has been modified, this hash differs from the expected
    # value on the platform side.
    def compute_integrity_hash
      return "no-integrity-secret" if @integrity_secret.nil? || @integrity_secret.empty?

      OpenSSL::HMAC.hexdigest("SHA256", @integrity_secret, CRITICAL_PATHS + @api_key)[0, 16]
    end

    # Verifies that the SDK has not been tampered with. Returns
    # tampered: true if the integrity hash doesn't match expected_hash.
    def verify_integrity(expected_hash = nil)
      current_hash = compute_integrity_hash
      return { tampered: false, hash: current_hash } unless expected_hash

      { tampered: current_hash != expected_hash, hash: current_hash }
    end

    # ── Cleanup ────────────────────────────────────────────────

    # Stops the periodic check thread (if any) and clean up. Safe to call
    # more than once.
    def destroy
      @mutex.synchronize do
        @stop = true
        @stop_cv.broadcast
      end
      @check_thread&.join
      @check_thread = nil
      @initialized = false
    end

    private

    def periodic_check
      loop do
        stop = @mutex.synchronize do
          @stop_cv.wait(@mutex, @check_interval_seconds)
          @stop
        end
        break if stop

        check_license
      end
    end

    def handle_check_failure(reason)
      @mutex.synchronize do
        @license_state.consecutive_failures += 1
        baseline_time = @license_state.last_checked_at.zero? ? now_ms : @license_state.last_checked_at
        time_since_last_success_ms = now_ms - baseline_time
        grace_period_ms = @grace_period_seconds * 1000

        if time_since_last_success_ms >= grace_period_ms
          @license_state.degraded = true
          @license_state.degradation_reason =
            "License check failed for #{(time_since_last_success_ms / 3_600_000.0).round}h " \
            "(grace period: #{(grace_period_ms / 3_600_000.0).round}h). " \
            "Reason: #{reason}. SDK degraded to monitor-only mode."
          log(:warn, @license_state.degradation_reason)
        else
          remaining_h = ((grace_period_ms - time_since_last_success_ms) / 3_600_000.0).round
          log(:debug, "License check failed (#{reason}), " \
                      "#{@license_state.consecutive_failures} consecutive failures, " \
                      "#{remaining_h}h grace remaining")
        end
      end
    end

    def sign_headers(url, body)
      headers = @signer.sign("POST", Signer.request_target_from_url(url), body)
      headers["Content-Type"] = "application/json"
      headers
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end

    def log(level, message)
      return if level == :debug && !@debug

      prefix = "[DevFortress:License]"
      case level
      when :warn, :error
        warn("#{prefix} #{message}")
      else
        puts("#{prefix} #{message}")
      end
    end
  end
end
