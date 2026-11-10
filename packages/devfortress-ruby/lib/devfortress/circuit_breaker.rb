# frozen_string_literal: true

module DevFortress
  # Platform Circuit Breaker.
  #
  # Mirrors packages/devfortress-sdk/src/circuit-breaker.ts. Monitors
  # connectivity to the DevFortress platform and provides automatic
  # failover from external to internal closed-loop mode.
  #
  # Three states:
  #   :closed    - Platform is reachable, external CL is active
  #   :open      - Platform is unreachable, internal CL takes over
  #   :half_open - Testing if the platform has recovered
  #
  # Transition rules:
  #   closed -> open:      After failure_threshold consecutive failures
  #   open -> half_open:   After recovery_time_seconds elapsed
  #   half_open -> closed: First successful call
  #   half_open -> open:   First failed call
  class PlatformCircuitBreaker
    # Rules older than 5 minutes without a platform sync are
    # considered stale.
    STALE_THRESHOLD_SECONDS = 300

    Diagnostics = Struct.new(
      :state, :failure_count, :last_failure_time, :seconds_until_recovery_attempt,
      :rules_stale, :stale_duration_seconds,
      keyword_init: true
    )

    def initialize(failure_threshold: 3, recovery_time_seconds: 60, on_state_change: nil)
      @failure_threshold = failure_threshold
      @recovery_time_seconds = recovery_time_seconds
      @on_state_change = on_state_change

      @state = :closed
      @failure_count = 0
      @last_failure_time = Time.at(0)
      # Tracks when internal rules became stale (circuit opened).
      @stale_since = nil
      @mutex = Mutex.new
    end

    # Returns whether external platform calls should be attempted
    # (true if closed or half-open).
    def should_call_external?
      @mutex.synchronize do
        case @state
        when :closed
          true
        when :open
          if Time.now - @last_failure_time >= @recovery_time_seconds
            transition(:half_open, "recovery_timeout_elapsed")
            true # allow one test call
          else
            false
          end
        else # :half_open
          true
        end
      end
    end

    # Records a successful external call.
    def record_success
      @mutex.synchronize do
        transition(:closed, "test_call_succeeded") if @state == :half_open
        @failure_count = 0
        @stale_since = nil
      end
    end

    # Records a failed external call.
    def record_failure
      @mutex.synchronize do
        @failure_count += 1
        @last_failure_time = Time.now

        if @state == :half_open
          transition(:open, "test_call_failed")
        elsif @state == :closed && @failure_count >= @failure_threshold
          transition(:open, "consecutive_failures")
        end
      end
    end

    # Returns the current circuit state.
    def state
      @mutex.synchronize { @state }
    end

    # Returns diagnostics info.
    def diagnostics
      @mutex.synchronize do
        seconds_until_recovery =
          if @state == :open
            elapsed = Time.now - @last_failure_time
            elapsed < @recovery_time_seconds ? @recovery_time_seconds - elapsed : 0
          else
            0
          end

        stale_duration = @stale_since ? Time.now - @stale_since : 0

        Diagnostics.new(
          state: @state, failure_count: @failure_count, last_failure_time: @last_failure_time,
          seconds_until_recovery_attempt: seconds_until_recovery,
          rules_stale: stale_duration > STALE_THRESHOLD_SECONDS,
          stale_duration_seconds: stale_duration
        )
      end
    end

    # Forces the circuit breaker back to the closed state.
    def reset
      @mutex.synchronize do
        transition(:closed, "manual_reset")
        @failure_count = 0
        @last_failure_time = Time.at(0)
        @stale_since = nil
      end
    end

    # Returns whether internal rules are stale (no platform sync for
    # longer than STALE_THRESHOLD_SECONDS).
    def rules_stale?
      @mutex.synchronize { !@stale_since.nil? && (Time.now - @stale_since) > STALE_THRESHOLD_SECONDS }
    end

    private

    def transition(to, reason)
      from = @state
      return if from == to

      @state = to

      @stale_since = Time.now if to == :open && @stale_since.nil?

      return unless @on_state_change

      begin
        @on_state_change.call(from, to, reason)
      rescue StandardError
        # Callback errors should not break the circuit breaker.
      end
    end
  end
end
