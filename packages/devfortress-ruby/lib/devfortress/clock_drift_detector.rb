# frozen_string_literal: true

module DevFortress
  # Clock Drift Anomaly Detector (Invention A18).
  #
  # Mirrors packages/devfortress-sdk/src/security-extensions.ts's
  # ClockDriftDetector. TODO 419/422 — one of the 20 Node-only claims
  # identified by the 2026-11-02 patent audit; ported to Python and Go in
  # that session, here extended to Ruby.
  #
  # Compares a client-supplied timestamp against server time and
  # classifies the drift into an escalating action: allow, warn (audit
  # with server time), use_server_time (enforce server-authoritative
  # timestamps), or reject (possible timestamp manipulation).
  class ClockDriftDetector
    Result = Struct.new(:valid, :drift_ms, :severity, :action, :reason, keyword_init: true)
    Trend = Struct.new(:avg_drift, :increasing, keyword_init: true)

    MAX_HISTORY_PER_CLIENT = 100

    def initialize(acceptable_threshold_ms: 30_000, suspicious_threshold_ms: 120_000,
                   critical_threshold_ms: 300_000)
      @acceptable_threshold_ms = acceptable_threshold_ms
      @suspicious_threshold_ms = suspicious_threshold_ms
      @critical_threshold_ms = critical_threshold_ms
      @drift_history = {}
    end

    # Check a client timestamp (epoch milliseconds) against server time.
    def check(client_timestamp_ms, client_id: nil)
      server_time_ms = Time.now.to_f * 1000
      drift_ms = (client_timestamp_ms - server_time_ms).abs
      direction = client_timestamp_ms > server_time_ms ? "ahead" : "behind"

      if client_id
        history = (@drift_history[client_id] ||= [])
        history.push(drift_ms)
        history.shift while history.length > MAX_HISTORY_PER_CLIENT
      end

      if drift_ms <= @acceptable_threshold_ms
        Result.new(valid: true, drift_ms: drift_ms, severity: "LOW", action: "allow",
                    reason: "Clock drift #{drift_ms.round}ms (#{direction}) within acceptable range")
      elsif drift_ms <= @suspicious_threshold_ms
        Result.new(valid: true, drift_ms: drift_ms, severity: "MEDIUM", action: "warn",
                    reason: "Clock drift #{drift_ms.round}ms (#{direction}) — suspicious, using server time for audit")
      elsif drift_ms <= @critical_threshold_ms
        Result.new(valid: true, drift_ms: drift_ms, severity: "HIGH", action: "use_server_time",
                    reason: "Clock drift #{drift_ms.round}ms (#{direction}) — enforcing server-authoritative timestamps")
      else
        Result.new(valid: false, drift_ms: drift_ms, severity: "CRITICAL", action: "reject",
                    reason: "Clock drift #{drift_ms.round}ms (#{direction}) exceeds critical threshold — possible timestamp manipulation")
      end
    end

    # Returns the drift trend for a client, or nil if fewer than 3 samples.
    def get_drift_trend(client_id)
      history = @drift_history[client_id]
      return nil if history.nil? || history.length < 3

      avg_drift = history.sum / history.length.to_f
      recent = history.last(3)
      recent_avg = recent.sum / 3.0
      Trend.new(avg_drift: avg_drift, increasing: recent_avg > avg_drift * 1.2)
    end

    def get_stats
      { tracked_clients: @drift_history.size }
    end
  end
end
