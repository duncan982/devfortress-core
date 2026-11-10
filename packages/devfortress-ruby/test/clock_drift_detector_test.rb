# frozen_string_literal: true

require_relative "test_helper"
require_relative "../lib/devfortress"

# ClockDriftDetector (Invention A18, TODO 419/422): server-authoritative
# clock drift detection, ported from security-extensions.ts.
class ClockDriftDetectorTest < Minitest::Test
  def now_ms
    Time.now.to_f * 1000
  end

  def test_within_acceptable_threshold_is_allowed
    detector = DevFortress::ClockDriftDetector.new
    result = detector.check(now_ms)
    assert result.valid
    assert_equal "LOW", result.severity
    assert_equal "allow", result.action
  end

  def test_suspicious_drift_warns_but_stays_valid
    detector = DevFortress::ClockDriftDetector.new
    result = detector.check(now_ms - 60_000)
    assert result.valid
    assert_equal "MEDIUM", result.severity
    assert_equal "warn", result.action
  end

  def test_high_drift_enforces_server_time
    detector = DevFortress::ClockDriftDetector.new
    result = detector.check(now_ms - 200_000)
    assert result.valid
    assert_equal "HIGH", result.severity
    assert_equal "use_server_time", result.action
  end

  def test_critical_drift_is_rejected
    detector = DevFortress::ClockDriftDetector.new
    result = detector.check(now_ms - 600_000)
    refute result.valid
    assert_equal "CRITICAL", result.severity
    assert_equal "reject", result.action
  end

  def test_ahead_of_server_time_is_also_detected
    detector = DevFortress::ClockDriftDetector.new
    result = detector.check(now_ms + 600_000)
    refute result.valid
    assert_includes result.reason, "ahead"
  end

  def test_custom_thresholds_are_respected
    detector = DevFortress::ClockDriftDetector.new(
      acceptable_threshold_ms: 1_000, suspicious_threshold_ms: 5_000, critical_threshold_ms: 10_000
    )
    assert_equal "warn", detector.check(now_ms - 2_000).action
    assert_equal "reject", detector.check(now_ms - 20_000).action
  end

  def test_drift_trend_requires_at_least_three_samples
    detector = DevFortress::ClockDriftDetector.new
    detector.check(now_ms - 1_000, client_id: "c1")
    detector.check(now_ms - 2_000, client_id: "c1")
    assert_nil detector.get_drift_trend("c1")

    detector.check(now_ms - 3_000, client_id: "c1")
    trend = detector.get_drift_trend("c1")
    refute_nil trend
    assert trend.avg_drift > 0
  end

  def test_drift_trend_detects_increasing_drift
    detector = DevFortress::ClockDriftDetector.new
    [1_000, 1_000, 1_000, 5_000, 5_000, 5_000].each do |drift_ms|
      detector.check(now_ms - drift_ms, client_id: "growing")
    end
    trend = detector.get_drift_trend("growing")
    assert trend.increasing
  end

  def test_history_is_bounded_per_client
    detector = DevFortress::ClockDriftDetector.new
    150.times { detector.check(now_ms, client_id: "busy-client") }
    assert_equal 100, detector.instance_variable_get(:@drift_history)["busy-client"].length
  end

  def test_get_stats_counts_tracked_clients
    detector = DevFortress::ClockDriftDetector.new
    detector.check(now_ms, client_id: "a")
    detector.check(now_ms, client_id: "b")
    detector.check(now_ms) # no client_id — not tracked
    assert_equal({ tracked_clients: 2 }, detector.get_stats)
  end
end
