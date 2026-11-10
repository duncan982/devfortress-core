# frozen_string_literal: true

require_relative "test_helper"

class CircuitBreakerTest < Minitest::Test
  def test_starts_closed_and_allows_external_calls
    breaker = DevFortress::PlatformCircuitBreaker.new
    assert_equal :closed, breaker.state
    assert breaker.should_call_external?
  end

  def test_opens_after_consecutive_failures
    transitions = []
    breaker = DevFortress::PlatformCircuitBreaker.new(
      failure_threshold: 3,
      on_state_change: ->(from, to, _reason) { transitions << "#{from}->#{to}" }
    )

    2.times { breaker.record_failure }
    assert_equal :closed, breaker.state

    breaker.record_failure
    assert_equal :open, breaker.state
    assert_equal ["closed->open"], transitions
    refute breaker.should_call_external?
  end

  def test_half_open_after_recovery_time_elapsed
    breaker = DevFortress::PlatformCircuitBreaker.new(failure_threshold: 1, recovery_time_seconds: 0.01)
    breaker.record_failure
    sleep 0.02

    assert breaker.should_call_external?
    assert_equal :half_open, breaker.state
  end

  def test_half_open_success_closes_circuit
    breaker = DevFortress::PlatformCircuitBreaker.new(failure_threshold: 1, recovery_time_seconds: 0.01)
    breaker.record_failure
    sleep 0.02
    breaker.should_call_external?

    breaker.record_success
    assert_equal :closed, breaker.state
  end

  def test_half_open_failure_reopens_circuit
    breaker = DevFortress::PlatformCircuitBreaker.new(failure_threshold: 1, recovery_time_seconds: 0.01)
    breaker.record_failure
    sleep 0.02
    breaker.should_call_external?

    breaker.record_failure
    assert_equal :open, breaker.state
  end

  def test_reset_forces_closed_and_clears_failures
    breaker = DevFortress::PlatformCircuitBreaker.new(failure_threshold: 1)
    breaker.record_failure
    assert_equal :open, breaker.state

    breaker.reset
    assert_equal :closed, breaker.state
    assert_equal 0, breaker.diagnostics.failure_count
  end

  def test_rules_become_stale_after_threshold
    breaker = DevFortress::PlatformCircuitBreaker.new(failure_threshold: 1)
    breaker.record_failure

    breaker.instance_variable_set(:@stale_since, Time.now - DevFortress::PlatformCircuitBreaker::STALE_THRESHOLD_SECONDS - 1)

    assert breaker.rules_stale?
    assert breaker.diagnostics.rules_stale
  end

  def test_success_resets_stale_tracking
    breaker = DevFortress::PlatformCircuitBreaker.new(failure_threshold: 1, recovery_time_seconds: 0.01)
    breaker.record_failure
    sleep 0.02
    breaker.should_call_external?
    breaker.record_success

    refute breaker.rules_stale?
  end
end
