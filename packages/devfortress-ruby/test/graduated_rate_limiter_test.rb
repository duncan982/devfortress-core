# frozen_string_literal: true

require_relative "test_helper"

class GraduatedRateLimiterTest < Minitest::Test
  def teardown
    @limiter&.destroy
  end

  def test_observation_stage_below_half_limit
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 100)
    result = @limiter.check("alias-1")
    assert_equal :observation, result.stage
    refute result.blocked
  end

  def test_warning_stage_at_half_limit
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 10)
    result = nil
    5.times { result = @limiter.check("alias-1") }
    assert_equal :warning, result.stage
    refute result.blocked
  end

  def test_soft_limit_injects_latency_with_jitter
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 10, soft_limit_base_latency_ms: 2000)
    result = nil
    8.times { result = @limiter.check("alias-1") }
    assert_equal :soft_limit, result.stage
    refute result.blocked
    assert result.injected_latency_ms.positive?
  end

  def test_hard_block_at_limit
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 5)
    result = nil
    5.times { result = @limiter.check("alias-1") }
    assert_equal :hard_block, result.stage
    assert result.blocked
    assert_equal 60, result.cooldown_seconds
  end

  def test_escalating_cooldown_doubles_each_consecutive_block
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 1, initial_cooldown_seconds: 60)

    first = @limiter.check("alias-1")
    assert_equal :hard_block, first.stage
    assert_equal 60, first.cooldown_seconds

    # Force cooldown elapsed and the prior request aged out of the
    # sliding window (as it would by the time a real 60s cooldown
    # elapsed), so the next check records a fresh second consecutive
    # block rather than accumulating ratio from the still-windowed
    # first request.
    entry = @limiter.instance_variable_get(:@entries)["alias-1"]
    entry.cooldown_until = Time.now - 0.01
    entry.timestamps = []

    second = @limiter.check("alias-1")
    assert_equal :hard_block, second.stage
    assert_equal 120, second.cooldown_seconds
  end

  def test_revokes_after_max_consecutive_blocks
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 1, max_consecutive_blocks: 3)
    entries = @limiter.instance_variable_get(:@entries)

    3.times do
      @limiter.check("alias-1")
      entries["alias-1"].cooldown_until = Time.now - 0.01
    end

    result = @limiter.check("alias-1")
    assert_equal :revocation, result.stage
    assert @limiter.revoked?("alias-1")
  end

  def test_revoked_alias_stays_blocked_without_re_revoking
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 100)
    @limiter.revoke_alias("alias-1")
    result = @limiter.check("alias-1")
    assert_equal :revocation, result.stage
    refute result.revoke
  end

  def test_reset_alias_clears_escalation
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 1)
    entries = @limiter.instance_variable_get(:@entries)

    @limiter.check("alias-1")
    entries["alias-1"].cooldown_until = Time.now - 0.01
    entries["alias-1"].timestamps = []
    escalated = @limiter.check("alias-1")
    assert_equal 120, escalated.cooldown_seconds

    @limiter.reset_alias("alias-1")

    result = @limiter.check("alias-1")
    assert_equal 60, result.cooldown_seconds
  end

  def test_per_endpoint_limits_override_default
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 100, endpoint_limits: { "/api/auth/*" => 2 })
    @limiter.check("alias-1", "/api/auth/login")
    result = @limiter.check("alias-1", "/api/auth/login")
    assert_equal 2, result.limit
    assert_equal :hard_block, result.stage
  end

  def test_burst_detection_triggers_hard_block
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 1000, burst_limit: 3)
    result = nil
    4.times { result = @limiter.check("alias-1") }
    assert result.burst_detected
    assert_equal :hard_block, result.stage
  end

  def test_max_entries_evicts_oldest_alias
    @limiter = DevFortress::GraduatedRateLimiter.new(default_limit: 100, max_entries: 2)
    @limiter.check("alias-1")
    @limiter.check("alias-2")
    @limiter.check("alias-3")

    assert_equal 2, @limiter.size
    refute @limiter.instance_variable_get(:@entries).key?("alias-1")
  end
end
