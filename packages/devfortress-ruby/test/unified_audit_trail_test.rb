# frozen_string_literal: true

require_relative "test_helper"

class UnifiedAuditTrailTest < Minitest::Test
  def make_entry(overrides = {})
    base = {
      event_id: "evt_#{rand(36**6).to_s(36)}",
      timestamp: Time.now,
      source: :internal,
      tier: 1,
      decision: "allow",
      score: 10,
      severity: "low",
      latency_ms: 0.5,
      ip: "192.168.1.1",
      path: "/api/test",
      method: "GET",
      matched_rules: [],
    }
    DevFortress::UnifiedAuditTrail::Entry.new(**base.merge(overrides))
  end

  def setup
    @audit = DevFortress::UnifiedAuditTrail.new(debug: false)
  end

  # ── Record & Query ────────────────────────────────────────

  def test_record_and_retrieve_entries
    @audit.record(make_entry(ip: "10.0.0.1"))
    @audit.record(make_entry(ip: "10.0.0.2"))
    assert_equal 2, @audit.query.length
  end

  def test_filter_by_source
    @audit.record(make_entry(source: :internal))
    @audit.record(make_entry(source: :external))
    @audit.record(make_entry(source: :hybrid))

    assert_equal 1, @audit.query(source: :internal).length
    assert_equal 1, @audit.query(source: :external).length
    assert_equal 1, @audit.query(source: :hybrid).length
  end

  def test_filter_by_decision
    @audit.record(make_entry(decision: "allow"))
    @audit.record(make_entry(decision: "block"))
    @audit.record(make_entry(decision: "rate_limit"))

    assert_equal 1, @audit.query(decision: "block").length
  end

  def test_filter_by_ip
    @audit.record(make_entry(ip: "1.2.3.4"))
    @audit.record(make_entry(ip: "5.6.7.8"))
    assert_equal 1, @audit.query(ip: "1.2.3.4").length
  end

  def test_filter_by_user_id
    @audit.record(make_entry(user_id: "user-1"))
    @audit.record(make_entry(user_id: "user-2"))
    assert_equal 1, @audit.query(user_id: "user-1").length
  end

  def test_filter_by_agent_id
    @audit.record(make_entry(agent_id: "agent-A"))
    @audit.record(make_entry(agent_id: "agent-B"))
    assert_equal 1, @audit.query(agent_id: "agent-A").length
  end

  def test_filter_by_min_score
    @audit.record(make_entry(score: 20))
    @audit.record(make_entry(score: 60))
    @audit.record(make_entry(score: 90))
    assert_equal 2, @audit.query(min_score: 50).length
  end

  def test_filter_by_since
    now = Time.now
    @audit.record(make_entry(timestamp: now - 10))
    @audit.record(make_entry(timestamp: now - 5))
    @audit.record(make_entry(timestamp: now))
    assert_equal 2, @audit.query(since: now - 7).length
  end

  def test_limit_results
    50.times { @audit.record(make_entry) }
    assert_equal 10, @audit.query(limit: 10).length
  end

  def test_combine_multiple_filters
    @audit.record(make_entry(source: :internal, decision: "block", score: 85))
    @audit.record(make_entry(source: :internal, decision: "allow", score: 10))
    @audit.record(make_entry(source: :external, decision: "block", score: 90))

    results = @audit.query(source: :internal, decision: "block", min_score: 80)
    assert_equal 1, results.length
    assert_equal 85, results[0].score
  end

  # ── Statistics ────────────────────────────────────────────

  def test_counts_decisions_by_source
    @audit.record(make_entry(source: :internal))
    @audit.record(make_entry(source: :internal))
    @audit.record(make_entry(source: :external))
    @audit.record(make_entry(source: :hybrid))

    stats = @audit.get_stats
    assert_equal 4, stats[:total]
    assert_equal 2, stats[:internal_decisions]
    assert_equal 1, stats[:external_decisions]
    assert_equal 1, stats[:hybrid_decisions]
  end

  def test_counts_blocks_allows_rate_limits
    @audit.record(make_entry(decision: "block"))
    @audit.record(make_entry(decision: "allow"))
    @audit.record(make_entry(decision: "allow"))
    @audit.record(make_entry(decision: "rate_limit"))

    stats = @audit.get_stats
    assert_equal 1, stats[:total_blocks]
    assert_equal 2, stats[:total_allows]
    assert_equal 1, stats[:total_rate_limits]
  end

  def test_tracks_fallback_events
    @audit.record(make_entry(source: :hybrid, fallback_mode: true))
    @audit.record(make_entry(source: :hybrid, fallback_mode: false))
    assert_equal 1, @audit.get_stats[:fallback_events]
  end

  def test_computes_average_latencies
    @audit.record(make_entry(source: :internal, latency_ms: 0.5))
    @audit.record(make_entry(source: :internal, latency_ms: 1.5))
    @audit.record(make_entry(source: :external, latency_ms: 100))
    @audit.record(make_entry(source: :external, latency_ms: 200))

    stats = @audit.get_stats
    assert_equal 1, stats[:avg_internal_latency_ms]
    assert_equal 150, stats[:avg_external_latency_ms]
  end

  # ── Decision Distribution ─────────────────────────────────

  def test_decision_distribution_returns_source_decision_counts
    @audit.record(make_entry(source: :internal, decision: "allow"))
    @audit.record(make_entry(source: :internal, decision: "allow"))
    @audit.record(make_entry(source: :internal, decision: "block"))
    @audit.record(make_entry(source: :external, decision: "allow"))

    dist = @audit.get_decision_distribution
    assert_equal 2, dist["internal:allow"]
    assert_equal 1, dist["internal:block"]
    assert_equal 1, dist["external:allow"]
  end

  # ── Latency Histogram ─────────────────────────────────────

  def test_latency_histogram_buckets_correctly
    @audit.record(make_entry(latency_ms: 0.3))
    @audit.record(make_entry(latency_ms: 2))
    @audit.record(make_entry(latency_ms: 30))
    @audit.record(make_entry(latency_ms: 100))
    @audit.record(make_entry(latency_ms: 500))
    @audit.record(make_entry(latency_ms: 2000))

    hist = @audit.get_latency_histogram
    assert_equal 1, hist[:under_1ms]
    assert_equal 1, hist[:under_5ms]
    assert_equal 1, hist[:under_50ms]
    assert_equal 1, hist[:under_200ms]
    assert_equal 1, hist[:under_1s]
    assert_equal 1, hist[:over_1s]
  end

  # ── Export ────────────────────────────────────────────────

  def test_export_json_exports_all_entries
    @audit.record(make_entry(ip: "1.1.1.1"))
    @audit.record(make_entry(ip: "2.2.2.2"))

    parsed = JSON.parse(@audit.export_json)
    assert_equal 2, parsed.length
  end

  def test_export_json_exports_entries_since_timestamp
    now = Time.now
    @audit.record(make_entry(timestamp: now - 10))
    @audit.record(make_entry(timestamp: now))

    parsed = JSON.parse(@audit.export_json(since: now - 5))
    assert_equal 1, parsed.length
  end

  # ── Bounded Storage ───────────────────────────────────────

  def test_bounded_storage_evicts_oldest_10pct_when_max_entries_reached
    small = DevFortress::UnifiedAuditTrail.new(max_entries: 100)
    110.times { |i| small.record(make_entry(event_id: "evt_#{i}")) }

    stats = small.get_stats
    assert_operator stats[:total], :<=, 110
    assert_operator stats[:total], :>, 90
  end

  # ── Reset ─────────────────────────────────────────────────

  def test_reset_clears_all_entries_and_stats
    @audit.record(make_entry)
    @audit.record(make_entry)
    assert_equal 2, @audit.get_stats[:total]

    @audit.reset
    assert_equal 0, @audit.get_stats[:total]
    assert_equal 0, @audit.get_stats[:internal_decisions]
  end

  # ── onEntry Callback ──────────────────────────────────────

  def test_on_entry_callback_fires_for_each_recorded_entry
    received = []
    tracked = DevFortress::UnifiedAuditTrail.new(on_entry: ->(e) { received << e })
    tracked.record(make_entry)
    tracked.record(make_entry)
    assert_equal 2, received.length
  end

  def test_on_entry_callback_survives_errors
    error_audit = DevFortress::UnifiedAuditTrail.new(on_entry: ->(_e) { raise "callback error" })
    error_audit.record(make_entry) # must not raise
    assert_equal 1, error_audit.get_stats[:total]
  end

  # ── Dedup/merge (S27) ─────────────────────────────────────

  def test_dedup_merges_external_over_internal_within_window
    @audit.record(make_entry(event_id: "evt_dup", source: :internal, decision: "allow"))
    @audit.record(make_entry(event_id: "evt_dup", source: :external, decision: "block"))

    results = @audit.query
    assert_equal 1, results.length
    assert_equal :hybrid, results[0].source
    assert_equal "block", results[0].decision
  end

  def test_dedup_skips_duplicate_internal_without_merging
    @audit.record(make_entry(event_id: "evt_dup2", source: :internal, decision: "allow"))
    @audit.record(make_entry(event_id: "evt_dup2", source: :internal, decision: "block"))

    results = @audit.query
    assert_equal 1, results.length
    assert_equal "allow", results[0].decision
  end
end
