# frozen_string_literal: true

require_relative "test_helper"

# InternalClosedLoopEngine (TODO 407 port): internal-mode decision engine,
# ported from internal-closed-loop-engine.ts, mirroring the substance of
# this session's Python test suite
# (devfortress-python/tests/test_internal_closed_loop_engine.py).
class InternalClosedLoopEngineTest < Minitest::Test
  Request = DevFortress::InternalClosedLoopEngine::Request

  def req(**kwargs)
    base = { ip: "203.0.113.5", method: "GET", path: "/" }
    Request.new(**base.merge(kwargs))
  end

  # ── Tier 1 rule matching ──────────────────────────────────────────

  def test_sql_injection_blocks_via_or_1_equals_1
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/products", query: "search=' OR 1=1 --"))
    assert_equal :block, result.decision
    assert_includes result.matched_rules, "sql_injection"
    assert_equal 1, result.tier
  end

  def test_sql_injection_blocks_via_drop_table
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/products", query: "id=1; DROP TABLE users"))
    assert_equal :block, result.decision
    assert_includes result.matched_rules, "sql_injection"
  end

  def test_sql_injection_blocks_via_union_select
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/search", query: "UNION SELECT password FROM users"))
    assert_equal :block, result.decision
    assert_includes result.matched_rules, "sql_injection"
  end

  def test_clean_request_allowed
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/products", query: "search=laptop"))
    assert_equal :allow, result.decision
    assert_equal [], result.matched_rules
    assert_equal 0, result.score
  end

  def test_literal_percent_not_false_positived
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/products", query: "discount=50%"))
    assert_equal :allow, result.decision
  end

  def test_xss_blocks
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/comment", query: "text=<script>alert(1)</script>"))
    assert_equal :block, result.decision
    assert_includes result.matched_rules, "xss_attempt"
  end

  def test_path_traversal_blocks
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/files/../../etc/passwd"))
    assert_equal :block, result.decision
    assert_includes result.matched_rules, "path_traversal"
  end

  def test_scanner_user_agent_blocks
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/", user_agent: "sqlmap/1.7"))
    assert_equal :block, result.decision
    assert_includes result.matched_rules, "scanner_detected"
  end

  def test_sensitive_file_access_blocks
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/.env"))
    assert_equal :block, result.decision
    assert_includes result.matched_rules, "sensitive_file_access"
  end

  def test_credential_stuffing_rate_limits
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(method: "POST", path: "/api/login"))
    assert_equal :rate_limit, result.decision
    assert_includes result.matched_rules, "credential_stuffing_pattern"
  end

  def test_agent_unsanctioned_tool_quarantines
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(agent_id: "agent-1", tool_name: "shell_exec"))
    assert_equal :quarantine, result.decision
    assert_includes result.matched_rules, "agent_unsanctioned_tool"
    assert engine.agent_quarantined?("agent-1")
  end

  # ── Pre-check (already-blocked) short-circuit ────────────────────

  def test_blocked_ip_short_circuits_before_rules
    engine = DevFortress::InternalClosedLoopEngine.new
    engine.block_ip("203.0.113.5", "manual_block")
    result = engine.evaluate(req(path: "/anything"))
    assert_equal :block, result.decision
    assert_equal ["ip_blocked:manual_block"], result.matched_rules
  end

  def test_unblock_ip_allows_again
    engine = DevFortress::InternalClosedLoopEngine.new
    engine.block_ip("203.0.113.5", "test")
    engine.unblock_ip("203.0.113.5")
    result = engine.evaluate(req(path: "/products"))
    assert_equal :allow, result.decision
  end

  def test_block_action_also_blocks_session_and_agent
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/.env", session_id: "sess-1", agent_id: "agent-9"))
    assert_equal :block, result.decision
    action_types = result.actions.map(&:type)
    assert_includes action_types, :block_ip
    assert_includes action_types, :block_session
    assert_includes action_types, :quarantine_agent
  end

  # ── Rate limiting ─────────────────────────────────────────────────

  def test_rate_limit_triggers_after_max_requests
    engine = DevFortress::InternalClosedLoopEngine.new(rate_limit_max: 3, rate_limit_window_seconds: 60.0)
    3.times do
      result = engine.evaluate(req(path: "/products", query: "p=1"))
      assert_equal :allow, result.decision
    end
    result = engine.evaluate(req(path: "/products", query: "p=1"))
    assert_equal :rate_limit, result.decision
    assert_equal ["rate_limit_exceeded"], result.matched_rules
  end

  # ── Tier 2: unimplemented/pass-through by default ────────────────

  def test_tier2_scorer_unset_by_default_skips_tier2
    engine = DevFortress::InternalClosedLoopEngine.new
    result = engine.evaluate(req(path: "/products", query: "p=1"))
    assert_equal :allow, result.decision
    assert_equal 1, result.tier # never reaches tier 2 scoring at all
  end

  def test_tier2_scorer_when_supplied_can_block
    scorer = ->(_req) { 90.0 }
    engine = DevFortress::InternalClosedLoopEngine.new(tier2_scorer: scorer)
    result = engine.evaluate(req(path: "/products", query: "p=1"))
    assert_equal :block, result.decision
    assert_equal 2, result.tier
    assert_equal ["tier2_ml_score"], result.matched_rules
  end

  def test_tier2_scorer_elevated_rate_limits_without_blocking
    scorer = ->(_req) { 70.0 }
    engine = DevFortress::InternalClosedLoopEngine.new(tier2_scorer: scorer)
    result = engine.evaluate(req(path: "/products", query: "p=1"))
    assert_equal :rate_limit, result.decision
    assert_equal 2, result.tier
  end

  def test_tier2_scorer_can_be_any_callable_object
    scorer_obj = Object.new
    def scorer_obj.call(_req)
      95
    end
    engine = DevFortress::InternalClosedLoopEngine.new(tier2_scorer: scorer_obj)
    result = engine.evaluate(req(path: "/products", query: "p=1"))
    assert_equal :block, result.decision
  end

  # ── Tier 3: relay callback (hybrid mode only) ────────────────────

  def test_relay_not_called_when_external_relay_disabled
    calls = []
    engine = DevFortress::InternalClosedLoopEngine.new(on_relay: ->(result, _req) { calls << result })
    engine.evaluate(req(path: "/.env"))
    assert_empty calls
  end

  def test_relay_called_for_flagged_decision_when_enabled
    calls = []
    engine = DevFortress::InternalClosedLoopEngine.new(
      enable_external_relay: true,
      on_relay: ->(result, _req) { calls << result },
    )
    # "/.env" matches both path_traversal (score 90) and
    # sensitive_file_access (score 85) in Node's own pattern set
    # (path_traversal's own "(/\.env|/\.git|/\.ssh)" sub-pattern overlaps
    # sensitive_file_access) — not a porting bug, reproduced deliberately,
    # same overlap the Python port found and documented.
    engine.evaluate(req(path: "/.env"))
    assert_equal 1, calls.length
    assert_equal %w[path_traversal sensitive_file_access], calls[0].matched_rules
  end

  def test_relay_not_called_for_allowed_decision
    calls = []
    engine = DevFortress::InternalClosedLoopEngine.new(
      enable_external_relay: true,
      on_relay: ->(result, _req) { calls << result },
    )
    engine.evaluate(req(path: "/products"))
    assert_empty calls
  end

  # ── Fail mode ─────────────────────────────────────────────────────

  def test_fail_closed_blocks_on_rule_error_is_contained_per_rule
    engine = DevFortress::InternalClosedLoopEngine.new(fail_mode: :closed)
    broken = DevFortress::InternalClosedLoopEngine::Rule.new(
      name: "broken", description: "x", severity: "low", score: 1, decision: :allow,
      match: ->(_req) { raise "boom" }, enabled: true,
    )
    engine.add_rule(broken)
    # Individual rule errors are swallowed per-rule (matching Node), not
    # escalated to the top-level fail-mode handler — #evaluate must not
    # raise.
    result = engine.evaluate(req(path: "/products"))
    assert_equal :allow, result.decision
  end

  def test_fail_closed_on_uncaught_top_level_error
    engine = DevFortress::InternalClosedLoopEngine.new(fail_mode: :closed)
    engine.stub :check_blocked, ->(_req, _now) { raise "boom" } do
      result = engine.evaluate(req(path: "/products"))
      assert_equal :block, result.decision
      assert_equal 100, result.score
      assert_equal ["fail_closed_error"], result.matched_rules
    end
  end

  def test_fail_open_on_uncaught_top_level_error
    engine = DevFortress::InternalClosedLoopEngine.new(fail_mode: :open)
    engine.stub :check_blocked, ->(_req, _now) { raise "boom" } do
      result = engine.evaluate(req(path: "/products"))
      assert_equal :allow, result.decision
      assert_equal 0, result.score
      assert_equal ["fail_open_error"], result.matched_rules
    end
  end

  # ── Client wiring: mode selection, observe(), is_blocked?() ──────

  def test_client_external_mode_observe_is_noop
    client = DevFortress::Client.new("vx_live_test_vector_key_do_not_use", mode: "external")
    assert_nil client.internal_engine
    assert_nil client.observe(req(path: "/.env"))
    refute client.is_blocked?("203.0.113.5")
  end

  def test_client_internal_mode_observe_blocks_attack
    client = DevFortress::Client.new("vx_live_test_vector_key_do_not_use", mode: "internal")
    refute_nil client.internal_engine
    result = client.observe(req(path: "/.env"))
    refute_nil result
    assert result[:flagged]
    assert_equal :block, result[:decision]
    assert client.is_blocked?("203.0.113.5")
  end

  def test_client_internal_mode_observe_allows_clean_request
    client = DevFortress::Client.new("vx_live_test_vector_key_do_not_use", mode: "internal")
    result = client.observe(req(path: "/products", query: "q=laptop"))
    assert_nil result
  end

  def test_client_hybrid_mode_blocks_via_internal_first
    client = DevFortress::Client.new("vx_live_test_vector_key_do_not_use", mode: "hybrid")
    refute_nil client.circuit_breaker
    result = client.observe(req(path: "/.env"))
    refute_nil result
    assert result[:flagged]
  end

  def test_client_hybrid_mode_allows_clean_request_and_keeps_circuit_closed
    client = DevFortress::Client.new("vx_live_test_vector_key_do_not_use", mode: "hybrid")
    result = client.observe(req(path: "/products", query: "q=laptop"))
    assert_nil result
    assert_equal :closed, client.circuit_breaker.state
  end

  def test_client_hybrid_mode_relays_flagged_decision_exactly_once
    transport = ScriptedTransport.new([DevFortress::TransportResponse.new(status_code: 200, body: "{}")])
    client = DevFortress::Client.new(
      "vx_live_test_vector_key_do_not_use", "http://platform.test/api/events/ingest",
      transport: transport, batch_size: 1, mode: "hybrid",
    )
    client.observe(req(path: "/.env"))
    # The relay enqueues via track_event (batch_size: 1 auto-flushes), so
    # exactly one delivery attempt reaches the transport — not two (no
    # double-billing, matching Node's TODO-210 fix and the Python port).
    assert_equal 1, transport.requests.length
  end
end
