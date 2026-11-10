# frozen_string_literal: true

require_relative "test_helper"

# Exercises LicenseManager (CV-M1/M4/M7), TelemetryManager +
# TelemetryRollupBuffer (CV-M2), and TierGate (CV-S2-S6) — newly ported
# from the Node SDK (license-manager.ts, telemetry.ts,
# telemetry-rollup-buffer.ts, tier-gate.ts). Uses ScriptedTransport (see
# test_helper.rb) rather than hitting a live platform.
class LicenseTelemetryTierGateTest < Minitest::Test
  def test_license_manager_resolves_tier_on_successful_check
    transport = ScriptedTransport.new([
      DevFortress::TransportResponse.new(
        status_code: 200, body: JSON.generate({ "tier" => "pro", "modelVersion" => "v7" })
      ),
    ])
    manager = DevFortress::LicenseManager.new(api_key: "df_test_key", endpoint: "https://example.test",
                                               transport: transport)

    state = manager.check_license
    assert state.valid
    assert_equal "pro", state.tier
    assert_equal 0, state.consecutive_failures
    refute state.degraded

    assert_equal "v7", manager.model_state.model_version
    refute manager.model_state.expired

    # TierGate takes the platform-resolved tier as its input — the
    # dependency the brief calls out.
    gate = DevFortress::TierGate.new(state.tier)
    assert_equal "pro", gate.tier
    assert gate.can_block?
  end

  def test_license_manager_degrades_and_logs_visibly_on_check_failure
    transport = ScriptedTransport.new([StandardError.new("platform returned 404")])
    manager = DevFortress::LicenseManager.new(
      api_key: "df_test_key", endpoint: "https://example.test", grace_period_seconds: 0, transport: transport
    )

    out, err = capture_io { manager.check_license }

    state = manager.license_state
    assert state.degraded, "a failed license check past the (zero-length) grace period must degrade, not fail silently"
    assert_match(/degraded to monitor-only mode/, state.degradation_reason)
    assert_equal 1, state.consecutive_failures

    # TODO 321's fix intent: a failing license check must be loud, not
    # invisible — something is written to stdout/stderr, never swallowed.
    assert_match(/License check failed for/, out + err)

    # Degraded mode means monitor-only: observe is still allowed, block/rate_limit are not.
    assert manager.can_perform_action?("observe")
    refute manager.can_perform_action?("block")
    refute manager.can_perform_action?("rate_limit")
  end

  def test_license_manager_integrity_hash_detects_tampering
    manager = DevFortress::LicenseManager.new(api_key: "df_test_key", endpoint: "https://example.test",
                                               integrity_secret: "shh")
    tampered = manager.verify_integrity("not-the-real-hash")
    assert tampered[:tampered]

    matching = manager.verify_integrity(manager.compute_integrity_hash)
    refute matching[:tampered]
  end

  def test_tier_gate_blocks_tier_ineligible_feature
    starter = DevFortress::TierGate.new("starter")
    refute starter.can_block?
    assert_match(/not available on the starter tier/, starter.validate_block_action("block_ip"))
    assert_match(/not available on the starter tier/, starter.validate_mode("hybrid"))
    assert_equal "external", starter.effective_mode("hybrid")

    pro = DevFortress::TierGate.new("pro")
    assert pro.can_block?
    refute_nil pro.validate_mode("hybrid") # Pro has no ICL/hybrid access at all (Package A)
    assert_equal 0, pro.max_icl_tier

    team = DevFortress::TierGate.new("team")
    assert_nil team.validate_mode("hybrid")
    assert_equal 2, team.max_icl_tier
    assert team.icl_tier_available?(2)
    refute team.icl_tier_available?(3)
  end

  def test_tier_gate_event_limit_and_snapshot_roundtrip
    gate = DevFortress::TierGate.new("starter")
    9_999.times { gate.record_event }
    allowed = gate.check_event_limit
    assert allowed[:allowed]
    assert_equal 1, allowed[:remaining]

    gate.record_event
    blocked = gate.check_event_limit
    refute blocked[:allowed]
    assert_equal 0, blocked[:remaining]

    snapshot = gate.to_snapshot
    restored = DevFortress::TierGate.from_snapshot(snapshot)
    assert_equal "starter", restored.tier
    refute restored.check_event_limit[:allowed]
  end

  def test_telemetry_manager_sends_heartbeat_and_resets_counters
    transport = ScriptedTransport.new([DevFortress::TransportResponse.new(status_code: 200, body: "{}")])
    telemetry = DevFortress::TelemetryManager.new(api_key: "df_test_key", endpoint: "https://example.test",
                                                   transport: transport)
    telemetry.record_event
    telemetry.record_event
    telemetry.record_block
    telemetry.record_latency(42)

    telemetry.send_heartbeat

    sent = JSON.parse(transport.requests.first[:body])
    assert_equal 2, sent["eventCount"]
    assert_equal 1, sent["blockCount"]
    assert_equal 42, sent["p99LatencyMs"]

    # Counters reset after a successful send.
    state = telemetry.state
    assert_equal 0, state[:event_count]
    assert_equal 0, state[:block_count]
  end

  def test_telemetry_manager_heartbeat_failure_is_logged_not_raised
    transport = ScriptedTransport.new([StandardError.new("connection refused")])
    telemetry = DevFortress::TelemetryManager.new(api_key: "df_test_key", endpoint: "https://example.test",
                                                   debug: true, transport: transport)
    telemetry.record_event

    capture_io { telemetry.send_heartbeat }

    # Fire-and-forget: a failed heartbeat must not raise, and must not
    # clear counters that were never successfully delivered.
    assert_equal 1, telemetry.state[:event_count]
  end

  def test_telemetry_rollup_buffer_batches_contributions_by_alias_and_period
    transport = ScriptedTransport.new([DevFortress::TransportResponse.new(status_code: 200, body: "{}")])
    buffer = DevFortress::TelemetryRollupBuffer.new(api_key: "df_test_key", endpoint: "https://example.test",
                                                     transport: transport)

    buffer.add(alias_or_ip_key: "1.2.3.4", endpoint: "/api/widgets", is_error: false, latency_ms: 10)
    buffer.add(alias_or_ip_key: "1.2.3.4", endpoint: "/api/widgets", is_error: true, latency_ms: 20)
    buffer.add(alias_or_ip_key: "5.6.7.8", endpoint: "/api/other", is_error: false, latency_ms: 5)

    buffer.flush

    body = JSON.parse(transport.requests.first[:body])
    contributions = body["contributions"].sort_by { |c| c["aliasOrIpKey"] }
    assert_equal 2, contributions.length
    first = contributions.first
    assert_equal "1.2.3.4", first["aliasOrIpKey"]
    assert_equal 2, first["requestCount"]
    assert_equal 1, first["errorCount"]
    assert_equal 30, first["latencySumMs"]
  end
end
