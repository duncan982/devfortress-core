# frozen_string_literal: true

require_relative "test_helper"

# Exercises AgentOutputExfiltrationDetector (B7) and ShadowAgentRegistry
# (B10), newly ported as public SDK surface — not gated under
# Tier2Gated/internal.rb, same posture as B3/B4 (see
# test/consent_and_trust_chain_test.rb).
class AgentOutputAndShadowRegistryTest < Minitest::Test
  def test_agent_output_exfiltration_detector_is_public_and_flags_credential_leak
    detector = DevFortress::AgentOutputExfiltrationDetector.new
    output = DevFortress::AgentOutputExfiltrationDetector::AgentOutput.new(
      agent_id: "agent-1", output_content: "your key is AKIAABCDEFGHIJKLMNOP", output_type: "text",
      destination_type: "user", timestamp: (Time.now.to_f * 1000).to_i
    )

    result = detector.analyze(output)
    assert result[:detected]
    assert_equal "credential-leak", result[:threat_type]
    assert_equal "block", result[:recommendation]
    refute_includes result[:redacted_output], "AKIAABCDEFGHIJKLMNOP"
  end

  def test_agent_output_exfiltration_detector_allows_benign_output
    detector = DevFortress::AgentOutputExfiltrationDetector.new
    output = DevFortress::AgentOutputExfiltrationDetector::AgentOutput.new(
      agent_id: "agent-1", output_content: "The weather in Nairobi is sunny today.", output_type: "text",
      destination_type: "user", timestamp: (Time.now.to_f * 1000).to_i
    )

    result = detector.analyze(output)
    refute result[:detected]
    assert_equal "none", result[:threat_type]
    assert_equal "allow", result[:recommendation]
  end

  def test_shadow_agent_registry_is_public_and_distinguishes_registered_from_shadow
    registry = DevFortress::ShadowAgentRegistry.new
    registered = registry.register(agent_id: "agent-1", name: "Support Bot", owner: "team-a", permissions: ["read"])
    assert registered[:active]
    assert registry.heartbeat("agent-1")

    known = registry.detect("agent-1", [])
    refute known[:detected]

    shadow = registry.detect("unknown-agent", [
                                "automated request pattern seen (>100 req/min)",
                                "consistent timing between requests observed",
                                "sequential resource enumeration detected",
                              ])
    assert shadow[:detected]
    assert_operator shadow[:confidence], :>, 0.3
    assert_includes %w[register block], shadow[:recommendation]
  end
end
