# frozen_string_literal: true

require_relative "test_helper"
require_relative "../lib/devfortress/response_webhook_client"

# Closed-loop local self-enforcement — TODO 358 regression coverage.
#
# Node's own external-mode reference (devfortress.ts's handleWebhook/
# isBlocked pair) and Python's ClosedLoopEngine both self-enforce
# block/revocation decisions via a local cache, checked unconditionally
# before any remote fallback. This SDK previously only delivered and
# verified these commands, leaving every embedding app to implement its
# own cache. These tests cover the ported local-cache behavior.
class ResponseWebhookClientClosedLoopTest < Minitest::Test
  def setup
    @client = DevFortress::ResponseWebhookClient.new("https://example.test/webhook", "secret")
  end

  def test_ip_block_cached_when_severity_high_or_critical
    refute @client.ip_blocked?("1.2.3.4")

    @client.record_inbound_command({ "type" => "ip_block", "ip" => "1.2.3.4", "severity" => "high" })

    assert @client.ip_blocked?("1.2.3.4")
  end

  def test_ip_block_not_cached_when_severity_low
    @client.record_inbound_command({ "type" => "ip_block", "ip" => "5.6.7.8", "severity" => "low" })

    refute @client.ip_blocked?("5.6.7.8")
  end

  def test_ip_block_defaults_to_cached_when_severity_unset
    @client.record_inbound_command({ "type" => "ip_block", "ip" => "9.9.9.9" })

    assert @client.ip_blocked?("9.9.9.9")
  end

  def test_session_revocation_caches_user_and_ip
    refute @client.user_blocked?("user-1")

    @client.record_inbound_command({ "type" => "session_revocation", "user_id" => "user-1", "ip" => "10.0.0.1" })

    assert @client.user_blocked?("user-1")
    assert @client.ip_blocked?("10.0.0.1")
  end

  def test_unrelated_ip_or_user_not_blocked
    @client.record_inbound_command({ "type" => "ip_block", "ip" => "1.1.1.1", "severity" => "critical" })

    refute @client.ip_blocked?("2.2.2.2")
    refute @client.user_blocked?("unrelated-user")
  end
end
