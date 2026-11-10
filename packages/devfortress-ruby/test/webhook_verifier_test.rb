# frozen_string_literal: true

require_relative "test_helper"
require "openssl"

class WebhookVerifierTest < Minitest::Test
  def test_every_webhook_vector_gives_its_expected_verdict
    vectors = Vectors.webhook["vectors"]
    assert_operator vectors.length, :>=, 15
    vectors.each do |v|
      result = DevFortress::WebhookVerifier.verify(
        raw_body: v["body"], signature: v["signature"], timestamp: v["timestamp"],
        secret: v["secret"], now: v["now"]
      )
      assert_equal v["expected_valid"], result.valid?, "#{v['name']}: #{result.reason}"
    end
  end

  def sign(ts, body, secret)
    OpenSSL::HMAC.hexdigest("SHA256", secret, "#{ts}.#{body}")
  end

  def test_valid_tampered_stale_and_wrong_secret_cases
    secret = "whsec_unit_test_secret"
    body = '{"event_id":"e1"}'
    ts = "2026-01-15T12:00:00.000Z"
    sig = sign(ts, body, secret)

    assert DevFortress::WebhookVerifier.verify(raw_body: body, signature: sig, timestamp: ts, secret: secret, now: ts).valid?
    assert_equal "signature_mismatch", DevFortress::WebhookVerifier.verify(raw_body: "#{body} ", signature: sig, timestamp: ts, secret: secret, now: ts).reason
    assert_equal "signature_mismatch", DevFortress::WebhookVerifier.verify(raw_body: body, signature: sign(ts, body, "other"), timestamp: ts, secret: secret, now: ts).reason
    assert_equal "timestamp_expired", DevFortress::WebhookVerifier.verify(raw_body: body, signature: sig, timestamp: ts, secret: secret, now: "2026-01-15T12:05:01.000Z").reason
    assert DevFortress::WebhookVerifier.verify(raw_body: body, signature: sig, timestamp: ts, secret: secret, now: "2026-01-15T12:05:00.000Z").valid?
    assert_equal "invalid_timestamp", DevFortress::WebhookVerifier.verify(raw_body: body, signature: sig, timestamp: "yesterday", secret: secret, now: ts).reason
    assert_equal "invalid_signature", DevFortress::WebhookVerifier.verify(raw_body: body, signature: "abc", timestamp: ts, secret: secret, now: ts).reason
    assert_equal "invalid_signature", DevFortress::WebhookVerifier.verify(raw_body: body, signature: "#{sig}\n", timestamp: ts, secret: secret, now: ts).reason
  end

  def test_an_offset_timestamp_is_converted_to_utc
    secret = "s"
    body = "{}"
    ts = "2026-01-15T14:00:00.000+02:00"
    sig = sign(ts, body, secret)
    assert DevFortress::WebhookVerifier.verify(raw_body: body, signature: sig, timestamp: ts, secret: secret, now: "2026-01-15T12:00:10.000Z").valid?
    assert_equal "timestamp_expired", DevFortress::WebhookVerifier.verify(raw_body: body, signature: sig, timestamp: ts, secret: secret, now: "2026-01-15T12:06:00.000Z").reason
  end

  def test_nonce_replay_is_detected_through_the_callback
    body = '{"nonce":"a1b2c3d4e5f60718293a4b5c6d7e8f90"}'
    ts = "2026-01-15T12:00:00.000Z"
    sig = sign(ts, body, "s")
    seen = {}
    check = ->(nonce) {
      return false if seen[nonce]

      seen[nonce] = true
      true
    }

    assert DevFortress::WebhookVerifier.verify(raw_body: body, signature: sig, timestamp: ts, secret: "s", now: ts, nonce_check: check).valid?
    second = DevFortress::WebhookVerifier.verify(raw_body: body, signature: sig, timestamp: ts, secret: "s", now: ts, nonce_check: check)
    refute second.valid?
    assert_equal "replay_detected", second.reason
  end

  def test_a_missing_or_malformed_nonce_fails_when_replay_tracking_is_on
    ts = "2026-01-15T12:00:00.000Z"
    always = ->(_n) { true }
    { "{}" => "nonce_invalid", '{"nonce":"short"}' => "nonce_invalid", "[1]" => "invalid_body", "not json" => "invalid_body" }.each do |body, reason|
      result = DevFortress::WebhookVerifier.verify(
        raw_body: body, signature: sign(ts, body, "s"), timestamp: ts, secret: "s", now: ts, nonce_check: always
      )
      assert_equal reason, result.reason, body
    end
  end
end
