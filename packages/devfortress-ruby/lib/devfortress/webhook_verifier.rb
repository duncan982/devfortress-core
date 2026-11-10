# frozen_string_literal: true

require "json"
require "openssl"
require "time"

require_relative "webhook_verification"

module DevFortress
  # Inbound webhook signature verification.
  #
  # Contract (platform dispatcher, POST /api/webhooks/deliver):
  #
  # - X-DevFortress-Timestamp: ISO-8601 UTC timestamp of dispatch.
  # - X-DevFortress-Signature: hex HMAC-SHA256, keyed with the project's
  #   webhook secret, over the UTF-8 bytes of "{timestamp}.{rawBody}".
  # - Timestamps older than 300 seconds are rejected.
  # - The body carries a 32-char lowercase-hex "nonce". Replay tracking is left
  #   to the caller through +nonce_check+ so the library keeps no state.
  module WebhookVerifier
    TOLERANCE_SECONDS = 300
    SIGNATURE_HEADER = "X-DevFortress-Signature"
    TIMESTAMP_HEADER = "X-DevFortress-Timestamp"

    HEX_SIGNATURE = /\A[0-9a-fA-F]{64}\z/.freeze
    HEX_NONCE = /\A[0-9a-f]{32}\z/.freeze

    # Verify a DevFortress webhook. Pass the body exactly as received.
    #
    # +nonce_check+ should return true the first time a nonce is seen and
    # false on replay; when supplied, a missing or malformed nonce fails.
    # +now+ is for tests: a Time, or an ISO-8601 string.
    def self.verify(raw_body:, signature:, timestamp:, secret:, tolerance_seconds: TOLERANCE_SECONDS, now: nil, nonce_check: nil)
      ts_ms = parse_iso_ms(timestamp)
      return WebhookVerification.new(false, "invalid_timestamp") if ts_ms.nil?

      age_ms = now_ms(now) - ts_ms
      return WebhookVerification.new(false, "timestamp_expired") if age_ms > tolerance_seconds * 1000

      return WebhookVerification.new(false, "invalid_signature") unless HEX_SIGNATURE.match?(signature)

      expected = OpenSSL::HMAC.digest("SHA256", secret, "#{timestamp}.#{raw_body}")
      given = [signature].pack("H*")
      return WebhookVerification.new(false, "signature_mismatch") unless secure_compare(expected, given)

      if nonce_check
        decoded = begin
          JSON.parse(raw_body)
        rescue JSON::ParserError
          nil
        end
        return WebhookVerification.new(false, "invalid_body") unless decoded.is_a?(Hash)

        nonce = decoded["nonce"]
        return WebhookVerification.new(false, "nonce_invalid") unless nonce.is_a?(String) && HEX_NONCE.match?(nonce)
        return WebhookVerification.new(false, "replay_detected") unless nonce_check.call(nonce)
      end

      WebhookVerification.new(true, nil)
    end

    # Epoch milliseconds for a strict ISO-8601 timestamp with a zone, or nil
    # when malformed or not a real calendar date/time.
    def self.parse_iso_ms(value)
      t = Time.iso8601(value)
      (t.to_r * 1000).to_i
    rescue ArgumentError
      nil
    end
    private_class_method :parse_iso_ms

    def self.now_ms(now)
      case now
      when nil
        (Time.now.to_r * 1000).to_i
      when Time
        (now.to_r * 1000).to_i
      when String
        parse_iso_ms(now) or raise ArgumentError, "now must be an ISO-8601 timestamp"
      else
        (now.to_r * 1000).to_i
      end
    end
    private_class_method :now_ms

    def self.secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end
    private_class_method :secure_compare
  end
end
