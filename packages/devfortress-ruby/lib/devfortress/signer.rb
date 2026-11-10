# frozen_string_literal: true

require "digest"
require "openssl"
require "securerandom"

module DevFortress
  # Request integrity headers for every SDK-to-platform call (contract v2).
  #
  # Canonical string: "{METHOD}.{requestTarget}.{timestamp}.{nonce}.{payloadHash}"
  # where METHOD is the uppercase HTTP method, requestTarget is the URL path plus
  # "?query" exactly as sent (no host, no re-encoding), and payloadHash is the
  # lowercase hex SHA-256 of the exact body bytes (the empty string for a request
  # with no body). The signature is the lowercase hex HMAC-SHA256 of that string,
  # keyed with the project API key (UTF-8). The timestamp is Unix epoch
  # milliseconds; the nonce is a dashed UUID v4, fresh for every request attempt.
  # Tolerance is 300 seconds.
  #
  # The API key never travels on a signed request. X-DevFortress-Key-Id is a
  # non-secret identifier derived from the key (first 32 hex characters of its
  # SHA-256); the platform verifies the HMAC with the key it has stored.
  class Signer
    SIGNATURE_VERSION = "2"
    TOLERANCE_SECONDS = 300

    KEY_ID_HEADER = "X-DevFortress-Key-Id"
    VERSION_HEADER = "X-DevFortress-Signature-Version"
    NONCE_HEADER = "X-DevFortress-Nonce"
    TIMESTAMP_HEADER = "X-DevFortress-Timestamp"
    PAYLOAD_HASH_HEADER = "X-DevFortress-Payload-Hash"
    SIGNATURE_HEADER = "X-DevFortress-Signature"

    class Error < StandardError; end

    def initialize(api_key)
      raise Error, "DevFortress: an API key is required" if api_key.nil? || api_key.empty?

      @api_key = api_key
    end

    # Non-secret key ID: first 32 hex characters of SHA-256 over the UTF-8 key.
    def self.derive_key_id(api_key)
      Digest::SHA256.hexdigest(api_key)[0, 32]
    end

    def key_id
      self.class.derive_key_id(@api_key)
    end

    # Returns the six signing headers (key ID, version, nonce, timestamp, hash, signature).
    def sign(method, request_target, body, timestamp: nil, nonce: nil)
      ts = timestamp || self.class.now_ms
      n = nonce || self.class.uuid_v4
      digest = self.class.digest(@api_key, method, request_target, ts, n, body)

      {
        KEY_ID_HEADER => key_id,
        VERSION_HEADER => SIGNATURE_VERSION,
        NONCE_HEADER => n,
        TIMESTAMP_HEADER => ts,
        PAYLOAD_HASH_HEADER => digest[:payload_hash],
        SIGNATURE_HEADER => digest[:signature],
      }
    end

    # Returns "valid", "invalid", "expired", "missing" or "unsupported_version".
    #
    # +headers+ uses the wire header names. Mirrors the platform's check.
    def self.verify(api_key, method, request_target, body, headers, now_ms: nil)
      nonce = headers[NONCE_HEADER]
      ts = headers[TIMESTAMP_HEADER]
      payload_hash = headers[PAYLOAD_HASH_HEADER]
      signature = headers[SIGNATURE_HEADER]
      if blank?(nonce) || blank?(ts) || blank?(payload_hash) || blank?(signature)
        return "missing"
      end
      return "unsupported_version" unless headers[VERSION_HEADER] == SIGNATURE_VERSION

      expected = digest(api_key, method, request_target, ts, nonce, body)
      hash_ok = secure_compare(expected[:payload_hash], payload_hash.downcase)
      sig_ok = secure_compare(expected[:signature], signature.downcase)
      return "invalid" unless hash_ok && sig_ok
      return "invalid" unless ts.match?(/\A-?[0-9]+\z/)

      now = now_ms || self.now_ms
      age = (now.to_i - ts.to_i).abs
      age > TOLERANCE_SECONDS * 1000 ? "expired" : "valid"
    end

    # The request target for a URL: path plus "?query" as written, no scheme,
    # host or fragment, and nothing re-encoded or normalised. An empty path is "/".
    def self.request_target_from_url(url)
      url = url.split("#", 2).first || url
      rest = url.sub(%r{\A[A-Za-z][A-Za-z0-9+.\-]*://[^/?]*}, "")
      return "/#{rest}" if rest.empty? || rest.start_with?("?")

      rest
    end

    # A dashed UUID v4 from SecureRandom.
    def self.uuid_v4
      SecureRandom.uuid
    end

    # Unix epoch milliseconds as a decimal string.
    def self.now_ms
      (Time.now.to_r * 1000).to_i.to_s
    end

    # Not private: #sign (an instance method) calls this via the explicit
    # `self.class.digest` receiver, which Ruby's `private_class_method`
    # would reject even though both live on this class.
    def self.digest(api_key, method, request_target, timestamp, nonce, body)
      payload_hash = Digest::SHA256.hexdigest(body)
      canonical = "#{method.to_s.upcase}.#{request_target}.#{timestamp}.#{nonce}.#{payload_hash}"
      {
        payload_hash: payload_hash,
        signature: OpenSSL::HMAC.hexdigest("SHA256", api_key, canonical),
      }
    end

    def self.secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end
    private_class_method :secure_compare

    def self.blank?(value)
      value.nil? || value.empty?
    end
    private_class_method :blank?
  end
end
