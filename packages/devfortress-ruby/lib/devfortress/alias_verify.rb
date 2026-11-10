# frozen_string_literal: true

require "json"
require "uri"
require_relative "transport"
require_relative "version"

module DevFortress
  # Alias binding verification helper.
  #
  # Thin HTTP transport for POST /api/aliases/[id]/verify. All binding
  # checks run server-side; nothing is evaluated locally. Retry behaviour
  # matches Client: exponential backoff on 5xx and network errors only,
  # never on 4xx. Mirrors
  # packages/devfortress-sdk/src/alias-verify.ts.
  class AliasVerifyError < StandardError
    attr_reader :http_status, :body

    def initialize(message, http_status: nil, body: nil)
      super(message)
      @http_status = http_status
      @body = body
    end
  end

  module AliasVerify
    DEFAULT_BASE_URL = "https://www.devfortress.net"
    DEFAULT_TIMEOUT = 15
    DEFAULT_RETRIES = 3

    # Verify an alias's observed context against its recorded binding.
    # Resolves for 200 and 403 responses (the platform's normal verdicts).
    # Raises AliasVerifyError for 400/401 and for 5xx/network failures
    # once retries are exhausted.
    def self.verify_alias_binding(alias_id, alias_key, context, base_url: DEFAULT_BASE_URL, timeout: DEFAULT_TIMEOUT,
                                   retries: DEFAULT_RETRIES, transport: nil, sleeper: nil)
      raise ArgumentError, "verify_alias_binding: alias_id is required" if alias_id.nil? || alias_id.empty?
      raise ArgumentError, "verify_alias_binding: alias_key is required" if alias_key.nil? || alias_key.empty?

      base = (base_url || DEFAULT_BASE_URL).sub(%r{/+\z}, "")
      transport ||= Transport.new
      sleeper ||= ->(seconds) { sleep(seconds) if seconds.positive? }
      url = "#{base}/api/aliases/#{URI.encode_www_form_component(alias_id)}/verify"
      raw = JSON.generate({ "aliasKey" => alias_key, "context" => context })
      headers = { "Content-Type" => "application/json", "X-DevFortress-SDK-Version" => VERSION }

      attempt = 1
      loop do
        begin
          response = transport.send_request("POST", url, headers, raw, timeout)
          data = begin
            response.body.to_s.empty? ? {} : JSON.parse(response.body)
          rescue JSON::ParserError
            {}
          end
          status = response.status_code

          return { "httpStatus" => status, "violations" => [] }.merge(data) if [200, 403].include?(status)

          message = data["error"] || "Alias verification failed with status #{status}"
          raise AliasVerifyError.new(message, http_status: status, body: data) if status < 500 || attempt >= retries
        rescue TransportError => e
          raise AliasVerifyError.new("Alias verification request failed: #{e.message}") if attempt >= retries
        end

        sleeper.call(2**attempt)
        attempt += 1
      end
    end
  end
end
