# frozen_string_literal: true

require "cgi"

module DevFortress
  # Maps an HTTP response to a DevFortress event.
  module Classifier
    SQL = [
      /\bor\b.*=.*/i,
      /\bunion\b.*\bselect\b/i,
      /\bdrop\b.*\btable\b/i,
      /'\s*or\s*'1'\s*=\s*'1/i,
    ].freeze

    XSS = [
      %r{<script[^>]*>[\s\S]*?</script>}i,
      /javascript:/i,
      /onerror\s*=\s*/i,
      /onload\s*=\s*/i,
    ].freeze

    TRAVERSAL = [
      %r{\.\.[/\\]},
      %r{/etc/passwd}i,
    ].freeze

    # Names of the suspicious patterns found in +text+.
    #
    # Matches the raw text and one percent-decoding pass. An invalid byte
    # sequence (text is not valid UTF-8) is treated as not suspicious rather
    # than raised, matching the PHP and Go classifiers' behaviour.
    def self.detect_suspicious(text)
      return [] unless text.valid_encoding?

      candidates = [text]
      decoded = CGI.unescape(text)
      candidates << decoded if decoded != text && decoded.valid_encoding?

      found = []
      found << "sql_injection" if hit?(SQL, candidates)
      found << "xss" if hit?(XSS, candidates)
      found << "path_traversal" if hit?(TRAVERSAL, candidates)
      found
    end

    # An event Hash, or nil when the request is not security-relevant.
    def self.build_event(ip:, method:, path:, status_code:, latency_ms:, user_agent: nil, query: "", user_id: nil)
      event_type = nil
      severity = "LOW"
      reason = nil
      action = "monitored"

      case status_code
      when 401, 403
        event_type = "auth_failure"
        severity = "MEDIUM"
        reason = "Authentication or authorization failed"
        action = "blocked"
      when 400, 422
        event_type = "validation_error"
        reason = "Request validation failed"
      when 429
        event_type = "rate_limit_exceeded"
        severity = "MEDIUM"
        reason = "Rate limit exceeded"
        action = "rate_limited"
      else
        if status_code >= 500
          event_type = "5xx_error"
          severity = "HIGH"
          reason = "Server error: #{status_code}"
        elsif status_code >= 400
          event_type = "4xx_error"
          reason = "Client error: #{status_code}"
        end
      end

      suspicious = detect_suspicious("#{path} #{query}")
      unless suspicious.empty?
        event_type = "suspicious_pattern"
        severity = "HIGH"
        reason = "Suspicious patterns detected: #{suspicious.join(', ')}"
        action = "flagged"
      end

      return nil if event_type.nil?

      {
        "eventType" => event_type,
        "ip" => ip.nil? || ip.empty? ? "0.0.0.0" : ip,
        "method" => method,
        "path" => path,
        "userAgent" => user_agent,
        "statusCode" => status_code,
        "severity" => severity,
        "clMode" => "external",
        "authPhase" => user_id.nil? || user_id.to_s.empty? ? "pre_auth" : "post_auth",
        "actionTaken" => action,
        "responseLatencyMs" => latency_ms,
        "userId" => user_id,
        "metadata" => { "reason" => reason },
      }
    end

    def self.hit?(patterns, candidates)
      candidates.any? { |candidate| patterns.any? { |pattern| pattern.match?(candidate) } }
    end
    private_class_method :hit?
  end
end
