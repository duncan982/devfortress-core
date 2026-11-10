# frozen_string_literal: true

module DevFortress
  # Agent Output Exfiltration Detector (B7).
  #
  # Monitors AI agent outputs for potential data exfiltration patterns.
  # Detects when agent responses contain sensitive data that shouldn't be
  # included in outputs (PII, credentials, internal system info). Mirrors
  # packages/devfortress-sdk/src/agent-output-exfiltration-detector.ts.
  class AgentOutputExfiltrationDetector
    AgentOutput = Struct.new(:agent_id, :output_content, :output_type, :destination_type, :timestamp,
                              keyword_init: true)

    DEFAULT_SENSITIVE_PATTERNS = [
      # Credit cards
      '\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
      # SSN
      '\b\d{3}-\d{2}-\d{4}\b',
      # Email addresses in unexpected contexts
      '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b',
      # API keys / tokens (high entropy strings)
      '(?:api[_-]?key|token|secret|password|credential)[\s:=]+["\']?[A-Za-z0-9+/=_-]{20,}["\']?',
      # AWS keys
      '(?:AKIA|ASIA)[A-Z0-9]{16}',
      # Private keys
      '-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
      # Internal IPs
      '\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+\b',
    ].freeze

    def initialize(sensitive_patterns: nil, max_output_size_bytes: 1_048_576, entropy_detection: true,
                   entropy_threshold: 4.5)
      @sensitive_patterns = sensitive_patterns || DEFAULT_SENSITIVE_PATTERNS
      @max_output_size_bytes = max_output_size_bytes
      @entropy_detection = entropy_detection
      @entropy_threshold = entropy_threshold
      @compiled_patterns = @sensitive_patterns.map { |p| Regexp.new(p, Regexp::IGNORECASE) }
    end

    # output: an AgentOutput (or any object responding to #output_content).
    def analyze(output)
      if ENV["FEATURE_PLATFORM_INTEL"] == "false"
        return { detected: false, threat_type: "none", confidence: 0, matched_patterns: [], recommendation: "allow" }
      end

      if output.output_content.bytesize > @max_output_size_bytes
        return { detected: true, threat_type: "oversized-output", confidence: 0.7, matched_patterns: [],
                 recommendation: "warn" }
      end

      matched_patterns = []
      @compiled_patterns.each_with_index do |pattern, i|
        matched_patterns << @sensitive_patterns[i] if pattern.match?(output.output_content)
      end

      if matched_patterns.any?
        threat_type =
          if matched_patterns.any? { |p| p.include?("PRIVATE KEY") || p.include?("AKIA") }
            "credential-leak"
          elsif matched_patterns.any? { |p| p.include?("SSN") || p.include?("credit") }
            "pii-leak"
          else
            "system-info-leak"
          end

        return {
          detected: true,
          threat_type: threat_type,
          confidence: [1, 0.5 + (matched_patterns.length * 0.15)].min,
          matched_patterns: matched_patterns,
          recommendation: threat_type == "credential-leak" ? "block" : "redact",
          redacted_output: redact(output.output_content),
        }
      end

      # Entropy detection for unknown secrets
      if @entropy_detection
        high_entropy_segments = find_high_entropy_segments(output.output_content)
        if high_entropy_segments.any?
          return { detected: true, threat_type: "high-entropy-secret", confidence: 0.6,
                   matched_patterns: high_entropy_segments, recommendation: "warn" }
        end
      end

      { detected: false, threat_type: "none", confidence: 0, matched_patterns: [], recommendation: "allow" }
    end

    private

    def redact(content)
      redacted = content
      @compiled_patterns.each { |pattern| redacted = redacted.gsub(pattern, "[REDACTED]") }
      redacted
    end

    def find_high_entropy_segments(content)
      segments = []
      candidates = content.scan(%r{[A-Za-z0-9+/=_-]{32,}})
      candidates.each do |candidate|
        segments << "#{candidate[0, 20]}..." if shannon_entropy(candidate) > @entropy_threshold
      end
      segments
    end

    def shannon_entropy(str)
      freq = Hash.new(0)
      str.each_char { |c| freq[c] += 1 }
      len = str.length
      -freq.values.reduce(0.0) do |sum, count|
        p = count.to_f / len
        sum + (p * Math.log2(p))
      end
    end
  end
end
