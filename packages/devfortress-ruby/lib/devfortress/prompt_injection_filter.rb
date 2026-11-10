# frozen_string_literal: true

module DevFortress
  # A16: Indirect Prompt Injection Filter.
  #
  # Mirrors packages/devfortress-sdk/src/security-extensions.ts's
  # PromptInjectionFilter.
  class PromptInjectionFilter
    INJECTION_PATTERNS = [
      { pattern: 'ignore\s+(previous|above|all|prior)\s+(instructions?|context|rules?)', name: "instruction_override", weight: 40 },
      { pattern: 'you\s+are\s+now\s+(a|an|the)', name: "role_assignment", weight: 35 },
      { pattern: 'system\s*:\s*|\[SYSTEM\]|<\|system\|>', name: "system_prompt_injection", weight: 45 },
      { pattern: 'forget\s+(everything|all|what)', name: "memory_wipe", weight: 40 },
      { pattern: 'do\s+not\s+(follow|obey|listen)', name: "disobedience_injection", weight: 35 },
      { pattern: 'act\s+as\s+(if|though)|pretend\s+(to\s+be|you)', name: "persona_injection", weight: 30 },
      { pattern: "<script>|javascript:|onerror=|onload=", name: "xss_in_data", weight: 50 },
      { pattern: '\bexec\s*\(|eval\s*\(|__import__', name: "code_execution", weight: 50 },
      { pattern: "translate.*to.*base64|encode.*payload", name: "encoding_evasion", weight: 25 },
      { pattern: 'reveal\s+(your|the)\s+(system|secret|api|key|password)', name: "secret_extraction", weight: 45 },
    ].freeze

    def initialize(sensitivity: "medium", custom_patterns: [], max_scan_length: 100_000)
      @sensitivity = sensitivity
      @max_scan_length = max_scan_length

      @patterns = INJECTION_PATTERNS.map { |p| { regex: Regexp.new(p[:pattern], Regexp::IGNORECASE), name: p[:name], weight: p[:weight] } }
      custom_patterns.each_with_index do |pattern, i|
        @patterns << { regex: Regexp.new(pattern, Regexp::IGNORECASE), name: "custom_#{i}", weight: 30 }
      end
    end

    def scan(content)
      text = content[0, @max_scan_length]
      detected_patterns = []
      total_weight = 0

      @patterns.each do |pattern|
        if pattern[:regex].match?(text)
          detected_patterns << pattern[:name]
          total_weight += pattern[:weight]
        end
      end

      sensitivity_multiplier = case @sensitivity
                                when "high" then 1.5
                                when "low" then 0.7
                                else 1.0
                                end

      score = [100, (total_weight * sensitivity_multiplier).round].min
      confidence = detected_patterns.empty? ? 0.1 : [0.99, 0.5 + (detected_patterns.length * 0.15)].min

      severity = if score >= 70
                   "CRITICAL"
                 elsif score >= 45
                   "HIGH"
                 elsif score >= 20
                   "MEDIUM"
                 else
                   "LOW"
                 end

      {
        safe: score < 30,
        confidence: confidence,
        severity: severity,
        detected_patterns: detected_patterns,
        reason: detected_patterns.empty? ? "Content appears safe" : "Prompt injection detected: #{detected_patterns.join(', ')} (score=#{score})",
      }
    end
    alias scan_agent_input scan
  end
end
