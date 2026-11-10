# frozen_string_literal: true

module DevFortress
  # Shadow Agent Registry (B10).
  #
  # Detects and tracks unauthorized ("shadow") AI agents that operate
  # without proper registration. Maintains a registry of known agents and
  # flags unregistered agent-like behavior. Mirrors
  # packages/devfortress-sdk/src/shadow-agent-registry.ts.
  class ShadowAgentRegistry
    DEFAULT_AGENT_PATTERNS = [
      "automated request pattern (>100 req/min)",
      "consistent timing between requests (<50ms variance)",
      "sequential resource enumeration",
      "user-agent indicates bot/automation",
      "no mouse/keyboard entropy in session",
      "API-only access (no page loads)",
    ].freeze

    def initialize(heartbeat_timeout_seconds: 300, agent_patterns: nil, auto_block: false)
      @heartbeat_timeout_seconds = heartbeat_timeout_seconds
      @agent_patterns = agent_patterns || DEFAULT_AGENT_PATTERNS
      @auto_block = auto_block
      @registry = {}
      @shadow_detections = {}
      @stats = { registered_count: 0, active_count: 0, shadow_detections: 0, blocked_shadows: 0 }
    end

    # Registers a known agent. agent: a Hash with :agent_id, :name, :owner,
    # :permissions (symbol keys) — :registered_at/:last_heartbeat/:active
    # are set here, not supplied by the caller.
    def register(agent)
      if ENV["FEATURE_PLATFORM_INTEL"] == "false"
        return agent.merge(registered_at: 0, last_heartbeat: 0, active: false)
      end

      registered = agent.merge(registered_at: now_ms, last_heartbeat: now_ms, active: true)
      @registry[agent[:agent_id]] = registered
      @stats[:registered_count] += 1
      @stats[:active_count] += 1
      registered
    end

    # Records a heartbeat from a registered agent.
    def heartbeat(agent_id)
      agent = @registry[agent_id]
      return false unless agent

      agent[:last_heartbeat] = now_ms
      agent[:active] = true
      true
    end

    # Checks whether a request source is a registered agent or a shadow.
    def detect(fingerprint, indicators)
      if ENV["FEATURE_PLATFORM_INTEL"] == "false"
        return { detected: false, agent_fingerprint: fingerprint, indicators: [], confidence: 0,
                  recommendation: "monitor", matched_patterns: [] }
      end

      # Check if any registered agent matches this fingerprint
      @registry.each_value do |agent|
        if agent[:agent_id] == fingerprint && agent[:active]
          return { detected: false, agent_fingerprint: fingerprint, indicators: [], confidence: 0,
                    recommendation: "monitor", matched_patterns: [] }
        end
      end

      # Check indicators against known agent patterns
      matched_patterns = @agent_patterns.select do |pattern|
        pattern_key = pattern.split("(").first.strip.downcase
        indicators.any? { |i| i.downcase.include?(pattern_key) }
      end

      confidence = [1, matched_patterns.length / 3.0].min
      detected = confidence > 0.3

      if detected
        @stats[:shadow_detections] += 1
        @stats[:blocked_shadows] += 1 if @auto_block && confidence > 0.7
      end

      result = {
        detected: detected,
        agent_fingerprint: fingerprint,
        indicators: indicators,
        confidence: confidence,
        recommendation: confidence > 0.7 ? (@auto_block ? "block" : "register") : "monitor",
        matched_patterns: matched_patterns,
      }
      @shadow_detections[fingerprint] = result if detected
      result
    end

    # Prunes inactive agents (no heartbeat within the configured timeout).
    def prune_inactive
      cutoff = now_ms - (@heartbeat_timeout_seconds * 1000)
      pruned = []
      @registry.each do |id, agent|
        if agent[:last_heartbeat] < cutoff
          agent[:active] = false
          @stats[:active_count] -= 1
          pruned << id
        end
      end
      pruned
    end

    def stats
      @stats.dup
    end

    def registered
      @registry.values
    end

    private

    def now_ms
      (Time.now.to_f * 1000).to_i
    end
  end
end
