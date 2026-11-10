# frozen_string_literal: true

require "json"
require_relative "agent_adapter"
require_relative "credential_isolation"

module DevFortress
  # Agent Credential Aliasing & Security (IP-C2, IP-C3, IP-C4, IP-C5).
  #
  # Extends the core credential isolation system for AI agent credentials.
  # Mirrors packages/devfortress-sdk/src/agent-security.ts.

  AgentCredentialAliasData = Struct.new(
    :alias_id, :agent_id, :credential_type, :created_at, :quarantined,
    :quarantine_reason, :quarantined_at, :execution_context, keyword_init: true,
  )

  AgentBaselineMetrics = Struct.new(
    :avg_tools_per_session, :tool_diversity_entropy, :avg_data_volume_bytes,
    :avg_session_duration_ms, :top_tools, :total_sessions, :created_at,
    :last_updated_at, :task_definition, keyword_init: true,
  )

  AgentSessionRecord = Struct.new(:session_id, :agent_id, :tool_calls, :started_at, :ended_at, :total_data_bytes, keyword_init: true)

  AgentAnomalySignal = Struct.new(:type, :agent_id, :severity, :description, :detected_at, :details, keyword_init: true)

  AgentScopeDefinition = Struct.new(:agent_id, :allowed_tools, :strict_mode, :created_at, :updated_at, keyword_init: true)

  def self.shannon_entropy(items)
    return 0.0 if items.empty?

    freq = Hash.new(0)
    items.each { |item| freq[item] += 1 }
    total = items.length.to_f
    freq.values.reduce(0.0) do |entropy, count|
      p = count / total
      p.positive? ? entropy - (p * Math.log2(p)) : entropy
    end
  end

  # Agent Credential Manager (IP-C2).
  class AgentCredentialManager
    def initialize(token_manager, cache: nil)
      @token_manager = token_manager
      @cache = cache
      @credentials = {}
      @quarantines = {}
    end

    def create_agent_alias(real_credential, agent_id, credential_type, ttl_seconds: 7200, execution_context: nil)
      DevFortress.validate_agent_id(agent_id)
      alias_id = @token_manager.create_alias(real_credential, agent_id, ttl_seconds: ttl_seconds)

      data = AgentCredentialAliasData.new(
        alias_id: alias_id, agent_id: agent_id, credential_type: credential_type,
        created_at: now_ms, quarantined: false, execution_context: execution_context,
      )
      (@credentials[agent_id] ||= []) << data

      if @cache
        begin
          existing = @cache.get("agent:creds:#{agent_id}")
          list = existing ? JSON.parse(existing) : []
          list << data.to_h
          @cache.set("agent:creds:#{agent_id}", JSON.generate(list), ttl_seconds)
        rescue StandardError
          # In-memory is already set
        end
      end

      alias_id
    end

    # Revoke ALL credentials for an agent (IP-C2).
    def revoke_agent_access(agent_id, reason: "active_threat")
      creds = @credentials[agent_id] || []
      revoked_count = 0
      creds.each do |cred|
        @token_manager.revoke_by_alias(cred.alias_id, reason: reason, subject_id: agent_id)
        revoked_count += 1
      rescue StandardError
        # Continue revoking remaining credentials
      end

      @credentials.delete(agent_id)
      @quarantines.delete(agent_id)

      if @cache
        begin
          @cache.del("agent:creds:#{agent_id}")
          @cache.del("agent:quarantine:#{agent_id}")
        rescue StandardError
          # Best-effort
        end
      end

      revoked_count
    end

    # Quarantine an agent (IP-C2) — suspend tool access but preserve
    # session for forensics. Reversible, unlike revocation.
    def quarantine_agent(agent_id, reason)
      quarantine = { reason: reason, at: now_ms }
      @quarantines[agent_id] = quarantine

      (@credentials[agent_id] || []).each do |cred|
        cred.quarantined = true
        cred.quarantine_reason = reason
        cred.quarantined_at = quarantine[:at]
      end

      return unless @cache

      begin
        @cache.set("agent:quarantine:#{agent_id}", JSON.generate(quarantine), 86_400)
      rescue StandardError
        # In-memory is set
      end
    end

    # Lift quarantine for an agent. Rejects if not currently quarantined.
    def unquarantine_agent(agent_id)
      unless @quarantines.key?(agent_id)
        raise ArgumentError, "Agent \"#{agent_id}\" is not currently quarantined — nothing to reinstate."
      end

      @quarantines.delete(agent_id)
      (@credentials[agent_id] || []).each do |cred|
        cred.quarantined = false
        cred.quarantine_reason = nil
        cred.quarantined_at = nil
      end

      return unless @cache

      begin
        @cache.del("agent:quarantine:#{agent_id}")
      rescue StandardError
        # Best-effort
      end
    end

    def quarantined?(agent_id)
      @quarantines.key?(agent_id)
    end

    def quarantine_details(agent_id)
      @quarantines[agent_id]
    end

    def agent_credentials(agent_id)
      @credentials[agent_id] || []
    end

    private

    def now_ms
      (Time.now.to_f * 1000).to_i
    end
  end

  # Agent Behavioral Baseline (IP-C3).
  class AgentBaselineEngine
    BASELINE_WINDOW_DAYS = 30
    MIN_SESSIONS_FOR_BASELINE = 5

    def initialize
      @sessions = {}
      @baselines = {}
    end

    def record_session(record)
      sessions = (@sessions[record.agent_id] ||= [])
      window_start = now_ms - (BASELINE_WINDOW_DAYS * 24 * 60 * 60 * 1000)
      filtered = sessions.select { |s| s.started_at > window_start }
      filtered << record
      @sessions[record.agent_id] = filtered

      recalculate_baseline(record.agent_id) if filtered.length >= MIN_SESSIONS_FOR_BASELINE
    end

    # Establish a baseline from a task definition (IP-C3).
    def agent_baseline(agent_id, task_definition)
      existing = @baselines[agent_id]
      if existing
        existing.task_definition = task_definition
        existing.last_updated_at = now_ms
        return existing
      end

      sessions = @sessions[agent_id] || []
      return nil if sessions.length < MIN_SESSIONS_FOR_BASELINE

      recalculate_baseline(agent_id, task_definition)
    end

    def baseline(agent_id)
      @baselines[agent_id]
    end

    def sessions_for(agent_id)
      @sessions[agent_id] || []
    end

    def is_3_sigma_deviation?(values, new_value)
      return false if values.length < 2

      mean = values.sum.to_f / values.length
      sd = std_dev(values)
      return new_value != mean if sd.zero?

      (new_value - mean).abs > 3 * sd
    end

    private

    def recalculate_baseline(agent_id, task_definition = nil)
      sessions = @sessions[agent_id] || []

      tools_per_session = sessions.map { |s| s.tool_calls.length }
      avg_tools_per_session = tools_per_session.sum.to_f / sessions.length

      all_tools = sessions.flat_map { |s| s.tool_calls.map { |tc| tc[:tool] || tc["tool"] } }
      tool_diversity_entropy = DevFortress.shannon_entropy(all_tools)

      data_volumes = sessions.map(&:total_data_bytes)
      avg_data_volume_bytes = data_volumes.sum.to_f / sessions.length

      durations = sessions.select(&:ended_at).map { |s| s.ended_at - s.started_at }
      avg_session_duration_ms = durations.empty? ? 0 : durations.sum.to_f / durations.length

      tool_freq = Hash.new(0)
      all_tools.each { |tool| tool_freq[tool] += 1 }
      top_tools = tool_freq.sort_by { |_, count| -count }.first(10).map(&:first)

      baseline = AgentBaselineMetrics.new(
        avg_tools_per_session: avg_tools_per_session,
        tool_diversity_entropy: tool_diversity_entropy,
        avg_data_volume_bytes: avg_data_volume_bytes,
        avg_session_duration_ms: avg_session_duration_ms,
        top_tools: top_tools,
        total_sessions: sessions.length,
        created_at: @baselines[agent_id]&.created_at || now_ms,
        last_updated_at: now_ms,
        task_definition: task_definition || @baselines[agent_id]&.task_definition,
      )

      @baselines[agent_id] = baseline
      baseline
    end

    def std_dev(values)
      return 0.0 if values.length < 2

      mean = values.sum.to_f / values.length
      sq_diffs = values.map { |v| (v - mean)**2 }
      Math.sqrt(sq_diffs.sum / values.length)
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end
  end

  # Agent Anomaly Detector (IP-C4), with unsanctioned-tool scope
  # enforcement (IP-C5) integrated here for convenience — mirrors the Go
  # SDK's merged AgentAnomalyDetector, since scope enforcement is only
  # ever consumed from inside #analyze_tool_call anyway.
  class AgentAnomalyDetector
    def initialize(baseline_engine)
      @baseline_engine = baseline_engine
      @anomaly_handlers = []
      @credential_usage = {}
      @scopes = {}
    end

    def on_anomaly(&handler)
      @anomaly_handlers << handler
    end

    # Register the sanctioned tool scope for an agent (IP-C5). In strict
    # mode, any tool outside allowed_tools fires a critical anomaly
    # immediately.
    def define_agent_scope(agent_id, allowed_tools, strict_mode: true)
      scope = AgentScopeDefinition.new(
        agent_id: agent_id, allowed_tools: allowed_tools, strict_mode: strict_mode,
        created_at: @scopes[agent_id]&.created_at || now_ms, updated_at: now_ms,
      )
      @scopes[agent_id] = scope
      scope
    end

    # Whether tool_name is within agent_id's defined scope. Allows by
    # default when no scope is defined, or when not in strict mode.
    def tool_allowed?(agent_id, tool_name)
      scope = @scopes[agent_id]
      return true unless scope
      return true unless scope.strict_mode

      scope.allowed_tools.include?(tool_name)
    end

    def scope(agent_id)
      @scopes[agent_id]
    end

    def remove_scope(agent_id)
      @scopes.delete(agent_id)
    end

    def add_allowed_tools(agent_id, tools)
      scope = @scopes[agent_id]
      unless scope
        define_agent_scope(agent_id, tools, strict_mode: true)
        return
      end
      scope.allowed_tools = (scope.allowed_tools + tools).uniq
      scope.updated_at = now_ms
    end

    def remove_allowed_tools(agent_id, tools)
      scope = @scopes[agent_id]
      return unless scope

      scope.allowed_tools -= tools
      scope.updated_at = now_ms
    end

    # Analyze a tool call for anomalies against the agent's baseline.
    def analyze_tool_call(agent_id, tool_name, data_bytes: 0, credential_alias: nil)
      signals = []
      baseline = @baseline_engine.baseline(agent_id)

      scope = @scopes[agent_id]
      if scope && scope.strict_mode && !scope.allowed_tools.include?(tool_name)
        signal = AgentAnomalySignal.new(
          type: "unsanctioned_tool", agent_id: agent_id, severity: "critical",
          description: "Agent #{agent_id} invoked unsanctioned tool \"#{tool_name}\". Allowed: [#{scope.allowed_tools.join(', ')}]",
          detected_at: now_ms, details: { tool: tool_name, allowed_tools: scope.allowed_tools },
        )
        signals << signal
        emit_signal(signal)
      end

      return signals unless baseline

      # IP-C4.1: Tool invocation scope deviation
      if !baseline.top_tools.empty? && !baseline.top_tools.include?(tool_name)
        signal = AgentAnomalySignal.new(
          type: "scope_deviation", agent_id: agent_id, severity: "medium",
          description: "Agent #{agent_id} invoked tool \"#{tool_name}\" outside its baseline tool set",
          detected_at: now_ms, details: { tool: tool_name, baseline_tools: baseline.top_tools },
        )
        signals << signal
        emit_signal(signal)
      end

      # IP-C4.3: Data volume anomaly (3σ deviation)
      if data_bytes.positive?
        sessions = @baseline_engine.sessions_for(agent_id)
        volumes = sessions.map(&:total_data_bytes)
        if @baseline_engine.is_3_sigma_deviation?(volumes, data_bytes)
          signal = AgentAnomalySignal.new(
            type: "data_volume_anomaly", agent_id: agent_id, severity: "high",
            description: "Agent #{agent_id} data volume #{data_bytes}B is 3σ deviation from baseline avg #{baseline.avg_data_volume_bytes.round}B",
            detected_at: now_ms, details: { data_bytes: data_bytes, baseline_avg: baseline.avg_data_volume_bytes },
          )
          signals << signal
          emit_signal(signal)
        end
      end

      # IP-C4.4: Cross-agent credential sharing detection
      if credential_alias
        agents = (@credential_usage[credential_alias] ||= [])
        agents << agent_id unless agents.include?(agent_id)

        if agents.size > 1
          signal = AgentAnomalySignal.new(
            type: "cross_agent_credential_sharing", agent_id: agent_id, severity: "critical",
            description: "Credential #{credential_alias[0, 16]}... shared across #{agents.size} agents: [#{agents.join(', ')}]",
            detected_at: now_ms, details: { credential_alias: "#{credential_alias[0, 16]}...", sharing_agents: agents.dup },
          )
          signals << signal
          emit_signal(signal)
        end
      end

      signals
    end

    # Analyze a completed session for sequence entropy anomaly (IP-C4.1).
    def analyze_session(record)
      signals = []
      baseline = @baseline_engine.baseline(record.agent_id)
      return signals if !baseline || baseline.total_sessions < 5

      session_tools = record.tool_calls.map { |tc| tc[:tool] || tc["tool"] }
      session_entropy = DevFortress.shannon_entropy(session_tools)
      entropy_deviation = (session_entropy - baseline.tool_diversity_entropy).abs

      if baseline.tool_diversity_entropy.positive? && (entropy_deviation / baseline.tool_diversity_entropy) > 0.5
        deviation_percent = (entropy_deviation / baseline.tool_diversity_entropy) * 100
        signal = AgentAnomalySignal.new(
          type: "sequence_entropy_anomaly", agent_id: record.agent_id, severity: "high",
          description: format("Agent %s session entropy %.2f deviates %d%% from baseline %.2f", record.agent_id, session_entropy, deviation_percent.round, baseline.tool_diversity_entropy),
          detected_at: now_ms, details: { session_entropy: session_entropy, baseline_entropy: baseline.tool_diversity_entropy, deviation_percent: deviation_percent },
        )
        signals << signal
        emit_signal(signal)
      end

      signals
    end

    private

    def emit_signal(signal)
      @anomaly_handlers.each do |handler|
        handler.call(signal)
      rescue StandardError
        # Handler errors don't block detection
      end
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end
  end
end
