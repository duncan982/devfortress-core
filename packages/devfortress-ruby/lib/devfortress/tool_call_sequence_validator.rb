# frozen_string_literal: true

module DevFortress
  # Tool-Call Sequence Validator (A7).
  #
  # Validates AI agent tool calls against an authorized directed acyclic
  # graph (DAG). Detects out-of-sequence tool calls that indicate prompt
  # injection attacks — e.g., an agent jumping directly to `place_order`
  # without first calling `add_to_cart`. Graduated response: log →
  # rate-limit → block → revoke session. Mirrors
  # packages/devfortress-sdk/src/tool-call-sequence-validator.ts.
  #
  # The graph is a Hash of tool_name => { requires: [...], max_calls:,
  # risk_level: }.
  class ToolCallSequenceValidator
    MAX_SESSIONS = 50_000

    def initialize(graph:, max_violations: 3, violation_window_ms: 300_000, graduated_response: true)
      @graph = graph
      @max_violations = max_violations
      @violation_window_ms = violation_window_ms
      @graduated_response = graduated_response
      @sessions = {}
    end

    def validate(session_id, tool_name, timestamp: nil)
      session = get_or_create_session(session_id)
      now = timestamp || now_ms

      session[:violations] = session[:violations].select { |v| now - v[:timestamp] < @violation_window_ms }

      graph_node = @graph[tool_name]

      unless graph_node
        session[:violations] << { timestamp: now, tool: tool_name, reason: "unknown_tool" }
        return build_result(session, false, "unknown_tool", tool_name, [])
      end

      missing_prereqs = (graph_node[:requires] || []).reject { |req| session[:call_history].include?(req) }
      unless missing_prereqs.empty?
        session[:violations] << { timestamp: now, tool: tool_name, reason: "missing_prerequisites: #{missing_prereqs.join(', ')}" }
        return build_result(session, false, "out_of_sequence", tool_name, missing_prereqs)
      end

      current_calls = session[:call_counts][tool_name] || 0
      max_calls = graph_node[:max_calls]
      if max_calls && max_calls.positive? && current_calls >= max_calls
        session[:violations] << { timestamp: now, tool: tool_name, reason: "max_calls_exceeded: #{current_calls}/#{max_calls}" }
        return build_result(session, false, "max_calls_exceeded", tool_name, [])
      end

      session[:call_history] << tool_name
      session[:call_counts][tool_name] = current_calls + 1

      {
        allowed: true, reason: "valid_sequence", action: "allow", prompt_injection_likely: false,
        violation_count: session[:violations].length, call_history: session[:call_history].dup,
      }
    end

    def reset_session(session_id)
      @sessions.delete(session_id)
    end
    alias clear_session reset_session

    def history(session_id)
      session = @sessions[session_id]
      session ? session[:call_history].dup : []
    end

    def session_stats(session_id)
      session = @sessions[session_id]
      return { exists: false, call_count: 0, violation_count: 0, history: [] } unless session

      { exists: true, call_count: session[:call_history].length, violation_count: session[:violations].length,
        history: session[:call_history].dup }
    end

    def destroy
      @sessions.clear
    end

    private

    def get_or_create_session(session_id)
      session = @sessions[session_id]
      unless session
        @sessions.delete(@sessions.first[0]) if @sessions.size >= MAX_SESSIONS
        session = { call_history: [], call_counts: {}, violations: [], created_at: now_ms }
        @sessions[session_id] = session
      end
      session
    end

    def build_result(session, allowed, reason, tool_name, missing_prerequisites)
      violation_count = session[:violations].length

      action = if @graduated_response
                 if violation_count >= @max_violations
                   "revoke_session"
                 elsif violation_count >= 2
                   "block"
                 elsif violation_count >= 1
                   "rate_limit"
                 else
                   "log"
                 end
               else
                 "block"
               end

      graph_node = @graph[tool_name]
      prompt_injection_likely = reason == "out_of_sequence" && %w[high critical].include?(graph_node&.[](:risk_level)&.to_s)

      {
        allowed: allowed, reason: reason, action: action, prompt_injection_likely: prompt_injection_likely,
        violation_count: violation_count, call_history: session[:call_history].dup,
        missing_prerequisites: missing_prerequisites.empty? ? nil : missing_prerequisites,
      }
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end
  end
end
