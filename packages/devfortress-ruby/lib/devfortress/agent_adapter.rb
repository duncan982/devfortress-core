# frozen_string_literal: true

require "json"

module DevFortress
  AGENT_ID_MAX_LENGTH = 128
  AGENT_ID_PATTERN = /\A[a-zA-Z0-9_\-.:@]+\z/.freeze

  # Validate agent ID to prevent injection and ensure safe usage as cache
  # keys and pseudo-URL path segments.
  def self.validate_agent_id(agent_id)
    raise ArgumentError, "agent_id is required and must be a non-empty string" if agent_id.nil? || !agent_id.is_a?(String) || agent_id.empty?
    raise ArgumentError, "agent_id must be at most #{AGENT_ID_MAX_LENGTH} characters" if agent_id.length > AGENT_ID_MAX_LENGTH
    unless AGENT_ID_PATTERN.match?(agent_id)
      raise ArgumentError, "agent_id may only contain alphanumeric characters, hyphens, underscores, dots, colons, and @"
    end
  end

  # DevFortress Agent Security Adapter (IP-C1).
  #
  # Wraps Client#track_event for AI agent tool invocations. Intercepts
  # agent_id, tool_name, and input_summary from LangChain/LangGraph tool
  # calls, OpenAI function calling, or raw HTTP-based agent tool
  # invocations.
  #
  # Unlike the Node SDK's synchronous df.observe() (which can return a
  # server-decided flagged verdict on the same call), Ruby's Tier 1 Client
  # queues events asynchronously (#track_event/#flush) — there is no
  # per-call server round trip here to carry a flagged verdict back, so
  # this adapter has no on_flagged callback, matching the Go SDK's same
  # adaptation for the same reason. The event shape (agent_id, tool_name,
  # input_summary, framework, session tracking) matches the Node SDK
  # field-for-field.
  class AgentAdapter
    MAX_TRACKED_SESSIONS = 10_000

    def initialize(client, agent_id:, agent_name: nil, agent_ip: "127.0.0.1",
                   max_input_summary_length: 256, sanitize_inputs: true)
      DevFortress.validate_agent_id(agent_id)
      @client = client
      @agent_id = agent_id
      @agent_name = agent_name || agent_id
      @agent_ip = agent_ip
      @max_input_summary_length = max_input_summary_length
      @sanitize_inputs = sanitize_inputs
      @session_tool_counts = {}
    end

    # Queue an observation of an AI agent tool invocation.
    def observe_tool_call(tool:, input: nil, duration_ms: nil, model: nil, framework: "custom", meta: nil, session_id: nil)
      summary = summarize_input(input)

      sid = session_id || "default"
      @session_tool_counts[sid] = (@session_tool_counts[sid] || 0) + 1
      count = @session_tool_counts[sid]

      metadata = {
        "agent_id" => @agent_id,
        "agent_name" => @agent_name,
        "tool_name" => tool,
        "input_summary" => summary,
        "duration_ms" => duration_ms,
        "model" => model,
        "framework" => framework || "custom",
        "session_tool_count" => count,
        "session_id" => session_id,
        "event_category" => "agent_tool_call",
      }
      metadata.merge!(meta) if meta

      @client.track_event(
        "eventType" => "custom",
        "method" => "TOOL_CALL",
        "path" => "/agent/#{@agent_id}/tool/#{tool}",
        "ip" => @agent_ip,
        "userAgent" => "DevFortress-Agent/#{@agent_name}",
        "severity" => "LOW",
        "metadata" => metadata,
      )
    end

    # Convenience wrapper for a LangChain/LangGraph tool call.
    def observe_lang_chain_tool(tool_name, tool_input, session_id: nil, model: nil, duration_ms: nil)
      observe_tool_call(tool: tool_name, input: tool_input, framework: "langchain", model: model,
                         duration_ms: duration_ms, session_id: session_id)
    end

    # Convenience wrapper extracting from an OpenAI tool_calls entry.
    def observe_openai_tool_call(function_name, arguments_json, session_id: nil, model: nil, duration_ms: nil)
      parsed = begin
        JSON.parse(arguments_json)
      rescue JSON::ParserError
        { "raw" => arguments_json }
      end
      observe_tool_call(tool: function_name, input: parsed, framework: "openai", model: model,
                         duration_ms: duration_ms, session_id: session_id)
    end

    # Observe a raw HTTP tool call (e.g. an agent calling an external API).
    def observe_http_tool_call(url, method, status_code: nil, duration_ms: nil, session_id: nil, meta: nil)
      observe_tool_call(
        tool: "http:#{method.to_s.upcase}",
        input: { "url" => url, "status_code" => status_code },
        framework: "raw_http",
        duration_ms: duration_ms,
        meta: meta,
        session_id: session_id,
      )
    end

    # Track the start of an agent session (task/conversation).
    def track_session_start(session_id, task_description: nil)
      if @session_tool_counts.size >= MAX_TRACKED_SESSIONS
        @session_tool_counts.delete(@session_tool_counts.first[0])
      end
      @session_tool_counts[session_id] = 0

      @client.track_event(
        "eventType" => "custom",
        "method" => "SESSION_START",
        "path" => "/agent/#{@agent_id}/session/#{session_id}",
        "ip" => @agent_ip,
        "userAgent" => "DevFortress-Agent/#{@agent_name}",
        "severity" => "LOW",
        "metadata" => {
          "agent_id" => @agent_id, "session_id" => session_id,
          "task_description" => task_description, "event_category" => "agent_session_start",
        },
      )
    end

    # Track the end of an agent session with summary metrics.
    def track_session_end(session_id, total_tools: nil, duration_ms: nil, success: nil)
      tool_count = @session_tool_counts.delete(session_id) || 0

      @client.track_event(
        "eventType" => "custom",
        "method" => "SESSION_END",
        "path" => "/agent/#{@agent_id}/session/#{session_id}",
        "ip" => @agent_ip,
        "userAgent" => "DevFortress-Agent/#{@agent_name}",
        "severity" => "LOW",
        "metadata" => {
          "agent_id" => @agent_id, "session_id" => session_id,
          "total_tools" => total_tools || tool_count, "total_duration_ms" => duration_ms,
          "success" => success, "event_category" => "agent_session_end",
        },
      )
    end

    def session_tool_count(session_id)
      @session_tool_counts[session_id] || 0
    end

    private

    def summarize_input(input)
      return "{}" unless input

      summary = {}
      input.each do |key, val|
        summary[key.to_s] =
          if val.nil?
            "null"
          elsif val.is_a?(String)
            key_str = key.to_s.downcase
            if @sanitize_inputs && (key_str.include?("key") || key_str.include?("token") || key_str.include?("secret") || key_str.include?("password"))
              "[REDACTED]"
            else
              val.length > 64 ? "#{val[0, 61]}..." : val
            end
          elsif val.is_a?(Numeric) || val == true || val == false
            val.to_s
          elsif val.is_a?(Array)
            "Array(#{val.length})"
          else
            "{...}"
          end
      end

      str = JSON.generate(summary)
      str.length > @max_input_summary_length ? "#{str[0, @max_input_summary_length - 3]}..." : str
    end
  end
end
