# frozen_string_literal: true

require "json"

module DevFortress
  # Agent Loop Detector (A10).
  #
  # Instruments the SDK to track agent execution cycles and token
  # consumption. Detects infinite loops via cycle count, time budget, and
  # token budget thresholds. Implements an automatic circuit breaker: pause
  # agent, alert owner. Distinguishes legitimate long operations from
  # runaway loops via progress metrics. Mirrors
  # packages/devfortress-sdk/src/agent-loop-detector.ts.
  class AgentLoopDetector
    def initialize(max_cycles: 20, max_duration_ms: 120_000, max_tokens: 100_000,
                    progress_threshold: { unique_tools: 2, window_cycles: 5 }, max_sessions: 50_000)
      @max_cycles = max_cycles
      @max_duration_ms = max_duration_ms
      @max_tokens = max_tokens
      @progress_threshold = progress_threshold
      @max_sessions = max_sessions
      @sessions = {}
    end

    # Record a new execution cycle for an agent session.
    def record_cycle(agent_id, session_id, tokens_used: 0, tool_name: nil, tool_args: nil, progress_metric: nil)
      session = get_or_create_session(agent_id, session_id)
      now = now_ms

      return build_result(session, now, true, "agent_paused", "TERMINATE") if session[:paused]

      session[:cycles] += 1
      session[:total_tokens] += tokens_used || 0
      session[:tool_history] << tool_name if tool_name
      session[:arg_hashes] << hash_args(tool_args) if tool_args
      session[:progress_metrics] << progress_metric unless progress_metric.nil?

      elapsed_ms = now - session[:started_at]
      making_progress = check_progress(session)
      repetition_score = compute_repetition_score(session)

      if session[:cycles] >= @max_cycles && !making_progress
        session[:paused] = true
        return build_result(session, now, true, "max_cycles", "PAUSE_AGENT")
      end

      if elapsed_ms >= @max_duration_ms
        session[:paused] = true
        return build_result(session, now, true, "max_duration", "PAUSE_AGENT")
      end

      if session[:total_tokens] >= @max_tokens
        session[:paused] = true
        return build_result(session, now, true, "max_tokens", "PAUSE_AGENT")
      end

      if repetition_score > 0.8 && session[:cycles] > 5 && !making_progress
        session[:paused] = true
        return build_result(session, now, true, "repetitive_pattern", "PAUSE_AGENT")
      end

      if session[:cycles] >= @max_cycles * 0.8 || elapsed_ms >= @max_duration_ms * 0.8 || session[:total_tokens] >= @max_tokens * 0.8
        return build_result(session, now, false, "approaching_limit", "WARN")
      end

      build_result(session, now, false, "within_limits", "CONTINUE")
    end

    def clear_session(agent_id_or_session_id, session_id = nil)
      key = session_id ? "#{agent_id_or_session_id}:#{session_id}" : agent_id_or_session_id
      @sessions.delete(key)
    end

    def release_agent(session_id)
      session = @sessions[session_id]
      return false unless session

      session[:paused] = false
      session[:cycles] = 0
      session[:total_tokens] = 0
      session[:tool_history] = []
      session[:arg_hashes] = []
      true
    end

    def paused?(session_id)
      @sessions[session_id]&.[](:paused) || false
    end

    def metrics(session_id)
      session = @sessions[session_id]
      return { exists: false, cycles: 0, tokens: 0, elapsed_ms: 0, paused: false } unless session

      { exists: true, cycles: session[:cycles], tokens: session[:total_tokens],
        elapsed_ms: now_ms - session[:started_at], paused: session[:paused] }
    end

    def destroy
      @sessions.clear
    end

    private

    def get_or_create_session(agent_id, session_id)
      session = @sessions[session_id]
      unless session
        @sessions.delete(@sessions.first[0]) if @sessions.size >= @max_sessions
        session = { agent_id: agent_id, started_at: now_ms, cycles: 0, total_tokens: 0, tool_history: [],
                    arg_hashes: [], progress_metrics: [], paused: false }
        @sessions[session_id] = session
      end
      session
    end

    def check_progress(session)
      unique_tools = @progress_threshold[:unique_tools]
      window_cycles = @progress_threshold[:window_cycles]
      recent_tools = session[:tool_history].last(window_cycles)
      return true if recent_tools.uniq.length >= unique_tools

      if session[:progress_metrics].length >= 2
        recent = session[:progress_metrics].last(3)
        increasing = recent.each_cons(2).all? { |a, b| b > a }
        return true if increasing
      end

      false
    end

    def compute_repetition_score(session)
      return 0 if session[:arg_hashes].length < 3

      recent = session[:arg_hashes].last(10)
      unique_hashes = recent.uniq.length
      1 - (unique_hashes.to_f / recent.length)
    end

    def hash_args(args)
      sorted_keys = args.keys.sort_by(&:to_s)
      sorted = sorted_keys.to_h { |k| [k, args[k]] }
      str = JSON.generate(sorted)
      hash = 0
      str.each_byte do |byte|
        hash = ((hash << 5) - hash + byte) & 0xFFFFFFFF
      end
      # Mirror JS's `| 0` (32-bit signed wraparound) before base-36 encoding.
      hash -= 0x100000000 if hash >= 0x80000000
      hash.to_s(36)
    end

    def build_result(session, now, loop_detected, reason, action)
      elapsed_ms = now - session[:started_at]
      making_progress = check_progress(session)
      repetition_score = compute_repetition_score(session)

      {
        loop: loop_detected, reason: reason, action: action, cycles: session[:cycles],
        total_tokens: session[:total_tokens], elapsed_ms: elapsed_ms, making_progress: making_progress,
        repetition_score: repetition_score,
      }
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end
  end
end
