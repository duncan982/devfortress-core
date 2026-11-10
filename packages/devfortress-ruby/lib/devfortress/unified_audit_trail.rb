# frozen_string_literal: true

module DevFortress
  # Unified Audit Trail (CL-M3).
  #
  # Mirrors packages/devfortress-sdk/src/unified-audit.ts. Merges internal
  # and external closed-loop audit events into a single in-memory
  # timeline with consistent fields regardless of source.
  #
  # NOTE on tamper-evidence: this is an in-memory log only -- it is not
  # cryptographically signed or hash-chained, and neither is Node's own
  # UnifiedAuditTrail. The HMAC-signed, hash-chained tamper-evident audit
  # trail (TODO 265/266/272) is a separate, server-side Next.js module
  # (lib/audit-trail-signer.ts) operating directly on the LiveThreatEvent
  # Postgres table. It has no SDK-side analog in any language, including
  # Node, so this port does not and cannot provide tamper-evidence either.
  class UnifiedAuditTrail
    DEDUP_WINDOW_SECONDS = 5
    DEDUP_MAP_CAP = 10_000
    DEFAULT_MAX_ENTRIES = 100_000

    Entry = Struct.new(
      :event_id, :timestamp, :source, :tier, :decision, :score, :severity,
      :latency_ms, :ip, :path, :method, :matched_rules, :user_id, :agent_id,
      :session_id, :fallback_mode, :meta,
      keyword_init: true
    ) do
      def to_h_ordered
        {
          event_id: event_id, timestamp: timestamp, source: source, tier: tier,
          decision: decision, score: score, severity: severity, latency_ms: latency_ms,
          ip: ip, path: path, method: method, matched_rules: matched_rules,
          user_id: user_id, agent_id: agent_id, session_id: session_id,
          fallback_mode: fallback_mode, meta: meta,
        }
      end
    end

    def initialize(max_entries: DEFAULT_MAX_ENTRIES, on_entry: nil, debug: false)
      @max_entries = max_entries
      @on_entry = on_entry
      @debug = debug
      @mutex = Mutex.new
      @entries = []
      @recent_event_ids = {}
      @stats = {
        internal_decisions: 0, external_decisions: 0, hybrid_decisions: 0,
        fallback_events: 0, total_blocks: 0, total_allows: 0, total_rate_limits: 0,
        internal_latency_sum: 0.0, external_latency_sum: 0.0,
      }
    end

    # Records an audit entry from any source. S27: the same event_id
    # within the 5s dedup window is merged (external overrides internal),
    # not duplicated.
    def record(entry)
      fire_entry = nil

      @mutex.synchronize do
        now = Time.now
        existing = @recent_event_ids[entry.event_id]
        if existing && (now - existing) < DEDUP_WINDOW_SECONDS
          if entry.source == :external || entry.source == "external"
            idx = @entries.index { |e| e.event_id == entry.event_id && (e.source == :internal || e.source == "internal") }
            if idx
              merged = @entries[idx].to_h_ordered.merge(entry.to_h_ordered).merge(source: :hybrid)
              @entries[idx] = Entry.new(**merged)
              warn "[DF Audit] DEDUP: merged #{entry.event_id} (external overrides internal)" if @debug
            end
          end
          next
        end

        @recent_event_ids[entry.event_id] = now
        if @recent_event_ids.size > DEDUP_MAP_CAP
          cutoff = now - DEDUP_WINDOW_SECONDS
          @recent_event_ids.delete_if { |_id, ts| ts < cutoff }
        end

        @entries.shift((@max_entries * 0.1).floor) if @entries.size >= @max_entries
        @entries << entry
        update_stats(entry)
        fire_entry = entry
      end

      return unless fire_entry

      if @on_entry
        begin
          @on_entry.call(fire_entry)
        rescue StandardError
          # Callback errors must not break the audit trail.
        end
      end

      return unless @debug

      warn "[DF Audit] #{entry.source}:tier#{entry.tier} #{entry.decision} " \
           "score=#{entry.score} #{entry.ip} #{entry.method} #{entry.path} (#{entry.latency_ms}ms)"
    end

    # Queries audit entries with filters.
    def query(source: nil, decision: nil, ip: nil, user_id: nil, agent_id: nil,
              min_score: nil, since: nil, limit: 100)
      result = @mutex.synchronize { @entries.dup }

      result = result.select { |e| e.source.to_s == source.to_s } if source
      result = result.select { |e| e.decision.to_s == decision.to_s } if decision
      result = result.select { |e| e.ip == ip } if ip
      result = result.select { |e| e.user_id == user_id } if user_id
      result = result.select { |e| e.agent_id == agent_id } if agent_id
      result = result.select { |e| e.score >= min_score } if min_score
      result = result.select { |e| e.timestamp >= since } if since

      limit && limit > 0 ? result.last(limit) : result
    end

    # Returns aggregated statistics.
    def get_stats
      stats, total = @mutex.synchronize { [@stats.dup, @entries.size] }

      avg_internal = stats[:internal_decisions].positive? ? (stats[:internal_latency_sum] / stats[:internal_decisions]).round : 0
      avg_external = stats[:external_decisions].positive? ? (stats[:external_latency_sum] / stats[:external_decisions]).round : 0

      {
        total: total,
        internal_decisions: stats[:internal_decisions],
        external_decisions: stats[:external_decisions],
        hybrid_decisions: stats[:hybrid_decisions],
        fallback_events: stats[:fallback_events],
        total_blocks: stats[:total_blocks],
        total_allows: stats[:total_allows],
        total_rate_limits: stats[:total_rate_limits],
        avg_internal_latency_ms: avg_internal,
        avg_external_latency_ms: avg_external,
      }
    end

    # Returns source:decision counts, for dashboard visualization.
    def get_decision_distribution
      entries = @mutex.synchronize { @entries.dup }
      dist = {}
      entries.each do |e|
        key = "#{e.source}:#{e.decision}"
        dist[key] = (dist[key] || 0) + 1
      end
      dist
    end

    # Returns latency histogram buckets.
    def get_latency_histogram
      entries = @mutex.synchronize { @entries.dup }
      hist = { under_1ms: 0, under_5ms: 0, under_50ms: 0, under_200ms: 0, under_1s: 0, over_1s: 0 }
      entries.each do |e|
        key = if e.latency_ms < 1 then :under_1ms
              elsif e.latency_ms < 5 then :under_5ms
              elsif e.latency_ms < 50 then :under_50ms
              elsif e.latency_ms < 200 then :under_200ms
              elsif e.latency_ms < 1000 then :under_1s
              else :over_1s
              end
        hist[key] += 1
      end
      hist
    end

    # Exports entries as JSON (for compliance/archival).
    def export_json(since: nil)
      entries = @mutex.synchronize { @entries.dup }
      entries = entries.select { |e| e.timestamp >= since } if since
      require "json"
      JSON.pretty_generate(entries.map(&:to_h_ordered))
    end

    # Resets the audit trail (for testing). @internal
    def reset
      @mutex.synchronize do
        @entries = []
        @recent_event_ids = {}
        @stats = @stats.transform_values { 0 }
      end
    end

    private

    def update_stats(entry)
      source = entry.source.to_s
      case source
      when "internal"
        @stats[:internal_decisions] += 1
        @stats[:internal_latency_sum] += entry.latency_ms
      when "external"
        @stats[:external_decisions] += 1
        @stats[:external_latency_sum] += entry.latency_ms
      else
        @stats[:hybrid_decisions] += 1
        if entry.tier.to_i > 0
          @stats[:internal_latency_sum] += entry.latency_ms
        else
          @stats[:external_latency_sum] += entry.latency_ms
        end
      end

      @stats[:fallback_events] += 1 if entry.fallback_mode

      case entry.decision.to_s
      when "block" then @stats[:total_blocks] += 1
      when "allow" then @stats[:total_allows] += 1
      when "rate_limit" then @stats[:total_rate_limits] += 1
      end
    end
  end
end
