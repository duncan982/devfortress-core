# frozen_string_literal: true

module DevFortress
  # Graduated Rate Limiter (Invention A3).
  #
  # Mirrors packages/devfortress-sdk/src/graduated-rate-limiter.ts.
  # Implements alias-scoped graduated rate limiting with multi-stage
  # response escalation. Addresses GAP-A3-1 through GAP-A3-4:
  #
  #   GAP-A3-1: Latency jitter (+/-20%) in soft-limit injection
  #   GAP-A3-2: Per-endpoint hierarchical rate limits (configurable)
  #   GAP-A3-3: Burst detection (1-second micro-window)
  #   GAP-A3-4: Escalating cooldowns (60s->120s->240s, revoke after 3)
  #
  # Four-stage graduated response:
  #
  #   Stage 1: Observation (< 50% of limit)
  #   Stage 2: Warning (50%-75% of limit)
  #   Stage 3: Soft-limit with latency injection (75%-100% of limit)
  #   Stage 4: Hard-block with escalating cooldowns (>= 100% of limit)
  #   Stage 5: Alias revocation (>= 120% of limit or 3 consecutive blocks)
  class GraduatedRateLimiter
    RateLimitResult = Struct.new(
      :stage, :current_rate, :limit, :ratio, :injected_latency_ms, :blocked,
      :revoke, :cooldown_seconds, :remaining, :burst_detected,
      keyword_init: true
    )

    Entry = Struct.new(:timestamps, :cooldown_until, :consecutive_blocks, :revoked, :burst_timestamps)

    def initialize(default_limit: 100, window_seconds: 60, soft_limit_base_latency_ms: 2000,
                   max_entries: 50_000, endpoint_limits: {}, burst_limit: 20,
                   initial_cooldown_seconds: 60, max_consecutive_blocks: 3)
      @default_limit = default_limit
      @window_seconds = window_seconds
      @soft_limit_base_latency_ms = soft_limit_base_latency_ms
      @max_entries = max_entries
      @endpoint_limits = endpoint_limits.dup
      @burst_limit = burst_limit
      @initial_cooldown_seconds = initial_cooldown_seconds
      @max_consecutive_blocks = max_consecutive_blocks

      @entries = {}
      # Insertion order for oldest-first eviction, mirroring the
      # iteration order of Node's Map (a key's position is set once, at
      # first insertion, unaffected by later updates to the same key).
      @order = []
      @mutex = Mutex.new
      @stop = false
      @stop_cv = ConditionVariable.new
      @cleanup_thread = Thread.new { periodic_cleanup }
    end

    # Stops the periodic cleanup thread and clears tracked state.
    def destroy
      @mutex.synchronize do
        @stop = true
        @stop_cv.broadcast
      end
      @cleanup_thread&.join
      @mutex.synchronize do
        @entries = {}
        @order = []
      end
    end

    # Checks the rate limit for an alias (identified by key, typically
    # an IP or session ID). Records the request and returns the
    # graduated response. endpoint is optional and enables
    # per-endpoint limits (GAP-A3-2).
    def check(key, endpoint = nil)
      @mutex.synchronize { check_locked(key, endpoint) }
    end

    # Manually revokes an alias (e.g. from an external security
    # decision).
    def revoke_alias(key)
      @mutex.synchronize do
        entry = @entries[key]
        if entry.nil?
          entry = Entry.new([], Time.at(0), 0, true, [])
          @order << key
        else
          entry.revoked = true
        end
        @entries[key] = entry
      end
    end

    # Resets an alias's rate limit state (e.g. after an admin
    # override).
    def reset_alias(key)
      @mutex.synchronize { @entries.delete(key) }
    end

    # Returns whether an alias has been revoked.
    def revoked?(key)
      @mutex.synchronize { @entries[key]&.revoked || false }
    end

    # Sets per-endpoint rate limits (merged into any existing endpoint
    # limits). GAP-A3-2.
    def set_endpoint_limits(limits)
      @mutex.synchronize { @endpoint_limits.merge!(limits) }
    end

    # Returns the current number of tracked aliases.
    def size
      @mutex.synchronize { @entries.size }
    end

    private

    def check_locked(key, endpoint)
      now = Time.now
      entry = @entries[key] || Entry.new([], Time.at(0), 0, false, [])
      existed = @entries.key?(key)

      if entry.revoked
        return RateLimitResult.new(
          stage: :revocation, current_rate: 0, limit: 0, ratio: Float::INFINITY,
          injected_latency_ms: 0, blocked: true, revoke: false, cooldown_seconds: 0,
          remaining: 0, burst_detected: false
        )
      end

      if entry.cooldown_until > now
        cooldown_remaining = (entry.cooldown_until - now).ceil
        return RateLimitResult.new(
          stage: :hard_block, current_rate: entry.timestamps.size, limit: effective_limit(endpoint),
          ratio: 1.0, injected_latency_ms: 0, blocked: true, revoke: false,
          cooldown_seconds: cooldown_remaining, remaining: 0, burst_detected: false
        )
      end

      window_start = now - @window_seconds
      entry.timestamps = entry.timestamps.select { |t| t > window_start }

      # GAP-A3-3: clean burst micro-window (1 second).
      burst_window_start = now - 1
      entry.burst_timestamps = entry.burst_timestamps.select { |t| t > burst_window_start }

      entry.timestamps << now
      entry.burst_timestamps << now

      if !existed && @entries.size >= @max_entries
        evict_oldest
      end
      @order << key unless existed
      @entries[key] = entry

      limit = effective_limit(endpoint)
      current_rate = entry.timestamps.size
      ratio = current_rate.to_f / limit

      burst_detected = entry.burst_timestamps.size > @burst_limit

      if ratio >= 1.2 || entry.consecutive_blocks >= @max_consecutive_blocks
        entry.revoked = true
        return RateLimitResult.new(
          stage: :revocation, current_rate: current_rate, limit: limit, ratio: ratio,
          injected_latency_ms: 0, blocked: true, revoke: true, cooldown_seconds: 0,
          remaining: 0, burst_detected: burst_detected
        )
      end

      if ratio >= 1.0 || burst_detected
        entry.consecutive_blocks += 1
        cooldown_multiplier = 2**(entry.consecutive_blocks - 1)
        cooldown_seconds = @initial_cooldown_seconds * cooldown_multiplier
        entry.cooldown_until = now + cooldown_seconds

        return RateLimitResult.new(
          stage: :hard_block, current_rate: current_rate, limit: limit, ratio: ratio,
          injected_latency_ms: 0, blocked: true, revoke: false, cooldown_seconds: cooldown_seconds,
          remaining: 0, burst_detected: burst_detected
        )
      end

      if ratio >= 0.75
        entry.consecutive_blocks = 0

        progress = (ratio - 0.75) / 0.25
        base_latency = @soft_limit_base_latency_ms * (progress**2)
        jitter = 0.8 + (0.4 * rand)
        injected_latency_ms = (base_latency * jitter).round

        return RateLimitResult.new(
          stage: :soft_limit, current_rate: current_rate, limit: limit, ratio: ratio,
          injected_latency_ms: injected_latency_ms, blocked: false, revoke: false,
          cooldown_seconds: 0, remaining: [0, limit - current_rate].max, burst_detected: burst_detected
        )
      end

      if ratio >= 0.5
        entry.consecutive_blocks = 0
        return RateLimitResult.new(
          stage: :warning, current_rate: current_rate, limit: limit, ratio: ratio,
          injected_latency_ms: 0, blocked: false, revoke: false, cooldown_seconds: 0,
          remaining: [0, limit - current_rate].max, burst_detected: false
        )
      end

      entry.consecutive_blocks = 0
      RateLimitResult.new(
        stage: :observation, current_rate: current_rate, limit: limit, ratio: ratio,
        injected_latency_ms: 0, blocked: false, revoke: false, cooldown_seconds: 0,
        remaining: [0, limit - current_rate].max, burst_detected: false
      )
    end

    def effective_limit(endpoint)
      return @default_limit if endpoint.nil? || @endpoint_limits.empty?

      return @endpoint_limits[endpoint] if @endpoint_limits.key?(endpoint)

      @endpoint_limits.each do |pattern, limit|
        if pattern.end_with?("*") && endpoint.start_with?(pattern[0..-2])
          return limit
        end
      end

      @default_limit
    end

    def evict_oldest
      while (oldest = @order.shift)
        if @entries.key?(oldest)
          @entries.delete(oldest)
          return
        end
      end
    end

    # Mirrors the Node SDK's 30-second cleanup interval: removes
    # entries with no recent activity that are not in cooldown and not
    # revoked.
    def periodic_cleanup
      loop do
        stop = @mutex.synchronize do
          # Check @stop before waiting: if destroy already set it and
          # broadcast before this thread reached here, waiting again
          # would miss that wakeup and block for the full interval.
          if @stop
            true
          else
            @stop_cv.wait(@mutex, 30)
            @stop
          end
        end
        break if stop

        cleanup
      end
    end

    def cleanup
      @mutex.synchronize do
        now = Time.now
        window_start = now - @window_seconds

        @entries.delete_if do |_key, entry|
          has_recent_activity = entry.timestamps.any? { |t| t > window_start }
          in_cooldown = entry.cooldown_until > now
          !has_recent_activity && !in_cooldown && !entry.revoked
        end
      end
    end
  end
end
