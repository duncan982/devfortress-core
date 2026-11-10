# frozen_string_literal: true

require "json"
require "thread"

require_relative "signer"
require_relative "transport"
require_relative "version"

module DevFortress
  # Telemetry Heartbeat — CV-M2.
  #
  # Sends anonymised usage telemetry to the platform periodically (default
  # every 5 minutes). No PII is transmitted — only aggregate counts and
  # operational metadata.
  #
  # If the heartbeat stops, the platform dashboard shows: "SDK offline —
  # upgrade to Hybrid for guaranteed visibility." Mirrors
  # packages/devfortress-sdk/src/telemetry.ts.
  #
  # A background periodic-heartbeat thread is only started if
  # heartbeat_interval_seconds is given and positive (mirrors Client's own
  # opt-in flush_interval convention) — #send_heartbeat is always callable
  # directly, which is what the test suite uses.
  class TelemetryManager
    DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 5 * 60 # 5 minutes
    DEFAULT_TIMEOUT_SECONDS = 5
    MAX_LATENCY_SAMPLES = 100
    INITIAL_HEARTBEAT_DELAY_SECONDS = 5

    def initialize(
      api_key:,
      endpoint:,
      heartbeat_interval_seconds: nil,
      debug: false,
      timeout: DEFAULT_TIMEOUT_SECONDS,
      transport: nil
    )
      @api_key = api_key
      @endpoint = endpoint
      @signer = Signer.new(api_key)
      @heartbeat_interval_seconds = heartbeat_interval_seconds
      @debug = debug
      @timeout = timeout
      @transport = transport || Transport.new

      @event_count = 0
      @block_count = 0
      @rate_limit_count = 0
      @latencies = []

      @started_at = now_ms
      @snapshot_provider = nil

      @mutex = Mutex.new
      @heartbeat_thread = nil
      @stop = false
      @stop_cv = ConditionVariable.new
    end

    # Starts sending periodic heartbeats if heartbeat_interval_seconds was
    # configured and positive. snapshot_provider, if given, is a callable
    # (#call) returning a Hash with symbol keys (:cl_mode, :tier,
    # :sdk_version, :model_expired, :license_degraded, :integrity_hash)
    # used to enrich each heartbeat with live SDK state.
    def start(snapshot_provider: nil)
      return if @heartbeat_thread

      @snapshot_provider = snapshot_provider
      @started_at = now_ms
      return unless @heartbeat_interval_seconds && @heartbeat_interval_seconds.positive?

      @heartbeat_thread = Thread.new { periodic_heartbeat }
      log(:info, "Telemetry heartbeat started (interval: #{@heartbeat_interval_seconds}s)")
    end

    def record_event
      @mutex.synchronize { @event_count += 1 }
    end

    def record_block
      @mutex.synchronize { @block_count += 1 }
    end

    def record_rate_limit
      @mutex.synchronize { @rate_limit_count += 1 }
    end

    # Records observe latency for p99 calculation (bounded reservoir
    # sampling, matching the Node source).
    def record_latency(latency_ms)
      @mutex.synchronize do
        if @latencies.length >= MAX_LATENCY_SAMPLES
          idx = rand(@latencies.length)
          @latencies[idx] = latency_ms
        else
          @latencies << latency_ms
        end
      end
    end

    # Sends a heartbeat to the platform. Fire-and-forget — failures are
    # logged, never raised. Public (rather than private, as on the Node
    # source) so it can be called directly in tests without waiting on the
    # background thread's timing.
    def send_heartbeat
      enriched = @snapshot_provider ? (@snapshot_provider.call || {}) : {}

      snapshot = {
        "eventCount" => @event_count,
        "blockCount" => @block_count,
        "rateLimitCount" => @rate_limit_count,
        "clMode" => enriched[:cl_mode] || "external",
        "tier" => enriched[:tier] || "starter",
        "sdkVersion" => enriched[:sdk_version] || VERSION,
        "modelExpired" => enriched.fetch(:model_expired, false),
        "licenseDegraded" => enriched.fetch(:license_degraded, false),
        "integrityHash" => enriched[:integrity_hash] || "",
        "uptimeSeconds" => ((now_ms - @started_at) / 1000),
        "p99LatencyMs" => compute_p99,
      }

      url = "#{@endpoint}/api/sdk/heartbeat"
      body = JSON.generate(snapshot.merge("timestamp" => now_ms))
      headers = @signer.sign("POST", Signer.request_target_from_url(url), body)
      headers["Content-Type"] = "application/json"

      begin
        @transport.send_request("POST", url, headers, body, @timeout)
        log(:debug,
            "Heartbeat sent: events=#{snapshot['eventCount']}, blocks=#{snapshot['blockCount']}, " \
            "uptime=#{snapshot['uptimeSeconds']}s")
        @mutex.synchronize do
          @event_count = 0
          @block_count = 0
          @rate_limit_count = 0
          @latencies = []
        end
      rescue StandardError => e
        log(:debug, "Heartbeat failed: #{e.message}")
      end
    end

    # Current telemetry state (for diagnostics).
    def state
      @mutex.synchronize do
        {
          event_count: @event_count,
          block_count: @block_count,
          rate_limit_count: @rate_limit_count,
          uptime_seconds: ((now_ms - @started_at) / 1000),
        }
      end
    end

    # Stops sending heartbeats and clean up. Safe to call more than once.
    def destroy
      @mutex.synchronize do
        @stop = true
        @stop_cv.broadcast
      end
      @heartbeat_thread&.join
      @heartbeat_thread = nil
    end

    private

    def periodic_heartbeat
      # Send the first heartbeat after a short delay so #start doesn't
      # block init, then on the configured interval thereafter.
      stop = @mutex.synchronize do
        @stop_cv.wait(@mutex, INITIAL_HEARTBEAT_DELAY_SECONDS)
        @stop
      end
      return if stop

      send_heartbeat

      loop do
        stop = @mutex.synchronize do
          @stop_cv.wait(@mutex, @heartbeat_interval_seconds)
          @stop
        end
        break if stop

        send_heartbeat
      end
    end

    def compute_p99
      return 0 if @latencies.empty?

      sorted = @latencies.sort
      idx = (sorted.length * 0.99).floor
      sorted[[idx, sorted.length - 1].min]
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end

    def log(level, message)
      return if level == :debug && !@debug

      prefix = "[DevFortress:Telemetry]"
      case level
      when :warn
        warn("#{prefix} #{message}")
      else
        puts("#{prefix} #{message}")
      end
    end
  end

  # Anomaly-Gated Metering: Aggregate Telemetry Rollup Buffer.
  #
  # Option B (2026-08-27): CLEAN/unflagged traffic no longer gets a full,
  # billed LiveThreatEvent row per request. Instead, this buffer
  # accumulates lightweight per-alias/IP-per-hour counters in memory
  # (request count, unique endpoints seen, error count, latency sum) and
  # flushes them as a small number of upsert-increment rows to
  # /api/events/telemetry-rollup on a short interval — not per request.
  # This is what feeds B1/B10's population-level baseline needs without
  # counting toward the customer's billed event quota (see
  # AliasTelemetryRollup in prisma/schema.prisma and
  # DF-Session-task-report-27-08-26.md, Section 1/4). Mirrors
  # packages/devfortress-sdk/src/telemetry-rollup-buffer.ts.
  #
  # The Node source keys its in-memory buckets on a NUL-byte string
  # concatenation (`"#{aliasOrIpKey}\x00#{periodKey}"`) as a
  # collision-free composite map key. This port uses BucketKey, a frozen
  # Struct of (alias_or_ip_key, period_key), as the Hash key instead — the
  # same collision-free bucketing semantics, without embedding a control
  # character in a string.
  class TelemetryRollupBuffer
    # Bounded per-bucket endpoint tracking — uniqueEndpoints is an
    # approximation (this is non-billing, best-effort aggregate
    # telemetry, not an exact count).
    MAX_ENDPOINTS_TRACKED_PER_BUCKET = 50
    # Matches TelemetryManager's DEFAULT_HEARTBEAT_INTERVAL_SECONDS — this
    # is aggregate, non-billing telemetry, not real-time-critical, so a
    # wider batching window means fewer platform requests.
    DEFAULT_FLUSH_INTERVAL_SECONDS = 5 * 60
    DEFAULT_MAX_BUFFERED_KEYS = 500
    DEFAULT_TIMEOUT_SECONDS = 10

    BucketKey = Struct.new(:alias_or_ip_key, :period_key)

    # Hour-bucket period key, e.g. "2026-08-27T14" (UTC) — matches
    # AliasTelemetryRollup.periodKey.
    def self.hourly_period_key(time = Time.now)
      time.utc.strftime("%Y-%m-%dT%H")
    end

    def initialize(
      api_key:,
      endpoint:,
      flush_interval_seconds: nil,
      max_buffered_keys: DEFAULT_MAX_BUFFERED_KEYS,
      debug: false,
      timeout: DEFAULT_TIMEOUT_SECONDS,
      transport: nil
    )
      @api_key = api_key
      @endpoint = endpoint
      @signer = Signer.new(api_key)
      @flush_interval_seconds = flush_interval_seconds
      @max_buffered_keys = max_buffered_keys || DEFAULT_MAX_BUFFERED_KEYS
      @debug = debug
      @timeout = timeout
      @transport = transport || Transport.new

      @buckets = {}
      @mutex = Mutex.new
      @flush_thread = nil
      @stop = false
      @stop_cv = ConditionVariable.new
    end

    # Starts the periodic flush thread, if flush_interval_seconds was
    # configured and positive. Safe to call multiple times (no-op if
    # already started).
    def start
      return if @flush_thread
      return unless @flush_interval_seconds && @flush_interval_seconds.positive?

      @flush_thread = Thread.new { periodic_flush }
    end

    # Buffers one clean (non-flagged) request's contribution. Synchronous,
    # no network call — actual delivery happens on the next #flush.
    def add(alias_or_ip_key:, endpoint:, is_error:, latency_ms:)
      period_key = self.class.hourly_period_key
      key = BucketKey.new(alias_or_ip_key, period_key)
      now = now_ms
      force_flush = false

      @mutex.synchronize do
        bucket = @buckets[key]
        unless bucket
          # Bound total buffered keys so a burst of unique IPs can't grow
          # memory unbounded — force an early flush and drop this one
          # contribution. Acceptable: this is approximate, non-billing
          # aggregate telemetry.
          if @buckets.size >= @max_buffered_keys
            force_flush = true
          else
            bucket = {
              alias_or_ip_key: alias_or_ip_key,
              period_key: period_key,
              request_count: 0,
              endpoints: {},
              error_count: 0,
              latency_sum_ms: 0,
              window_start: now,
              window_end: now,
            }
            @buckets[key] = bucket
          end
        end

        if bucket
          bucket[:request_count] += 1
          bucket[:endpoints][endpoint] = true if bucket[:endpoints].size < MAX_ENDPOINTS_TRACKED_PER_BUCKET
          bucket[:error_count] += 1 if is_error
          bucket[:latency_sum_ms] += latency_ms
          bucket[:window_end] = now
        end
      end

      flush if force_flush
    end

    # Flushes all buffered buckets to the platform in one batch request.
    def flush
      contributions = @mutex.synchronize do
        break nil if @buckets.empty?

        list = @buckets.values.map do |b|
          {
            "aliasOrIpKey" => b[:alias_or_ip_key],
            "periodKey" => b[:period_key],
            "requestCount" => b[:request_count],
            "uniqueEndpointsInBatch" => b[:endpoints].size,
            "errorCount" => b[:error_count],
            "latencySumMs" => b[:latency_sum_ms],
            "windowStart" => b[:window_start],
            "windowEnd" => b[:window_end],
          }
        end
        @buckets.clear
        list
      end
      return if contributions.nil?

      post(contributions)
    end

    # Cleans up the flush thread and drops any unflushed buckets.
    def destroy
      @mutex.synchronize do
        @stop = true
        @stop_cv.broadcast
        @buckets.clear
      end
      @flush_thread&.join
      @flush_thread = nil
    end

    private

    def periodic_flush
      loop do
        stop = @mutex.synchronize do
          @stop_cv.wait(@mutex, @flush_interval_seconds)
          @stop
        end
        break if stop

        flush
      end
    end

    def post(contributions)
      url = "#{@endpoint}/api/events/telemetry-rollup"
      body = JSON.generate({ "contributions" => contributions })
      headers = @signer.sign("POST", Signer.request_target_from_url(url), body)
      headers["Content-Type"] = "application/json"
      @transport.send_request("POST", url, headers, body, @timeout)
    rescue StandardError => e
      # Best-effort — aggregate telemetry is not billing-relevant, so
      # dropping a batch on transient failure is acceptable (unlike the
      # full event relay path, which retries).
      log(:debug, "telemetry rollup flush failed: #{e.message}")
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end

    def log(level, message)
      return if level == :debug && !@debug

      puts("[DevFortress:TelemetryRollup] #{message}")
    end
  end
end
