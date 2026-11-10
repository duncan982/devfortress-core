# frozen_string_literal: true

require "digest"
require "json"
require "thread"

require_relative "signer"
require_relative "transport"
require_relative "delivery_result"
require_relative "version"
require_relative "internal_closed_loop_engine"
require_relative "circuit_breaker"

module DevFortress
  # DevFortress event client (external mode, plus internal/hybrid
  # closed-loop mode — see #observe).
  #
  # Events are queued in memory (track_event, track_events) and delivered in
  # batches ({"events": [...]}, server maximum MAX_SERVER_BATCH) by #flush.
  # Every request is signed with the request signature contract (see Signer):
  # the API key never goes on the wire, only a key ID does.
  #
  # Retry: up to +retries+ attempts, exponential backoff, only on 5xx
  # responses and network errors. 3xx and 4xx responses are never retried.
  # Every attempt is signed again with a fresh nonce and timestamp.
  #
  # Delivery never raises into the host application: a failed delivery comes
  # back as a DeliveryResult and is logged. Only a missing API key raises, at
  # construction. The queue is safe for concurrent use.
  class Client
    DEFAULT_ENDPOINT = "https://www.devfortress.net/api/events/ingest"
    DEFAULT_TIMEOUT = 15
    DEFAULT_RETRIES = 3
    DEFAULT_BATCH_SIZE = 25
    # MAX_SERVER_BATCH is the largest number of events the platform accepts
    # in one ingest request; #flush splits the queue into chunks this size.
    MAX_SERVER_BATCH = 100

    # Current closed-loop mode ("external", "internal" or "hybrid").
    attr_reader :mode
    # The InternalClosedLoopEngine instance, or nil in external mode.
    attr_reader :internal_engine
    # The PlatformCircuitBreaker instance, or nil outside hybrid mode.
    attr_reader :circuit_breaker

    def initialize(
      api_key,
      endpoint = DEFAULT_ENDPOINT,
      timeout: DEFAULT_TIMEOUT,
      retries: DEFAULT_RETRIES,
      batch_size: DEFAULT_BATCH_SIZE,
      backoff_base: 1.0,
      defaults: {},
      privacy: "standard",
      logger: nil,
      transport: nil,
      sleeper: nil,
      flush_interval: nil,
      mode: "external",
      circuit_breaker_failure_threshold: 3,
      circuit_breaker_recovery_time_seconds: 60
    )
      @signer = Signer.new(api_key)
      @endpoint = endpoint.nil? || endpoint.empty? ? DEFAULT_ENDPOINT : endpoint
      @request_target = Signer.request_target_from_url(@endpoint)
      @timeout = timeout
      @retries = [retries, 1].max
      @batch_size = [batch_size, 1].max
      @backoff_base = backoff_base
      @defaults = defaults || {}
      @privacy = privacy
      @logger = logger
      @transport = transport || Transport.new
      @sleeper = sleeper || ->(seconds) { sleep(seconds) if seconds.positive? }

      @mutex = Mutex.new
      @queue = []
      @stop_cv = ConditionVariable.new

      @flush_thread = nil
      @stop = false

      # Mirrors Node's DevFortressCore and this session's Python port:
      # internal/hybrid mode gets its own InternalClosedLoopEngine
      # instance; hybrid additionally gets a PlatformCircuitBreaker.
      # Default "external" is a no-op here — existing callers that never
      # pass `mode:` see no behaviour change.
      @mode = mode
      @internal_engine = nil
      @circuit_breaker = nil
      if %w[internal hybrid].include?(@mode)
        @internal_engine = InternalClosedLoopEngine.new(
          enable_external_relay: @mode == "hybrid",
          on_relay: @mode == "hybrid" ? method(:relay_internal_decision_to_platform) : nil,
        )
      end
      if @mode == "hybrid"
        @circuit_breaker = PlatformCircuitBreaker.new(
          failure_threshold: circuit_breaker_failure_threshold,
          recovery_time_seconds: circuit_breaker_recovery_time_seconds,
        )
      end

      @flush_thread = Thread.new { background_flush(flush_interval) } if flush_interval && flush_interval.positive?
    end

    # ── Internal / hybrid closed-loop mode ────────────────────────────
    # Mirrors Node's DevFortressCore#observeInternal/#observeHybrid and
    # this session's Python port's #observe(): a pre-response gate the
    # caller (typically middleware) invokes before the request reaches
    # the application. Mode is fixed at construction time; external mode
    # has no #observe behaviour — external-mode reporting stays on the
    # existing after-response track_event path, unchanged.
    #
    # Returns a Hash (flagged: true, event_id:, confidence:, decision:,
    # matched_rules:) if the request should be blocked/rate-limited/
    # challenged/quarantined, else nil (allowed). Always nil in external
    # mode (no internal engine exists to ask).
    def observe(req)
      case @mode
      when "internal" then observe_internal(req)
      when "hybrid" then observe_hybrid(req)
      end
    end

    # Ruby-idiomatic equivalent of Node's isIPBlocked()/Python's
    # is_blocked(), named to match this SDK's own public API exactly as
    # specified (TODO 407). Whether +ip+ is currently blocked by the
    # internal engine's in-memory cache. Always false in external mode.
    def is_blocked?(ip) # rubocop:disable Naming/PredicateName
      return false unless @internal_engine

      @internal_engine.ip_blocked?(ip)
    end

    # Queues one event. The queue is sent (synchronously, like #flush) once
    # it reaches the batch size; it is also sent when #flush is called, or
    # at #close. A caller that must not block on delivery runs track_event
    # from its own thread (see Rack::Middleware).
    def track_event(event)
      enqueue([event])
    end

    # Queues several events.
    def track_events(events)
      enqueue(events)
    end

    # Sends everything queued, in chunks of at most MAX_SERVER_BATCH events,
    # and returns one DeliveryResult per chunk. #flush never raises; failures
    # are reported through the returned results.
    def flush
      events = @mutex.synchronize do
        q = @queue
        @queue = []
        q
      end
      return [] if events.empty?

      events.each_slice(MAX_SERVER_BATCH).map { |chunk| post({ "events" => chunk }) }
    end

    # Number of events waiting to be flushed.
    def pending_events
      @mutex.synchronize { @queue.length }
    end

    # Reports whether the platform accepts a signed test event with this key.
    # Never raises; an unreachable platform or a rejected key both report false.
    def test_connection
      event = prepare(
        "eventType" => "custom",
        "ip" => "127.0.0.1",
        "method" => "GET",
        "path" => "/__devfortress/test",
        "severity" => "LOW",
        "authPhase" => "pre_auth",
        "actionTaken" => "monitored",
        "responseLatencyMs" => 0,
        "clMode" => "external",
        "metadata" => { "test" => true, "sdk" => "ruby" },
      )
      post(event).ok
    end

    # Stops the background flush thread (if any) and flushes whatever is
    # still queued. Safe to call more than once.
    def close
      @mutex.synchronize do
        @stop = true
        @stop_cv.broadcast # wakes background_flush immediately, instead of after its current sleep
      end
      @flush_thread&.join
      flush
    end

    private

    def observe_internal(req)
      result = @internal_engine.evaluate(req)
      return nil if result.decision == :allow

      {
        flagged: true,
        event_id: result.event_id,
        confidence: result.score / 100.0,
        decision: result.decision,
        matched_rules: result.matched_rules,
      }
    end

    def observe_hybrid(req)
      # Step 1: internal evaluation (immediate, sub-ms, no round-trip).
      internal_result = observe_internal(req)
      if internal_result
        # The internal engine's own on_relay callback (wired in
        # #initialize) already handles the Tier-3 relay for this
        # decision — no second relay call here, matching Node's TODO-210
        # double-billing fix and the Python port's own observe_hybrid.
        return internal_result
      end

      # Step 2: external enrichment, circuit-breaker gated.
      #
      # KNOWN LIMITATION (documented, not silently overclaimed): Node's
      # observeHybrid() calls observeExternal() here for a real
      # platform-side enrichment verdict. This port does not yet make
      # that platform call — it only exercises the circuit breaker's
      # success/failure bookkeeping around a no-op enrichment step, so
      # clean traffic is allowed and the circuit stays closed, but a
      # request that internal mode missed and only the platform's own
      # cross-customer intelligence would have caught is not enriched
      # here. Matches the Python port's identically-documented gap.
      @circuit_breaker.record_success if @circuit_breaker&.should_call_external?
      nil
    end

    # Tier-3 relay target for hybrid mode — wired as the internal
    # engine's on_relay callable (see #initialize). Reuses the existing
    # #track_event path, same as every other outbound event from this
    # client, rather than opening a second HTTP path. #track_event only
    # enqueues (fast, in-memory, safe to call synchronously here, matching
    # the engine's own documented expectation that on_relay stay
    # zero-network in its own critical path); flushing happens in its own
    # Thread.new below, mirroring Observer.observe_and_flush's exact
    # pattern, so a single hybrid-mode relay (sparse traffic — the common
    # case) is actually delivered promptly instead of sitting queued until
    # this client's batch size or flush interval is reached. Found live,
    # via this port's own end-to-end demo proof against a real platform.
    def relay_internal_decision_to_platform(result, req)
      event_type = result.matched_rules.first || "icl_#{result.decision}"
      severity = if result.score >= 85
                   "CRITICAL"
                 elsif result.score >= 60
                   "HIGH"
                 elsif result.score >= 35
                   "MEDIUM"
                 else
                   "LOW"
                 end
      action_map = {
        allow: "allowed", block: "blocked", rate_limit: "rate_limited",
        challenge: "challenge_required", quarantine: "flagged",
      }

      track_event(
        "eventType" => event_type,
        "ip" => req.ip,
        "severity" => severity,
        "method" => req.method,
        "path" => req.path,
        "userAgent" => req.user_agent,
        "authPhase" => req.user_id ? "post_auth" : "pre_auth",
        "actionTaken" => action_map[result.decision] || "flagged",
        "responseLatencyMs" => (result.evaluation_time_us / 1000.0).round,
        "clMode" => "hybrid",
        "metadata" => {
          "source" => "internal-closed-loop-engine",
          "tier" => result.tier,
          "matchedRules" => result.matched_rules,
          "internalEventId" => result.event_id,
          "sessionId" => req.session_id,
          "agentId" => req.agent_id,
        },
      )
      Thread.new { flush }
    end

    # Waits on a ConditionVariable rather than plain `sleep`, so #close can
    # wake this loop immediately via @stop_cv.broadcast instead of leaving it
    # to sleep out its current interval first — a real bug found via live
    # testing (devfortress-sdk-rails's demo hung at shutdown for a full
    # flush_interval, because Thread#join had nothing to wake it early).
    def background_flush(interval)
      loop do
        stop = @mutex.synchronize do
          @stop_cv.wait(@mutex, interval)
          @stop
        end
        break if stop

        flush
      end
    end

    def enqueue(events)
      should_flush = @mutex.synchronize do
        events.each { |event| @queue << prepare(event) }
        @queue.length >= @batch_size
      end
      flush if should_flush
    end

    def prepare(event)
      item = @defaults.merge(event)
      item["timestamp"] ||= Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S.%LZ")
      if @privacy == "strict"
        item.delete("userAgent")
        if item["ip"].is_a?(String)
          item["ip"] = Digest::SHA256.hexdigest(item["ip"])[0, 16]
        end
      end
      item["metadata"] = {} if item.key?("metadata") && item["metadata"].nil?
      item
    end

    def post(payload)
      raw = JSON.generate(payload)
      last = DeliveryResult.new(ok: false, error: "no delivery attempt was made", attempts: 0)

      1.upto(@retries) do |attempt|
        # A fresh nonce and timestamp on every attempt, so a retry is not a replay.
        headers = @signer.sign("POST", @request_target, raw)
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        headers["User-Agent"] = "devfortress-sdk-ruby/#{VERSION}"

        begin
          response = @transport.send_request("POST", @endpoint, headers, raw, @timeout)
          body = decode(response.body)
          if response.status_code >= 200 && response.status_code < 300
            return DeliveryResult.new(ok: true, status_code: response.status_code, body: body, attempts: attempt)
          end

          last = DeliveryResult.new(ok: false, status_code: response.status_code, body: body,
                                     error: "HTTP #{response.status_code}", attempts: attempt)
          return fail(last) if response.status_code < 500 # 3xx and 4xx: never retried
        rescue TransportError => e
          last = DeliveryResult.new(ok: false, error: "request failed: #{e.message}", attempts: attempt)
        end

        @sleeper.call(@backoff_base * (2**(attempt - 1))) if attempt < @retries
      end

      fail(last)
    end

    def fail(result)
      log("warning", "devfortress: delivery failed: #{result.error || 'unknown error'}",
          status: result.status_code, attempts: result.attempts)
      result
    end

    def decode(raw)
      return {} if raw.nil? || raw.empty?

      JSON.parse(raw)
    rescue JSON::ParserError
      raw
    end

    def log(level, message, fields = {})
      return unless @logger

      @logger.log(level, message, fields)
    rescue StandardError
      # A failing logger must not reach the host application either.
    end
  end
end
