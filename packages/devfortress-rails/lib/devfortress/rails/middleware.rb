# frozen_string_literal: true

require "rack"
require "json"
require "stringio"

module DevFortress
  module Rails
    # Rack middleware that observes each request (method, path, status,
    # timing, client IP and classifier result) and reports a security event
    # for it, the same way devfortress-laravel's DevFortressMiddleware does
    # for Laravel: #call only measures the request — nothing here changes or
    # fails the response. Reporting itself happens from ResponseBodyProxy#close,
    # which Rack guarantees the app server calls only once it is done writing
    # the response body to the client (see the Rack SGI spec on the response
    # body: "the server must call close... if it responds to it"). That is
    # this adapter's Rack-appropriate equivalent of Laravel's terminate()
    # hook, which likewise runs only after the response has gone out.
    #
    # Internally this calls DevFortress::Observer.observe_and_flush — not
    # .observe — so a single request is delivered even under sparse traffic.
    # This is the Go SDK's gin-adapter sparse-traffic gap (Brief 10.1), fixed
    # in Brief 10.2 and ported here from the start: do not change this to
    # .observe without also wiring in some other guaranteed flush path
    # (Client's flush_interval:, or an explicit #flush/#close elsewhere),
    # or a lone event can sit queued and undelivered indefinitely.
    class Middleware
      # +client+ is a DevFortress::Client. +exclude_paths+ (default
      # %w[/health /up], matching devfortress-laravel's default) skips
      # reporting for path prefixes you don't want noise from.
      def initialize(app, client:, exclude_paths: %w[/health /up])
        @app = app
        @client = client
        @exclude_paths = exclude_paths
      end

      def call(env)
        # Pre-response internal/hybrid-mode gate (TODO 407): runs before
        # the request ever reaches @app, same early-return shape used
        # below for excluded paths — a flagged request never calls
        # @app.call at all. External mode's @client.mode is "external"
        # and #internal_gate is never even attempted, so existing
        # external-mode callers see no behaviour change.
        if %w[internal hybrid].include?(@client.mode)
          blocked = internal_gate(env)
          return blocked if blocked
        end

        started = monotonic_ms
        # @app.call is intentionally OUTSIDE the rescue below: an exception
        # from the wrapped application (a handler panic) must propagate
        # exactly as it would without this middleware. Only the reporting
        # logic that follows is allowed to fail silently.
        status, headers, body = @app.call(env)

        begin
          [status, headers, wrap(env, status, headers, body, monotonic_ms - started)]
        rescue StandardError
          # Reporting must never affect the application; the client already
          # logs delivery failures, so a failure building the report itself
          # (a malformed env, an unreadable request) must not surface either.
          [status, headers, body]
        end
      end

      private

      # Pre-response internal/hybrid-mode gate. Returns a Rack triplet
      # ([403, headers, [body]]) if the request was blocked (the caller
      # must not forward it to @app), else nil.
      #
      # Scope: unlike the Python SDK's ASGI/FastAPI gate — which cannot
      # safely re-read the request body without a replay mechanism the
      # ASGI protocol doesn't provide here — Rack's `rack.input` is
      # required by the Rack SPEC to be rewindable (confirmed directly:
      # Rack::MockRequest's input responds to #rewind and re-reads the
      # same bytes afterwards). So this gate reads the body, evaluates it,
      # and rewinds the IO before returning, which is byte-for-byte safe
      # for whatever reads it next (the app, or this same middleware's own
      # eventual Rack::Request#body call downstream) — body-based Tier-1
      # rules (SQLi/XSS matched against the request body) DO fire on this
      # path, matching the Python SDK's Flask gate (which can also see the
      # body, since Flask buffers it eagerly) rather than its more limited
      # ASGI/FastAPI gate.
      def internal_gate(env)
        request = Rack::Request.new(env)
        ip = DevFortress::ClientIp.resolve(env["HTTP_X_FORWARDED_FOR"], env["HTTP_X_REAL_IP"], env["REMOTE_ADDR"])

        icl_request = DevFortress::InternalClosedLoopEngine::Request.new(
          ip: ip,
          method: request.request_method,
          path: request.path,
          user_agent: env["HTTP_USER_AGENT"],
          query: env["QUERY_STRING"].to_s,
          headers: rack_headers(env),
          body: read_body_safely(env),
        )

        result = @client.observe(icl_request)
        return nil unless result && result[:flagged]

        body = JSON.generate({ "error" => "blocked", "reason" => result[:decision].to_s, "eventId" => result[:event_id] })
        [403, { "Content-Type" => "application/json" }, [body]]
      rescue StandardError
        # A failure building/evaluating the gate itself (a malformed env)
        # must not block a request that the engine never actually flagged
        # — fail open at the GATE level only. This is distinct from the
        # engine's own fail_mode (default fail-closed), which governs an
        # error *inside* a matched/evaluated request, not a broken gate.
        nil
      end

      # Reads the full request body for Tier-1 matching, then REPLACES
      # env["rack.input"] with a fresh StringIO over the same bytes, so the
      # downstream app (or this middleware's own later Rack::Request#body
      # read) sees the exact same bytes from the start.
      #
      # Does NOT call #rewind on the original input object — found live
      # (via this gate's own end-to-end demo proof, not assumed) that
      # real Rack handlers' rack.input does not reliably support it: under
      # WEBrick, env["rack.input"] is a Rackup::Handler::WEBrick::Input,
      # which raises NoMethodError on #rewind. This method's own prior doc
      # comment had verified rewindability only against Rack::MockRequest's
      # input (a test double), not against a real handler's — the two are
      # different classes with different capabilities, and verifying
      # against the test double was not sufficient proof for the real one.
      # Replacing with a StringIO sidesteps the question entirely: a
      # freshly-constructed StringIO is always rewound to position 0, on
      # every real Rack handler.
      def read_body_safely(env)
        input = env["rack.input"]
        return nil unless input

        data = input.read
        env["rack.input"] = StringIO.new(data || "")
        data.nil? || data.empty? ? nil : data
      end

      def rack_headers(env)
        headers = {}
        env.each do |key, value|
          next unless key.start_with?("HTTP_")

          name = key.sub(/^HTTP_/, "").split("_").map(&:capitalize).join("-")
          headers[name] = value
        end
        headers
      end

      def wrap(env, status, headers, body, latency_ms)
        request = Rack::Request.new(env)
        path = request.path
        return body if @exclude_paths.any? { |prefix| path.start_with?(prefix) }

        input = DevFortress::Observer::Input.new(
          method: request.request_method,
          path: path,
          raw_query: env["QUERY_STRING"].to_s,
          status_code: status,
          latency_ms: latency_ms.round,
          user_agent: env["HTTP_USER_AGENT"],
          forwarded_for: env["HTTP_X_FORWARDED_FOR"],
          real_ip: env["HTTP_X_REAL_IP"],
          remote_addr: env["REMOTE_ADDR"],
          user_id: env["devfortress.user_id"],
        )

        ResponseBodyProxy.new(body) { DevFortress::Observer.observe_and_flush(@client, input) }
      end

      def monotonic_ms
        Process.clock_gettime(Process::CLOCK_MONOTONIC) * 1000
      end
    end

    # Wraps a Rack response body so +on_close+ fires once the server has
    # finished writing the body to the client — never before, and never
    # blocking the server's own close call (DevFortress::Observer spawns its
    # own Thread).
    class ResponseBodyProxy
      def initialize(body, &on_close)
        @body = body
        @on_close = on_close
      end

      def each(&block)
        @body.each(&block)
      end

      def close
        @body.close if @body.respond_to?(:close)
      ensure
        @on_close.call
      end
    end
  end
end
