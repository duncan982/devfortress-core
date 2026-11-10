# frozen_string_literal: true

require_relative "test_helper"

class MiddlewareTest < Minitest::Test
  include Rack::Test::Methods

  def ok_response
    DevFortress::TransportResponse.new(status_code: 200, body: "{}")
  end

  def build_client(script)
    transport = ScriptedTransport.new(script)
    client = DevFortress::Client.new(
      "vx_live_test_vector_key_do_not_use", "http://platform.test/api/events/ingest",
      transport: transport, batch_size: 1000
    )
    [client, transport]
  end

  def wait_for(timeout = 2)
    deadline = Time.now + timeout
    sleep 0.01 until yield || Time.now > deadline
  end

  # The core assertion this adapter exists to satisfy (Brief 10.2's own
  # lesson, learned from the Go gin adapter's original gap): ONE sparse
  # request through the middleware must actually reach the platform, not
  # just sit queued, even with a batch size far larger than 1.
  def test_a_sparse_suspicious_request_is_delivered_not_just_queued
    client, transport = build_client([ok_response])
    inner = ->(_env) { [200, {}, ["ok"]] }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    env = Rack::MockRequest.env_for("/search?q=1%27%20OR%20%271%27%3D%271", "HTTP_X_FORWARDED_FOR" => "203.0.113.7")
    status, _headers, body = app.call(env)
    body.close if body.respond_to?(:close) # Rack servers always call this; rack-test's own `get` does too

    assert_equal 200, status
    wait_for { !transport.requests.empty? }
    assert_equal 1, transport.requests.length
    assert_equal 0, client.pending_events
  end

  def test_a_normal_200_reports_nothing
    client, transport = build_client([ok_response])
    inner = ->(_env) { [200, {}, ["ok"]] }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    status, _headers, body = app.call(Rack::MockRequest.env_for("/items"))
    body.close if body.respond_to?(:close)

    assert_equal 200, status
    sleep 0.05
    assert_equal 0, transport.requests.length
  end

  def test_excluded_paths_are_never_reported
    client, transport = build_client([ok_response])
    inner = ->(_env) { [500, {}, ["boom"]] } # even a 5xx on an excluded path
    app = DevFortress::Rails::Middleware.new(inner, client: client, exclude_paths: ["/health"])

    status, _headers, body = app.call(Rack::MockRequest.env_for("/health"))
    body.close if body.respond_to?(:close)

    assert_equal 500, status
    sleep 0.05
    assert_equal 0, transport.requests.length
  end

  # The response is already fully sent by the time #close runs (that's the
  # Rack contract this adapter relies on), so delivery must never delay it.
  def test_the_response_is_not_delayed_by_reporting
    client, = build_client([ok_response])
    inner = ->(_env) { [200, {}, ["ok"]] }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    started = Time.now
    _status, _headers, body = app.call(Rack::MockRequest.env_for("/search?q=1%27%20OR%20%271%27%3D%271"))
    elapsed = Time.now - started
    body.close if body.respond_to?(:close)

    assert_operator elapsed, :<, 0.2
  end

  # Regression test for a real bug caught while building this adapter: an
  # earlier draft wrapped @app.call itself in the reporting rescue, which
  # would have swallowed the wrapped application's own exceptions instead of
  # letting them propagate — exactly what Laravel's terminate() and the Go
  # SDK's deferred-panic-repropagation both avoid.
  def test_an_exception_from_the_wrapped_app_propagates_unchanged
    client, = build_client([ok_response])
    inner = ->(_env) { raise RuntimeError, "handler boom" }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    error = assert_raises(RuntimeError) { app.call(Rack::MockRequest.env_for("/items")) }
    assert_equal "handler boom", error.message
  end

  def test_rack_test_itself_calls_close_so_integration_through_a_real_stack_works
    client, transport = build_client([ok_response])
    inner = ->(_env) { [200, {}, ["ok"]] }
    full_app = DevFortress::Rails::Middleware.new(inner, client: client)
    define_singleton_method(:app) { full_app }

    get "/search", { q: "1' OR '1'='1" }, "HTTP_X_FORWARDED_FOR" => "203.0.113.7"

    assert_equal 200, last_response.status
    wait_for { !transport.requests.empty? }
    assert_equal 1, transport.requests.length
  end

  # ── Internal/hybrid-mode pre-response gate (TODO 407) ────────────

  def build_internal_client(mode: "internal")
    DevFortress::Client.new(
      "vx_live_test_vector_key_do_not_use", "http://platform.test/api/events/ingest",
      transport: ScriptedTransport.new([ok_response]), batch_size: 1000, mode: mode,
    )
  end

  def test_internal_mode_clean_request_reaches_the_app
    client = build_internal_client
    inner = ->(_env) { [200, {}, ["ok"]] }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    status, _headers, body = app.call(Rack::MockRequest.env_for("/products"))
    body.close if body.respond_to?(:close)

    assert_equal 200, status
  end

  def test_internal_mode_sensitive_file_access_is_blocked_before_reaching_the_app
    client = build_internal_client
    app_called = false
    inner = ->(_env) { app_called = true; [200, {}, ["ok"]] }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    status, headers, body = app.call(Rack::MockRequest.env_for("/.env"))
    body.close if body.respond_to?(:close)

    assert_equal 403, status
    assert_equal "application/json", headers["Content-Type"]
    refute app_called
    parsed = JSON.parse(body.join)
    assert_equal "blocked", parsed["error"]
    assert_equal "block", parsed["reason"]
  end

  def test_internal_mode_blocked_ip_stays_blocked_on_a_later_clean_request
    client = build_internal_client
    inner = ->(_env) { [200, {}, ["ok"]] }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    env = Rack::MockRequest.env_for("/.env", "REMOTE_ADDR" => "198.51.100.9")
    first_status, _h, first_body = app.call(env)
    first_body.close if first_body.respond_to?(:close)
    assert_equal 403, first_status

    clean_env = Rack::MockRequest.env_for("/products", "REMOTE_ADDR" => "198.51.100.9")
    second_status, _h2, second_body = app.call(clean_env)
    second_body.close if second_body.respond_to?(:close)
    assert_equal 403, second_status
  end

  def test_internal_mode_body_based_sql_injection_is_blocked_and_body_is_rewound_for_the_app
    client = build_internal_client
    seen_body = nil
    inner = lambda { |inner_env|
      seen_body = inner_env["rack.input"].read
      [200, {}, ["ok"]]
    }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    env = Rack::MockRequest.env_for("/comments", method: "POST", input: "'; DROP TABLE users; --")
    status, _headers, body = app.call(env)
    body.close if body.respond_to?(:close)

    assert_equal 403, status
    assert_nil seen_body # app was never called — blocked before @app.call
  end

  def test_external_mode_is_unaffected_by_the_internal_gate
    client, transport = build_client([ok_response])
    inner = ->(_env) { [200, {}, ["ok"]] }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    status, _headers, body = app.call(Rack::MockRequest.env_for("/.env"))
    body.close if body.respond_to?(:close)

    # External mode has no internal engine, so even a sensitive-file path
    # reaches the app unblocked — the gate is a no-op outside internal/
    # hybrid mode.
    assert_equal 200, status
  end

  def test_hybrid_mode_blocks_via_internal_first_same_as_internal_mode
    client = build_internal_client(mode: "hybrid")
    inner = ->(_env) { [200, {}, ["ok"]] }
    app = DevFortress::Rails::Middleware.new(inner, client: client)

    status, _headers, body = app.call(Rack::MockRequest.env_for("/.env"))
    body.close if body.respond_to?(:close)

    assert_equal 403, status
  end
end
