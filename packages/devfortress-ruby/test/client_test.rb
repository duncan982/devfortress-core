# frozen_string_literal: true

require_relative "test_helper"

class ClientTest < Minitest::Test
  KEY = "vx_live_test_vector_key_do_not_use"
  EVENT = { "eventType" => "auth_failure", "ip" => "203.0.113.7", "method" => "POST", "path" => "/login", "severity" => "LOW" }.freeze

  def ok_response
    DevFortress::TransportResponse.new(status_code: 200, body: '{"success":true}')
  end

  def test_construction_requires_an_api_key
    assert_raises(DevFortress::Signer::Error) { DevFortress::Client.new("") }
  end

  def test_defaults_match_the_other_sdks
    assert_equal 15, DevFortress::Client::DEFAULT_TIMEOUT
    assert_equal 3, DevFortress::Client::DEFAULT_RETRIES
    assert_equal 25, DevFortress::Client::DEFAULT_BATCH_SIZE
    assert_equal 100, DevFortress::Client::MAX_SERVER_BATCH
  end

  def test_the_queue_auto_flushes_once_it_reaches_the_batch_size
    transport = ScriptedTransport.new([ok_response])
    client = DevFortress::Client.new(KEY, "http://platform.test/api/events/ingest", transport: transport, batch_size: 3)

    2.times { client.track_event(EVENT) }
    assert_equal 2, client.pending_events
    assert_equal 0, transport.requests.length

    client.track_event(EVENT)
    assert_equal 0, client.pending_events
    assert_equal 1, transport.requests.length
  end

  def test_flush_sends_nothing_queued_as_an_empty_request_and_returns_no_results
    transport = ScriptedTransport.new([ok_response])
    client = DevFortress::Client.new(KEY, "http://platform.test/api/events/ingest", transport: transport)
    assert_equal [], client.flush
    assert_equal 0, transport.requests.length
  end

  def test_a_5xx_response_is_retried_with_backoff_and_a_4xx_is_not
    five_xx = DevFortress::TransportResponse.new(status_code: 502, body: "")
    sleeps = []
    client = DevFortress::Client.new(
      KEY, "http://platform.test/api/events/ingest",
      transport: ScriptedTransport.new([five_xx]), retries: 3, backoff_base: 1,
      sleeper: ->(s) { sleeps << s }
    )
    client.track_event(EVENT)
    result = client.flush.first
    refute result.ok?
    assert_equal 3, result.attempts
    assert_equal [1.0, 2.0], sleeps

    four_xx = DevFortress::TransportResponse.new(status_code: 400, body: "")
    transport = ScriptedTransport.new([four_xx])
    client2 = DevFortress::Client.new(KEY, "http://platform.test/api/events/ingest", transport: transport, retries: 3)
    client2.track_event(EVENT)
    client2.flush
    assert_equal 1, transport.requests.length # never retried
  end

  def test_a_fresh_nonce_and_timestamp_sign_every_retry_attempt
    five_xx = DevFortress::TransportResponse.new(status_code: 503, body: "")
    transport = ScriptedTransport.new([five_xx, ok_response])
    client = DevFortress::Client.new(KEY, "http://platform.test/api/events/ingest", transport: transport, retries: 2, sleeper: ->(_s) {})
    client.track_event(EVENT)
    client.flush
    assert_equal 2, transport.requests.length
    n1 = transport.requests[0][:headers][DevFortress::Signer::NONCE_HEADER]
    n2 = transport.requests[1][:headers][DevFortress::Signer::NONCE_HEADER]
    refute_equal n1, n2
  end

  def test_delivery_never_raises_on_a_transport_error
    transport = ScriptedTransport.new([StandardError.new("connection refused")])
    client = DevFortress::Client.new(KEY, "http://platform.test/api/events/ingest", transport: transport, retries: 1)
    client.track_event(EVENT)
    result = client.flush.first
    refute result.ok?
    assert_match(/connection refused/, result.error)
  end

  def test_strict_privacy_hashes_the_ip_and_drops_the_user_agent
    transport = ScriptedTransport.new([ok_response])
    client = DevFortress::Client.new(KEY, "http://platform.test/api/events/ingest", transport: transport, privacy: "strict")
    client.track_event(EVENT.merge("userAgent" => "Mozilla/5.0"))
    client.flush
    body = JSON.parse(transport.requests.first[:body])
    sent = body["events"].first
    refute sent.key?("userAgent")
    refute_equal "203.0.113.7", sent["ip"]
    assert_equal 16, sent["ip"].length
  end

  def test_close_flushes_whatever_is_still_queued
    transport = ScriptedTransport.new([ok_response])
    client = DevFortress::Client.new(KEY, "http://platform.test/api/events/ingest", transport: transport)
    client.track_event(EVENT)
    client.close
    assert_equal 1, transport.requests.length
    assert_equal 0, client.pending_events
  end

  def test_the_api_key_never_appears_on_the_wire
    transport = ScriptedTransport.new([ok_response])
    client = DevFortress::Client.new(KEY, "http://platform.test/api/events/ingest", transport: transport)
    client.track_event(EVENT)
    client.flush
    req = transport.requests.first
    refute_includes req[:body], KEY
    req[:headers].each_value { |v| refute_includes v.to_s, KEY }
    assert_equal DevFortress::Signer.derive_key_id(KEY), req[:headers][DevFortress::Signer::KEY_ID_HEADER]
  end
end
