# frozen_string_literal: true

require_relative "test_helper"

class ObserverTest < Minitest::Test
  def input(status_code:, path: "/items", query: "")
    DevFortress::Observer::Input.new(
      method: "GET", path: path, raw_query: query, status_code: status_code, latency_ms: 1,
      user_agent: "ua", forwarded_for: "203.0.113.7", real_ip: nil, remote_addr: nil, user_id: nil
    )
  end

  # The sparse-traffic fix (Brief 10.2, ported from the Go SDK's
  # ObserveAndFlush): a single suspicious request must be DELIVERED, not just
  # queued, even with a batch size far larger than 1 — so a Rack adapter that
  # calls .observe_and_flush does not repeat the Go gin adapter's original
  # gap (events enqueued but never flushed under normal, non-bursty traffic).
  def test_observe_and_flush_delivers_a_single_event_without_waiting_for_the_batch_size
    transport = ScriptedTransport.new([DevFortress::TransportResponse.new(status_code: 200, body: "{}")])
    client = DevFortress::Client.new("vx_live_test_vector_key_do_not_use", "http://platform.test/api/events/ingest", transport: transport, batch_size: 1000)

    DevFortress::Observer.observe_and_flush(client, input(status_code: 200, query: "id=1%27%20or%20%271%27%3D%271"))

    deadline = Time.now + 2
    sleep 0.01 while transport.requests.empty? && Time.now < deadline

    assert_equal 1, transport.requests.length
    assert_equal 0, client.pending_events
  end

  # .observe alone (no flush) is the documented lower-level primitive: it
  # only queues. This is what Observer's doc comment warns adapters away
  # from using directly for exactly this reason.
  def test_observe_alone_only_queues_and_does_not_deliver
    transport = ScriptedTransport.new([DevFortress::TransportResponse.new(status_code: 200, body: "{}")])
    client = DevFortress::Client.new("vx_live_test_vector_key_do_not_use", "http://platform.test/api/events/ingest", transport: transport, batch_size: 1000)

    DevFortress::Observer.observe(client, input(status_code: 200, query: "id=1%27%20or%20%271%27%3D%271"))

    deadline = Time.now + 1
    sleep 0.01 while client.pending_events.zero? && Time.now < deadline

    assert_equal 1, client.pending_events
    assert_equal 0, transport.requests.length
  end

  def test_a_normal_200_queues_nothing
    transport = ScriptedTransport.new([DevFortress::TransportResponse.new(status_code: 200, body: "{}")])
    client = DevFortress::Client.new("vx_live_test_vector_key_do_not_use", "http://platform.test/api/events/ingest", transport: transport)

    DevFortress::Observer.observe_and_flush(client, input(status_code: 200))
    sleep 0.05

    assert_equal 0, client.pending_events
    assert_equal 0, transport.requests.length
  end
end
