# frozen_string_literal: true

require_relative "classifier"
require_relative "client_ip"

module DevFortress
  # Shared "classify this request/response, queue an event for it" logic for
  # every Ruby framework adapter (the Rack middleware in
  # devfortress-sdk-rails, and any future one), the same way the Go SDK's
  # Observe/ObserveAndFlush is shared by its net/http and gin adapters.
  #
  # ObserveAndFlush is the one adapters should call, not Observe:
  # Observe only queues the event; under sparse traffic (fewer requests than
  # the client's batch size between flushes) a queued-only event can sit
  # undelivered indefinitely. This is the exact gap the Go SDK's gin adapter
  # and demos/go-non-agentic had (Brief 10.1), fixed in Brief 10.2 by having
  # the adapter flush after observing — ported here from the start so the
  # Ruby adapter never ships with the same gap.
  module Observer
    Input = Struct.new(
      :method, :path, :raw_query, :status_code, :latency_ms,
      :user_agent, :forwarded_for, :real_ip, :remote_addr, :user_id,
      keyword_init: true
    )

    # Classifies and queues an event in its own Thread, detached from the
    # request so delivery never delays the response. Only queues — see the
    # module doc for why adapters should prefer ObserveAndFlush.
    def self.observe(client, input)
      queue(client, input, flush: false)
    end

    # Behaves like .observe, but also flushes the queue once the event has
    # been classified and queued, in that same detached Thread — so a single
    # event is delivered even under sparse traffic, with no separate thread
    # racing the enqueue.
    def self.observe_and_flush(client, input)
      queue(client, input, flush: true)
    end

    def self.queue(client, input, flush:)
      ip = ClientIp.resolve(input.forwarded_for, input.real_ip, input.remote_addr)
      Thread.new do
        event = Classifier.build_event(
          ip: ip,
          method: input.method,
          path: input.path,
          status_code: input.status_code,
          latency_ms: input.latency_ms,
          user_agent: input.user_agent,
          query: input.raw_query.to_s,
          user_id: input.user_id,
        )
        next if event.nil?

        client.track_event(event)
        client.flush if flush
      end
    end
    private_class_method :queue
  end
end
