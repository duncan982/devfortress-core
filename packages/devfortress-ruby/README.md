# devfortress-sdk (Ruby)

Event reporting client for DevFortress (external mode). Pre-release, not published.

Requires Ruby 3.0 or newer. There are no runtime dependencies outside the standard library (`net/http`, `openssl`, `digest`, `json`, `securerandom`, `ipaddr`). A Rack middleware adapter (`devfortress-sdk-rails`, gem name proposed — Duncan's call) lives at `../devfortress-ruby-rails`.

## Install

Not published to RubyGems yet. Until it is, reference the local path in your `Gemfile`:

```ruby
gem "devfortress-sdk", path: "../devfortress-ruby"
```

## The DevFortress Textbook

DevFortress implements 34 novel security inventions. Patent Pending.

These 34 inventions are documented in depth across 5 volumes.

**"Credential Isolation Closed-Loop Security"**
_Duncan Ndungu Ndegwa — DevFortress, 2026_

→ Available on Gumroad: [https://devfortress.gumroad.com/l/master-edition]

## Quick start

```ruby
require "devfortress"

client = DevFortress::Client.new(ENV.fetch("DEVFORTRESS_API_KEY"))

client.track_event(
  "eventType" => "auth_failure",
  "ip" => "203.0.113.7",
  "method" => "POST",
  "path" => "/login",
  "severity" => "MEDIUM",
)

client.close # flushes whatever is still queued
```

`track_event` and `track_events` queue events in memory; the queue also flushes itself (synchronously, on the caller's thread) once it reaches the batch size. `flush` sends whatever is queued and `close` flushes on shutdown. `test_connection` sends one test event and reports whether the platform accepts the key.

`Client.new(api_key, endpoint = DEFAULT_ENDPOINT, **options)` takes `timeout:` (15s), `retries:` (3 attempts), `batch_size:` (25), `defaults:`, `privacy:` (`"standard"` or `"strict"`), `logger:` (anything responding to `#log(level, message, fields)`), `transport:`, `flush_interval:` (a background `Thread` that flushes on that cadence; `nil`, the default, disables it — callers then flush explicitly), and `mode:` (see below).

Delivery never raises into your application. A failed delivery is returned as a `DeliveryResult` from `#flush` and logged through the optional `logger:`. Failed deliveries are retried automatically on network errors and 5xx responses; a 3xx or 4xx response is never retried. Only a missing API key raises, at construction.

## Closed-loop mode

`mode:` selects the closed-loop delivery mode: `"external"` (default — every event ships to the platform, no behavior change for existing callers), `"internal"` (decisions are made locally, nothing leaves your infrastructure), or `"hybrid"` (local-first, with automatic cloud enrichment and failover). Internal/hybrid require Team tier or above.

```ruby
client = DevFortress::Client.new(
  ENV.fetch("DEVFORTRESS_API_KEY"),
  mode: ENV.fetch("DEVFORTRESS_CL_MODE", "external"),
)
```

Reading the mode from a `DEVFORTRESS_CL_MODE` env var (`external`, `internal`, or `hybrid`) is the convention this SDK's demo apps use so the same process can be started in any mode without a code change.

## Rack / framework adapters: use `Observer.observe_and_flush`, not `Observer.observe`

`DevFortress::Observer` is the shared "classify this request/response, queue an event for it" logic every Ruby adapter should build on (the same role the Go SDK's `Observe`/`ObserveAndFlush` plays for its `net/http` and `gin` adapters):

```ruby
DevFortress::Observer.observe_and_flush(client, DevFortress::Observer::Input.new(
  method: request.request_method,
  path: request.path,
  raw_query: request.query_string,
  status_code: response_status,
  latency_ms: latency_ms,
  user_agent: request.user_agent,
  forwarded_for: request.get_header("HTTP_X_FORWARDED_FOR"),
  real_ip: request.get_header("HTTP_X_REAL_IP"),
  remote_addr: request.get_header("REMOTE_ADDR"),
))
```

`.observe_and_flush` classifies, queues **and delivers** the event in one detached `Thread`, after the response has already gone out, so a single request's event is delivered even under sparse traffic. **`.observe` alone only queues** — without something else to flush the queue (a steady stream of other requests reaching the batch size, `flush_interval:`, or an explicit `#flush`/`#close`), a lone event can sit undelivered indefinitely. This is exactly the gap the Go SDK's gin adapter and `demos/go-non-agentic` had before Brief 10.2 fixed it (enqueued events that never reached the platform under normal, non-bursty traffic) — ported here as `.observe_and_flush` from the start so the Ruby adapter never ships with the same gap. `devfortress-sdk-rails`'s Rack middleware calls `.observe_and_flush`.

## Request signing

Every request is signed with your API key (contract v2). The key itself is never sent — only a non-secret key ID derived from it.

## Webhook verification

```ruby
result = DevFortress::WebhookVerifier.verify(
  raw_body: body, # the bytes exactly as received
  signature: headers["X-DevFortress-Signature"],
  timestamp: headers["X-DevFortress-Timestamp"],
  secret: ENV.fetch("DEVFORTRESS_WEBHOOK_SECRET"),
  nonce_check: ->(nonce) { remember_nonce(nonce) }, # true the first time only
)
unless result.valid?
  status = result.reason == "replay_detected" ? 409 : 401
  # ...
end
```

Stale timestamps are rejected. `nonce_check:` is optional; the library keeps no state, so replay tracking is yours.

## Request classification

`DevFortress::Classifier.build_event` turns a response status plus the request path and query into an event Hash, or `nil` when nothing is worth reporting. It flags suspicious patterns in the path and query string (one percent-decoding pass; a double-encoded payload is a known, deliberate limitation shared with every other SDK — see `contracts/`). `DevFortress::ClientIp.resolve` picks the end-user IP the same way the middleware does: `X-Forwarded-For`, then `X-Real-IP`, then the socket address.

## Other modules

`DevFortress::UnifiedAuditTrail` merges internal and external closed-loop audit events into one in-memory timeline. `DevFortress::GraduatedRateLimiter` applies alias-scoped rate limiting with multi-stage escalation (observe, warn, soft-limit, hard-block, revoke).

## Tests

```
rake test
```

The signing and webhook tests read the shared cross-language vector files from `../../contracts` (set `DEVFORTRESS_CONTRACTS_DIR` to override).

License: BUSL-1.1
