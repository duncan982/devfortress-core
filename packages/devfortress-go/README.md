# devfortress-sdk-go

Event reporting client for DevFortress (external mode). Pre-release, not published.

Requires Go 1.26 or newer. There are no runtime dependencies outside the standard library. A `gin` adapter (module `github.com/duncan982/devfortress-sdk-go/gin`) is nested under `gin/`.

## Install

Not published to a module proxy yet. Until it is, use a `replace` directive:

```
replace github.com/duncan982/devfortress-sdk-go => ../devfortress-go
```

## The DevFortress Textbook

DevFortress implements 34 novel security inventions. Patent Pending.

These 34 inventions are documented in depth across 5 volumes.

**"Credential Isolation Closed-Loop Security"**
_Duncan Ndungu Ndegwa — DevFortress, 2026_

→ Available on Gumroad: [https://devfortress.gumroad.com/l/master-edition]

## Quick start

```go
client, err := devfortress.NewClient(os.Getenv("DEVFORTRESS_API_KEY"), "")
if err != nil {
	log.Fatal(err)
}
defer client.Close(context.Background())

client.TrackEvent(ctx, devfortress.Event{
	"eventType": "auth_failure",
	"ip":        "203.0.113.7",
	"method":    "POST",
	"path":      "/login",
	"severity":  "MEDIUM",
})
```

`TrackEvent` and `TrackEvents` queue events in memory; the queue also flushes itself (in the background, never blocking the caller) once it reaches the batch size. `Flush` sends whatever is queued and `Close` flushes on shutdown. `TestConnection` sends one test event and reports whether the platform accepts the key.

`NewClient(apiKey, endpoint string, opts ...Option)` takes `WithTimeout` (15s), `WithRetries` (3 attempts), `WithBatchSize` (25), `WithDefaults`, `WithPrivacy` (`"standard"` or `"strict"`), `WithLogger`, `WithTransport`, `WithFlushInterval` and `WithMode` (see below).

Delivery never panics or returns a Go error into your application. A failed delivery is returned as a `DeliveryResult` from `Flush` and logged through the optional `Logger` (a `log/slog` adapter is included). Failed deliveries are retried automatically on network errors and 5xx responses; a 3xx or 4xx response is never retried. Only a missing API key fails `NewClient`.

## Closed-loop mode

`WithMode` selects the closed-loop delivery mode: `devfortress.ModeExternal` (default — every event ships to the platform, no behavior change for existing callers), `devfortress.ModeInternal` (decisions are made locally, nothing leaves your infrastructure), or `devfortress.ModeHybrid` (local-first, with automatic cloud enrichment and failover). Internal/hybrid require Team tier or above.

```go
client, err := devfortress.NewClient(
	os.Getenv("DEVFORTRESS_API_KEY"), "",
	devfortress.WithMode(devfortress.CLMode(os.Getenv("DEVFORTRESS_CL_MODE"))),
)
```

Reading the mode from a `DEVFORTRESS_CL_MODE` env var (`external`, `internal`, or `hybrid`) is the convention this SDK's demo apps use so the same binary can be started in any mode without a code change.

## `net/http` middleware

```go
mux := http.NewServeMux()
handler := devfortress.Middleware(client)(mux)
```

`Middleware` observes each request (method, path, status, timing, client IP and classifier result) and both queues and flushes an event for it, off the request path, via `ObserveAndFlush`: classification, queuing and delivery all happen in one detached goroutine after the response has already gone out, so a single request is delivered even under sparse traffic — it does not wait for the batch size, `WithFlushInterval`, or `Close`. If you build your own adapter on `Observe` instead of `ObserveAndFlush`, note that `Observe` only queues: a lone event can sit undelivered indefinitely unless something else flushes it.

## Request signing

Every request is signed with your API key. The key itself is never sent.

## Webhook verification

```go
result := devfortress.VerifyWebhook(
	body,                                        // the bytes exactly as received
	r.Header.Get("X-DevFortress-Signature"),
	r.Header.Get("X-DevFortress-Timestamp"),
	os.Getenv("DEVFORTRESS_WEBHOOK_SECRET"),
	devfortress.WithNonceCheck(rememberNonce), // true the first time only
)
if !result.Valid {
	status := http.StatusUnauthorized
	if result.Reason == "replay_detected" {
		status = http.StatusConflict
	}
	http.Error(w, "", status)
	return
}
```

Stale timestamps are rejected. `WithNonceCheck` is optional; the library keeps no state, so replay tracking is yours.

## Request classification

`BuildEvent` turns a response status plus the request path and query into an event, or `nil` when nothing is worth reporting. It flags suspicious patterns in the path and query string. `ResolveClientIP` picks the end-user IP the same way the middleware does: `X-Forwarded-For`, then `X-Real-IP`, then the socket address.

## Other modules

`UnifiedAuditTrail` merges internal and external closed-loop audit events into one in-memory timeline. `GraduatedRateLimiter` applies alias-scoped rate limiting with multi-stage escalation (observe, warn, soft-limit, hard-block, revoke).

## Tests

```
go test ./... -race
```

The signing and webhook tests read the shared cross-language vector files from `../../contracts` (set `DEVFORTRESS_CONTRACTS_DIR` to override).

## Versioning (Go module proxy)

This module's path is `github.com/duncan982/devfortress-core/packages/devfortress-go` — it lives inside the `devfortress-core` monorepo as a nested module, not a standalone repo. The Go module proxy requires a nested module's release tags to be prefixed with its own path within the repo — **tag releases for this module as `packages/devfortress-go/v1.0.0`, `packages/devfortress-go/v1.1.0`, etc., never a bare `v1.0.0`** (a bare tag would be read as a release of the repo root, not this module, and `go get` would fail to resolve the intended version).

License: BUSL-1.1
