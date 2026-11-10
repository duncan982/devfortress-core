# DevFortress .NET SDK

Event reporting client for DevFortress (external mode). Pre-release, not published.

Requires .NET 8.0 or newer. There are no runtime dependencies outside the BCL. An ASP.NET Core middleware adapter (`DevFortress.AspNetCore`) lives at `../devfortress-aspnetcore`.

## Install

Not published to NuGet.org yet. Until it is, reference the project directly or build a local package:

```bash
dotnet pack DevFortress.Sdk.csproj -c Release -o ./local-nuget
```

## The DevFortress Textbook

DevFortress implements 34 novel security inventions. Patent Pending.

These 34 inventions are documented in depth across 5 volumes.

**"Credential Isolation Closed-Loop Security"**
_Duncan Ndungu Ndegwa — DevFortress, 2026_

→ Available on Gumroad: [https://devfortress.gumroad.com/l/master-edition]

## Quick start

```csharp
using DevFortress;

using var client = Client.Create(Environment.GetEnvironmentVariable("DEVFORTRESS_API_KEY")!)
    .Build();

client.TrackEvent(new Dictionary<string, object?>
{
    ["eventType"] = "auth_failure",
    ["ip"] = "203.0.113.7",
    ["method"] = "POST",
    ["path"] = "/login",
    ["severity"] = "MEDIUM",
});
// Dispose (via `using`) flushes whatever is still queued.
```

`TrackEvent`/`TrackEvents` queue events in memory; the queue also flushes itself once it reaches the batch size. `Flush`/`FlushAsync` send whatever is queued, and disposing the client flushes on shutdown. `TestConnection` sends one test event and reports whether the platform accepts the key.

A framework adapter observing one request at a time should use `Observer.ObserveAndFlush`, not `TrackEvent` alone — see `Observer`'s doc comments for why: under sparse traffic, a queued-only event can sit undelivered indefinitely without it.

## Closed-loop mode

`Client.Create(...).Mode(...)` selects the closed-loop delivery mode: `"external"` (default — every event ships to the platform, no behavior change for existing callers), `"internal"` (decisions are made locally, nothing leaves your infrastructure), or `"hybrid"` (local-first, with automatic cloud enrichment and failover). Internal/hybrid require Team tier or above.

```csharp
string clMode = Environment.GetEnvironmentVariable("DEVFORTRESS_CL_MODE") is { Length: > 0 } m ? m : "external";
using var client = Client.Create(Environment.GetEnvironmentVariable("DEVFORTRESS_API_KEY")!)
    .Mode(clMode)
    .Build();
```

Reading the mode from a `DEVFORTRESS_CL_MODE` env var (`external`, `internal`, or `hybrid`) is the convention this SDK's demo apps use so the same build can be started in any mode without a code change.

## Other modules

`UnifiedAuditTrail` merges internal and external closed-loop audit events into one in-memory timeline. `GraduatedRateLimiter` applies alias-scoped rate limiting with multi-stage escalation (observe, warn, soft-limit, hard-block, revoke).

## Tests

```bash
dotnet test tests/DevFortress.Sdk.Tests/DevFortress.Sdk.Tests.csproj
```

248 tests covering the Client/Builder API, signing, webhook verification, the closed-loop engines, and the other modules above.

## License

BUSL-1.1
