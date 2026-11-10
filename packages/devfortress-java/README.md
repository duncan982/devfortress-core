# devfortress-sdk (Java)

Event reporting client for DevFortress (external mode). Pre-release, not published.

Requires Java 17 or newer. There are no runtime dependencies outside the JDK (the HTTP transport is `java.net.http.HttpClient`; JSON encoding/decoding is a small internal codec, since the JDK has no built-in JSON library). A Spring Boot filter adapter (`devfortress-spring-boot`, name proposed — Duncan's call) lives at `../devfortress-spring-boot`.

## Install

Not published to Maven Central yet. Until it is, `mvn install` this module and reference it by coordinates:

```xml
<dependency>
    <groupId>net.devfortress</groupId>
    <artifactId>devfortress-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

## The DevFortress Textbook

DevFortress implements 34 novel security inventions. Patent Pending.

These 34 inventions are documented in depth across 5 volumes.

**"Credential Isolation Closed-Loop Security"**
_Duncan Ndungu Ndegwa — DevFortress, 2026_

→ Available on Gumroad: [https://devfortress.gumroad.com/l/master-edition]

## Quick start

```java
import net.devfortress.Client;
import java.util.Map;

try (Client client = Client.builder(System.getenv("DEVFORTRESS_API_KEY")).build()) {
    client.trackEvent(Map.of(
            "eventType", "auth_failure",
            "ip", "203.0.113.7",
            "method", "POST",
            "path", "/login",
            "severity", "MEDIUM"));
} // close() flushes whatever is still queued
```

`trackEvent`/`trackEvents` queue events in memory; the queue also flushes itself (synchronously, on the caller's thread) once it reaches the batch size. `flush` sends whatever is queued and `close` flushes on shutdown. `testConnection` sends one test event and reports whether the platform accepts the key.

A framework adapter observing one request at a time should use `Observer.observeAndFlush`, not `trackEvent` alone and not `Observer.observe` — see `Observer`'s class doc for why: under sparse traffic, a queued-only event can sit undelivered indefinitely without it.

## Closed-loop mode

`Client.builder(...).mode(...)` selects the closed-loop delivery mode: `"external"` (default — every event ships to the platform, no behavior change for existing callers), `"internal"` (decisions are made locally, nothing leaves your infrastructure), or `"hybrid"` (local-first, with automatic cloud enrichment and failover). Internal/hybrid require Team tier or above.

```java
String clMode = System.getenv("DEVFORTRESS_CL_MODE");
Client client = Client.builder(System.getenv("DEVFORTRESS_API_KEY"))
        .mode(clMode != null ? clMode : "external")
        .build();
```

Reading the mode from a `DEVFORTRESS_CL_MODE` env var (`external`, `internal`, or `hybrid`) is the convention this SDK's demo apps use so the same build can be started in any mode without a code change.

## Other modules

`UnifiedAuditTrail` merges internal and external closed-loop audit events into one in-memory timeline. `GraduatedRateLimiter` applies alias-scoped rate limiting with multi-stage escalation (observe, warn, soft-limit, hard-block, revoke).

## License

BUSL-1.1
