# devfortress-sdk-python

Event reporting client for DevFortress (external mode). Pre-release, not published.

```python
from devfortress import DevFortressClient

client = DevFortressClient(api_key="...", endpoint="https://www.devfortress.net/api/events/ingest")
client.track_event({"eventType": "auth_failure", "ip": "203.0.113.7", "method": "POST",
                    "path": "/login", "severity": "MEDIUM"})
```

Also included: `flush`, `track_events`, `test_connection`, FastAPI and Flask middleware, and `verify_webhook_signature`.

`DevFortressClient(..., mode="external")` selects the closed-loop delivery mode: `"external"` (default — every event ships to the platform, no behavior change for existing callers), `"internal"` (decisions are made locally, nothing leaves your infrastructure), or `"hybrid"` (local-first, with automatic cloud enrichment and failover; both require Team tier or above). Reading it from a `DEVFORTRESS_CL_MODE` env var (`os.environ.get("DEVFORTRESS_CL_MODE", "external")`) is the convention this SDK's demo apps use so the same process can be started in any mode without a code change.

Also included: `UnifiedAuditTrail` (merges internal/external closed-loop audit events into one timeline) and `GraduatedRateLimiter` (alias-scoped rate limiting with multi-stage escalation).

## The DevFortress Textbook

DevFortress implements 34 novel security inventions. Patent Pending.

These 34 inventions are documented in depth across 5 volumes.

**"Credential Isolation Closed-Loop Security"**
_Duncan Ndungu Ndegwa — DevFortress, 2026_

→ Available on Gumroad: [https://devfortress.gumroad.com/l/master-edition]

License: BUSL-1.1
