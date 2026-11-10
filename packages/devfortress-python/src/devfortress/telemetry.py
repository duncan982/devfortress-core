"""DevFortress SDK — Telemetry Heartbeat (CV-M2) and Rollup Buffer.

Port of the Node SDK's ``telemetry.ts`` (``TelemetryManager``) and
``telemetry-rollup-buffer.ts`` (``TelemetryRollupBuffer`` +
``hourlyPeriodKey``). Both live in this one file, matching how every other
non-Node SDK port keeps a single telemetry module.

``TelemetryManager`` sends anonymised usage telemetry to the platform
roughly every 5 minutes. No PII is transmitted — only aggregate counts and
operational metadata. If heartbeat stops, the platform dashboard shows:
"SDK offline — upgrade to Hybrid for guaranteed visibility."

``TelemetryRollupBuffer`` (Option B, 2026-08-27) is the non-billing
counterpart: CLEAN/unflagged traffic no longer gets a full, billed event
row per request. Instead this buffer accumulates lightweight
per-alias/IP-per-hour counters in memory (request count, unique endpoints
seen, error count, latency sum) and flushes them as a small number of
upsert-increment rows to ``/api/events/telemetry-rollup`` on a long
interval — not per request. This is what feeds population-level baseline
needs without counting toward the customer's billed event quota.

Where Node keys its in-memory buckets with a NUL-byte-joined composite
string (``f"{aliasOrIpKey}\\x00{periodKey}"``), this port uses the
Python-idiomatic equivalent: a ``(alias_or_ip_key, period_key)`` tuple as
the dict key. Same collision-free bucketing semantics.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlsplit

import requests

from .signing import sign_request
from .version import SDK_VERSION

CLMode = Literal["external", "internal", "hybrid"]
SubscriptionTier = Literal["starter", "pro", "team", "enterprise"]

# ── Constants ────────────────────────────────────────────────

DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 5 * 60  # 5 minutes
HEARTBEAT_TIMEOUT_SECONDS = 5.0
HEARTBEAT_INITIAL_DELAY_SECONDS = 5.0


def _request_target(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


# ── Types ────────────────────────────────────────────────────


@dataclass
class TelemetrySnapshot:
    """One heartbeat's worth of aggregate, non-PII operational state."""

    event_count: int
    block_count: int
    rate_limit_count: int
    cl_mode: CLMode
    tier: SubscriptionTier
    sdk_version: str
    model_expired: bool
    license_degraded: bool
    integrity_hash: str
    uptime_seconds: int
    p99_latency_ms: float


# ── Telemetry Manager ────────────────────────────────────────


class TelemetryManager:
    """Sends periodic, anonymised usage heartbeats to the platform."""

    def __init__(
        self,
        api_key: str,
        endpoint: str,
        *,
        heartbeat_interval_seconds: float = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        debug: bool = False,
        timeout: float = HEARTBEAT_TIMEOUT_SECONDS,
        session: Optional[requests.Session] = None,
    ):
        if not api_key:
            raise ValueError("TelemetryManager: api_key is required")
        if not endpoint:
            raise ValueError("TelemetryManager: endpoint is required")

        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.debug = debug
        self.timeout = timeout
        self._session = session or requests.Session()

        # Counters (reset after each heartbeat)
        self._event_count = 0
        self._block_count = 0
        self._rate_limit_count = 0

        # Latency tracking (sampled)
        self._latencies: List[float] = []
        self._max_latency_samples = 100

        self._started_at = time.time()
        self._timer: Optional[threading.Timer] = None
        self._first_timer: Optional[threading.Timer] = None
        self._snapshot_provider: Optional[Callable[[], dict]] = None

    def start(self, snapshot_provider: Optional[Callable[[], dict]] = None) -> None:
        """Start sending periodic heartbeats.

        ``snapshot_provider`` optionally enriches each heartbeat with live
        SDK state (``cl_mode``, ``tier``, ``model_expired``, etc).
        """
        if self._timer is not None or self._first_timer is not None:
            return  # already started

        self._snapshot_provider = snapshot_provider
        self._started_at = time.time()

        # Send first heartbeat after a short delay (don't block init)
        first = threading.Timer(HEARTBEAT_INITIAL_DELAY_SECONDS, self.send_heartbeat)
        first.daemon = True
        self._first_timer = first
        first.start()

        # Schedule periodic heartbeats
        self._schedule_next()

        self._log(
            "info",
            f"Telemetry heartbeat started (interval: {self.heartbeat_interval_seconds}s)",
        )

    def _schedule_next(self) -> None:
        timer = threading.Timer(self.heartbeat_interval_seconds, self._tick)
        timer.daemon = True  # never blocks process exit
        self._timer = timer
        timer.start()

    def _tick(self) -> None:
        self.send_heartbeat()
        self._schedule_next()

    def record_event(self) -> None:
        """Record an observed event."""
        self._event_count += 1

    def record_block(self) -> None:
        """Record a blocked event."""
        self._block_count += 1

    def record_rate_limit(self) -> None:
        """Record a rate-limited event."""
        self._rate_limit_count += 1

    def record_latency(self, ms: float) -> None:
        """Record observe latency for p99 calculation (reservoir sampling)."""
        if len(self._latencies) >= self._max_latency_samples:
            import random

            idx = random.randrange(len(self._latencies))
            self._latencies[idx] = ms
        else:
            self._latencies.append(ms)

    def send_heartbeat(self) -> None:
        """Send a heartbeat to the platform.

        Fire-and-forget — failures are logged (debug level), never raised.
        Public so it can be invoked directly (e.g. from tests) without
        waiting on the background timer.
        """
        try:
            enriched = self._snapshot_provider() if self._snapshot_provider else {}

            snapshot = TelemetrySnapshot(
                event_count=self._event_count,
                block_count=self._block_count,
                rate_limit_count=self._rate_limit_count,
                cl_mode=enriched.get("cl_mode", "external"),
                tier=enriched.get("tier", "starter"),
                sdk_version=enriched.get("sdk_version", SDK_VERSION),
                model_expired=enriched.get("model_expired", False),
                license_degraded=enriched.get("license_degraded", False),
                integrity_hash=enriched.get("integrity_hash", ""),
                uptime_seconds=int(time.time() - self._started_at),
                p99_latency_ms=self._compute_p99(),
            )

            url = f"{self.endpoint}/api/sdk/heartbeat"
            body = json.dumps(
                {
                    "timestamp": int(time.time() * 1000),
                    "eventCount": snapshot.event_count,
                    "blockCount": snapshot.block_count,
                    "rateLimitCount": snapshot.rate_limit_count,
                    "clMode": snapshot.cl_mode,
                    "tier": snapshot.tier,
                    "sdkVersion": snapshot.sdk_version,
                    "modelExpired": snapshot.model_expired,
                    "licenseDegraded": snapshot.license_degraded,
                    "integrityHash": snapshot.integrity_hash,
                    "uptimeSeconds": snapshot.uptime_seconds,
                    "p99LatencyMs": snapshot.p99_latency_ms,
                },
                separators=(",", ":"),
            ).encode("utf-8")

            headers = {"Content-Type": "application/json"}
            headers.update(sign_request(self.api_key, "POST", _request_target(url), body))
            self._session.post(url, data=body, headers=headers, timeout=self.timeout)

            self._log(
                "debug",
                f"Heartbeat sent: events={snapshot.event_count}, "
                f"blocks={snapshot.block_count}, uptime={snapshot.uptime_seconds}s",
            )

            # Reset counters after successful send
            self._event_count = 0
            self._block_count = 0
            self._rate_limit_count = 0
            self._latencies = []
        except Exception as error:  # noqa: BLE001 - fire-and-forget, never raise
            self._log("debug", f"Heartbeat failed: {error}")

    def _compute_p99(self) -> float:
        if not self._latencies:
            return 0.0
        sorted_latencies = sorted(self._latencies)
        idx = int(len(sorted_latencies) * 0.99)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]

    def get_state(self) -> dict:
        """Current telemetry state (for diagnostics)."""
        return {
            "event_count": self._event_count,
            "block_count": self._block_count,
            "rate_limit_count": self._rate_limit_count,
            "uptime_seconds": int(time.time() - self._started_at),
        }

    def destroy(self) -> None:
        """Stop sending heartbeats and clean up."""
        if self._timer:
            self._timer.cancel()
            self._timer = None
        if self._first_timer:
            self._first_timer.cancel()
            self._first_timer = None

    def _log(self, level: Literal["info", "warn", "debug"], message: str) -> None:
        if not self.debug and level == "debug":
            return
        print(f"[DevFortress:Telemetry] {message}")  # noqa: T201


# ── Telemetry Rollup Buffer ──────────────────────────────────


@dataclass
class RollupContributionInput:
    """One clean (non-flagged) request's contribution to the rollup."""

    alias_or_ip_key: str
    endpoint: str
    is_error: bool
    latency_ms: float


@dataclass
class _RollupBucket:
    alias_or_ip_key: str
    period_key: str
    request_count: int = 0
    endpoints: set = field(default_factory=set)
    error_count: int = 0
    latency_sum_ms: float = 0.0
    window_start: float = 0.0
    window_end: float = 0.0


# Bounded per-bucket endpoint tracking — uniqueEndpoints is an approximation
# (this is non-billing, best-effort aggregate telemetry, not an exact count).
MAX_ENDPOINTS_TRACKED_PER_BUCKET = 50
# Matches TelemetryManager's DEFAULT_HEARTBEAT_INTERVAL_SECONDS above — this
# is aggregate, non-billing telemetry, not real-time-critical, so a wider
# batching window means fewer platform requests and keeps this interval
# consistent with the SDK's other background timer.
DEFAULT_FLUSH_INTERVAL_SECONDS = 5 * 60
DEFAULT_MAX_BUFFERED_KEYS = 500


def hourly_period_key(dt: Optional[datetime] = None) -> str:
    """Hour-bucket period key, e.g. "2026-08-27T14" — matches
    AliasTelemetryRollup.periodKey.
    """
    moment = dt if dt is not None else datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H")


class TelemetryRollupBuffer:
    """Buffers clean-traffic contributions in memory, keyed by
    ``(alias_or_ip_key, period_key)``, and flushes them as a batch to the
    platform on a long interval instead of per-request.
    """

    def __init__(
        self,
        api_key: str,
        endpoint: str,
        *,
        flush_interval_seconds: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        max_buffered_keys: int = DEFAULT_MAX_BUFFERED_KEYS,
        debug: bool = False,
        timeout: float = HEARTBEAT_TIMEOUT_SECONDS,
        session: Optional[requests.Session] = None,
    ):
        if not api_key:
            raise ValueError("TelemetryRollupBuffer: api_key is required")
        if not endpoint:
            raise ValueError("TelemetryRollupBuffer: endpoint is required")

        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.flush_interval_seconds = flush_interval_seconds
        self.max_buffered_keys = max_buffered_keys
        self.debug = debug
        self.timeout = timeout
        self._session = session or requests.Session()

        self._buckets: Dict[Tuple[str, str], _RollupBucket] = {}
        self._timer: Optional[threading.Timer] = None

    def start(self) -> None:
        """Start the periodic flush timer. Safe to call multiple times (no-op if already started)."""
        if self._timer is not None:
            return
        self._schedule_next()

    def _schedule_next(self) -> None:
        timer = threading.Timer(self.flush_interval_seconds, self._tick)
        timer.daemon = True  # never blocks process exit
        self._timer = timer
        timer.start()

    def _tick(self) -> None:
        try:
            self.flush()
        finally:
            self._schedule_next()

    def add(self, contribution: RollupContributionInput) -> None:
        """Buffer one clean request's contribution. Synchronous, no network
        call — actual delivery happens on the next ``flush()``.
        """
        period_key = hourly_period_key()
        bucket_key = (contribution.alias_or_ip_key, period_key)
        bucket = self._buckets.get(bucket_key)
        now = time.time()

        if bucket is None:
            # Bound total buffered keys so a burst of unique IPs can't grow
            # memory unbounded — force an early flush and drop this one
            # contribution. Acceptable: approximate, non-billing telemetry.
            if len(self._buckets) >= self.max_buffered_keys:
                self.flush()
                return
            bucket = _RollupBucket(
                alias_or_ip_key=contribution.alias_or_ip_key,
                period_key=period_key,
                window_start=now,
                window_end=now,
            )
            self._buckets[bucket_key] = bucket

        bucket.request_count += 1
        if len(bucket.endpoints) < MAX_ENDPOINTS_TRACKED_PER_BUCKET:
            bucket.endpoints.add(contribution.endpoint)
        if contribution.is_error:
            bucket.error_count += 1
        bucket.latency_sum_ms += contribution.latency_ms
        bucket.window_end = now

    def flush(self) -> None:
        """Flush all buffered buckets to the platform in one batch request."""
        if not self._buckets:
            return

        contributions = [
            {
                "aliasOrIpKey": b.alias_or_ip_key,
                "periodKey": b.period_key,
                "requestCount": b.request_count,
                "uniqueEndpointsInBatch": len(b.endpoints),
                "errorCount": b.error_count,
                "latencySumMs": b.latency_sum_ms,
                "windowStart": b.window_start,
                "windowEnd": b.window_end,
            }
            for b in self._buckets.values()
        ]
        self._buckets.clear()

        try:
            url = f"{self.endpoint}/api/events/telemetry-rollup"
            body = json.dumps({"contributions": contributions}, separators=(",", ":")).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            headers.update(sign_request(self.api_key, "POST", _request_target(url), body))
            self._session.post(url, data=body, headers=headers, timeout=self.timeout)
        except Exception as e:  # noqa: BLE001
            # Best-effort — aggregate telemetry is not billing-relevant, so
            # dropping a batch on transient failure is acceptable (unlike the
            # full event ingest path, which retries).
            if self.debug:
                print(f"[DevFortress] telemetry rollup flush failed: {e}")  # noqa: T201

    def destroy(self) -> None:
        """Clean up the flush timer and drop any unflushed buckets."""
        if self._timer:
            self._timer.cancel()
            self._timer = None
        self._buckets.clear()
