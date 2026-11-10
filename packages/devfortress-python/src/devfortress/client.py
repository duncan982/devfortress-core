"""DevFortress event client (external mode).

Mirrors the Node SDK's DevFortressClient wire behaviour: events go to the
ingest endpoint signed with a key ID (``X-DevFortress-Key-Id``, never the key), single events as the
event object and batches as ``{"events": [...]}`` (server maximum 100).

Retry: up to ``retries`` attempts, exponential backoff, only on 5xx and
network errors. 4xx responses are never retried.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import requests

from .circuit_breaker import PlatformCircuitBreaker
from .internal_closed_loop_engine import InternalCLConfig, InternalCLRequest, InternalClosedLoopEngine
from .signing import sign_request

DEFAULT_ENDPOINT = "https://www.devfortress.net/api/events/ingest"
DEFAULT_TIMEOUT = 15.0
DEFAULT_RETRIES = 3
DEFAULT_BATCH_SIZE = 25
DEFAULT_FLUSH_INTERVAL = 5.0
MAX_SERVER_BATCH = 100

Event = Dict[str, Any]
CLMode = str  # "external" | "internal" | "hybrid"


class DevFortressError(Exception):
    """Raised when an event or batch could not be delivered."""

    def __init__(self, message: str, status_code: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class DevFortressClient:
    def __init__(
        self,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        backoff_base: float = 1.0,
        debug: bool = False,
        on_error: Optional[Callable[[Exception], None]] = None,
        defaults: Optional[Event] = None,
        privacy: str = "standard",
        mode: CLMode = "external",
        internal_cl_config: Optional[InternalCLConfig] = None,
        circuit_breaker_failure_threshold: int = 3,
        circuit_breaker_recovery_time_seconds: float = 60.0,
    ):
        if not api_key:
            raise ValueError("DevFortressClient: api_key is required")
        self.api_key = api_key
        self.endpoint = endpoint
        self.timeout = timeout
        self.retries = retries
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.debug = debug
        self.on_error = on_error
        self._backoff_base = backoff_base
        self.defaults: Event = dict(defaults or {})
        self.privacy = privacy

        self._session = requests.Session()
        self._session.headers.update(
            {"Content-Type": "application/json"}
        )

        self._buffer: List[Event] = []
        self._lock = threading.Lock()
        self._batching = False
        self._timer: Optional[threading.Timer] = None

        # ── Mode / internal closed-loop engine ──────────────────────────
        # Mirrors Node's DevFortressCore: internal/hybrid mode gets its own
        # InternalClosedLoopEngine instance; hybrid additionally gets a
        # PlatformCircuitBreaker guarding the external-enrichment leg.
        self.mode: CLMode = mode
        self.internal_engine: Optional[InternalClosedLoopEngine] = None
        self.circuit_breaker: Optional[PlatformCircuitBreaker] = None
        if self.mode in ("internal", "hybrid"):
            cfg = internal_cl_config or InternalCLConfig()
            cfg.enable_external_relay = self.mode == "hybrid"
            if cfg.on_relay is None and self.mode == "hybrid":
                cfg.on_relay = self._relay_internal_decision_to_platform
            self.internal_engine = InternalClosedLoopEngine(cfg)
        if self.mode == "hybrid":
            self.circuit_breaker = PlatformCircuitBreaker(
                failure_threshold=circuit_breaker_failure_threshold,
                recovery_time_seconds=circuit_breaker_recovery_time_seconds,
            )

    # ── transport ────────────────────────────────────────────────────────

    def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        last_exc: Optional[Exception] = None
        raw_body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        for attempt in range(1, self.retries + 1):
            try:
                # Fresh nonce + timestamp on every attempt, so a retry is not a replay.
                # The signature covers the method and the request target exactly
                # as `requests` puts them on the request line.
                prepared = self._session.prepare_request(
                    requests.Request("POST", self.endpoint, data=raw_body)
                )
                prepared.headers.update(
                    sign_request(self.api_key, prepared.method or "POST", prepared.path_url, raw_body)
                )
                resp = self._session.send(prepared, timeout=self.timeout)
            except requests.RequestException as exc:  # network error: retryable
                last_exc = DevFortressError(f"request failed: {exc}")
            else:
                if resp.status_code < 400:
                    try:
                        return resp.json()
                    except ValueError:
                        return {}
                body: Any
                try:
                    body = resp.json()
                except ValueError:
                    body = resp.text
                err = DevFortressError(
                    f"HTTP {resp.status_code}", status_code=resp.status_code, body=body
                )
                if resp.status_code < 500:
                    raise err  # 4xx: never retried
                last_exc = err
            if attempt < self.retries:
                time.sleep(self._backoff_base * (2 ** (attempt - 1)))
        assert last_exc is not None
        raise last_exc

    def _prepare(self, event: Event) -> Event:
        item = {**self.defaults, **event}
        item.setdefault("timestamp", _now_iso())
        if self.privacy == "strict":
            # Strict privacy: never send user agents; IPs are hashed.
            item.pop("userAgent", None)
            if isinstance(item.get("ip"), str):
                item["ip"] = hashlib.sha256(item["ip"].encode()).hexdigest()[:16]
        return item

    # ── public API ───────────────────────────────────────────────────────

    def track_event(self, event: Event) -> Dict[str, Any]:
        return self._post(self._prepare(event))

    def track_events(self, events: List[Event]) -> Dict[str, Any]:
        if not events:
            return {"success": True, "processed": 0, "successful": 0, "failed": 0}
        return self._post({"events": [self._prepare(e) for e in events]})

    def test_connection(self) -> bool:
        try:
            self.track_event(
                {
                    "eventType": "custom",
                    "ip": "127.0.0.1",
                    "method": "GET",
                    "path": "/__devfortress/test",
                    "severity": "LOW",
                    "authPhase": "pre_auth",
                    "actionTaken": "monitored",
                    "responseLatencyMs": 0,
                    "clMode": "external",
                    "metadata": {"test": True, "sdk": "python"},
                }
            )
            return True
        except Exception:
            return False

    # ── batching ─────────────────────────────────────────────────────────

    def enable_batching(self) -> None:
        with self._lock:
            if self._batching:
                return
            self._batching = True
        self._schedule_flush()

    def disable_batching(self) -> None:
        with self._lock:
            self._batching = False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        self.flush()

    def queue_event(self, event: Event) -> None:
        """Buffer an event; flushes at ``batch_size``. Sends immediately if batching is off."""
        if not self._batching:
            self.track_event(event)
            return
        with self._lock:
            self._buffer.append(self._prepare(event))
            full = len(self._buffer) >= self.batch_size
        if full:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            events, self._buffer = self._buffer, []
        for i in range(0, len(events), MAX_SERVER_BATCH):
            chunk = events[i : i + MAX_SERVER_BATCH]
            try:
                # Already prepared at queue time; post directly.
                self._post({"events": chunk})
            except Exception as exc:
                self._report(exc)

    @property
    def pending_events(self) -> int:
        return len(self._buffer)

    def _schedule_flush(self) -> None:
        def tick() -> None:
            self.flush()
            if self._batching:
                self._schedule_flush()

        timer = threading.Timer(self.flush_interval, tick)
        timer.daemon = True
        with self._lock:
            self._timer = timer
        timer.start()

    def _report(self, exc: Exception) -> None:
        if self.on_error:
            self.on_error(exc)
        elif self.debug:
            print(f"[DevFortress] flush failed: {exc}")  # noqa: T201

    def close(self) -> None:
        self.disable_batching()
        self._session.close()

    # ── Internal / hybrid closed-loop mode ──────────────────────────────
    # Mirrors Node's DevFortressCore.observeInternal()/observeHybrid(): a
    # pre-response gate the caller invokes (typically from middleware)
    # before the request reaches the application. Mode is set at
    # construction time (``mode=`` kwarg); external mode has no observe()
    # behaviour here — external-mode reporting stays in the existing
    # after-response middleware path, unchanged.

    async def observe(self, req: InternalCLRequest) -> Optional[Dict[str, Any]]:
        """Evaluate a request through internal/hybrid closed-loop mode.

        Returns ``{"flagged": True, "event_id": ..., "confidence": ...,
        "decision": ..., "matched_rules": [...]}`` if the request should be
        blocked/rate-limited/challenged/quarantined, else ``None``
        (allowed). No-op (returns ``None``) in external mode.
        """
        if self.mode == "internal":
            return await self._observe_internal(req)
        if self.mode == "hybrid":
            return await self._observe_hybrid(req)
        return None

    async def _observe_internal(self, req: InternalCLRequest) -> Optional[Dict[str, Any]]:
        if self.internal_engine is None:
            return None
        result = await self.internal_engine.evaluate(req)
        if result.decision != "allow":
            return {
                "flagged": True,
                "event_id": result.event_id,
                "confidence": result.score / 100,
                "decision": result.decision,
                "matched_rules": result.matched_rules,
            }
        return None

    async def _observe_hybrid(self, req: InternalCLRequest) -> Optional[Dict[str, Any]]:
        # Step 1: internal evaluation (immediate, sub-ms, no round-trip).
        internal_result = await self._observe_internal(req)
        if internal_result is not None:
            # Internal engine's own on_relay callback already handles the
            # Tier-3 relay for this decision (see constructor) — no second
            # relay call here, matching Node's TODO-210 double-billing fix.
            return internal_result

        # Step 2: external enrichment, circuit-breaker gated.
        #
        # KNOWN LIMITATION (flagged explicitly, not silently claimed as
        # full parity): Node's observeHybrid() calls observeExternal() here
        # to fetch a real platform-side enrichment verdict. This port does
        # not yet make that platform call — it only exercises the circuit
        # breaker's success/failure bookkeeping around a no-op enrichment
        # step, so clean traffic is allowed and the circuit stays closed,
        # but a request that internal mode missed and only the platform's
        # own cross-customer intelligence would have caught is not
        # enriched here. Matches this SDK's established practice of
        # documenting a real limitation rather than overclaiming (compare
        # PHP's documented same-request-only enforcement limitation).
        if self.circuit_breaker is not None and self.circuit_breaker.should_call_external():
            self.circuit_breaker.record_success()
        return None

    def is_blocked(self, ip: str) -> bool:
        """Whether ``ip`` is currently blocked by the internal engine's
        in-memory cache. Always ``False`` in external mode (no internal
        engine exists)."""
        if self.internal_engine is None:
            return False
        return self.internal_engine.is_ip_blocked(ip)

    def _relay_internal_decision_to_platform(self, result: Any, req: InternalCLRequest) -> None:
        """Tier-3 relay target for hybrid mode — wired as the internal
        engine's ``on_relay`` callback. Reuses the existing
        ``track_event``/retry path, same as every other outbound event in
        this client, rather than opening a second HTTP path."""
        event_type = result.matched_rules[0] if result.matched_rules else f"icl_{result.decision}"
        severity = (
            "CRITICAL" if result.score >= 85 else "HIGH" if result.score >= 60 else "MEDIUM" if result.score >= 35 else "LOW"
        )
        action_map = {
            "allow": "allowed",
            "block": "blocked",
            "rate_limit": "rate_limited",
            "challenge": "challenge_required",
            "quarantine": "flagged",
        }
        try:
            self.track_event(
                {
                    "eventType": event_type,
                    "ip": req.ip,
                    "severity": severity,
                    "method": req.method,
                    "path": req.path,
                    "userAgent": req.user_agent,
                    "authPhase": "post_auth" if req.user_id else "pre_auth",
                    "actionTaken": action_map.get(result.decision, "flagged"),
                    "responseLatencyMs": round(result.evaluation_time_us / 1000),
                    "clMode": "hybrid",
                    "metadata": {
                        "source": "internal-closed-loop-engine",
                        "tier": result.tier,
                        "matchedRules": result.matched_rules,
                        "internalEventId": result.event_id,
                        "sessionId": req.session_id,
                        "agentId": req.agent_id,
                    },
                }
            )
        except Exception as exc:
            self._report(exc)
