"""Closed-Loop Response — inbound webhook orchestration + outbound delivery.

Port of the relevant parts of the Node SDK's ``devfortress.ts``:
``handleWebhook`` (inbound: platform -> SDK revocation/quarantine signal),
and ``deliverSessionRevocation``/``deliverIPBlock`` (outbound: platform ->
customer's own webhook endpoint).

Inbound signature verification itself is unchanged — this module builds on
the existing ``webhook.verify_webhook_signature`` rather than re-implementing
it, and adds everything downstream: in-memory IP/user blocking, audit
recording, and severity-routed handler dispatch.

Outbound delivery (``deliver_session_revocation``/``deliver_ip_block``) uses
the *same* simple HMAC-SHA256-over-``timestamp.body`` scheme as inbound
verification (confirmed identical in the Node source) — not the 5-part
``ingest-signing.ty`` canonical-string scheme used for the main ingest API.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional, Union

import requests

from .bounded_map import BoundedMap
from .webhook import verify_webhook_signature

ThreatSeverity = Literal["low", "medium", "high", "critical"]
ThreatHandler = Callable[["ThreatEvent"], Union[Awaitable[None], None]]

MAX_CACHE_ENTRIES = 10_000
WEBHOOK_MAX_AGE_SECONDS = 5 * 60  # 5 minutes
WEBHOOK_RATE_LIMIT = 60  # max deliveries per minute per endpoint
WEBHOOK_RATE_WINDOW_MS = 60_000


@dataclass
class ThreatEvent:
    event_id: str
    threat_type: str
    severity: ThreatSeverity
    confidence: float
    composite_score: float
    ip: str
    identity: Dict[str, Optional[str]]
    endpoint: str
    method: str
    timestamp: str
    meta: Dict[str, Any] = field(default_factory=dict)
    geo: Optional[Dict[str, str]] = None
    abuseipdb: Optional[Dict[str, Any]] = None


@dataclass
class AuditRecord:
    event_id: str
    timestamp: float
    source: str
    tier: int
    decision: str
    score: float
    severity: str
    latency_ms: float
    ip: str
    path: str
    method: str
    matched_rules: List[str]
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


class InMemoryAuditTrail:
    """Minimal local audit sink. The Node platform's ``UnifiedAuditTrail`` has
    no Python/local equivalent yet — this keeps the last N records in memory
    so handlers/tests can inspect
    what closed-loop activity happened, without inventing durable persistence
    this port wasn't asked to add."""

    def __init__(self, max_records: int = MAX_CACHE_ENTRIES):
        self._records: "List[AuditRecord]" = []
        self._max_records = max_records

    def record(self, rec: AuditRecord) -> None:
        self._records.append(rec)
        if len(self._records) > self._max_records:
            del self._records[: len(self._records) - self._max_records]

    def all(self) -> List[AuditRecord]:
        return list(self._records)


class _TTLCache:
    """In-memory cache for blocking decisions — LRU bounded, matching Node's
    module-level ``memoryCache``."""

    def __init__(self, max_entries: int = MAX_CACHE_ENTRIES):
        self._map: "BoundedMap[str, tuple]" = BoundedMap(max_entries)

    def get(self, key: str) -> Optional[str]:
        entry = self._map.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.time() * 1000 > expires_at:
            self._map.delete(key)
            return None
        return value

    def set(self, key: str, value: str, ttl_seconds: float) -> None:
        self._map.set(key, (value, time.time() * 1000 + ttl_seconds * 1000))


class ClosedLoopEngine:
    """Orchestrates inbound webhook handling and outbound delivery for a
    single DevFortress client instance.

    ``can_block`` mirrors Node's ``tierGate.canBlock()`` gate: pass a
    zero-arg callable returning ``bool`` if the embedding app has its own
    tier gate, or leave it ``None`` to always allow blocking (matches a
    client with no tier restrictions configured).
    """

    def __init__(
        self,
        *,
        webhook_secret: Optional[str] = None,
        response_webhook_url: Optional[str] = None,
        allow_legacy_unsigned_webhooks: bool = False,
        cache_ttl_seconds: int = 3600,
        can_block: Optional[Callable[[], bool]] = None,
        nonce_check: Optional[Callable[[str], bool]] = None,
        log: Optional[Callable[[str, str], None]] = None,
    ):
        self._webhook_secret = webhook_secret
        self._response_webhook_url = response_webhook_url
        self._allow_legacy_unsigned_webhooks = allow_legacy_unsigned_webhooks
        self._cache_ttl_seconds = cache_ttl_seconds
        self._can_block = can_block or (lambda: True)
        self._nonce_check = nonce_check
        self._log = log or (lambda level, msg: None)

        self._cache = _TTLCache()
        self.audit_trail = InMemoryAuditTrail()
        self._handlers: "Dict[str, List[ThreatHandler]]" = {}
        self._webhook_delivery_counts: "Dict[str, Dict[str, float]]" = {}

    # ── Handler registration ────────────────────────────────

    def on_threat_detected(self, severity_or_wildcard: str, handler: ThreatHandler) -> None:
        self._handlers.setdefault(severity_or_wildcard, []).append(handler)

    def is_blocked_ip(self, ip: str) -> bool:
        return self._cache.get(f"blocked:ip:{ip}") is not None

    def is_blocked_user(self, user_id: str) -> bool:
        return self._cache.get(f"blocked:user:{user_id}") is not None

    # ── Inbound: platform -> SDK ────────────────────────────

    async def handle_webhook(self, raw_body: str, signature: str, timestamp: str) -> bool:
        """Verify and process an inbound threat-response webhook. Returns
        True if the payload was accepted and dispatched, False on rejection
        (signature, replay, or structural failure) — never raises for an
        untrusted/malformed request."""
        if not self._webhook_secret:
            self._log("error", "handle_webhook() called but no webhook secret configured")
            return False

        # Signature + timestamp only here (nonce_check=None) — nonce handling
        # below mirrors Node's exact structure: the registry is consulted
        # only when the payload actually carries a nonce; a payload with no
        # nonce field at all falls through to the legacy-sender check
        # instead, regardless of whether a nonce_check callback is
        # configured. Folding nonce_check into this call would make a
        # missing nonce fail before that legacy check ever runs.
        verification = verify_webhook_signature(
            raw_body,
            signature,
            timestamp,
            self._webhook_secret,
            tolerance_seconds=WEBHOOK_MAX_AGE_SECONDS,
        )
        if not verification.valid:
            self._log("warn", f"Webhook rejected: {verification.reason}")
            return False

        try:
            payload = json.loads(raw_body)
        except Exception:
            self._log("error", "Webhook rejected: invalid JSON body")
            return False

        # Nonce-based replay prevention — mandatory by default.
        nonce = payload.get("nonce")
        if nonce is not None:
            if self._nonce_check is not None and not self._nonce_check(nonce):
                self._log("warn", f"Webhook rejected: replay detected (nonce={str(nonce)[:8]}...)")
                return False
        elif not self._allow_legacy_unsigned_webhooks:
            self._log(
                "warn",
                "Webhook rejected: missing nonce (replay protection is mandatory) — "
                "set allow_legacy_unsigned_webhooks=True to permit legacy senders",
            )
            return False

        identity = payload.get("identity") or {}
        threat_event = ThreatEvent(
            event_id=payload.get("event_id", ""),
            threat_type=payload.get("threat_type", ""),
            severity=payload.get("severity", "low"),
            confidence=payload.get("confidence", 0.0),
            composite_score=payload.get("composite_score", 0.0),
            ip=payload.get("ip", "0.0.0.0"),
            identity={"user_id": identity.get("user_id"), "session_id": identity.get("session_id")},
            geo=payload.get("geo"),
            abuseipdb=payload.get("abuseipdb"),
            endpoint=payload.get("endpoint", ""),
            method=payload.get("method", ""),
            timestamp=payload.get("timestamp", ""),
            meta=payload.get("meta") or {},
        )

        if self._can_block():
            if threat_event.severity in ("critical", "high"):
                self._cache.set(f"blocked:ip:{threat_event.ip}", "1", self._cache_ttl_seconds)
                user_id = threat_event.identity.get("user_id")
                if user_id:
                    self._cache.set(f"blocked:user:{user_id}", "1", self._cache_ttl_seconds)

        self.audit_trail.record(
            AuditRecord(
                event_id=threat_event.event_id,
                timestamp=time.time() * 1000,
                source="external",
                tier=0,
                decision="webhook_response",
                score=threat_event.composite_score,
                severity=threat_event.severity,
                latency_ms=0,
                ip=threat_event.ip,
                path=threat_event.endpoint,
                method=threat_event.method,
                matched_rules=[threat_event.threat_type],
                user_id=threat_event.identity.get("user_id"),
                session_id=threat_event.identity.get("session_id"),
            )
        )

        specific_handlers = self._handlers.get(threat_event.severity, [])
        wildcard_handlers = self._handlers.get("*", [])
        for handler in [*specific_handlers, *wildcard_handlers]:
            try:
                result = handler(threat_event)
                if result is not None:
                    await result
            except Exception as error:
                self._log("error", f"Threat handler error: {error}")

        self._log(
            "info",
            f"Webhook processed: {threat_event.event_id} [{threat_event.severity}] {threat_event.threat_type}",
        )
        return True

    # ── Outbound: platform -> customer's own webhook ────────

    def _check_webhook_rate_limit(self, endpoint_url: str) -> bool:
        now = time.time() * 1000
        bucket = self._webhook_delivery_counts.get(endpoint_url)

        if not bucket or now - bucket["windowStart"] >= WEBHOOK_RATE_WINDOW_MS:
            self._webhook_delivery_counts[endpoint_url] = {"count": 1, "windowStart": now}
            return True

        if bucket["count"] >= WEBHOOK_RATE_LIMIT:
            return False

        bucket["count"] += 1
        return True

    def _sign_outbound(self, timestamp: str, body: str) -> str:
        return hmac.new(
            self._webhook_secret.encode("utf-8"), f"{timestamp}.{body}".encode("utf-8"), hashlib.sha256
        ).hexdigest()

    async def deliver_session_revocation(
        self, *, session_id: str, reason: str, user_id: Optional[str] = None, ip: Optional[str] = None
    ) -> Dict[str, Any]:
        if not self._response_webhook_url or not self._webhook_secret:
            self._log("warn", "deliver_session_revocation: no webhook configured")
            return {"delivered": False, "ackMs": 0}

        if not self._check_webhook_rate_limit(self._response_webhook_url):
            self._log("warn", f"deliver_session_revocation: rate limited (max {WEBHOOK_RATE_LIMIT}/min)")
            return {"delivered": False, "ackMs": 0}

        timestamp = _iso_now()
        body = json.dumps(
            {
                "type": "session_revocation",
                "session_id": session_id,
                "user_id": user_id,
                "reason": reason,
                "ip": ip,
                "issued_at": timestamp,
            }
        )
        signature = self._sign_outbound(timestamp, body)

        start_ms = time.time() * 1000
        try:
            await asyncio.to_thread(
                requests.post,
                self._response_webhook_url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-DevFortress-Signature": signature,
                    "X-DevFortress-Timestamp": timestamp,
                },
                timeout=2.0,
            )
            ack_ms = time.time() * 1000 - start_ms
            self._log("info", f"Session revocation delivered in {ack_ms:.0f}ms (session={session_id})")

            self.audit_trail.record(
                AuditRecord(
                    event_id=f"wr_{_base36(int(time.time() * 1000))}",
                    timestamp=time.time() * 1000,
                    source="external",
                    tier=0,
                    decision="block",
                    score=0,
                    severity="high",
                    latency_ms=ack_ms,
                    ip=ip or "0.0.0.0",
                    path="/webhook/session-revocation",
                    method="POST",
                    matched_rules=["session_revocation_webhook"],
                    session_id=session_id,
                    meta={
                        "webhookAction": "session_revocation_delivered",
                        "detail": f"Revocation webhook for session {session_id} acked in {ack_ms:.0f}ms",
                    },
                )
            )
            return {"delivered": True, "ackMs": ack_ms}
        except Exception as error:
            ack_ms = time.time() * 1000 - start_ms
            self._log("error", f"Session revocation webhook failed: {error} ({ack_ms:.0f}ms)")
            return {"delivered": False, "ackMs": ack_ms}

    async def deliver_ip_block(
        self, *, ip: str, reason: str, ttl_seconds: int = 3600, severity: ThreatSeverity = "high"
    ) -> Dict[str, Any]:
        if not self._response_webhook_url or not self._webhook_secret:
            self._log("warn", "deliver_ip_block: no webhook configured")
            return {"delivered": False, "ackMs": 0}

        if not self._check_webhook_rate_limit(self._response_webhook_url):
            self._log("warn", f"deliver_ip_block: rate limited (max {WEBHOOK_RATE_LIMIT}/min)")
            return {"delivered": False, "ackMs": 0}

        timestamp = _iso_now()
        body = json.dumps(
            {
                "type": "ip_block",
                "ip": ip,
                "reason": reason,
                "ttl_seconds": ttl_seconds,
                "severity": severity,
                "issued_at": timestamp,
            }
        )
        signature = self._sign_outbound(timestamp, body)

        start_ms = time.time() * 1000
        try:
            await asyncio.to_thread(
                requests.post,
                self._response_webhook_url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-DevFortress-Signature": signature,
                    "X-DevFortress-Timestamp": timestamp,
                },
                timeout=5.0,
            )
            ack_ms = time.time() * 1000 - start_ms
            self._log("info", f"IP block webhook delivered in {ack_ms:.0f}ms (ip={ip})")

            self.audit_trail.record(
                AuditRecord(
                    event_id=f"wb_{_base36(int(time.time() * 1000))}",
                    timestamp=time.time() * 1000,
                    source="external",
                    tier=0,
                    decision="block",
                    score=0,
                    severity=severity,
                    latency_ms=ack_ms,
                    ip=ip,
                    path="/webhook/ip-block",
                    method="POST",
                    matched_rules=["ip_block_webhook"],
                    meta={
                        "webhookAction": "ip_block_delivered",
                        "detail": f"Block webhook for {ip} acked in {ack_ms:.0f}ms",
                    },
                )
            )
            return {"delivered": True, "ackMs": ack_ms}
        except Exception as error:
            ack_ms = time.time() * 1000 - start_ms
            self._log("error", f"IP block webhook failed: {error} ({ack_ms:.0f}ms)")
            return {"delivered": False, "ackMs": ack_ms}


def _iso_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _base36(n: int) -> str:
    if n == 0:
        return "0"
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = []
    while n:
        n, rem = divmod(n, 36)
        out.append(digits[rem])
    return "".join(reversed(out))
