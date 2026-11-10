import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest

from devfortress.closed_loop import ClosedLoopEngine

SECRET = "shhh"


def _sign(timestamp: str, body: str) -> str:
    return hmac.new(SECRET.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _payload(**overrides) -> dict:
    base = {
        "event_id": "evt_1",
        "threat_type": "credential_leak",
        "severity": "critical",
        "confidence": 0.9,
        "composite_score": 90,
        "ip": "203.0.113.5",
        "identity": {"user_id": "u1", "session_id": "s1"},
        "endpoint": "/api/x",
        "method": "GET",
        "timestamp": _now_iso(),
        "meta": {},
        "nonce": "a" * 32,
    }
    base.update(overrides)
    return base


async def test_handle_webhook_blocks_ip_and_user_on_critical():
    engine = ClosedLoopEngine(webhook_secret=SECRET)
    ts = _now_iso()
    body = json.dumps(_payload())
    sig = _sign(ts, body)

    accepted = await engine.handle_webhook(body, sig, ts)
    assert accepted is True
    assert engine.is_blocked_ip("203.0.113.5") is True
    assert engine.is_blocked_user("u1") is True


async def test_handle_webhook_rejects_bad_signature():
    engine = ClosedLoopEngine(webhook_secret=SECRET)
    ts = _now_iso()
    body = json.dumps(_payload())
    accepted = await engine.handle_webhook(body, "0" * 64, ts)
    assert accepted is False


async def test_handle_webhook_rejects_missing_nonce_without_legacy_flag():
    engine = ClosedLoopEngine(webhook_secret=SECRET, allow_legacy_unsigned_webhooks=False)
    payload = _payload()
    del payload["nonce"]
    ts = _now_iso()
    body = json.dumps(payload)
    sig = _sign(ts, body)
    accepted = await engine.handle_webhook(body, sig, ts)
    assert accepted is False


async def test_handle_webhook_allows_missing_nonce_with_legacy_flag():
    engine = ClosedLoopEngine(webhook_secret=SECRET, allow_legacy_unsigned_webhooks=True)
    payload = _payload()
    del payload["nonce"]
    ts = _now_iso()
    body = json.dumps(payload)
    sig = _sign(ts, body)
    accepted = await engine.handle_webhook(body, sig, ts)
    assert accepted is True


async def test_severity_specific_and_wildcard_handlers_both_fire():
    engine = ClosedLoopEngine(webhook_secret=SECRET)
    seen = []
    engine.on_threat_detected("critical", lambda ev: seen.append(("critical", ev.event_id)))
    engine.on_threat_detected("*", lambda ev: seen.append(("wildcard", ev.event_id)))

    ts = _now_iso()
    body = json.dumps(_payload())
    sig = _sign(ts, body)
    await engine.handle_webhook(body, sig, ts)

    assert ("critical", "evt_1") in seen
    assert ("wildcard", "evt_1") in seen


async def test_no_secret_configured_rejects():
    engine = ClosedLoopEngine()
    ts = _now_iso()
    body = json.dumps(_payload())
    accepted = await engine.handle_webhook(body, "irrelevant", ts)
    assert accepted is False


async def test_deliver_ip_block_without_config_returns_not_delivered():
    engine = ClosedLoopEngine(webhook_secret=SECRET)  # no response_webhook_url
    result = await engine.deliver_ip_block(ip="1.2.3.4", reason="test")
    assert result["delivered"] is False
