"""Inbound webhook signature verification.

Contract (platform dispatcher, POST /api/webhooks/deliver):

* ``X-DevFortress-Timestamp``: ISO-8601 UTC timestamp of dispatch.
* ``X-DevFortress-Signature``: hex HMAC-SHA256, keyed with the project's
  webhook secret, over the UTF-8 bytes of ``"{timestamp}.{raw_body}"``.
* Timestamps older than 300 seconds are rejected.
* The body carries a 32-char lowercase-hex ``nonce``. Replay tracking is
  left to the caller through ``nonce_check`` so the library keeps no state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, Union

TOLERANCE_SECONDS = 300
SIGNATURE_HEADER = "X-DevFortress-Signature"
TIMESTAMP_HEADER = "X-DevFortress-Timestamp"

_SIG_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$"
)


@dataclass(frozen=True)
class WebhookVerification:
    valid: bool
    reason: Optional[str] = None

    def __bool__(self) -> bool:
        return self.valid


def _parse_iso(value: str) -> Optional[datetime]:
    m = _ISO_RE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, sec, frac, tz = m.groups()
    micro = int((frac or "0")[:3].ljust(3, "0")) * 1000  # millisecond precision
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), micro, tzinfo=timezone.utc)
    except ValueError:
        return None
    if tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        dt -= sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6]))
    return dt


def _to_datetime(now: Union[None, float, datetime, str]) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime):
        return now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    if isinstance(now, str):
        parsed = _parse_iso(now)
        if parsed is None:
            raise ValueError("now must be an ISO-8601 timestamp")
        return parsed
    return datetime.fromtimestamp(now, tz=timezone.utc)


def verify_webhook_signature(
    raw_body: Union[str, bytes],
    signature: str,
    timestamp: str,
    secret: str,
    *,
    tolerance_seconds: int = TOLERANCE_SECONDS,
    now: Union[None, float, datetime, str] = None,
    nonce_check: Optional[Callable[[str], bool]] = None,
) -> WebhookVerification:
    """Verify a DevFortress webhook. Pass the body exactly as received.

    ``nonce_check(nonce)`` should return True the first time a nonce is seen
    and False on replay; when supplied, a missing or malformed nonce fails.
    """
    ts = _parse_iso(timestamp or "")
    if ts is None:
        return WebhookVerification(False, "invalid_timestamp")
    age_ms = (_to_datetime(now) - ts) // timedelta(milliseconds=1)
    if age_ms > tolerance_seconds * 1000:
        return WebhookVerification(False, "timestamp_expired")

    if not isinstance(signature, str) or not _SIG_RE.match(signature):
        return WebhookVerification(False, "invalid_signature")

    body_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
    message = timestamp.encode("utf-8") + b"." + body_bytes
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, bytes.fromhex(signature)):
        return WebhookVerification(False, "signature_mismatch")

    if nonce_check is not None:
        try:
            nonce = json.loads(body_bytes).get("nonce")
        except (ValueError, AttributeError):
            return WebhookVerification(False, "invalid_body")
        if not isinstance(nonce, str) or not _NONCE_RE.match(nonce):
            return WebhookVerification(False, "nonce_invalid")
        if not nonce_check(nonce):
            return WebhookVerification(False, "replay_detected")

    return WebhookVerification(True)
