"""Request integrity headers for every SDK-to-platform call (contract v2).

Canonical string: ``"{METHOD}.{request_target}.{timestamp}.{nonce}.{payload_hash}"``
where ``METHOD`` is the uppercase HTTP method, ``request_target`` is the URL
path plus ``?query`` exactly as sent (no host, no re-encoding), and
``payload_hash`` is the lowercase hex SHA-256 of the exact body bytes (the empty
string for a request with no body). The signature is the lowercase hex
HMAC-SHA256 of that string, keyed with the project API key (UTF-8). Timestamp
is Unix epoch milliseconds; nonce is a dashed UUID v4, fresh for every request
attempt. Tolerance is 300 seconds.
Shared vectors: contracts/ingest-signature-vectors.json.

The API key never travels on a signed request. ``X-DevFortress-Key-Id`` is a
non-secret identifier derived from the key (first 32 hex characters of its
SHA-256); the platform verifies the HMAC with the key it has stored.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Dict, Optional

SIGNATURE_VERSION = "2"
TOLERANCE_SECONDS = 300
KEY_ID_HEADER = "X-DevFortress-Key-Id"
VERSION_HEADER = "X-DevFortress-Signature-Version"
NONCE_HEADER = "X-DevFortress-Nonce"
TIMESTAMP_HEADER = "X-DevFortress-Timestamp"
PAYLOAD_HASH_HEADER = "X-DevFortress-Payload-Hash"
SIGNATURE_HEADER = "X-DevFortress-Signature"


def derive_key_id(api_key: str) -> str:
    """Non-secret key ID: first 32 hex characters of SHA-256 over the UTF-8 key."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:32]


def _digest(
    api_key: str, method: str, request_target: str, timestamp: str, nonce: str, body: bytes
) -> Dict[str, str]:
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}.{request_target}.{timestamp}.{nonce}.{payload_hash}"
    signature = hmac.new(
        api_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return {"payload_hash": payload_hash, "signature": signature}


def sign_request(
    api_key: str,
    method: str,
    request_target: str,
    body: bytes,
    timestamp: Optional[str] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """Return the six signing headers (key ID, version, nonce, timestamp, hash, signature)."""
    ts = timestamp if timestamp is not None else str(int(time.time() * 1000))
    n = nonce if nonce is not None else str(uuid.uuid4())
    d = _digest(api_key, method, request_target, ts, n, body)
    return {
        KEY_ID_HEADER: derive_key_id(api_key),
        VERSION_HEADER: SIGNATURE_VERSION,
        NONCE_HEADER: n,
        TIMESTAMP_HEADER: ts,
        PAYLOAD_HASH_HEADER: d["payload_hash"],
        SIGNATURE_HEADER: d["signature"],
    }


def verify_request_signature(
    api_key: str,
    method: str,
    request_target: str,
    body: bytes,
    headers: Dict[str, Optional[str]],
    now_ms: Optional[int] = None,
) -> str:
    """Return ``valid``, ``invalid``, ``expired``, ``missing`` or ``unsupported_version``.

    ``headers`` uses the wire header names. Mirrors the platform's check.
    """
    nonce = headers.get(NONCE_HEADER)
    ts = headers.get(TIMESTAMP_HEADER)
    ph = headers.get(PAYLOAD_HASH_HEADER)
    sig = headers.get(SIGNATURE_HEADER)
    if not (nonce and ts and ph and sig):
        return "missing"
    if headers.get(VERSION_HEADER) != SIGNATURE_VERSION:
        return "unsupported_version"
    expected = _digest(api_key, method, request_target, ts, nonce, body)
    if not (
        hmac.compare_digest(ph.lower().encode(), expected["payload_hash"].encode())
        and hmac.compare_digest(sig.lower().encode(), expected["signature"].encode())
    ):
        return "invalid"
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    try:
        age = abs(now - int(ts))
    except ValueError:
        return "invalid"
    return "expired" if age > TOLERANCE_SECONDS * 1000 else "valid"
