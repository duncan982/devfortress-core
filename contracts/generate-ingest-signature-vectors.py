#!/usr/bin/env python3
"""Generate contracts/ingest-signature-vectors.json (signature contract v2).

Independent of both SDKs and the platform: plain hashlib/hmac only. Keys below
are obviously fake test keys. Run from anywhere:

    python3 contracts/generate-ingest-signature-vectors.py
"""
import hashlib
import hmac
import json
from pathlib import Path

KEY = "vx_live_test_vector_key_do_not_use"
KEY_OTHER = "vx_live_other_project_vector_key_do_not_use"
KEY_THIRD = "vx_live_test_vector_third_key_do_not_use"
UNKNOWN_KEY = "vx_live_unregistered_vector_key_do_not_use"
NOW = 1768478400000
FRESH = str(NOW - 30_000)

INGEST = "/api/events/ingest"
BLOCKED_Q = "/api/events/blocked?ip=203.0.113.7&userId=u_1"

EVENT = (
    '{"eventType":"custom","ip":"203.0.113.7","method":"GET","path":"/api/items",'
    '"severity":"LOW","clMode":"external","authPhase":"pre_auth",'
    '"actionTaken":"monitored","responseLatencyMs":12,'
    '"timestamp":"2026-01-15T11:59:58.000Z"}'
)
BATCH = '{"events":[' + EVENT + "," + EVENT.replace("203.0.113.7", "203.0.113.8") + "]}"
UNICODE = '{"eventType":"custom","ip":"203.0.113.7","path":"/api/café/日本","note":"üñï"}'


def key_id(k):
    return hashlib.sha256(k.encode()).hexdigest()[:32]


def sign(k, method, target, ts, nonce, body):
    ph = hashlib.sha256(body.encode()).hexdigest()
    canonical = f"{method.upper()}.{target}.{ts}.{nonce}.{ph}"
    sig = hmac.new(k.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return ph, sig


def nonce(n):
    return f"7c1d5e20-4b3a-4f60-9e01-2a8b6c4d{n:04x}"


def headers(k, method, target, ts, n, body, version="2", with_key_id=False):
    ph, sig = sign(k, method, target, ts, n, body)
    h = {"nonce": n, "timestamp": ts, "payload_hash": ph, "signature": sig,
         "version": version}
    if with_key_id:
        h["key_id"] = key_id(k)
    return h


def sign_input(k, method, target, ts, n, body):
    return {"api_key": k, "method": method, "request_target": target,
            "timestamp": ts, "nonce": n, "body": body}


# ── verifier-level vectors ────────────────────────────────────────────────
vectors = []


def vec(name, desc, expected, *, key=KEY, method="POST", target=INGEST, body=EVENT,
        signed=None, ts=FRESH, n=None, now=NOW, mutate=None, drop=(), version="2"):
    """signed = (method, target, body) the signature was computed over."""
    n = n or nonce(len(vectors) + 1)
    sm, st, sb = signed or (method, target, body)
    h = headers(key, sm, st, ts, n, sb, version)
    if mutate:
        h.update(mutate)
    for d in drop:
        h[d] = None
    vectors.append({
        "name": name, "description": desc, "verify_key": KEY,
        "method": method, "request_target": target, "body": body,
        "headers": h, "now_ms": now, "expected": expected,
        # Vectors whose signature/hash headers were deliberately altered or
        # removed have no signing output to compare against.
        **({} if ("signature" in drop or (mutate and "payload_hash" in mutate))
           else {"sign_input": sign_input(key, sm, st, ts, n, sb)}),
    })


vec("valid_post_ingest", "POST ingest, fresh timestamp, correct signature", "valid")
vec("valid_batch", "POST ingest with a batch body", "valid", body=BATCH)
vec("valid_unicode_body", "Non-ASCII body: hash covers the UTF-8 bytes", "valid", body=UNICODE)
vec("valid_get_empty_body", "GET with an empty body: the hash is SHA-256 of the empty string",
    "valid", method="GET", target="/api/events/verify-connection", body="")
vec("valid_get_query", "GET with a query string: the target is signed exactly as sent",
    "valid", method="GET", target=BLOCKED_Q, body="")
vec("valid_post_prefixed_path", "POST under a path prefix: the prefix is part of the signed target",
    "valid", target="/gateway/api/sdk/heartbeat", body='{"timestamp":1768478370000}')
vec("valid_post_query_on_post", "POST with a query string", "valid",
    target="/api/sdk/license-check?v=1", body='{"sdkVersion":"4.11.0"}')
h = headers(KEY, "POST", INGEST, FRESH, nonce(90), EVENT)
vectors.append({
    "name": "uppercase_hex_accepted", "description": "Hex is compared case-insensitively",
    "verify_key": KEY, "method": "POST", "request_target": INGEST, "body": EVENT,
    "headers": {**h, "payload_hash": h["payload_hash"].upper(), "signature": h["signature"].upper()},
    "now_ms": NOW, "expected": "valid",
    "sign_input": sign_input(KEY, "POST", INGEST, FRESH, nonce(90), EVENT),
})
# negatives: same signature, different request
vec("different_path", "Signature made for /api/events/blocked?... presented on another path",
    "invalid", method="GET", target="/api/events/test-ips?ip=203.0.113.7&userId=u_1", body="",
    signed=("GET", BLOCKED_Q, ""))
vec("different_path_same_query", "Signature for one empty-body endpoint replayed on another",
    "invalid", method="GET", target="/api/events/verify-connection?ip=203.0.113.7&userId=u_1",
    body="", signed=("GET", BLOCKED_Q, ""))
vec("different_method", "Signature made for GET presented on POST", "invalid",
    method="POST", target=BLOCKED_Q, body="", signed=("GET", BLOCKED_Q, ""))
vec("changed_query", "Query string altered after signing", "invalid",
    method="GET", target="/api/events/blocked?ip=203.0.113.99&userId=u_1", body="",
    signed=("GET", BLOCKED_Q, ""))
vec("query_added", "Query string appended to a request signed without one", "invalid",
    method="GET", target="/api/events/verify-connection?x=1", body="",
    signed=("GET", "/api/events/verify-connection", ""))
vec("prefix_stripped", "Signed under a prefix, received without it", "invalid",
    target="/api/sdk/heartbeat", body='{"timestamp":1768478370000}',
    signed=("POST", "/gateway/api/sdk/heartbeat", '{"timestamp":1768478370000}'))
vec("tampered_body", "Body changed after signing", "invalid",
    body=EVENT.replace("LOW", "HIGH"), signed=("POST", INGEST, EVENT))
n = nonce(60)
h = headers(KEY, "POST", INGEST, FRESH, n, EVENT)
vectors.append({
    "name": "tampered_nonce", "description": "Nonce changed after signing", "verify_key": KEY,
    "method": "POST", "request_target": INGEST, "body": EVENT,
    "headers": {**h, "nonce": nonce(61)}, "now_ms": NOW, "expected": "invalid",
    "sign_input": sign_input(KEY, "POST", INGEST, FRESH, n, EVENT),
})
h = headers(KEY, "POST", INGEST, FRESH, nonce(62), EVENT)
vectors.append({
    "name": "tampered_timestamp", "description": "Timestamp changed after signing",
    "verify_key": KEY, "method": "POST", "request_target": INGEST, "body": EVENT,
    "headers": {**h, "timestamp": str(int(FRESH) + 1000)}, "now_ms": NOW, "expected": "invalid",
    "sign_input": sign_input(KEY, "POST", INGEST, FRESH, nonce(62), EVENT),
})
vec("wrong_key", "Signed with a different key than the verifier holds", "invalid", key=KEY_OTHER)
vec("payload_hash_mismatch", "Hash header does not match the body", "invalid",
    mutate={"payload_hash": "0" * 64})
vec("stale_timestamp", "Correct signature, timestamp 10 minutes old", "expired",
    ts=str(NOW - 600_000))
vec("future_timestamp", "Correct signature, timestamp 10 minutes ahead", "expired",
    ts=str(NOW + 600_000))
vec("missing_signature", "Signature header absent", "missing", drop=("signature",))
vec("missing_nonce", "Nonce header absent", "missing", drop=("nonce",))
vec("missing_version", "Signature version header absent", "unsupported_version",
    drop=("version",))
vec("version_1", "Version 1 is not accepted", "unsupported_version", version="1")
vec("version_3", "Unknown future version", "unsupported_version", version="3")

# ── server-level (signed path) vectors ────────────────────────────────────
KNOWN = [KEY, KEY_OTHER]
signed_vectors = []


def sv(name, desc, expected, *, key=KEY, method="POST", target=INGEST, body=EVENT,
       signed=None, ts=FRESH, n=None, mutate=None, drop=(), version="2",
       api_key_header=None, use_key_id=None):
    n = n or nonce(0x100 + len(signed_vectors))
    sm, st, sb = signed or (method, target, body)
    h = headers(key, sm, st, ts, n, sb, version, with_key_id=True)
    if use_key_id is not None:
        h["key_id"] = use_key_id
    if mutate:
        h.update(mutate)
    for d in drop:
        h[d] = None
    signed_vectors.append({
        "name": name, "description": desc, "known_keys": KNOWN,
        "api_key_header": api_key_header, "method": method, "request_target": target,
        "body": body, "headers": h, "now_ms": NOW, "expected": expected,
        **({"sign_input": sign_input(key, sm, st, ts, n, sb)}
           if expected["accepted"] else {}),
    })


ok = {"accepted": True, "status": 200, "reason": None}


def bad(status, reason):
    return {"accepted": False, "status": status, "reason": reason}


sv("signed_valid", "POST ingest, key ID only, correct signature", ok)
sv("signed_valid_get_empty", "Empty-body GET, key ID only", ok, method="GET",
   target="/api/events/verify-connection", body="")
sv("signed_valid_get_query", "GET with a query string", ok, method="GET",
   target=BLOCKED_Q, body="")
sv("signed_valid_prefixed", "POST under a path prefix", ok,
   target="/gateway/api/sdk/heartbeat", body='{"timestamp":1768478370000}')
sv("signed_different_path", "Signature for one endpoint presented on another",
   bad(401, "signature_invalid"), method="GET",
   target="/api/events/test-ips?ip=203.0.113.7&userId=u_1", body="",
   signed=("GET", BLOCKED_Q, ""))
sv("signed_different_method", "Signature made for GET presented on POST",
   bad(401, "signature_invalid"), method="POST", target=BLOCKED_Q, body="",
   signed=("GET", BLOCKED_Q, ""))
sv("signed_changed_query", "Query string altered after signing",
   bad(401, "signature_invalid"), method="GET",
   target="/api/events/blocked?ip=203.0.113.99&userId=u_1", body="",
   signed=("GET", BLOCKED_Q, ""))
sv("signed_missing_version", "All signature headers but no version",
   bad(401, "signature_version_unsupported"), drop=("version",))
sv("signed_version_1", "Version 1 is not accepted",
   bad(401, "signature_version_unsupported"), version="1")
sv("signed_key_id_no_signature", "Key ID with no signature headers",
   bad(401, "signature_missing"), drop=("nonce", "timestamp", "payload_hash", "signature", "version"))
sv("signed_bad_signature", "Signature does not match", bad(401, "signature_invalid"),
   mutate={"signature": "0" * 64})
sv("signed_tampered_body", "Body changed after signing", bad(401, "signature_invalid"),
   body=EVENT.replace("LOW", "HIGH"), signed=("POST", INGEST, EVENT))
n = nonce(0x200)
h = headers(KEY, "POST", INGEST, FRESH, n, EVENT, "2", with_key_id=True)
signed_vectors.append({
    "name": "signed_tampered_nonce", "description": "Nonce changed after signing",
    "known_keys": KNOWN, "api_key_header": None, "method": "POST", "request_target": INGEST,
    "body": EVENT, "headers": {**h, "nonce": nonce(0x201)}, "now_ms": NOW,
    "expected": bad(401, "signature_invalid"),
})
sv("signed_wrong_key", "Key ID of one project, signature made with another key",
   bad(401, "signature_invalid"), key=KEY_OTHER, use_key_id=key_id(KEY))
sv("signed_unknown_key_id", "Key ID that no project has, well-formed signature",
   bad(401, "signature_invalid"), key=UNKNOWN_KEY)
sv("signed_unknown_key_id_no_signature", "Unknown key ID and no signature headers",
   bad(401, "signature_missing"), key=UNKNOWN_KEY,
   drop=("nonce", "timestamp", "payload_hash", "signature", "version"))
sv("signed_stale_timestamp", "Correct signature, timestamp 10 minutes old",
   bad(400, "timestamp_expired"), ts=str(NOW - 600_000))
sv("ambiguous_credentials", "Key ID together with an API key header",
   bad(400, "ambiguous_credentials"), api_key_header=KEY)

# ── legacy path ───────────────────────────────────────────────────────────
legacy = [{
    "name": "legacy_unsigned", "description": "API key header only, no signature",
    "api_key_header": KEY, "known_keys": KNOWN, "method": "POST",
    "request_target": INGEST, "body": EVENT,
    "headers": {"key_id": None, "nonce": None, "timestamp": None,
                "payload_hash": None, "signature": None, "version": None},
    "now_ms": NOW,
    "expected_flag_off": ok,
    "expected_flag_on": bad(401, "signature_missing"),
}]

out = {
    "contract": "DevFortress SDK request signature, contract v2 (every SDK-to-platform call)",
    "signature_version": "2",
    "algorithm": "HMAC-SHA256 (lowercase hex) keyed with the project API key (UTF-8), over the UTF-8 canonical string; payload_hash is the lowercase hex SHA-256 of the exact request body bytes (empty body hashes the empty string)",
    "canonical_string": "{METHOD}.{request_target}.{timestamp}.{nonce}.{payload_hash}",
    "method": "uppercase HTTP method",
    "request_target": "URL path plus '?' plus query string exactly as sent: no host, no re-encoding, no normalisation",
    "headers": {
        "key_id": "X-DevFortress-Key-Id",
        "version": "X-DevFortress-Signature-Version",
        "nonce": "X-DevFortress-Nonce",
        "timestamp": "X-DevFortress-Timestamp",
        "payload_hash": "X-DevFortress-Payload-Hash",
        "signature": "X-DevFortress-Signature",
    },
    "timestamp_format": "Unix epoch milliseconds as a decimal string",
    "nonce_format": "dashed UUID v4, at most 128 characters, unique per request attempt",
    "tolerance_seconds": 300,
    "expected_values": {
        "valid": "signature and payload hash match",
        "invalid": "headers present but signature or payload hash does not match",
        "expired": "headers present and correct but timestamp outside tolerance",
        "missing": "one or more of nonce, timestamp, payload hash, signature absent",
        "unsupported_version": "version header absent or not 2",
    },
    "generated_by": "independent Python hmac/hashlib script (contracts/generate-ingest-signature-vectors.py), not by either SDK",
    "vectors": vectors,
    "key_id_derivation": {
        "algorithm": "first 32 lowercase hex characters of SHA-256 over the UTF-8 API key",
        "vectors": [{"api_key": k, "key_id": key_id(k)} for k in (KEY, KEY_OTHER, KEY_THIRD)],
    },
    "signed_path_vectors": signed_vectors,
    "legacy_path_vectors": legacy,
}

Path(__file__).with_name("ingest-signature-vectors.json").write_text(
    json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)
print(f"{len(vectors)} verifier, {len(signed_vectors)} signed-path, {len(legacy)} legacy")
