"""Request signing (contract v2): shared vectors plus wire-level checks."""

from devfortress import DevFortressClient, derive_key_id, sign_request, verify_request_signature
from devfortress.signing import (
    KEY_ID_HEADER,
    NONCE_HEADER,
    PAYLOAD_HASH_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    VERSION_HEADER,
)

KEY = "vx_live_test_vector_key_do_not_use"
EVENT = {"eventType": "custom", "ip": "203.0.113.5", "method": "GET", "path": "/x", "severity": "LOW"}


def _wire(h):
    return {
        NONCE_HEADER: h["nonce"],
        TIMESTAMP_HEADER: h["timestamp"],
        PAYLOAD_HASH_HEADER: h["payload_hash"],
        SIGNATURE_HEADER: h["signature"],
        VERSION_HEADER: h.get("version"),
    }


def test_vectors_verify(ingest_vectors):
    assert len(ingest_vectors) >= 20
    for v in ingest_vectors:
        got = verify_request_signature(
            v["verify_key"],
            v["method"],
            v["request_target"],
            v["body"].encode("utf-8"),
            _wire(v["headers"]),
            now_ms=v["now_ms"],
        )
        assert got == v["expected"], v["name"]


def test_signing_matches_vectors_byte_for_byte(ingest_vectors):
    signing = [v for v in ingest_vectors if "sign_input" in v and v["expected"] in ("valid", "expired")]
    assert len(signing) >= 8
    for v in signing:
        i = v["sign_input"]
        h = sign_request(
            i["api_key"], i["method"], i["request_target"], i["body"].encode("utf-8"),
            i["timestamp"], i["nonce"],
        )
        want = {k: (val.lower() if k in (PAYLOAD_HASH_HEADER, SIGNATURE_HEADER) else val)
                for k, val in _wire(v["headers"]).items()}
        assert {k: h[k] for k in want} == want, v["name"]


def test_negative_vectors_do_not_match_what_the_signer_produces(ingest_vectors):
    # A signature made for one request must not equal the signature of the
    # request the server actually received (different path, method or query).
    names = {"different_path", "different_path_same_query", "different_method",
             "changed_query", "query_added", "prefix_stripped", "tampered_body", "wrong_key"}
    seen = 0
    for v in ingest_vectors:
        if v["name"] not in names:
            continue
        seen += 1
        h = sign_request(
            v["verify_key"], v["method"], v["request_target"], v["body"].encode("utf-8"),
            v["headers"]["timestamp"], v["headers"]["nonce"],
        )
        assert h[SIGNATURE_HEADER] != v["headers"]["signature"], v["name"]
    assert seen == len(names)


def _verify_request(req, now_ms=None):
    hdrs = {
        k: req["headers"].get(k)
        for k in (NONCE_HEADER, TIMESTAMP_HEADER, PAYLOAD_HASH_HEADER, SIGNATURE_HEADER, VERSION_HEADER)
    }
    return verify_request_signature(KEY, req["method"], req["path"], req["raw"], hdrs, now_ms=now_ms)


def test_track_event_is_signed(stub_server):
    s = stub_server([(200, {"success": True})])
    DevFortressClient(KEY, endpoint=s.url).track_event(EVENT)
    assert _verify_request(s.requests[0]) == "valid"
    assert s.requests[0]["headers"][VERSION_HEADER] == "2"


def test_signature_covers_the_request_target_as_sent(stub_server):
    # Query string and path prefix are signed exactly as they go on the wire.
    s = stub_server([(200, {"success": True})])
    DevFortressClient(KEY, endpoint=s.url.replace("/api/events/ingest", "/gateway/api/events/ingest?v=1&x=a%20b")).track_event(EVENT)
    r = s.requests[0]
    assert r["path"] == "/gateway/api/events/ingest?v=1&x=a%20b"
    assert _verify_request(r) == "valid"


def test_track_events_and_flush_are_signed(stub_server):
    s = stub_server([(200, {"success": True})])
    c = DevFortressClient(KEY, endpoint=s.url)
    c.track_events([EVENT, EVENT])
    c.queue_event(EVENT)
    c.flush()
    assert len(s.requests) == 2
    assert all(_verify_request(r) == "valid" for r in s.requests)


def test_retry_gets_fresh_nonce_and_valid_signature(stub_server):
    s = stub_server([(503, {"error": "x"}), (200, {"success": True})])
    DevFortressClient(KEY, endpoint=s.url, retries=2, backoff_base=0.01).track_event(EVENT)
    assert len(s.requests) == 2
    nonces = {r["headers"][NONCE_HEADER] for r in s.requests}
    assert len(nonces) == 2
    assert all(_verify_request(r) == "valid" for r in s.requests)


def test_key_id_derivation_matches_vectors(ingest_vector_file):
    vs = ingest_vector_file["key_id_derivation"]["vectors"]
    assert len(vs) >= 3
    for v in vs:
        assert derive_key_id(v["api_key"]) == v["key_id"]


def test_signed_path_vector_headers_match(ingest_vector_file):
    signed = [x for x in ingest_vector_file["signed_path_vectors"] if "sign_input" in x]
    assert len(signed) >= 4
    for v in signed:
        i = v["sign_input"]
        h = sign_request(
            i["api_key"], i["method"], i["request_target"], i["body"].encode("utf-8"),
            i["timestamp"], i["nonce"],
        )
        assert h[KEY_ID_HEADER] == v["headers"]["key_id"], v["name"]
        assert h[SIGNATURE_HEADER] == v["headers"]["signature"], v["name"]


def _carries_key(req, key):
    k = key.encode("utf-8")
    return (
        any(k in str(val).encode("utf-8") for val in req["headers"].values())
        or k in req["raw"]
        or k in req["path"].encode("utf-8")
    )


def test_key_never_on_the_wire(stub_server):
    s = stub_server([(200, {"success": True})])
    c = DevFortressClient(KEY, endpoint=s.url)
    c.track_event(EVENT)
    c.track_events([EVENT, EVENT])
    c.queue_event(EVENT)
    c.flush()
    assert len(s.requests) == 3
    for r in s.requests:
        assert not _carries_key(r, KEY)
        assert "X-DevFortress-Key" not in r["headers"]
        assert r["headers"][KEY_ID_HEADER] == derive_key_id(KEY)


def test_retry_never_sends_the_key(stub_server):
    s = stub_server([(503, {"error": "x"}), (200, {"success": True})])
    DevFortressClient(KEY, endpoint=s.url, retries=2, backoff_base=0.01).track_event(EVENT)
    assert len(s.requests) == 2
    assert not any(_carries_key(r, KEY) for r in s.requests)
