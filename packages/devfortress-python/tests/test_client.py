import time

import pytest

from devfortress import DevFortressClient, DevFortressError, derive_key_id

EVENT = {"eventType": "auth_failure", "ip": "203.0.113.7", "method": "POST", "path": "/login", "severity": "LOW"}


def test_requires_api_key():
    with pytest.raises(ValueError):
        DevFortressClient(api_key="")


def test_sends_key_id_not_key_and_timestamp(stub_server):
    s = stub_server([(200, {"success": True, "eventId": "e1"})])
    c = DevFortressClient("vx_live_x", endpoint=s.url)
    assert c.track_event(EVENT)["success"] is True
    req = s.requests[0]
    assert "X-DevFortress-Key" not in req["headers"]
    assert req["headers"]["X-DevFortress-Key-Id"] == derive_key_id("vx_live_x")
    assert "timestamp" in req["body"]


def test_retries_5xx_then_succeeds(stub_server):
    s = stub_server([(503, {"error": "x"}), (500, {"error": "x"}), (200, {"success": True})])
    c = DevFortressClient("vx_live_x", endpoint=s.url, retries=3, backoff_base=0.01)
    assert c.track_event(EVENT)["success"] is True
    assert len(s.requests) == 3


def test_gives_up_after_retries_on_5xx(stub_server):
    s = stub_server([(502, {"error": "bad gateway"})])
    c = DevFortressClient("vx_live_x", endpoint=s.url, retries=3, backoff_base=0.01)
    with pytest.raises(DevFortressError) as ei:
        c.track_event(EVENT)
    assert ei.value.status_code == 502
    assert len(s.requests) == 3


@pytest.mark.parametrize("status", [400, 401, 403, 429])
def test_no_retry_on_4xx(stub_server, status):
    s = stub_server([(status, {"error": "nope"})])
    c = DevFortressClient("vx_live_x", endpoint=s.url, retries=3, backoff_base=0.01)
    with pytest.raises(DevFortressError) as ei:
        c.track_event(EVENT)
    assert ei.value.status_code == status
    assert len(s.requests) == 1


def test_retries_network_errors():
    c = DevFortressClient("vx_live_x", endpoint="http://127.0.0.1:1/x", retries=3, backoff_base=0.01, timeout=1)
    with pytest.raises(DevFortressError):
        c.track_event(EVENT)


def test_backoff_is_exponential(stub_server, monkeypatch):
    s = stub_server([(500, {})])
    sleeps = []
    monkeypatch.setattr(time, "sleep", lambda d: sleeps.append(d))
    c = DevFortressClient("vx_live_x", endpoint=s.url, retries=3, backoff_base=1.0)
    with pytest.raises(DevFortressError):
        c.track_event(EVENT)
    assert sleeps == [1.0, 2.0]


def test_batch_flushes_at_25(stub_server):
    s = stub_server([(200, {"success": True})])
    c = DevFortressClient("vx_live_x", endpoint=s.url, flush_interval=60)
    c.enable_batching()
    for _ in range(24):
        c.queue_event(EVENT)
    assert len(s.requests) == 0 and c.pending_events == 24
    c.queue_event(EVENT)
    assert len(s.requests) == 1
    assert len(s.requests[0]["body"]["events"]) == 25
    c.close()


def test_batch_flushes_on_interval(stub_server):
    s = stub_server([(200, {"success": True})])
    c = DevFortressClient("vx_live_x", endpoint=s.url, flush_interval=0.2)
    c.enable_batching()
    c.queue_event(EVENT)
    deadline = time.time() + 3
    while not s.requests and time.time() < deadline:
        time.sleep(0.05)
    assert len(s.requests) == 1
    c.close()


def test_defaults_are_25_events_and_5_seconds():
    c = DevFortressClient("k")
    assert c.batch_size == 25 and c.flush_interval == 5.0 and c.retries == 3


def test_flush_splits_at_server_max(stub_server):
    s = stub_server([(200, {"success": True})])
    c = DevFortressClient("k", endpoint=s.url, batch_size=1000, flush_interval=60)
    c.enable_batching()
    for _ in range(150):
        c.queue_event(EVENT)
    c.flush()
    assert [len(r["body"]["events"]) for r in s.requests] == [100, 50]
    c.close()


def test_track_events_empty_makes_no_request(stub_server):
    s = stub_server([(200, {})])
    c = DevFortressClient("k", endpoint=s.url)
    assert c.track_events([])["processed"] == 0
    assert s.requests == []


def test_strict_privacy_hashes_ip(stub_server):
    s = stub_server([(200, {"success": True})])
    c = DevFortressClient("k", endpoint=s.url, privacy="strict")
    c.track_event({**EVENT, "userAgent": "ua"})
    body = s.requests[0]["body"]
    assert body["ip"] != EVENT["ip"] and "userAgent" not in body
