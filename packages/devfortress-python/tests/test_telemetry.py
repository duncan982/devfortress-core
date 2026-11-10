"""TelemetryManager (CV-M2 heartbeat) and TelemetryRollupBuffer
(non-billing aggregate rollup), plus hourly_period_key.
"""

from datetime import datetime, timezone

from devfortress import derive_key_id
from devfortress.telemetry import (
    RollupContributionInput,
    TelemetryManager,
    TelemetryRollupBuffer,
    hourly_period_key,
)


def _base_url(stub_url: str) -> str:
    return stub_url.rsplit("/api/events/ingest", 1)[0]


# ── TelemetryManager ─────────────────────────────────────────


def test_heartbeat_sends_signed_request_with_counts(stub_server):
    s = stub_server([(200, {"success": True})])
    tm = TelemetryManager("vx_live_x", _base_url(s.url))
    tm.record_event()
    tm.record_event()
    tm.record_block()
    tm.record_rate_limit()
    tm.record_latency(12.5)

    tm.send_heartbeat()

    req = s.requests[0]
    assert req["path"] == "/api/sdk/heartbeat"
    assert "X-DevFortress-Key" not in req["headers"]
    assert req["headers"]["X-DevFortress-Key-Id"] == derive_key_id("vx_live_x")
    assert req["body"]["eventCount"] == 2
    assert req["body"]["blockCount"] == 1
    assert req["body"]["rateLimitCount"] == 1
    assert req["body"]["p99LatencyMs"] == 12.5

    # Counters reset after a successful send.
    state = tm.get_state()
    assert state["event_count"] == 0
    assert state["block_count"] == 0
    assert state["rate_limit_count"] == 0


def test_heartbeat_enriched_by_snapshot_provider(stub_server):
    s = stub_server([(200, {})])
    tm = TelemetryManager("vx_live_x", _base_url(s.url))
    tm.start(lambda: {"tier": "enterprise", "cl_mode": "hybrid", "license_degraded": True})
    tm.send_heartbeat()
    tm.destroy()

    body = s.requests[0]["body"]
    assert body["tier"] == "enterprise"
    assert body["clMode"] == "hybrid"
    assert body["licenseDegraded"] is True


def test_heartbeat_failure_is_fire_and_forget(capsys):
    tm = TelemetryManager("vx_live_x", "http://127.0.0.1:1", debug=True, timeout=1)
    tm.send_heartbeat()  # must not raise
    out = capsys.readouterr().out
    assert "[DevFortress:Telemetry]" in out


# ── TelemetryRollupBuffer ────────────────────────────────────


def test_hourly_period_key_matches_iso_hour_bucket():
    dt = datetime(2026, 8, 27, 14, 37, 0, tzinfo=timezone.utc)
    assert hourly_period_key(dt) == "2026-08-27T14"


def test_rollup_buffer_buckets_by_tuple_key_not_nul_separator(stub_server):
    s = stub_server([(200, {"success": True})])
    buf = TelemetryRollupBuffer("vx_live_x", _base_url(s.url))

    buf.add(RollupContributionInput(alias_or_ip_key="203.0.113.7", endpoint="/a", is_error=False, latency_ms=10))
    buf.add(RollupContributionInput(alias_or_ip_key="203.0.113.7", endpoint="/b", is_error=True, latency_ms=20))
    buf.add(RollupContributionInput(alias_or_ip_key="198.51.100.2", endpoint="/a", is_error=False, latency_ms=5))

    # Two distinct alias/IP keys in the same hour bucket, kept separate.
    assert len(buf._buckets) == 2
    key_a = ("203.0.113.7", hourly_period_key())
    assert key_a in buf._buckets
    bucket_a = buf._buckets[key_a]
    assert bucket_a.request_count == 2
    assert bucket_a.error_count == 1
    assert bucket_a.endpoints == {"/a", "/b"}

    buf.flush()
    assert len(buf._buckets) == 0  # cleared after flush

    req = s.requests[0]
    assert req["path"] == "/api/events/telemetry-rollup"
    contributions = {c["aliasOrIpKey"]: c for c in req["body"]["contributions"]}
    assert contributions["203.0.113.7"]["requestCount"] == 2
    assert contributions["203.0.113.7"]["errorCount"] == 1
    assert contributions["198.51.100.2"]["requestCount"] == 1


def test_rollup_buffer_flush_failure_is_best_effort(capsys):
    buf = TelemetryRollupBuffer("vx_live_x", "http://127.0.0.1:1", debug=True, timeout=1)
    buf.add(RollupContributionInput(alias_or_ip_key="1.2.3.4", endpoint="/a", is_error=False, latency_ms=1))
    buf.flush()  # must not raise
    assert buf._buckets == {}
    out = capsys.readouterr().out
    assert "telemetry rollup flush failed" in out


def test_rollup_buffer_forces_early_flush_at_max_buffered_keys(stub_server):
    s = stub_server([(200, {})])
    buf = TelemetryRollupBuffer("vx_live_x", _base_url(s.url), max_buffered_keys=2)

    buf.add(RollupContributionInput(alias_or_ip_key="ip-1", endpoint="/a", is_error=False, latency_ms=1))
    buf.add(RollupContributionInput(alias_or_ip_key="ip-2", endpoint="/a", is_error=False, latency_ms=1))
    assert len(buf._buckets) == 2
    # Third distinct key exceeds the cap: forces a flush and drops this contribution.
    buf.add(RollupContributionInput(alias_or_ip_key="ip-3", endpoint="/a", is_error=False, latency_ms=1))

    assert len(s.requests) == 1
    assert len(buf._buckets) == 0
