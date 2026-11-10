"""LicenseManager: tier resolution, graceful (never-silent) degradation on
check failure, and the integrity hash. Mirrors TODO 321's Node fix intent:
a failing license-check must degrade visibly, never silently.
"""

from devfortress import LicenseManager
from devfortress.tier_gate import TierGate


def _base_url(stub_url: str) -> str:
    # conftest's stub_server always answers at /api/events/ingest; our
    # endpoints hang their own paths off the same base (the stub responds
    # to any path), so just strip the ingest suffix.
    return stub_url.rsplit("/api/events/ingest", 1)[0]


def test_successful_tier_resolution_feeds_tier_gate(stub_server):
    s = stub_server([(200, {"tier": "pro", "modelVersion": "v2"})])
    lm = LicenseManager("vx_live_x", _base_url(s.url))

    state = lm.check_license()

    assert state.valid is True
    assert state.tier == "pro"
    assert state.degraded is False
    assert state.consecutive_failures == 0

    # The resolved tier is what callers hand to TierGate.
    gate = TierGate(state.tier)
    assert gate.get_tier() == "pro"
    assert gate.can_block() is True
    assert gate.capabilities.allowed_modes == ["external"]

    # CV-M4: model freshness synced from the same response.
    model_state = lm.get_model_state()
    assert model_state.model_version == "v2"
    assert model_state.expired is False


def test_license_check_sends_signed_request_not_the_raw_key(stub_server):
    s = stub_server([(200, {"tier": "starter"})])
    lm = LicenseManager("vx_live_x", _base_url(s.url))
    lm.check_license()

    req = s.requests[0]
    assert req["path"] == "/api/sdk/license-check"
    assert "X-DevFortress-Key" not in req["headers"]
    assert "X-DevFortress-Key-Id" in req["headers"]
    assert req["body"]["sdkVersion"]


def test_check_failure_degrades_visibly_not_silently(stub_server, capsys):
    # 500s are retried as "transient failure" by check_license (no retry
    # loop in this module itself — one check is one HTTP attempt); with
    # grace_period_seconds=0 the very first failure must degrade.
    s = stub_server([(500, {"error": "boom"})])
    lm = LicenseManager("vx_live_x", _base_url(s.url), grace_period_seconds=0)

    state = lm.check_license()

    assert state.degraded is True
    assert state.degradation_reason is not None
    assert "monitor-only" in state.degradation_reason

    # The bug class this fixes (TODO 321): degradation must be LOGGED, not
    # swallowed silently.
    out = capsys.readouterr().out
    assert "[DevFortress:License]" in out
    assert "degraded to monitor-only mode" in out


def test_check_failure_before_grace_period_does_not_degrade(stub_server):
    s = stub_server([(500, {"error": "boom"})])
    lm = LicenseManager("vx_live_x", _base_url(s.url), grace_period_seconds=3600)

    state = lm.check_license()

    assert state.degraded is False
    assert state.consecutive_failures == 1


def test_payment_required_response_degrades_immediately(stub_server):
    s = stub_server([(402, {"error": "payment required"})])
    lm = LicenseManager("vx_live_x", _base_url(s.url))

    state = lm.check_license()

    assert state.valid is False
    assert state.tier == "starter"
    assert state.degraded is True
    assert "HTTP 402" in state.degradation_reason


def test_network_error_degrades_after_grace_period(capsys):
    lm = LicenseManager(
        "vx_live_x", "http://127.0.0.1:1", grace_period_seconds=0, timeout=1
    )

    state = lm.check_license()

    assert state.degraded is True
    out = capsys.readouterr().out
    assert "degraded to monitor-only mode" in out


def test_can_perform_action_respects_degraded_state(stub_server):
    s = stub_server([(500, {})])
    lm = LicenseManager("vx_live_x", _base_url(s.url), grace_period_seconds=0)
    lm.check_license()

    assert lm.is_degraded() is True
    assert lm.can_perform_action("observe") is True  # always allowed
    assert lm.can_perform_action("block") is False  # degraded = monitor-only
    assert lm.can_perform_action("rate_limit") is False


def test_integrity_hash_requires_secret():
    lm = LicenseManager("vx_live_x", "https://platform.example.com")
    assert lm.compute_integrity_hash() == "no-integrity-secret"

    lm2 = LicenseManager("vx_live_x", "https://platform.example.com", integrity_secret="s3cr3t")
    h1 = lm2.compute_integrity_hash()
    assert len(h1) == 16
    verdict = lm2.verify_integrity(h1)
    assert verdict["tampered"] is False
    tampered_verdict = lm2.verify_integrity("deadbeefdeadbeef")
    assert tampered_verdict["tampered"] is True
