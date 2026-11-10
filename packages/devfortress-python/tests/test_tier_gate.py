"""TierGate: capability resolution per subscription tier and blocking a
tier-ineligible feature.
"""

import pytest

from devfortress import TierGate


def test_starter_cannot_block():
    gate = TierGate("starter")
    assert gate.can_block() is False
    assert gate.validate_block_action("block_ip") is not None
    assert "not available on the starter tier" in gate.validate_block_action("block_ip")


def test_pro_can_block_but_not_hybrid_mode():
    gate = TierGate("pro")
    assert gate.can_block() is True
    # Package A: Pro gets external CL only, never internal/hybrid.
    error = gate.validate_mode("hybrid")
    assert error is not None
    assert "not available on the pro tier" in error
    assert gate.get_effective_mode("hybrid") == "external"


def test_team_and_enterprise_allow_hybrid():
    for tier in ("team", "enterprise"):
        gate = TierGate(tier)
        assert gate.validate_mode("hybrid") is None
        assert gate.get_effective_mode("hybrid") == "hybrid"
        assert gate.get_effective_mode() == "hybrid"  # default


def test_icl_tier_ceilings_per_subscription():
    assert TierGate("starter").get_max_icl_tier() == 1
    assert TierGate("pro").get_max_icl_tier() == 0  # Package A: no ICL on Pro
    assert TierGate("team").get_max_icl_tier() == 2
    assert TierGate("enterprise").get_max_icl_tier() == 3
    assert TierGate("enterprise").is_icl_tier_available(3) is True
    assert TierGate("team").is_icl_tier_available(3) is False


def test_daily_event_limit_blocks_once_exhausted():
    gate = TierGate("starter")
    gate.capabilities.max_events_per_day = 2  # shrink for a fast test
    assert gate.check_event_limit()["allowed"] is True
    gate.record_event()
    gate.record_event()
    result = gate.check_event_limit()
    assert result["allowed"] is False
    assert result["remaining"] == 0


def test_monthly_quota_tracks_and_blocks():
    gate = TierGate("starter")
    gate.capabilities.max_events_per_month = 3
    for _ in range(3):
        assert gate.check_monthly_quota()["allowed"] is True
        gate.record_monthly_event()
    result = gate.check_monthly_quota()
    assert result["allowed"] is False
    assert result["remaining"] == 0
    assert result["limit"] == 3


def test_unlimited_tier_reports_allowed_with_infinite_remaining():
    gate = TierGate("enterprise")
    assert gate.check_event_limit()["allowed"] is True
    assert gate.check_event_limit()["remaining"] == float("inf")


def test_platform_feature_flags_match_matrix():
    starter = TierGate("starter")
    assert starter.has_platform_alerts() is False
    assert starter.has_shared_state() is False
    assert starter.has_compliance_evidence() is False

    team = TierGate("team")
    assert team.has_platform_alerts() is True
    assert team.has_shared_state() is True
    assert team.has_compliance_evidence() is True


def test_snapshot_round_trip_restores_same_period_counters():
    gate = TierGate("pro", hybrid_addon_enabled=False)
    gate.record_event()
    gate.record_monthly_event()
    snap = gate.to_snapshot()

    restored = TierGate.from_snapshot(snap)
    assert restored.get_tier() == "pro"
    assert restored._daily_event_count == gate._daily_event_count
    assert restored._monthly_event_count == gate._monthly_event_count


@pytest.mark.parametrize("tier", ["starter", "pro", "team", "enterprise"])
def test_has_feature_reflects_capability_values(tier):
    gate = TierGate(tier)
    assert gate.has_feature("can_observe") is True
    assert gate.has_feature("allowed_modes") is True  # non-empty list
