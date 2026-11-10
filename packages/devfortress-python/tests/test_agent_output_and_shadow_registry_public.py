"""AgentOutputExfiltrationDetector (B7) and ShadowAgentRegistry (B10), now
public SDK surface (moved out of tier2_gated/, TODO 380 — same mechanics
as TODO 367's B3/B4 move in the other five SDK ports).

tier2_gated/ now contains only ConsentAliasLifecycle (B3) and
MultiHopTrustChain (B4), which remain gated per TODO 368's audit.
"""

import time

import pytest

from devfortress import (
    AgentOutput,
    AgentOutputExfiltrationDetector,
    AgentRegistryStats,
    ExfiltrationResult,
    RegisteredAgent,
    ShadowAgentDetection,
    ShadowAgentRegistry,
)


def test_importable_from_top_level_package():
    # Presence/visibility: both classes (and their result/config types) are
    # reachable from `devfortress` directly, not just their submodules.
    assert AgentOutputExfiltrationDetector is not None
    assert ShadowAgentRegistry is not None
    assert AgentOutput is not None
    assert ExfiltrationResult is not None
    assert RegisteredAgent is not None
    assert ShadowAgentDetection is not None
    assert AgentRegistryStats is not None


def test_no_longer_reachable_from_tier2_gated():
    with pytest.raises(ImportError):
        from devfortress.tier2_gated import agent_output_exfiltration_detector  # noqa: F401

    with pytest.raises(ImportError):
        from devfortress.tier2_gated import shadow_agent_registry  # noqa: F401


def test_detector_still_works_from_its_new_public_location():
    detector = AgentOutputExfiltrationDetector()
    result = detector.analyze(
        AgentOutput(
            agent_id="agent-1",
            output_content="my ssn is 123-45-6789",
            output_type="text",
            destination_type="user",
            timestamp=time.time(),
        )
    )
    assert result.detected is True
    assert result.threat_type != "none"


def test_registry_still_works_from_its_new_public_location():
    registry = ShadowAgentRegistry()
    registry.register("agent-1", "Agent One", "owner@example.com", ["read"])
    stats = registry.get_stats()
    assert stats.registered_count == 1
    assert stats.active_count == 1
