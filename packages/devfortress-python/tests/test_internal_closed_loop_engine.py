"""InternalClosedLoopEngine (TODO 407 port): internal-mode decision engine,
ported from internal-closed-loop-engine.ts.
"""

import pytest

from devfortress import InternalCLConfig, InternalCLRequest, InternalClosedLoopEngine, matches_known_attack_pattern
from devfortress.client import DevFortressClient


def _req(**kwargs) -> InternalCLRequest:
    base = {"ip": "203.0.113.5", "method": "GET", "path": "/"}
    base.update(kwargs)
    return InternalCLRequest(**base)


# ── Tier 1 rule matching ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path,query",
    [
        ("/products", "search=' OR 1=1 --"),
        ("/products", "id=1; DROP TABLE users"),
        ("/search", "UNION SELECT password FROM users"),
    ],
)
async def test_sql_injection_blocks(path, query):
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path=path, query=query))
    assert result.decision == "block"
    assert "sql_injection" in result.matched_rules
    assert result.tier == 1


async def test_clean_request_allowed():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path="/products", query="search=laptop"))
    assert result.decision == "allow"
    assert result.matched_rules == []
    assert result.score == 0


async def test_literal_percent_not_false_positived():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path="/products", query="discount=50%"))
    assert result.decision == "allow"


async def test_xss_blocks():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path="/comment", query="text=<script>alert(1)</script>"))
    assert result.decision == "block"
    assert "xss_attempt" in result.matched_rules


async def test_path_traversal_blocks():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path="/files/../../etc/passwd"))
    assert result.decision == "block"
    assert "path_traversal" in result.matched_rules


async def test_scanner_user_agent_blocks():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path="/", user_agent="sqlmap/1.7"))
    assert result.decision == "block"
    assert "scanner_detected" in result.matched_rules


async def test_sensitive_file_access_blocks():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path="/.env"))
    assert result.decision == "block"
    assert "sensitive_file_access" in result.matched_rules


async def test_credential_stuffing_rate_limits():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(method="POST", path="/api/login"))
    assert result.decision == "rate_limit"
    assert "credential_stuffing_pattern" in result.matched_rules


async def test_agent_unsanctioned_tool_quarantines():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(agent_id="agent-1", tool_name="shell_exec"))
    assert result.decision == "quarantine"
    assert "agent_unsanctioned_tool" in result.matched_rules
    assert engine.is_agent_quarantined("agent-1") is True


# ── Pre-check (already-blocked) short-circuit ─────────────────────────────


async def test_blocked_ip_short_circuits_before_rules():
    engine = InternalClosedLoopEngine()
    engine.block_ip("203.0.113.5", "manual_block")
    result = await engine.evaluate(_req(path="/anything"))
    assert result.decision == "block"
    assert result.matched_rules == ["ip_blocked:manual_block"]


async def test_unblock_ip_allows_again():
    engine = InternalClosedLoopEngine()
    engine.block_ip("203.0.113.5", "test")
    engine.unblock_ip("203.0.113.5")
    result = await engine.evaluate(_req(path="/products"))
    assert result.decision == "allow"


async def test_block_action_also_blocks_session_and_agent():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path="/.env", session_id="sess-1", agent_id="agent-9"))
    assert result.decision == "block"
    action_types = {a.type for a in result.actions}
    assert "block_ip" in action_types
    assert "block_session" in action_types
    assert "quarantine_agent" in action_types


# ── Rate limiting ──────────────────────────────────────────────────────────


async def test_rate_limit_triggers_after_max_requests():
    config = InternalCLConfig(rate_limit_max=3, rate_limit_window_seconds=60.0)
    engine = InternalClosedLoopEngine(config)
    for _ in range(3):
        result = await engine.evaluate(_req(path="/products", query="p=1"))
        assert result.decision == "allow"
    result = await engine.evaluate(_req(path="/products", query="p=1"))
    assert result.decision == "rate_limit"
    assert result.matched_rules == ["rate_limit_exceeded"]


# ── Tier 2: unimplemented/pass-through by default ─────────────────────────


async def test_tier2_scorer_unset_by_default_skips_tier2():
    engine = InternalClosedLoopEngine()
    result = await engine.evaluate(_req(path="/products", query="p=1"))
    assert result.decision == "allow"
    assert result.tier == 1  # never reaches tier 2 scoring at all


async def test_tier2_scorer_when_supplied_can_block():
    def scorer(req):
        return 90.0

    config = InternalCLConfig(tier2_scorer=scorer)
    engine = InternalClosedLoopEngine(config)
    result = await engine.evaluate(_req(path="/products", query="p=1"))
    assert result.decision == "block"
    assert result.tier == 2
    assert result.matched_rules == ["tier2_ml_score"]


async def test_tier2_scorer_can_be_async():
    async def scorer(req):
        return 70.0

    config = InternalCLConfig(tier2_scorer=scorer)
    engine = InternalClosedLoopEngine(config)
    result = await engine.evaluate(_req(path="/products", query="p=1"))
    assert result.decision == "rate_limit"
    assert result.tier == 2


# ── Tier 3: relay callback (hybrid mode only) ─────────────────────────────


async def test_relay_not_called_when_external_relay_disabled():
    calls = []
    config = InternalCLConfig(on_relay=lambda result, req: calls.append(result))
    engine = InternalClosedLoopEngine(config)  # enable_external_relay defaults False
    await engine.evaluate(_req(path="/.env"))
    assert calls == []


async def test_relay_called_for_flagged_decision_when_enabled():
    calls = []
    config = InternalCLConfig(enable_external_relay=True, on_relay=lambda result, req: calls.append(result))
    engine = InternalClosedLoopEngine(config)
    # "/.env" matches both path_traversal (score 90) and sensitive_file_access
    # (score 85) in Node's own pattern set (path_traversal's own
    # `(/\.env|/\.git|/\.ssh)` sub-pattern overlaps sensitive_file_access) —
    # not a porting bug, reproduced here deliberately.
    await engine.evaluate(_req(path="/.env"))
    assert len(calls) == 1
    assert calls[0].matched_rules == ["path_traversal", "sensitive_file_access"]


async def test_relay_not_called_for_allowed_decision():
    calls = []
    config = InternalCLConfig(enable_external_relay=True, on_relay=lambda result, req: calls.append(result))
    engine = InternalClosedLoopEngine(config)
    await engine.evaluate(_req(path="/products"))
    assert calls == []


# ── Fail mode ───────────────────────────────────────────────────────────


async def test_fail_closed_blocks_on_rule_error():
    def bad_match(req):
        raise RuntimeError("boom")

    engine = InternalClosedLoopEngine(InternalCLConfig(fail_mode="closed"))
    from devfortress.internal_closed_loop_engine import InternalCLRule

    engine.add_rule(
        InternalCLRule(name="broken", description="x", severity="low", score=1, decision="allow", match=bad_match)
    )
    # Individual rule errors are swallowed per-rule (matching Node), not
    # escalated to the top-level fail-mode handler — evaluate() must not
    # raise.
    result = await engine.evaluate(_req(path="/products"))
    assert result.decision == "allow"


# ── matches_known_attack_pattern (Option B content check) ────────────────


def test_matches_known_attack_pattern_detects_sqli():
    assert matches_known_attack_pattern(path="/search", user_agent=None) is False
    assert matches_known_attack_pattern(path="/search?q=' OR 1=1 --") is True


def test_matches_known_attack_pattern_detects_scanner():
    assert matches_known_attack_pattern(path="/", user_agent="nikto/2.5") is True


# ── Client wiring: mode selection, observe(), is_blocked() ───────────────


async def test_client_external_mode_observe_is_noop():
    client = DevFortressClient(api_key="k", mode="external")
    assert client.internal_engine is None
    assert await client.observe(_req(path="/.env")) is None
    assert client.is_blocked("203.0.113.5") is False


async def test_client_internal_mode_observe_blocks_attack():
    client = DevFortressClient(api_key="k", mode="internal")
    assert client.internal_engine is not None
    result = await client.observe(_req(path="/.env"))
    assert result is not None
    assert result["flagged"] is True
    assert result["decision"] == "block"
    assert client.is_blocked("203.0.113.5") is True


async def test_client_internal_mode_observe_allows_clean_request():
    client = DevFortressClient(api_key="k", mode="internal")
    result = await client.observe(_req(path="/products", query="q=laptop"))
    assert result is None


async def test_client_hybrid_mode_blocks_via_internal_first():
    client = DevFortressClient(api_key="k", mode="hybrid")
    assert client.circuit_breaker is not None
    result = await client.observe(_req(path="/.env"))
    assert result is not None
    assert result["flagged"] is True


async def test_client_hybrid_mode_allows_clean_request_and_keeps_circuit_closed():
    client = DevFortressClient(api_key="k", mode="hybrid")
    result = await client.observe(_req(path="/products", query="q=laptop"))
    assert result is None
    assert client.circuit_breaker.state == "closed"
