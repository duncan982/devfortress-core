import pytest

from devfortress.agent_security import (
    AgentAnomalyDetector,
    AgentBaselineEngine,
    AgentCredentialManager,
    AgentScopeEnforcer,
    AgentSessionRecord,
    AgentToolCallRecord,
    _reset_agent_security_stores,
)
from devfortress.credential_isolation import CredentialIsolationManager


@pytest.fixture(autouse=True)
def reset_stores():
    _reset_agent_security_stores()
    yield
    _reset_agent_security_stores()


@pytest.fixture
def token_manager():
    return CredentialIsolationManager(encryption_key="b" * 64)


async def _fill_baseline(baseline_engine: AgentBaselineEngine, agent_id: str, sessions: int = 6):
    import time

    for _ in range(sessions):
        baseline_engine.record_session(
            AgentSessionRecord(
                session_id=f"s-{_}",
                agent_id=agent_id,
                tool_calls=[AgentToolCallRecord(tool="search_products"), AgentToolCallRecord(tool="add_to_cart")],
                started_at=time.time() * 1000,
                ended_at=time.time() * 1000 + 500,
                total_data_bytes=500,
            )
        )


class TestAgentCredentialManager:
    async def test_create_agent_alias_rejects_invalid_agent_id(self, token_manager):
        mgr = AgentCredentialManager(token_manager)
        with pytest.raises(ValueError):
            await mgr.create_agent_alias("real-cred", "bad id!", "agent_api_key")

    async def test_revoke_agent_access_revokes_all_credentials(self, token_manager):
        mgr = AgentCredentialManager(token_manager)
        await mgr.create_agent_alias("cred-1", "agent-x", "agent_api_key")
        await mgr.create_agent_alias("cred-2", "agent-x", "service_account")
        count = await mgr.revoke_agent_access("agent-x")
        assert count == 2
        assert mgr.get_agent_credentials("agent-x") == []

    async def test_quarantine_and_unquarantine(self, token_manager):
        mgr = AgentCredentialManager(token_manager)
        assert mgr.is_quarantined("agent-y") is False
        await mgr.quarantine_agent("agent-y", "suspicious activity")
        assert mgr.is_quarantined("agent-y") is True
        await mgr.unquarantine_agent("agent-y")
        assert mgr.is_quarantined("agent-y") is False

    async def test_unquarantine_non_quarantined_agent_raises(self, token_manager):
        mgr = AgentCredentialManager(token_manager)
        with pytest.raises(ValueError):
            await mgr.unquarantine_agent("never-quarantined")


class TestAgentBaselineEngine:
    async def test_baseline_requires_minimum_sessions(self):
        engine = AgentBaselineEngine()
        assert engine.agent_baseline("agent-1", "shop") is None
        await _fill_baseline(engine, "agent-1")
        baseline = engine.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.total_sessions == 6
        assert "search_products" in baseline.top_tools

    def test_3sigma_deviation(self):
        engine = AgentBaselineEngine()
        assert engine.is_3sigma_deviation([100, 100, 100, 100], 100) is False
        assert engine.is_3sigma_deviation([100, 100, 100, 100], 50000) is True
        assert engine.is_3sigma_deviation([], 1) is False


class TestAgentAnomalyDetector:
    async def test_unsanctioned_tool_fires_critical_signal(self):
        baseline_engine = AgentBaselineEngine()
        detector = AgentAnomalyDetector(baseline_engine)
        scope = AgentScopeEnforcer()
        scope.define_agent_scope("agent-2", ["search_products"], True)

        signals = detector.analyze_tool_call("agent-2", "delete_everything")
        assert any(s.type == "unsanctioned_tool" for s in signals)
        assert signals[0].severity == "critical"

    async def test_cross_agent_credential_sharing_detected(self):
        # Matches Node's analyzeToolCall exactly: everything past the scope
        # check — including cross-agent-sharing — sits behind an early
        # `if (!baseline) return signals`, so both agents need an established
        # baseline (5+ sessions) before this signal can fire at all.
        baseline_engine = AgentBaselineEngine()
        detector = AgentAnomalyDetector(baseline_engine)
        await _fill_baseline(baseline_engine, "agent-a")
        await _fill_baseline(baseline_engine, "agent-b")
        detector.analyze_tool_call("agent-a", "search_products", credential_alias="shared-alias")
        signals = detector.analyze_tool_call("agent-b", "search_products", credential_alias="shared-alias")
        assert any(s.type == "cross_agent_credential_sharing" for s in signals)

    async def test_data_volume_anomaly(self):
        baseline_engine = AgentBaselineEngine()
        detector = AgentAnomalyDetector(baseline_engine)
        await _fill_baseline(baseline_engine, "agent-3")
        signals = detector.analyze_tool_call("agent-3", "search_products", data_bytes=50_000_000)
        assert any(s.type == "data_volume_anomaly" for s in signals)


class TestAgentScopeEnforcer:
    def test_no_scope_defined_allows_by_default(self):
        enforcer = AgentScopeEnforcer()
        assert enforcer.is_tool_allowed("unscoped-agent", "anything") is True

    def test_strict_mode_blocks_unlisted_tool(self):
        enforcer = AgentScopeEnforcer()
        enforcer.define_agent_scope("agent-4", ["a", "b"], True)
        assert enforcer.is_tool_allowed("agent-4", "a") is True
        assert enforcer.is_tool_allowed("agent-4", "c") is False

    def test_add_and_remove_allowed_tools(self):
        enforcer = AgentScopeEnforcer()
        enforcer.define_agent_scope("agent-5", ["a"], True)
        enforcer.add_allowed_tools("agent-5", ["b", "c"])
        assert enforcer.is_tool_allowed("agent-5", "b") is True
        enforcer.remove_allowed_tools("agent-5", ["b"])
        assert enforcer.is_tool_allowed("agent-5", "b") is False
