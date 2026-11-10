"""Agent Credential Aliasing & Security.

Port of the Node SDK's ``agent-security.ts``. Extends the core credential
isolation system for AI agent credentials:

Agent Credential Aliasing
  - create_agent_alias() for credential_type: "agent_api_key" | "agent_oauth_token" | "service_account"
  - revoke_agent_access(agent_id, reason) — revoke all credentials for an agent
  - quarantine_agent(agent_id, reason) — suspend tool access, preserve session for forensics

Agent Behavioral Baseline
  - agent_baseline(agent_id, task_definition) — records normal tool patterns for N sessions
  - Metrics: avg tools/session, tool diversity entropy, data volumes, session duration
  - 30-day rolling update window

Agent Anomaly Detection Signals
  - API call sequence entropy anomaly
  - Tool invocation scope deviation
  - Data volume anomaly (3-sigma deviation)
  - Cross-agent credential sharing detection

Agent Access Scope Enforcement
  - define_agent_scope(agent_id, allowed_tools) — register sanctioned tools
  - Unsanctioned tool invocation fires critical signal immediately
  - Direct defence against prompt injection causing unauthorised tool calls
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional

from .agent import validate_agent_id
from .credential_isolation import CacheAdapter, CredentialIsolationManager, RevocationReason

AgentCredentialType = Literal["agent_api_key", "agent_oauth_token", "service_account"]
AgentAnomalyType = Literal[
    "sequence_entropy_anomaly",
    "scope_deviation",
    "data_volume_anomaly",
    "cross_agent_credential_sharing",
    "unsanctioned_tool",
]


@dataclass
class AgentExecutionContext:
    """Execution-context baseline captured at agent alias issuance."""

    container_id: Optional[str] = None
    expected_egress_path: Optional[str] = None
    expected_process_signature: Optional[str] = None


@dataclass
class AgentCredentialAliasData:
    alias: str
    agent_id: str
    credential_type: AgentCredentialType
    created_at: float
    quarantined: bool = False
    quarantine_reason: Optional[str] = None
    quarantined_at: Optional[float] = None
    execution_context: Optional[AgentExecutionContext] = None


@dataclass
class AgentBaselineMetrics:
    avg_tools_per_session: float
    tool_diversity_entropy: float
    avg_data_volume_bytes: float
    avg_session_duration_ms: float
    top_tools: List[str]
    total_sessions: int
    created_at: float
    last_updated_at: float
    task_definition: Optional[str] = None


@dataclass
class AgentToolCallRecord:
    tool: str
    duration_ms: Optional[float] = None
    data_bytes: Optional[int] = None


@dataclass
class AgentSessionRecord:
    session_id: str
    agent_id: str
    tool_calls: List[AgentToolCallRecord]
    started_at: float
    total_data_bytes: int
    ended_at: Optional[float] = None


@dataclass
class AgentAnomalySignal:
    type: AgentAnomalyType
    agent_id: str
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    detected_at: float
    details: Dict[str, Any]


@dataclass
class AgentScopeDefinition:
    agent_id: str
    allowed_tools: List[str]
    strict_mode: bool
    created_at: float
    updated_at: float


# ── In-Memory Stores (replaceable by a durable store in production) ───

_agent_credentials: "Dict[str, List[AgentCredentialAliasData]]" = {}
_agent_baselines: "Dict[str, AgentBaselineMetrics]" = {}
_agent_sessions: "Dict[str, List[AgentSessionRecord]]" = {}
_agent_scopes: "Dict[str, AgentScopeDefinition]" = {}
_agent_quarantines: "Dict[str, Dict[str, Any]]" = {}


def _reset_agent_security_stores() -> None:
    """Reset all in-memory stores. Used for testing only."""
    _agent_credentials.clear()
    _agent_baselines.clear()
    _agent_sessions.clear()
    _agent_scopes.clear()
    _agent_quarantines.clear()


def _shannon_entropy(items: List[str]) -> float:
    if not items:
        return 0.0
    freq: Dict[str, int] = {}
    for item in items:
        freq[item] = freq.get(item, 0) + 1
    total = len(items)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ── Agent Credential Manager ────────────────────────────────


class AgentCredentialManager:
    def __init__(self, token_manager: CredentialIsolationManager, cache: Optional[CacheAdapter] = None):
        self._token_manager = token_manager
        self._cache = cache

    async def create_agent_alias(
        self,
        real_credential: str,
        agent_id: str,
        credential_type: AgentCredentialType,
        ttl_seconds: int = 7200,
        execution_context: Optional[AgentExecutionContext] = None,
    ) -> str:
        """Create an alias for an agent credential (API key, OAuth token, etc.).
        The real credential never leaves the client application."""
        validate_agent_id(agent_id)
        alias = await self._token_manager.create_alias(real_credential, agent_id, ttl_seconds)

        data = AgentCredentialAliasData(
            alias=alias,
            agent_id=agent_id,
            credential_type=credential_type,
            created_at=time.time() * 1000,
            execution_context=execution_context,
        )
        _agent_credentials.setdefault(agent_id, []).append(data)

        if self._cache:
            try:
                import json

                existing = await self._cache.get(f"agent:creds:{agent_id}")
                existing_list = json.loads(existing) if existing else []
                existing_list.append(
                    {
                        "alias": data.alias,
                        "agentId": data.agent_id,
                        "credentialType": data.credential_type,
                        "createdAt": data.created_at,
                        "quarantined": data.quarantined,
                    }
                )
                await self._cache.set(f"agent:creds:{agent_id}", json.dumps(existing_list), ttl_seconds)
            except Exception:
                pass  # In-memory is already set

        return alias

    async def revoke_agent_access(
        self, agent_id: str, reason: RevocationReason = "active_threat"
    ) -> int:
        """Revoke ALL credentials for an agent.
        Used when an agent is compromised or decommissioned."""
        creds = _agent_credentials.get(agent_id, [])
        revoked_count = 0

        for cred in creds:
            try:
                await self._token_manager.revoke_by_alias(cred.alias, reason, agent_id)
                revoked_count += 1
            except Exception:
                pass  # Continue revoking remaining credentials

        _agent_credentials.pop(agent_id, None)
        _agent_quarantines.pop(agent_id, None)

        if self._cache:
            try:
                await self._cache.delete(f"agent:creds:{agent_id}")
                await self._cache.delete(f"agent:quarantine:{agent_id}")
            except Exception:
                pass

        return revoked_count

    async def quarantine_agent(self, agent_id: str, reason: str) -> None:
        """Quarantine an agent — suspend tool access but preserve session
        for forensics. Unlike revocation, quarantine is reversible and the
        session data remains intact."""
        quarantine = {"reason": reason, "at": time.time() * 1000}
        _agent_quarantines[agent_id] = quarantine

        for cred in _agent_credentials.get(agent_id, []):
            cred.quarantined = True
            cred.quarantine_reason = reason
            cred.quarantined_at = quarantine["at"]

        if self._cache:
            try:
                import json

                await self._cache.set(f"agent:quarantine:{agent_id}", json.dumps(quarantine), 86400)
            except Exception:
                pass

    async def unquarantine_agent(self, agent_id: str) -> None:
        """Lift quarantine for an agent, restoring normal tool access.
        Rejects if the agent isn't currently quarantined — reinstatement is
        only meaningful as the reverse of an active quarantine, not a silent no-op."""
        if agent_id not in _agent_quarantines:
            raise ValueError(f'Agent "{agent_id}" is not currently quarantined — nothing to reinstate.')

        del _agent_quarantines[agent_id]
        for cred in _agent_credentials.get(agent_id, []):
            cred.quarantined = False
            cred.quarantine_reason = None
            cred.quarantined_at = None

        if self._cache:
            try:
                await self._cache.delete(f"agent:quarantine:{agent_id}")
            except Exception:
                pass

    def is_quarantined(self, agent_id: str) -> bool:
        return agent_id in _agent_quarantines

    def get_quarantine_details(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return _agent_quarantines.get(agent_id)

    def get_agent_credentials(self, agent_id: str) -> List[AgentCredentialAliasData]:
        return _agent_credentials.get(agent_id, [])


# ── Agent Behavioral Baseline ───────────────────────────────


class AgentBaselineEngine:
    BASELINE_WINDOW_DAYS = 30
    MIN_SESSIONS_FOR_BASELINE = 5

    def record_session(self, record: AgentSessionRecord) -> None:
        """Record a completed agent session for baseline building."""
        sessions = _agent_sessions.setdefault(record.agent_id, [])

        window_start = time.time() * 1000 - self.BASELINE_WINDOW_DAYS * 24 * 60 * 60 * 1000
        filtered = [s for s in sessions if s.started_at > window_start]
        filtered.append(record)
        _agent_sessions[record.agent_id] = filtered

        if len(filtered) >= self.MIN_SESSIONS_FOR_BASELINE:
            self._recalculate_baseline(record.agent_id)

    def agent_baseline(self, agent_id: str, task_definition: str) -> Optional[AgentBaselineMetrics]:
        """Establish a baseline from a task definition.
        Call this at the start to register what "normal" looks like."""
        existing = _agent_baselines.get(agent_id)
        if existing:
            existing.task_definition = task_definition
            existing.last_updated_at = time.time() * 1000
            return existing

        sessions = _agent_sessions.get(agent_id, [])
        if len(sessions) < self.MIN_SESSIONS_FOR_BASELINE:
            return None

        return self._recalculate_baseline(agent_id, task_definition)

    def get_baseline(self, agent_id: str) -> Optional[AgentBaselineMetrics]:
        return _agent_baselines.get(agent_id)

    def _recalculate_baseline(
        self, agent_id: str, task_definition: Optional[str] = None
    ) -> AgentBaselineMetrics:
        sessions = _agent_sessions.get(agent_id, [])

        tools_per_session = [len(s.tool_calls) for s in sessions]
        avg_tools_per_session = sum(tools_per_session) / len(sessions)

        all_tools = [tc.tool for s in sessions for tc in s.tool_calls]
        tool_diversity_entropy = _shannon_entropy(all_tools)

        data_volumes = [s.total_data_bytes for s in sessions]
        avg_data_volume_bytes = sum(data_volumes) / len(sessions)

        durations = [s.ended_at - s.started_at for s in sessions if s.ended_at]
        avg_session_duration_ms = sum(durations) / len(durations) if durations else 0.0

        tool_freq: Dict[str, int] = {}
        for tool in all_tools:
            tool_freq[tool] = tool_freq.get(tool, 0) + 1
        top_tools = [t for t, _ in sorted(tool_freq.items(), key=lambda kv: kv[1], reverse=True)[:10]]

        existing = _agent_baselines.get(agent_id)
        baseline = AgentBaselineMetrics(
            avg_tools_per_session=avg_tools_per_session,
            tool_diversity_entropy=tool_diversity_entropy,
            avg_data_volume_bytes=avg_data_volume_bytes,
            avg_session_duration_ms=avg_session_duration_ms,
            top_tools=top_tools,
            total_sessions=len(sessions),
            created_at=existing.created_at if existing else time.time() * 1000,
            last_updated_at=time.time() * 1000,
            task_definition=task_definition or (existing.task_definition if existing else None),
        )
        _agent_baselines[agent_id] = baseline
        return baseline

    @staticmethod
    def _std_dev(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        sq_diffs = [(v - mean) ** 2 for v in values]
        return math.sqrt(sum(sq_diffs) / len(values))

    def is_3sigma_deviation(self, values: List[float], new_value: float) -> bool:
        """Check if a value is a 3-sigma deviation from a dataset."""
        if len(values) < 2:
            return False
        mean = sum(values) / len(values)
        sd = self._std_dev(values)
        if sd == 0:
            return new_value != mean
        return abs(new_value - mean) > 3 * sd


# ── Agent Anomaly Detector ───────────────────────────────────


class AgentAnomalyDetector:
    def __init__(self, baseline_engine: AgentBaselineEngine):
        self._baseline_engine = baseline_engine
        self._anomaly_handlers: "List[Callable[[AgentAnomalySignal], None]]" = []
        self._credential_usage: "Dict[str, set]" = {}

    def on_anomaly(self, handler: "Callable[[AgentAnomalySignal], None]") -> None:
        self._anomaly_handlers.append(handler)

    def analyze_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        data_bytes: int = 0,
        credential_alias: Optional[str] = None,
    ) -> List[AgentAnomalySignal]:
        """Analyze a tool call for anomalies against the agent's baseline."""
        signals: List[AgentAnomalySignal] = []
        baseline = self._baseline_engine.get_baseline(agent_id)

        # Scope check (integrated here for convenience)
        scope = _agent_scopes.get(agent_id)
        if scope and scope.strict_mode and tool_name not in scope.allowed_tools:
            signal = AgentAnomalySignal(
                type="unsanctioned_tool",
                agent_id=agent_id,
                severity="critical",
                description=(
                    f'Agent {agent_id} invoked unsanctioned tool "{tool_name}". '
                    f"Allowed: [{', '.join(scope.allowed_tools)}]"
                ),
                detected_at=time.time() * 1000,
                details={"tool": tool_name, "allowedTools": scope.allowed_tools},
            )
            signals.append(signal)
            self._emit_signal(signal)

        if not baseline:
            return signals

        # Tool invocation scope deviation
        if baseline.top_tools and tool_name not in baseline.top_tools:
            signal = AgentAnomalySignal(
                type="scope_deviation",
                agent_id=agent_id,
                severity="medium",
                description=f'Agent {agent_id} invoked tool "{tool_name}" outside its baseline tool set',
                detected_at=time.time() * 1000,
                details={"tool": tool_name, "baselineTools": baseline.top_tools},
            )
            signals.append(signal)
            self._emit_signal(signal)

        # Data volume anomaly (3-sigma deviation)
        if data_bytes > 0:
            sessions = _agent_sessions.get(agent_id, [])
            volumes = [float(s.total_data_bytes) for s in sessions]
            if self._baseline_engine.is_3sigma_deviation(volumes, float(data_bytes)):
                signal = AgentAnomalySignal(
                    type="data_volume_anomaly",
                    agent_id=agent_id,
                    severity="high",
                    description=(
                        f"Agent {agent_id} data volume {data_bytes}B is 3-sigma deviation "
                        f"from baseline avg {round(baseline.avg_data_volume_bytes)}B"
                    ),
                    detected_at=time.time() * 1000,
                    details={"dataBytes": data_bytes, "baselineAvg": baseline.avg_data_volume_bytes},
                )
                signals.append(signal)
                self._emit_signal(signal)

        # Cross-agent credential sharing detection
        if credential_alias:
            agents = self._credential_usage.setdefault(credential_alias, set())
            agents.add(agent_id)
            if len(agents) > 1:
                signal = AgentAnomalySignal(
                    type="cross_agent_credential_sharing",
                    agent_id=agent_id,
                    severity="critical",
                    description=(
                        f"Credential {credential_alias[:16]}... shared across "
                        f"{len(agents)} agents: [{', '.join(agents)}]"
                    ),
                    detected_at=time.time() * 1000,
                    details={
                        "credentialAlias": credential_alias[:16] + "...",
                        "sharingAgents": list(agents),
                    },
                )
                signals.append(signal)
                self._emit_signal(signal)

        return signals

    def analyze_session(self, record: AgentSessionRecord) -> List[AgentAnomalySignal]:
        """Analyze a completed session for sequence entropy anomaly."""
        signals: List[AgentAnomalySignal] = []
        baseline = self._baseline_engine.get_baseline(record.agent_id)
        if not baseline or baseline.total_sessions < 5:
            return signals

        session_tools = [tc.tool for tc in record.tool_calls]
        session_entropy = _shannon_entropy(session_tools)
        entropy_deviation = abs(session_entropy - baseline.tool_diversity_entropy)

        if baseline.tool_diversity_entropy > 0 and entropy_deviation / baseline.tool_diversity_entropy > 0.5:
            deviation_percent = (entropy_deviation / baseline.tool_diversity_entropy) * 100
            signal = AgentAnomalySignal(
                type="sequence_entropy_anomaly",
                agent_id=record.agent_id,
                severity="high",
                description=(
                    f"Agent {record.agent_id} session entropy {session_entropy:.2f} deviates "
                    f"{deviation_percent:.0f}% from baseline {baseline.tool_diversity_entropy:.2f}"
                ),
                detected_at=time.time() * 1000,
                details={
                    "sessionEntropy": session_entropy,
                    "baselineEntropy": baseline.tool_diversity_entropy,
                    "deviationPercent": deviation_percent,
                },
            )
            signals.append(signal)
            self._emit_signal(signal)

        return signals

    def _emit_signal(self, signal: AgentAnomalySignal) -> None:
        for handler in self._anomaly_handlers:
            try:
                handler(signal)
            except Exception:
                pass  # Handler errors don't block detection


# ── Agent Scope Enforcer ─────────────────────────────────────


class AgentScopeEnforcer:
    def define_agent_scope(
        self, agent_id: str, allowed_tools: List[str], strict_mode: bool = True
    ) -> AgentScopeDefinition:
        """Define the allowed tool scope for an agent.
        Any tool invocation outside this scope fires a critical event."""
        existing = _agent_scopes.get(agent_id)
        scope = AgentScopeDefinition(
            agent_id=agent_id,
            allowed_tools=allowed_tools,
            strict_mode=strict_mode,
            created_at=existing.created_at if existing else time.time() * 1000,
            updated_at=time.time() * 1000,
        )
        _agent_scopes[agent_id] = scope
        return scope

    def is_tool_allowed(self, agent_id: str, tool_name: str) -> bool:
        scope = _agent_scopes.get(agent_id)
        if not scope:
            return True  # No scope defined — allow by default
        if not scope.strict_mode:
            return True  # Non-strict mode — log but allow
        return tool_name in scope.allowed_tools

    def get_scope(self, agent_id: str) -> Optional[AgentScopeDefinition]:
        return _agent_scopes.get(agent_id)

    def remove_scope(self, agent_id: str) -> None:
        _agent_scopes.pop(agent_id, None)

    def add_allowed_tools(self, agent_id: str, tools: List[str]) -> None:
        scope = _agent_scopes.get(agent_id)
        if not scope:
            self.define_agent_scope(agent_id, tools, True)
            return
        tool_set = list(dict.fromkeys([*scope.allowed_tools, *tools]))
        scope.allowed_tools = tool_set
        scope.updated_at = time.time() * 1000

    def remove_allowed_tools(self, agent_id: str, tools: List[str]) -> None:
        scope = _agent_scopes.get(agent_id)
        if not scope:
            return
        remove_set = set(tools)
        scope.allowed_tools = [t for t in scope.allowed_tools if t not in remove_set]
        scope.updated_at = time.time() * 1000
