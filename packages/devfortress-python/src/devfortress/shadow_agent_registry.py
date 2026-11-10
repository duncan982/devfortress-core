"""DevFortress SDK — Shadow Agent Registry.

Port of the Node SDK's ``shadow-agent-registry.ts``.

Detects and tracks unauthorized ("shadow") AI agents that operate without
proper registration. Maintains a registry of known agents and flags
unregistered agent-like behavior.

Patent Pending.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

Recommendation = Literal["register", "block", "monitor"]

DEFAULT_AGENT_PATTERNS = [
    "automated request pattern (>100 req/min)",
    "consistent timing between requests (<50ms variance)",
    "sequential resource enumeration",
    "user-agent indicates bot/automation",
    "no mouse/keyboard entropy in session",
    "API-only access (no page loads)",
]


@dataclass
class RegisteredAgent:
    agent_id: str
    name: str
    owner: str
    permissions: List[str]
    registered_at: float = 0.0
    last_heartbeat: float = 0.0
    active: bool = False


@dataclass
class ShadowAgentDetection:
    detected: bool
    agent_fingerprint: str
    indicators: List[str]
    confidence: float
    recommendation: Recommendation
    matched_patterns: List[str]


@dataclass
class AgentRegistryStats:
    registered_count: int = 0
    active_count: int = 0
    shadow_detections: int = 0
    blocked_shadows: int = 0


def _feature_disabled() -> bool:
    return os.environ.get("FEATURE_PLATFORM_INTEL") == "false"


class ShadowAgentRegistry:
    def __init__(
        self,
        *,
        heartbeat_timeout_ms: int = 300_000,
        agent_patterns: Optional[List[str]] = None,
        auto_block: bool = False,
    ):
        self._heartbeat_timeout_ms = heartbeat_timeout_ms
        self._agent_patterns = agent_patterns or DEFAULT_AGENT_PATTERNS
        self._auto_block = auto_block

        self._registry: "Dict[str, RegisteredAgent]" = {}
        self._shadow_detections: "Dict[str, ShadowAgentDetection]" = {}
        self._stats = AgentRegistryStats()

    def register(self, agent_id: str, name: str, owner: str, permissions: List[str]) -> RegisteredAgent:
        if _feature_disabled():
            return RegisteredAgent(agent_id=agent_id, name=name, owner=owner, permissions=permissions)

        registered = RegisteredAgent(
            agent_id=agent_id, name=name, owner=owner, permissions=permissions,
            registered_at=time.time() * 1000, last_heartbeat=time.time() * 1000, active=True,
        )
        self._registry[agent_id] = registered
        self._stats.registered_count += 1
        self._stats.active_count += 1
        return registered

    def heartbeat(self, agent_id: str) -> bool:
        agent = self._registry.get(agent_id)
        if not agent:
            return False
        agent.last_heartbeat = time.time() * 1000
        agent.active = True
        return True

    def detect(self, fingerprint: str, indicators: List[str]) -> ShadowAgentDetection:
        if _feature_disabled():
            return ShadowAgentDetection(
                detected=False, agent_fingerprint=fingerprint, indicators=[],
                confidence=0, recommendation="monitor", matched_patterns=[],
            )

        for agent in self._registry.values():
            if agent.agent_id == fingerprint and agent.active:
                return ShadowAgentDetection(
                    detected=False, agent_fingerprint=fingerprint, indicators=[],
                    confidence=0, recommendation="monitor", matched_patterns=[],
                )

        matched_patterns = [
            pattern
            for pattern in self._agent_patterns
            if any(pattern.split("(")[0].strip().lower() in i.lower() for i in indicators)
        ]

        confidence = min(1.0, len(matched_patterns) / 3)
        detected = confidence > 0.3

        if detected:
            self._stats.shadow_detections += 1
            if self._auto_block and confidence > 0.7:
                self._stats.blocked_shadows += 1

        result = ShadowAgentDetection(
            detected=detected,
            agent_fingerprint=fingerprint,
            indicators=indicators,
            confidence=confidence,
            recommendation=(
                ("block" if self._auto_block else "register") if confidence > 0.7 else "monitor"
            ),
            matched_patterns=matched_patterns,
        )
        if detected:
            self._shadow_detections[fingerprint] = result
        return result

    def prune_inactive(self) -> List[str]:
        cutoff = time.time() * 1000 - self._heartbeat_timeout_ms
        pruned: List[str] = []
        for agent_id, agent in self._registry.items():
            if agent.last_heartbeat < cutoff:
                agent.active = False
                self._stats.active_count -= 1
                pruned.append(agent_id)
        return pruned

    def get_stats(self) -> AgentRegistryStats:
        return AgentRegistryStats(**self._stats.__dict__)

    def get_registered(self) -> List[RegisteredAgent]:
        return list(self._registry.values())
