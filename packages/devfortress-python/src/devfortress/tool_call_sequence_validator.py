"""DevFortress SDK — Tool-Call Sequence Validator.

Port of the Node SDK's ``tool-call-sequence-validator.ts``.

Validates AI agent tool calls against an authorized directed acyclic graph
(DAG). Detects out-of-sequence tool calls that indicate prompt injection
attacks — e.g., an agent jumping directly to ``place_order`` without first
calling ``add_to_cart``.

Graduated response: log -> rate-limit -> block -> revoke session.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

Action = Literal["allow", "log", "rate_limit", "block", "revoke_session"]


@dataclass
class ToolCallGraphNode:
    requires: List[str] = field(default_factory=list)
    max_calls: int = 0  # 0 = unlimited
    risk_level: Optional[Literal["low", "medium", "high", "critical"]] = None


ToolCallGraph = Dict[str, ToolCallGraphNode]


@dataclass
class ToolCallValidationResult:
    allowed: bool
    reason: str
    action: Action
    prompt_injection_likely: bool
    violation_count: int
    call_history: List[str]
    missing_prerequisites: Optional[List[str]] = None


@dataclass
class _Violation:
    timestamp: float
    tool: str
    reason: str


@dataclass
class _SessionState:
    call_history: List[str] = field(default_factory=list)
    call_counts: Dict[str, int] = field(default_factory=dict)
    violations: List[_Violation] = field(default_factory=list)
    created_at: float = field(default_factory=lambda: time.time() * 1000)


class ToolCallSequenceValidator:
    MAX_SESSIONS = 50_000

    def __init__(
        self,
        graph: ToolCallGraph,
        *,
        max_violations: int = 3,
        violation_window_ms: int = 300_000,
        graduated_response: bool = True,
        debug: bool = False,
    ):
        self._graph = graph
        self._max_violations = max_violations
        self._violation_window_ms = violation_window_ms
        self._graduated_response = graduated_response
        self._debug = debug
        self._sessions: "Dict[str, _SessionState]" = {}

    def validate(
        self, session_id: str, tool_name: str, *, timestamp: Optional[float] = None
    ) -> ToolCallValidationResult:
        session = self._get_or_create_session(session_id)
        now = timestamp if timestamp is not None else time.time() * 1000

        session.violations = [
            v for v in session.violations if now - v.timestamp < self._violation_window_ms
        ]

        graph_node = self._graph.get(tool_name)

        if graph_node is None:
            session.violations.append(_Violation(timestamp=now, tool=tool_name, reason="unknown_tool"))
            return self._build_result(session, False, "unknown_tool", tool_name, [])

        missing_prereqs = [req for req in graph_node.requires if req not in session.call_history]
        if missing_prereqs:
            session.violations.append(
                _Violation(
                    timestamp=now,
                    tool=tool_name,
                    reason=f"missing_prerequisites: {', '.join(missing_prereqs)}",
                )
            )
            return self._build_result(session, False, "out_of_sequence", tool_name, missing_prereqs)

        current_calls = session.call_counts.get(tool_name, 0)
        if graph_node.max_calls and graph_node.max_calls > 0 and current_calls >= graph_node.max_calls:
            session.violations.append(
                _Violation(
                    timestamp=now,
                    tool=tool_name,
                    reason=f"max_calls_exceeded: {current_calls}/{graph_node.max_calls}",
                )
            )
            return self._build_result(session, False, "max_calls_exceeded", tool_name, [])

        # Valid — record the call
        session.call_history.append(tool_name)
        session.call_counts[tool_name] = current_calls + 1

        if self._debug:
            print(f"[ToolCallValidator] Session {session_id}: {tool_name} ALLOWED (history: {' -> '.join(session.call_history)})")

        return ToolCallValidationResult(
            allowed=True,
            reason="valid_sequence",
            action="allow",
            prompt_injection_likely=False,
            violation_count=len(session.violations),
            call_history=list(session.call_history),
        )

    def reset_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def get_history(self, session_id: str) -> List[str]:
        session = self._sessions.get(session_id)
        return list(session.call_history) if session else []

    def clear_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def get_session_stats(self, session_id: str) -> Dict[str, object]:
        session = self._sessions.get(session_id)
        if not session:
            return {"exists": False, "callCount": 0, "violationCount": 0, "history": []}
        return {
            "exists": True,
            "callCount": len(session.call_history),
            "violationCount": len(session.violations),
            "history": list(session.call_history),
        }

    def destroy(self) -> None:
        self._sessions.clear()

    def _get_or_create_session(self, session_id: str) -> _SessionState:
        session = self._sessions.get(session_id)
        if session is None:
            if len(self._sessions) >= self.MAX_SESSIONS:
                first = next(iter(self._sessions), None)
                if first is not None:
                    del self._sessions[first]
            session = _SessionState()
            self._sessions[session_id] = session
        return session

    def _build_result(
        self,
        session: _SessionState,
        allowed: bool,
        reason: str,
        tool_name: str,
        missing_prerequisites: List[str],
    ) -> ToolCallValidationResult:
        violation_count = len(session.violations)

        action: Action = "log"
        if self._graduated_response:
            if violation_count >= self._max_violations:
                action = "revoke_session"
            elif violation_count >= 2:
                action = "block"
            elif violation_count >= 1:
                action = "rate_limit"
        else:
            action = "block"

        graph_node = self._graph.get(tool_name)
        prompt_injection_likely = reason == "out_of_sequence" and bool(
            graph_node and graph_node.risk_level in ("high", "critical")
        )

        if self._debug:
            print(
                f"[ToolCallValidator] Session violation: {tool_name} — {reason} "
                f"(violations: {violation_count}, action: {action})"
            )

        return ToolCallValidationResult(
            allowed=allowed,
            reason=reason,
            action=action,
            prompt_injection_likely=prompt_injection_likely,
            violation_count=violation_count,
            call_history=list(session.call_history),
            missing_prerequisites=missing_prerequisites or None,
        )
