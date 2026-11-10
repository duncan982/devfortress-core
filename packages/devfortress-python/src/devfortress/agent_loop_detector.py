"""DevFortress SDK — Agent Loop Detector.

Port of the Node SDK's ``agent-loop-detector.ts``.

Instruments the SDK to track agent execution cycles and token consumption.
Detects infinite loops via cycle count, time budget, and token budget
thresholds. Implements an automatic circuit breaker: pause agent, alert
owner. Distinguishes legitimate long operations from runaway loops via
progress metrics.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

LoopAction = Literal["CONTINUE", "WARN", "PAUSE_AGENT", "TERMINATE"]


@dataclass
class LoopDetectionResult:
    loop: bool
    reason: str
    action: LoopAction
    cycles: int
    total_tokens: int
    elapsed_ms: float
    making_progress: bool
    repetition_score: float


@dataclass
class _LoopSession:
    agent_id: str
    started_at: float
    cycles: int = 0
    total_tokens: int = 0
    tool_history: List[str] = field(default_factory=list)
    arg_hashes: List[str] = field(default_factory=list)
    progress_metrics: List[float] = field(default_factory=list)
    paused: bool = False


class AgentLoopDetector:
    def __init__(
        self,
        *,
        max_cycles: int = 20,
        max_duration_ms: int = 120_000,
        max_tokens: int = 100_000,
        progress_unique_tools: int = 2,
        progress_window_cycles: int = 5,
        max_sessions: int = 50_000,
        debug: bool = False,
    ):
        self._max_cycles = max_cycles
        self._max_duration_ms = max_duration_ms
        self._max_tokens = max_tokens
        self._progress_unique_tools = progress_unique_tools
        self._progress_window_cycles = progress_window_cycles
        self._max_sessions = max_sessions
        self._debug = debug
        self._sessions: "Dict[str, _LoopSession]" = {}

    def record_cycle(
        self,
        agent_id: str,
        session_id: str,
        *,
        tokens_used: int = 0,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        progress_metric: Optional[float] = None,
    ) -> LoopDetectionResult:
        """Record a new execution cycle for an agent session.
        Returns detection result — check `result.loop` and `result.action`."""
        session = self._get_or_create_session(agent_id, session_id)
        now = time.time() * 1000

        if session.paused:
            return self._build_result(session, now, True, "agent_paused", "TERMINATE")

        session.cycles += 1
        session.total_tokens += tokens_used

        if tool_name:
            session.tool_history.append(tool_name)
        if tool_args:
            session.arg_hashes.append(self._hash_args(tool_args))
        if progress_metric is not None:
            session.progress_metrics.append(progress_metric)

        elapsed_ms = now - session.started_at
        making_progress = self._check_progress(session)
        repetition_score = self._compute_repetition_score(session)

        if session.cycles >= self._max_cycles and not making_progress:
            session.paused = True
            return self._build_result(session, now, True, "max_cycles", "PAUSE_AGENT")

        if elapsed_ms >= self._max_duration_ms:
            session.paused = True
            return self._build_result(session, now, True, "max_duration", "PAUSE_AGENT")

        if session.total_tokens >= self._max_tokens:
            session.paused = True
            return self._build_result(session, now, True, "max_tokens", "PAUSE_AGENT")

        if repetition_score > 0.8 and session.cycles > 5 and not making_progress:
            session.paused = True
            return self._build_result(session, now, True, "repetitive_pattern", "PAUSE_AGENT")

        if (
            session.cycles >= self._max_cycles * 0.8
            or elapsed_ms >= self._max_duration_ms * 0.8
            or session.total_tokens >= self._max_tokens * 0.8
        ):
            return self._build_result(session, now, False, "approaching_limit", "WARN")

        return self._build_result(session, now, False, "within_limits", "CONTINUE")

    def clear_session(self, agent_id_or_session_id: str, session_id: Optional[str] = None) -> None:
        """Clear a session. Accepts (agent_id, session_id) or just (session_id) as key."""
        key = f"{agent_id_or_session_id}:{session_id}" if session_id else agent_id_or_session_id
        self._sessions.pop(key, None)

    def release_agent(self, session_id: str) -> bool:
        """Release an agent from paused state (after human review)."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.paused = False
        session.cycles = 0
        session.total_tokens = 0
        session.tool_history = []
        session.arg_hashes = []
        return True

    def is_paused(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        return session.paused if session else False

    def get_metrics(self, session_id: str) -> Dict[str, Any]:
        session = self._sessions.get(session_id)
        if not session:
            return {"exists": False, "cycles": 0, "tokens": 0, "elapsedMs": 0, "paused": False}
        return {
            "exists": True,
            "cycles": session.cycles,
            "tokens": session.total_tokens,
            "elapsedMs": time.time() * 1000 - session.started_at,
            "paused": session.paused,
        }

    def destroy(self) -> None:
        self._sessions.clear()

    # ── Private helpers ───────────────────────────────────────

    def _get_or_create_session(self, agent_id: str, session_id: str) -> _LoopSession:
        # NOTE: keyed by session_id alone, matching the Node source exactly
        # (a pre-existing quirk there, not fixed here — see session report).
        session = self._sessions.get(session_id)
        if session is None:
            if len(self._sessions) >= self._max_sessions:
                first = next(iter(self._sessions), None)
                if first is not None:
                    del self._sessions[first]
            session = _LoopSession(agent_id=agent_id, started_at=time.time() * 1000)
            self._sessions[session_id] = session
        return session

    def _check_progress(self, session: _LoopSession) -> bool:
        recent_tools = session.tool_history[-self._progress_window_cycles :]
        unique_in_window = len(set(recent_tools))
        if unique_in_window >= self._progress_unique_tools:
            return True

        if len(session.progress_metrics) >= 2:
            recent = session.progress_metrics[-3:]
            increasing = all(i == 0 or v > recent[i - 1] for i, v in enumerate(recent))
            if increasing:
                return True

        return False

    def _compute_repetition_score(self, session: _LoopSession) -> float:
        if len(session.arg_hashes) < 3:
            return 0.0
        recent = session.arg_hashes[-10:]
        unique_hashes = len(set(recent))
        return 1 - unique_hashes / len(recent)

    @staticmethod
    def _hash_args(args: Dict[str, Any]) -> str:
        """Simple deterministic hash for arg comparison — matches Node's
        32-bit rolling hash exactly (same algorithm, same wraparound)."""
        text = json.dumps(args, sort_keys=True, separators=(",", ":"))
        h = 0
        for ch in text:
            h = ((h << 5) - h + ord(ch)) & 0xFFFFFFFF
            if h >= 0x80000000:
                h -= 0x100000000
        return _to_base36(h)

    def _build_result(
        self,
        session: _LoopSession,
        now: float,
        loop: bool,
        reason: str,
        action: LoopAction,
    ) -> LoopDetectionResult:
        elapsed_ms = now - session.started_at
        making_progress = self._check_progress(session)
        repetition_score = self._compute_repetition_score(session)

        if self._debug:
            print(
                f"[LoopDetector] Agent {session.agent_id}: {reason} — cycles={session.cycles}, "
                f"tokens={session.total_tokens}, elapsed={elapsed_ms}ms, action={action}"
            )

        return LoopDetectionResult(
            loop=loop,
            reason=reason,
            action=action,
            cycles=session.cycles,
            total_tokens=session.total_tokens,
            elapsed_ms=elapsed_ms,
            making_progress=making_progress,
            repetition_score=repetition_score,
        )


def _to_base36(n: int) -> str:
    if n == 0:
        return "0"
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    negative = n < 0
    n = abs(n)
    out = []
    while n:
        n, rem = divmod(n, 36)
        out.append(digits[rem])
    if negative:
        out.append("-")
    return "".join(reversed(out))
