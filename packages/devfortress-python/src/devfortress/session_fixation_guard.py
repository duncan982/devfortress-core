"""DevFortress SDK — Session Fixation Guard (Invention A13).

Port of the Node SDK's ``security-extensions.ts`` ``SessionFixationGuard``
(TODO 419/429 — one of the 20 Node-only claims identified by the
2026-11-02 patent audit).

Binds a session to the IP range (first three octets) and user-agent it was
created with, and flags drift when either changes mid-session — a classic
session-fixation/hijack signal.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional

__all__ = [
    "SessionFingerprint",
    "SessionValidationResult",
    "SessionFixationGuard",
]


@dataclass
class SessionFingerprint:
    """The fingerprint recorded for one session at registration time."""

    session_id: str
    ip_prefix: str
    user_agent: str
    created_at: float
    last_verified: float


@dataclass(frozen=True)
class SessionValidationResult:
    """The outcome of one :meth:`SessionFixationGuard.validate_session` call."""

    valid: bool
    regenerate: bool
    reason: str
    drift_score: int


def _ip_prefix(ip: str) -> str:
    return ".".join(ip.split(".")[:3])


class SessionFixationGuard:
    """Tracks per-session IP/user-agent fingerprints and flags drift."""

    def __init__(
        self,
        bind_to_ip_range: bool = True,
        bind_to_user_agent: bool = True,
        max_fingerprint_drift: int = 2,
    ) -> None:
        self._bind_to_ip_range = bind_to_ip_range
        self._bind_to_user_agent = bind_to_user_agent
        self._max_fingerprint_drift = max_fingerprint_drift
        self._sessions: Dict[str, SessionFingerprint] = {}

    def register_session(
        self,
        ip: str,
        user_agent: str,
        old_session_id: Optional[str] = None,
        now_ms: Optional[float] = None,
    ) -> str:
        """Register a new session after authentication.

        Returns the new session ID; the caller must replace the old one.
        """
        import time

        now = now_ms if now_ms is not None else time.time() * 1000
        new_session_id = os.urandom(32).hex()

        if old_session_id:
            self._sessions.pop(old_session_id, None)

        self._sessions[new_session_id] = SessionFingerprint(
            session_id=new_session_id,
            ip_prefix=_ip_prefix(ip),
            user_agent=user_agent,
            created_at=now,
            last_verified=now,
        )
        return new_session_id

    def validate_session(
        self, session_id: str, ip: str, user_agent: str, now_ms: Optional[float] = None
    ) -> SessionValidationResult:
        """Validate an ongoing session against its recorded fingerprint."""
        import time

        fingerprint = self._sessions.get(session_id)
        if fingerprint is None:
            return SessionValidationResult(
                valid=False, regenerate=True, reason="Unknown session ID", drift_score=100
            )

        drift_score = 0
        reasons = []

        if self._bind_to_ip_range:
            current_prefix = _ip_prefix(ip)
            if current_prefix != fingerprint.ip_prefix:
                drift_score += 40
                reasons.append(
                    f"IP range changed: {fingerprint.ip_prefix}.* -> {current_prefix}.*"
                )

        if self._bind_to_user_agent and user_agent != fingerprint.user_agent:
            drift_score += 40
            reasons.append("User-agent changed mid-session")

        fingerprint.last_verified = now_ms if now_ms is not None else time.time() * 1000

        if drift_score > 50:
            return SessionValidationResult(
                valid=False,
                regenerate=True,
                reason=f"Session fixation/hijack suspected: {'; '.join(reasons)}",
                drift_score=drift_score,
            )

        if drift_score > 0:
            return SessionValidationResult(
                valid=True,
                regenerate=False,
                reason=f"Minor session drift: {'; '.join(reasons)}",
                drift_score=drift_score,
            )

        return SessionValidationResult(
            valid=True, regenerate=False, reason="Session fingerprint matches", drift_score=0
        )

    def remove_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def get_stats(self) -> Dict[str, int]:
        return {"active_sessions": len(self._sessions)}
