"""DevFortress SDK — Sensitive Action Monitor (Invention A6).

Port of the Node SDK's ``sensitive-action-monitor.ts`` ``SensitiveActionMonitor``
(TODO 419/424 — one of the 20 Node-only claims identified by the
2026-11-02 patent audit).

Monitors high-risk account operations (password change, email change, MFA
enrollment/removal, role escalation, ...) with weighted behavioral
deviation scoring over a sliding time window, and recommends an
escalating response (allow, require MFA, delay, revoke session, block).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

__all__ = [
    "SensitiveActionType",
    "SensitiveActionEvent",
    "SensitiveActionResult",
    "SensitiveActionMonitor",
]

SensitiveActionType = Literal[
    "password_change",
    "email_change",
    "mfa_enroll",
    "mfa_remove",
    "role_escalation",
    "api_key_create",
    "api_key_revoke",
    "account_delete",
    "payment_method_change",
    "session_export",
]

_ACTION_WEIGHTS: Dict[str, int] = {
    "password_change": 30,
    "email_change": 35,
    "mfa_enroll": 20,
    "mfa_remove": 40,
    "role_escalation": 45,
    "api_key_create": 15,
    "api_key_revoke": 25,
    "account_delete": 50,
    "payment_method_change": 30,
    "session_export": 20,
}


@dataclass(frozen=True)
class SensitiveActionEvent:
    user_id: str
    action_type: str
    ip: str
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    timestamp: Optional[float] = None


@dataclass(frozen=True)
class SensitiveActionResult:
    allowed: bool
    risk_score: int
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    action: Literal["allow", "require_mfa", "delay", "revoke_session", "block"]
    reason: str
    actions_in_window: int


@dataclass
class _UserActionRecord:
    actions: List[Dict[str, object]] = field(default_factory=list)
    last_ip: str = ""
    last_user_agent: str = ""


class SensitiveActionMonitor:
    """Weighted behavioral-deviation scoring over a sliding window of
    sensitive account actions, per user."""

    def __init__(
        self,
        window_ms: float = 600_000,
        max_actions_per_window: int = 3,
        score_multiplier: float = 2.0,
        auto_revoke: bool = True,
        max_entries: int = 50_000,
    ) -> None:
        self._window_ms = window_ms
        self._max_actions_per_window = max_actions_per_window
        self._score_multiplier = score_multiplier
        self._auto_revoke = auto_revoke
        self._max_entries = max_entries
        self._user_actions: Dict[str, _UserActionRecord] = {}

    def evaluate(self, event: SensitiveActionEvent) -> SensitiveActionResult:
        now = event.timestamp if event.timestamp is not None else time.time() * 1000

        if len(self._user_actions) >= self._max_entries and event.user_id not in self._user_actions:
            first_key = next(iter(self._user_actions), None)
            if first_key is not None:
                del self._user_actions[first_key]

        record = self._user_actions.get(event.user_id)
        if record is None:
            record = _UserActionRecord(last_ip=event.ip, last_user_agent=event.user_agent or "")
            self._user_actions[event.user_id] = record

        record.actions = [
            a for a in record.actions if now - a["timestamp"] <= self._window_ms
        ]
        record.actions.append({"type": event.action_type, "timestamp": now, "ip": event.ip})

        actions_in_window = len(record.actions)
        base_weight = _ACTION_WEIGHTS.get(event.action_type, 20)

        risk_score = base_weight

        if actions_in_window > 1:
            risk_score += (actions_in_window - 1) * 15

        unique_ips = {a["ip"] for a in record.actions}
        if len(unique_ips) > 1:
            risk_score += 20

        action_types = {a["type"] for a in record.actions}
        if "mfa_remove" in action_types and "password_change" in action_types:
            risk_score += 30
        if "email_change" in action_types and "password_change" in action_types:
            risk_score += 25
        if "role_escalation" in action_types and actions_in_window > 1:
            risk_score += 20

        risk_score = min(100, round(risk_score * self._score_multiplier))

        severity: str
        action: str
        allowed = True

        if risk_score >= 85:
            severity = "CRITICAL"
            action = "revoke_session" if self._auto_revoke else "block"
            allowed = False
        elif risk_score >= 65:
            severity = "HIGH"
            action = "require_mfa"
        elif risk_score >= 40:
            severity = "MEDIUM"
            action = "delay"
        else:
            severity = "LOW"
            action = "allow"

        record.last_ip = event.ip
        record.last_user_agent = event.user_agent or record.last_user_agent

        reason = (
            f"Sensitive action '{event.action_type}' for user {event.user_id}: "
            f"{actions_in_window} actions in window, risk={risk_score}, "
            f"{len(unique_ips)} unique IPs"
            + (f", {len(action_types)} action types" if len(action_types) > 1 else "")
        )

        return SensitiveActionResult(
            allowed=allowed,
            risk_score=risk_score,
            severity=severity,  # type: ignore[arg-type]
            action=action,  # type: ignore[arg-type]
            reason=reason,
            actions_in_window=actions_in_window,
        )

    def get_stats(self) -> Dict[str, int]:
        return {"tracked_users": len(self._user_actions)}

    def cleanup(self, now_ms: Optional[float] = None) -> None:
        """Purge expired actions and drop users with no remaining actions."""
        now = now_ms if now_ms is not None else time.time() * 1000
        to_delete = []
        for user_id, record in self._user_actions.items():
            record.actions = [a for a in record.actions if now - a["timestamp"] <= self._window_ms]
            if not record.actions:
                to_delete.append(user_id)
        for user_id in to_delete:
            del self._user_actions[user_id]
