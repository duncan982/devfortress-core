"""DevFortress SDK — Clock Drift Anomaly Detector (Invention A18).

Port of the Node SDK's ``security-extensions.ts`` ``ClockDriftDetector``
(TODO 419 — one of 17 Node-only claims identified by the 2026-11-02 patent
audit; this is the first ported as a small, self-contained claim).

Compares a client-supplied timestamp against server time and classifies
the drift into an escalating action: allow, warn (audit with server time),
use server time (enforce server-authoritative timestamps), or reject
(possible timestamp manipulation).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

__all__ = [
    "ClockDriftSeverity",
    "ClockDriftAction",
    "ClockDriftResult",
    "ClockDriftTrend",
    "ClockDriftDetector",
]

ClockDriftSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ClockDriftAction = Literal["allow", "warn", "use_server_time", "reject"]

_MAX_HISTORY_PER_CLIENT = 100


@dataclass(frozen=True)
class ClockDriftResult:
    """The outcome of one :meth:`ClockDriftDetector.check` call."""

    valid: bool
    drift_ms: float
    severity: ClockDriftSeverity
    action: ClockDriftAction
    reason: str


@dataclass(frozen=True)
class ClockDriftTrend:
    """Drift trend for a client, from :meth:`ClockDriftDetector.get_drift_trend`."""

    avg_drift: float
    increasing: bool


@dataclass
class _ClientHistory:
    drifts: List[float] = field(default_factory=list)


class ClockDriftDetector:
    """Server-authoritative clock drift detection with per-client history."""

    def __init__(
        self,
        acceptable_threshold_ms: float = 30_000,
        suspicious_threshold_ms: float = 120_000,
        critical_threshold_ms: float = 300_000,
    ) -> None:
        self._acceptable_threshold_ms = acceptable_threshold_ms
        self._suspicious_threshold_ms = suspicious_threshold_ms
        self._critical_threshold_ms = critical_threshold_ms
        self._drift_history: Dict[str, _ClientHistory] = {}

    def check(
        self, client_timestamp_ms: float, client_id: Optional[str] = None
    ) -> ClockDriftResult:
        """Check a client timestamp (epoch milliseconds) against server time."""
        server_time_ms = time.time() * 1000
        drift_ms = abs(client_timestamp_ms - server_time_ms)
        direction = "ahead" if client_timestamp_ms > server_time_ms else "behind"

        if client_id:
            history = self._drift_history.setdefault(client_id, _ClientHistory())
            history.drifts.append(drift_ms)
            if len(history.drifts) > _MAX_HISTORY_PER_CLIENT:
                history.drifts.pop(0)

        if drift_ms <= self._acceptable_threshold_ms:
            return ClockDriftResult(
                valid=True,
                drift_ms=drift_ms,
                severity="LOW",
                action="allow",
                reason=f"Clock drift {drift_ms:.0f}ms ({direction}) within acceptable range",
            )

        if drift_ms <= self._suspicious_threshold_ms:
            return ClockDriftResult(
                valid=True,
                drift_ms=drift_ms,
                severity="MEDIUM",
                action="warn",
                reason=(
                    f"Clock drift {drift_ms:.0f}ms ({direction}) — suspicious, "
                    "using server time for audit"
                ),
            )

        if drift_ms <= self._critical_threshold_ms:
            return ClockDriftResult(
                valid=True,
                drift_ms=drift_ms,
                severity="HIGH",
                action="use_server_time",
                reason=(
                    f"Clock drift {drift_ms:.0f}ms ({direction}) — enforcing "
                    "server-authoritative timestamps"
                ),
            )

        return ClockDriftResult(
            valid=False,
            drift_ms=drift_ms,
            severity="CRITICAL",
            action="reject",
            reason=(
                f"Clock drift {drift_ms:.0f}ms ({direction}) exceeds critical "
                "threshold — possible timestamp manipulation"
            ),
        )

    def get_drift_trend(self, client_id: str) -> Optional[ClockDriftTrend]:
        """Return the drift trend for a client, or ``None`` if fewer than 3 samples."""
        history = self._drift_history.get(client_id)
        if history is None or len(history.drifts) < 3:
            return None

        avg_drift = sum(history.drifts) / len(history.drifts)
        recent = history.drifts[-3:]
        recent_avg = sum(recent) / 3
        return ClockDriftTrend(avg_drift=avg_drift, increasing=recent_avg > avg_drift * 1.2)

    def get_stats(self) -> Dict[str, int]:
        """Return a metrics snapshot."""
        return {"tracked_clients": len(self._drift_history)}
