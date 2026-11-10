"""DevFortress SDK — Platform Circuit Breaker.

Port of the Node SDK's ``circuit-breaker.ts``.

Monitors connectivity to the DevFortress platform and provides
automatic failover from external to internal closed-loop mode.

Three states:

  closed:    Platform is reachable, external CL is active
  open:      Platform is unreachable, internal CL takes over
  half-open: Testing if the platform has recovered

Transition rules:

  closed -> open:      After failure_threshold consecutive failures
  open -> half-open:   After recovery_time_seconds elapsed
  half-open -> closed: First successful call
  half-open -> open:   First failed call
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Literal, Optional

CircuitState = Literal["closed", "open", "half-open"]

__all__ = [
    "CircuitState",
    "CircuitBreakerDiagnostics",
    "PlatformCircuitBreaker",
    "STALE_THRESHOLD_SECONDS",
]

#: Rules older than 5 minutes without a platform sync are considered stale.
STALE_THRESHOLD_SECONDS = 300.0


@dataclass(frozen=True)
class CircuitBreakerDiagnostics:
    """The result of :meth:`PlatformCircuitBreaker.get_diagnostics`."""

    state: CircuitState
    failure_count: int
    last_failure_time: float
    seconds_until_recovery_attempt: float
    rules_stale: bool
    stale_duration_seconds: float


class PlatformCircuitBreaker:
    """Tracks platform connectivity and signals external-vs-internal CL. Thread-safe."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_time_seconds: float = 60.0,
        on_state_change: Optional[Callable[[CircuitState, CircuitState, str], None]] = None,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._recovery_time_seconds = recovery_time_seconds
        self._on_state_change = on_state_change

        self._state: CircuitState = "closed"
        self._failure_count = 0
        self._last_failure_time = 0.0
        # When internal rules became stale (circuit opened); None if not stale.
        self._stale_since: Optional[float] = None
        self._lock = threading.Lock()

    def should_call_external(self) -> bool:
        """Return whether external platform calls should be attempted."""
        with self._lock:
            if self._state == "closed":
                return True

            if self._state == "open":
                if time.time() - self._last_failure_time >= self._recovery_time_seconds:
                    self._transition("half-open", "recovery_timeout_elapsed")
                    return True  # allow one test call
                return False

            # half-open: allow the test call.
            return True

    def record_success(self) -> None:
        """Record a successful external call."""
        with self._lock:
            if self._state == "half-open":
                self._transition("closed", "test_call_succeeded")
            self._failure_count = 0
            self._stale_since = None

    def record_failure(self) -> None:
        """Record a failed external call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == "half-open":
                self._transition("open", "test_call_failed")
                return

            if self._state == "closed" and self._failure_count >= self._failure_threshold:
                self._transition("open", "consecutive_failures")

    @property
    def state(self) -> CircuitState:
        """The current circuit state."""
        with self._lock:
            return self._state

    def get_diagnostics(self) -> CircuitBreakerDiagnostics:
        """Return diagnostics info."""
        with self._lock:
            seconds_until_recovery = 0.0
            if self._state == "open":
                elapsed = time.time() - self._last_failure_time
                if elapsed < self._recovery_time_seconds:
                    seconds_until_recovery = self._recovery_time_seconds - elapsed

            stale_duration = time.time() - self._stale_since if self._stale_since is not None else 0.0

            return CircuitBreakerDiagnostics(
                state=self._state,
                failure_count=self._failure_count,
                last_failure_time=self._last_failure_time,
                seconds_until_recovery_attempt=seconds_until_recovery,
                rules_stale=stale_duration > STALE_THRESHOLD_SECONDS,
                stale_duration_seconds=stale_duration,
            )

    def reset(self) -> None:
        """Force the circuit breaker back to the closed state."""
        with self._lock:
            self._transition("closed", "manual_reset")
            self._failure_count = 0
            self._last_failure_time = 0.0
            self._stale_since = None

    def is_rules_stale(self) -> bool:
        """Return whether internal rules are stale (no platform sync for longer than the threshold)."""
        with self._lock:
            return self._stale_since is not None and (time.time() - self._stale_since) > STALE_THRESHOLD_SECONDS

    def _transition(self, to: CircuitState, reason: str) -> None:
        from_state = self._state
        if from_state == to:
            return
        self._state = to

        if to == "open" and self._stale_since is None:
            self._stale_since = time.time()

        if self._on_state_change is not None:
            try:
                self._on_state_change(from_state, to, reason)
            except Exception:
                # Callback errors should not break the circuit breaker.
                pass
