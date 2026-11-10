"""DevFortress SDK — Graduated Rate Limiter (Invention A3).

Port of the Node SDK's ``graduated-rate-limiter.ts``.

Implements alias-scoped graduated rate limiting with multi-stage
response escalation. Addresses GAP-A3-1 through GAP-A3-4:

  GAP-A3-1: Latency jitter (+/-20%) in soft-limit injection
  GAP-A3-2: Per-endpoint hierarchical rate limits (configurable)
  GAP-A3-3: Burst detection (1-second micro-window)
  GAP-A3-4: Escalating cooldowns (60s->120s->240s, revoke after 3)

Four-stage graduated response:

  Stage 1: Observation (< 50% of limit)
  Stage 2: Warning (50%-75% of limit)
  Stage 3: Soft-limit with latency injection (75%-100% of limit)
  Stage 4: Hard-block with escalating cooldowns (>= 100% of limit)
  Stage 5: Alias revocation (>= 120% of limit or 3 consecutive blocks)
"""

from __future__ import annotations

import math
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

RateLimitStage = Literal["observation", "warning", "soft_limit", "hard_block", "revocation"]

__all__ = [
    "RateLimitStage",
    "RateLimitResult",
    "GraduatedRateLimiter",
]


@dataclass(frozen=True)
class RateLimitResult:
    """The outcome of one :meth:`GraduatedRateLimiter.check` call."""

    stage: RateLimitStage
    current_rate: int
    limit: int
    ratio: float
    injected_latency_ms: int
    blocked: bool
    revoke: bool
    cooldown_seconds: int
    remaining: int
    burst_detected: bool


@dataclass
class _Entry:
    timestamps: List[float] = field(default_factory=list)
    cooldown_until: float = 0.0
    consecutive_blocks: int = 0
    revoked: bool = False
    burst_timestamps: List[float] = field(default_factory=list)


class GraduatedRateLimiter:
    """Alias-scoped graduated rate limiter. Thread-safe."""

    def __init__(
        self,
        default_limit: int = 100,
        window_seconds: float = 60.0,
        soft_limit_base_latency_ms: int = 2000,
        max_entries: int = 50_000,
        endpoint_limits: Optional[Dict[str, int]] = None,
        burst_limit: int = 20,
        initial_cooldown_seconds: int = 60,
        max_consecutive_blocks: int = 3,
    ) -> None:
        self._default_limit = default_limit
        self._window_seconds = window_seconds
        self._soft_limit_base_latency_ms = soft_limit_base_latency_ms
        self._max_entries = max_entries
        self._endpoint_limits: Dict[str, int] = dict(endpoint_limits or {})
        self._burst_limit = burst_limit
        self._initial_cooldown_seconds = initial_cooldown_seconds
        self._max_consecutive_blocks = max_consecutive_blocks

        self._entries: Dict[str, _Entry] = {}
        # Insertion order, for oldest-first eviction mirroring Node's Map
        # iteration order.
        self._order: List[str] = []
        self._lock = threading.Lock()

        self._cleanup_timer: Optional[threading.Timer] = None
        self._destroyed = False
        self._schedule_cleanup()

    def _schedule_cleanup(self) -> None:
        timer = threading.Timer(30.0, self._cleanup_tick)
        timer.daemon = True  # never blocks process exit
        self._cleanup_timer = timer
        timer.start()

    def _cleanup_tick(self) -> None:
        self._cleanup()
        if not self._destroyed:
            self._schedule_cleanup()

    def check(self, key: str, endpoint: Optional[str] = None) -> RateLimitResult:
        """Check the rate limit for an alias, recording the request.

        ``key`` is an alias identifier (IP, session ID, or alias
        token). ``endpoint`` is optional and enables per-endpoint
        limits (GAP-A3-2).
        """
        with self._lock:
            now = time.time()
            existed = key in self._entries
            entry = self._entries.get(key) or _Entry()

            if entry.revoked:
                return RateLimitResult(
                    stage="revocation", current_rate=0, limit=0, ratio=math.inf,
                    injected_latency_ms=0, blocked=True, revoke=False,
                    cooldown_seconds=0, remaining=0, burst_detected=False,
                )

            if entry.cooldown_until > now:
                cooldown_remaining = math.ceil(entry.cooldown_until - now)
                return RateLimitResult(
                    stage="hard_block", current_rate=len(entry.timestamps),
                    limit=self._effective_limit(endpoint), ratio=1.0,
                    injected_latency_ms=0, blocked=True, revoke=False,
                    cooldown_seconds=cooldown_remaining, remaining=0, burst_detected=False,
                )

            window_start = now - self._window_seconds
            entry.timestamps = [t for t in entry.timestamps if t > window_start]

            # GAP-A3-3: clean burst micro-window (1 second).
            burst_window_start = now - 1.0
            entry.burst_timestamps = [t for t in entry.burst_timestamps if t > burst_window_start]

            entry.timestamps.append(now)
            entry.burst_timestamps.append(now)

            if not existed and len(self._entries) >= self._max_entries:
                self._evict_oldest()
            if not existed:
                self._order.append(key)
            self._entries[key] = entry

            limit = self._effective_limit(endpoint)
            current_rate = len(entry.timestamps)
            ratio = current_rate / limit

            # GAP-A3-3: burst detection.
            burst_detected = len(entry.burst_timestamps) > self._burst_limit

            if ratio >= 1.2 or entry.consecutive_blocks >= self._max_consecutive_blocks:
                entry.revoked = True
                return RateLimitResult(
                    stage="revocation", current_rate=current_rate, limit=limit, ratio=ratio,
                    injected_latency_ms=0, blocked=True, revoke=True,
                    cooldown_seconds=0, remaining=0, burst_detected=burst_detected,
                )

            if ratio >= 1.0 or burst_detected:
                entry.consecutive_blocks += 1
                cooldown_multiplier = 2 ** (entry.consecutive_blocks - 1)
                cooldown_seconds = self._initial_cooldown_seconds * cooldown_multiplier
                entry.cooldown_until = now + cooldown_seconds

                return RateLimitResult(
                    stage="hard_block", current_rate=current_rate, limit=limit, ratio=ratio,
                    injected_latency_ms=0, blocked=True, revoke=False,
                    cooldown_seconds=cooldown_seconds, remaining=0, burst_detected=burst_detected,
                )

            if ratio >= 0.75:
                entry.consecutive_blocks = 0

                progress = (ratio - 0.75) / 0.25
                base_latency = self._soft_limit_base_latency_ms * (progress ** 2)
                # GAP-A3-1: add +/-20% random jitter.
                jitter = 0.8 + 0.4 * random.random()
                injected_latency_ms = round(base_latency * jitter)

                return RateLimitResult(
                    stage="soft_limit", current_rate=current_rate, limit=limit, ratio=ratio,
                    injected_latency_ms=injected_latency_ms, blocked=False, revoke=False,
                    cooldown_seconds=0, remaining=max(0, limit - current_rate), burst_detected=burst_detected,
                )

            if ratio >= 0.5:
                entry.consecutive_blocks = 0
                return RateLimitResult(
                    stage="warning", current_rate=current_rate, limit=limit, ratio=ratio,
                    injected_latency_ms=0, blocked=False, revoke=False,
                    cooldown_seconds=0, remaining=max(0, limit - current_rate), burst_detected=False,
                )

            entry.consecutive_blocks = 0
            return RateLimitResult(
                stage="observation", current_rate=current_rate, limit=limit, ratio=ratio,
                injected_latency_ms=0, blocked=False, revoke=False,
                cooldown_seconds=0, remaining=max(0, limit - current_rate), burst_detected=False,
            )

    def revoke_alias(self, key: str) -> None:
        """Manually revoke an alias (e.g. from an external security decision)."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = _Entry(revoked=True)
                self._order.append(key)
            else:
                entry.revoked = True
            self._entries[key] = entry

    def reset_alias(self, key: str) -> None:
        """Reset an alias's rate limit state (e.g. after an admin override)."""
        with self._lock:
            self._entries.pop(key, None)

    def is_revoked(self, key: str) -> bool:
        """Return whether an alias has been revoked."""
        with self._lock:
            entry = self._entries.get(key)
            return entry.revoked if entry else False

    def set_endpoint_limits(self, limits: Dict[str, int]) -> None:
        """Set per-endpoint rate limits (merged into existing ones). GAP-A3-2."""
        with self._lock:
            self._endpoint_limits.update(limits)

    @property
    def size(self) -> int:
        """The current number of tracked aliases."""
        with self._lock:
            return len(self._entries)

    def _effective_limit(self, endpoint: Optional[str]) -> int:
        if not endpoint or not self._endpoint_limits:
            return self._default_limit

        if endpoint in self._endpoint_limits:
            return self._endpoint_limits[endpoint]

        for pattern, limit in self._endpoint_limits.items():
            if pattern.endswith("*") and endpoint.startswith(pattern[:-1]):
                return limit

        return self._default_limit

    def _evict_oldest(self) -> None:
        while self._order:
            oldest = self._order.pop(0)
            if self._entries.pop(oldest, None) is not None:
                return

    def _cleanup(self) -> None:
        with self._lock:
            now = time.time()
            window_start = now - self._window_seconds

            for key in list(self._entries.keys()):
                entry = self._entries[key]
                has_recent_activity = any(t > window_start for t in entry.timestamps)
                in_cooldown = entry.cooldown_until > now

                if not has_recent_activity and not in_cooldown and not entry.revoked:
                    del self._entries[key]

    def destroy(self) -> None:
        """Stop the limiter's cleanup timer and clear its state."""
        self._destroyed = True
        if self._cleanup_timer is not None:
            self._cleanup_timer.cancel()
        with self._lock:
            self._entries.clear()
            self._order.clear()
