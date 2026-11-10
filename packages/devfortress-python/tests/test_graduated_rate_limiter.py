"""GraduatedRateLimiter (Invention A3, TODO 373): alias-scoped graduated
rate limiting with multi-stage response escalation, ported from
graduated-rate-limiter.ts.
"""

import time

from devfortress import GraduatedRateLimiter


def test_observation_stage_below_half_limit():
    limiter = GraduatedRateLimiter(default_limit=100)
    result = limiter.check("alias-1")
    assert result.stage == "observation"
    assert result.blocked is False
    limiter.destroy()


def test_warning_stage_at_half_limit():
    limiter = GraduatedRateLimiter(default_limit=10)
    result = None
    for _ in range(5):
        result = limiter.check("alias-1")
    assert result.stage == "warning"
    assert result.blocked is False
    limiter.destroy()


def test_soft_limit_injects_latency_with_jitter():
    limiter = GraduatedRateLimiter(default_limit=10, soft_limit_base_latency_ms=2000)
    result = None
    for _ in range(8):
        result = limiter.check("alias-1")
    assert result.stage == "soft_limit"
    assert result.blocked is False
    assert result.injected_latency_ms > 0
    limiter.destroy()


def test_hard_block_at_limit():
    limiter = GraduatedRateLimiter(default_limit=5)
    result = None
    for _ in range(5):
        result = limiter.check("alias-1")
    assert result.stage == "hard_block"
    assert result.blocked is True
    assert result.cooldown_seconds == 60
    limiter.destroy()


def test_escalating_cooldown_doubles_each_consecutive_block():
    limiter = GraduatedRateLimiter(default_limit=1, initial_cooldown_seconds=60)

    first = limiter.check("alias-1")
    assert first.stage == "hard_block"
    assert first.cooldown_seconds == 60

    # Force cooldown elapsed and the prior request aged out of the
    # sliding window (as it would by the time a real 60s cooldown
    # elapsed), so the next check records a fresh second consecutive
    # block rather than accumulating ratio from the still-windowed
    # first request.
    entry = limiter._entries["alias-1"]
    entry.cooldown_until = time.time() - 0.01
    entry.timestamps = []

    second = limiter.check("alias-1")
    assert second.stage == "hard_block"
    assert second.cooldown_seconds == 120
    limiter.destroy()


def test_revokes_after_max_consecutive_blocks():
    limiter = GraduatedRateLimiter(default_limit=1, max_consecutive_blocks=3)

    for _ in range(3):
        limiter.check("alias-1")
        limiter._entries["alias-1"].cooldown_until = time.time() - 0.01

    result = limiter.check("alias-1")
    assert result.stage == "revocation"
    assert limiter.is_revoked("alias-1")
    limiter.destroy()


def test_revoked_alias_stays_blocked_without_re_revoking():
    limiter = GraduatedRateLimiter(default_limit=100)
    limiter.revoke_alias("alias-1")
    result = limiter.check("alias-1")
    assert result.stage == "revocation"
    assert result.revoke is False
    limiter.destroy()


def test_reset_alias_clears_escalation():
    limiter = GraduatedRateLimiter(default_limit=1)

    limiter.check("alias-1")
    entry = limiter._entries["alias-1"]
    entry.cooldown_until = time.time() - 0.01
    entry.timestamps = []
    escalated = limiter.check("alias-1")
    assert escalated.cooldown_seconds == 120

    limiter.reset_alias("alias-1")

    result = limiter.check("alias-1")
    assert result.cooldown_seconds == 60
    limiter.destroy()


def test_per_endpoint_limits_override_default():
    limiter = GraduatedRateLimiter(default_limit=100, endpoint_limits={"/api/auth/*": 2})
    limiter.check("alias-1", "/api/auth/login")
    result = limiter.check("alias-1", "/api/auth/login")
    assert result.limit == 2
    assert result.stage == "hard_block"
    limiter.destroy()


def test_burst_detection_triggers_hard_block():
    limiter = GraduatedRateLimiter(default_limit=1000, burst_limit=3)
    result = None
    for _ in range(4):
        result = limiter.check("alias-1")
    assert result.burst_detected is True
    assert result.stage == "hard_block"
    limiter.destroy()


def test_max_entries_evicts_oldest_alias():
    limiter = GraduatedRateLimiter(default_limit=100, max_entries=2)
    limiter.check("alias-1")
    limiter.check("alias-2")
    limiter.check("alias-3")

    assert limiter.size == 2
    assert "alias-1" not in limiter._entries
    limiter.destroy()
