"""PlatformCircuitBreaker (TODO 372): platform-connectivity breaker,
ported from circuit-breaker.ts.
"""

import time

from devfortress import PlatformCircuitBreaker
from devfortress.circuit_breaker import STALE_THRESHOLD_SECONDS


def test_starts_closed_and_allows_external_calls():
    breaker = PlatformCircuitBreaker()
    assert breaker.state == "closed"
    assert breaker.should_call_external() is True


def test_opens_after_consecutive_failures():
    transitions = []
    breaker = PlatformCircuitBreaker(
        failure_threshold=3,
        on_state_change=lambda f, t, r: transitions.append(f"{f}->{t}"),
    )

    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == "closed"

    breaker.record_failure()
    assert breaker.state == "open"
    assert transitions == ["closed->open"]
    assert breaker.should_call_external() is False


def test_half_open_after_recovery_time_elapsed():
    breaker = PlatformCircuitBreaker(failure_threshold=1, recovery_time_seconds=0.01)
    breaker.record_failure()
    time.sleep(0.02)

    assert breaker.should_call_external() is True
    assert breaker.state == "half-open"


def test_half_open_success_closes_circuit():
    breaker = PlatformCircuitBreaker(failure_threshold=1, recovery_time_seconds=0.01)
    breaker.record_failure()
    time.sleep(0.02)
    breaker.should_call_external()

    breaker.record_success()
    assert breaker.state == "closed"


def test_half_open_failure_reopens_circuit():
    breaker = PlatformCircuitBreaker(failure_threshold=1, recovery_time_seconds=0.01)
    breaker.record_failure()
    time.sleep(0.02)
    breaker.should_call_external()

    breaker.record_failure()
    assert breaker.state == "open"


def test_reset_forces_closed_and_clears_failures():
    breaker = PlatformCircuitBreaker(failure_threshold=1)
    breaker.record_failure()
    assert breaker.state == "open"

    breaker.reset()
    assert breaker.state == "closed"
    assert breaker.get_diagnostics().failure_count == 0


def test_rules_become_stale_after_threshold():
    breaker = PlatformCircuitBreaker(failure_threshold=1)
    breaker.record_failure()

    breaker._stale_since = time.time() - STALE_THRESHOLD_SECONDS - 1

    assert breaker.is_rules_stale() is True
    assert breaker.get_diagnostics().rules_stale is True


def test_success_resets_stale_tracking():
    breaker = PlatformCircuitBreaker(failure_threshold=1, recovery_time_seconds=0.01)
    breaker.record_failure()
    time.sleep(0.02)
    breaker.should_call_external()
    breaker.record_success()

    assert breaker.is_rules_stale() is False
