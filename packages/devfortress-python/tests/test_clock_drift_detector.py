"""ClockDriftDetector (Invention A18, TODO 419): server-authoritative
clock drift detection, ported from security-extensions.ts's
ClockDriftDetector.
"""

import time

from devfortress import ClockDriftDetector


def now_ms() -> float:
    return time.time() * 1000


def test_within_acceptable_threshold_is_allowed():
    detector = ClockDriftDetector()
    result = detector.check(now_ms())
    assert result.valid is True
    assert result.severity == "LOW"
    assert result.action == "allow"


def test_suspicious_drift_warns_but_stays_valid():
    detector = ClockDriftDetector()
    result = detector.check(now_ms() - 60_000)  # 60s behind
    assert result.valid is True
    assert result.severity == "MEDIUM"
    assert result.action == "warn"


def test_high_drift_enforces_server_time():
    detector = ClockDriftDetector()
    result = detector.check(now_ms() - 200_000)  # ~3.3min behind
    assert result.valid is True
    assert result.severity == "HIGH"
    assert result.action == "use_server_time"


def test_critical_drift_is_rejected():
    detector = ClockDriftDetector()
    result = detector.check(now_ms() - 600_000)  # 10min behind
    assert result.valid is False
    assert result.severity == "CRITICAL"
    assert result.action == "reject"


def test_ahead_of_server_time_is_also_detected():
    detector = ClockDriftDetector()
    result = detector.check(now_ms() + 600_000)  # 10min ahead
    assert result.valid is False
    assert "ahead" in result.reason


def test_custom_thresholds_are_respected():
    detector = ClockDriftDetector(
        acceptable_threshold_ms=1_000,
        suspicious_threshold_ms=5_000,
        critical_threshold_ms=10_000,
    )
    assert detector.check(now_ms() - 2_000).action == "warn"
    assert detector.check(now_ms() - 20_000).action == "reject"


def test_drift_trend_requires_at_least_three_samples():
    detector = ClockDriftDetector()
    detector.check(now_ms() - 1_000, client_id="c1")
    detector.check(now_ms() - 2_000, client_id="c1")
    assert detector.get_drift_trend("c1") is None

    detector.check(now_ms() - 3_000, client_id="c1")
    trend = detector.get_drift_trend("c1")
    assert trend is not None
    assert trend.avg_drift > 0


def test_drift_trend_detects_increasing_drift():
    detector = ClockDriftDetector()
    for drift_ms in (1_000, 1_000, 1_000, 5_000, 5_000, 5_000):
        detector.check(now_ms() - drift_ms, client_id="growing")

    trend = detector.get_drift_trend("growing")
    assert trend is not None
    assert trend.increasing is True


def test_history_is_bounded_per_client():
    detector = ClockDriftDetector()
    for _ in range(150):
        detector.check(now_ms(), client_id="busy-client")
    assert len(detector._drift_history["busy-client"].drifts) == 100


def test_get_stats_counts_tracked_clients():
    detector = ClockDriftDetector()
    detector.check(now_ms(), client_id="a")
    detector.check(now_ms(), client_id="b")
    detector.check(now_ms())  # no client_id — not tracked
    assert detector.get_stats() == {"tracked_clients": 2}
