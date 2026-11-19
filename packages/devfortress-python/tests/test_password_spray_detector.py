from devfortress.password_spray_detector import AuthFailureEvent, PasswordSprayDetector


def _event(account_id, credential_hash="hash-1", ip="1.1.1.1", ts=None):
    return AuthFailureEvent(ip=ip, credential_hash=credential_hash, account_id=account_id, timestamp=ts)


def test_below_threshold_allows():
    d = PasswordSprayDetector(account_threshold=5, window_ms=300_000)
    result = d.record_failure(_event("acct-1"))
    assert result.detected is False
    assert result.severity == "LOW"
    assert result.action == "allow"
    assert result.affected_accounts == 1


def test_medium_severity_rate_limits_with_graduated_response():
    d = PasswordSprayDetector(account_threshold=5, window_ms=300_000, graduated_response=True)
    result = None
    for i in range(6):
        result = d.record_failure(_event(f"acct-{i}"))
    assert result.detected is True
    assert result.severity == "MEDIUM"
    assert result.action == "rate_limit"


def test_high_severity_captcha_challenge():
    d = PasswordSprayDetector(account_threshold=5, window_ms=300_000, graduated_response=True)
    result = None
    for i in range(11):
        result = d.record_failure(_event(f"acct-{i}"))
    assert result.severity == "HIGH"
    assert result.action == "captcha_challenge"


def test_critical_severity_blocks():
    d = PasswordSprayDetector(account_threshold=5, window_ms=300_000)
    result = None
    for i in range(21):
        result = d.record_failure(_event(f"acct-{i}"))
    assert result.severity == "CRITICAL"
    assert result.action == "block"
    assert result.confidence == 0.98


def test_graduated_response_disabled_escalates_to_block_sooner():
    d = PasswordSprayDetector(account_threshold=5, window_ms=300_000, graduated_response=False)
    result = None
    for i in range(6):
        result = d.record_failure(_event(f"acct-{i}"))
    # MEDIUM band falls back to captcha_challenge (not rate_limit) when graduated_response=False.
    assert result.severity == "MEDIUM"
    assert result.action == "captcha_challenge"


def test_different_credentials_do_not_aggregate():
    d = PasswordSprayDetector(account_threshold=5, window_ms=300_000)
    result = None
    for i in range(6):
        result = d.record_failure(_event(f"acct-{i}", credential_hash=f"hash-{i}"))
    assert result.detected is False


def test_source_ips_are_tracked_across_accounts():
    d = PasswordSprayDetector(account_threshold=2, window_ms=300_000)
    d.record_failure(_event("acct-1", ip="10.0.0.1"))
    result = d.record_failure(_event("acct-2", ip="10.0.0.2"))
    assert sorted(result.source_ips) == ["10.0.0.1", "10.0.0.2"]


def test_entries_outside_window_are_not_counted():
    d = PasswordSprayDetector(account_threshold=3, window_ms=1000)
    d.record_failure(_event("acct-1", ts=0))
    d.record_failure(_event("acct-2", ts=0))
    # Far outside the window — the record resets instead of accumulating.
    result = d.record_failure(_event("acct-3", ts=1_000_000))
    assert result.affected_accounts == 1
    assert result.detected is False


def test_get_stats_reports_tracked_credentials_and_failures():
    d = PasswordSprayDetector(account_threshold=5, window_ms=300_000)
    d.record_failure(_event("acct-1"))
    d.record_failure(_event("acct-2"))
    stats = d.get_stats()
    assert stats["tracked_credentials"] == 1
    assert stats["total_failures"] == 2


def test_destroy_cancels_cleanup_timer():
    d = PasswordSprayDetector(window_ms=300_000)
    assert d._cleanup_timer is not None
    d.destroy()
    assert d._cleanup_timer is None
