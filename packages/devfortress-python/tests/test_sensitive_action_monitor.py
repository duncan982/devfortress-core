"""SensitiveActionMonitor (Invention A6, TODO 419/424): weighted
behavioral-deviation scoring over a sliding window of sensitive account
actions, ported from sensitive-action-monitor.ts.
"""

from devfortress import SensitiveActionEvent, SensitiveActionMonitor


def _event(user_id="u1", action_type="password_change", ip="203.0.113.7", timestamp=1_700_000_000_000):
    return SensitiveActionEvent(user_id=user_id, action_type=action_type, ip=ip, timestamp=timestamp)


def test_single_low_weight_action_is_allowed():
    monitor = SensitiveActionMonitor()
    result = monitor.evaluate(_event(action_type="api_key_create"))
    assert result.allowed is True
    assert result.severity == "LOW"
    assert result.action == "allow"


def test_account_takeover_combo_is_critical_and_revokes():
    monitor = SensitiveActionMonitor()
    monitor.evaluate(_event(action_type="mfa_remove", timestamp=1_700_000_000_000))
    result = monitor.evaluate(_event(action_type="password_change", timestamp=1_700_000_000_500))
    assert result.severity == "CRITICAL"
    assert result.action == "revoke_session"
    assert result.allowed is False


def test_auto_revoke_disabled_blocks_instead_of_revoking():
    monitor = SensitiveActionMonitor(auto_revoke=False)
    monitor.evaluate(_event(action_type="mfa_remove", timestamp=1_700_000_000_000))
    result = monitor.evaluate(_event(action_type="password_change", timestamp=1_700_000_000_500))
    assert result.action == "block"
    assert result.allowed is False


def test_ip_switching_during_sensitive_window_raises_risk():
    monitor = SensitiveActionMonitor()
    monitor.evaluate(_event(action_type="email_change", ip="203.0.113.7", timestamp=1_700_000_000_000))
    result = monitor.evaluate(_event(action_type="email_change", ip="198.51.100.1", timestamp=1_700_000_000_500))
    assert result.risk_score > 70  # base 35 + velocity 15 + ip-switch 20, x2 multiplier, capped


def test_actions_outside_window_are_purged():
    monitor = SensitiveActionMonitor(window_ms=1_000)
    monitor.evaluate(_event(action_type="mfa_remove", timestamp=0))
    result = monitor.evaluate(_event(action_type="password_change", timestamp=5_000))
    # The mfa_remove action is outside the 1s window by the time password_change arrives,
    # so the account-takeover combo should not fire.
    assert result.actions_in_window == 1


def test_get_stats_counts_tracked_users():
    monitor = SensitiveActionMonitor()
    monitor.evaluate(_event(user_id="u1"))
    monitor.evaluate(_event(user_id="u2"))
    assert monitor.get_stats() == {"tracked_users": 2}


def test_cleanup_drops_users_with_no_remaining_actions():
    monitor = SensitiveActionMonitor(window_ms=1_000)
    monitor.evaluate(_event(user_id="u1", timestamp=0))
    monitor.cleanup(now_ms=5_000)
    assert monitor.get_stats() == {"tracked_users": 0}
