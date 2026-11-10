"""SessionFixationGuard (Invention A13, TODO 419/429): binds a session to
its IP range and user-agent, ported from security-extensions.ts's
SessionFixationGuard.
"""

from devfortress import SessionFixationGuard


def test_registers_and_validates_a_matching_session():
    guard = SessionFixationGuard()
    session_id = guard.register_session("203.0.113.7", "curl/8.0")
    result = guard.validate_session(session_id, "203.0.113.7", "curl/8.0")
    assert result.valid is True
    assert result.regenerate is False
    assert result.drift_score == 0


def test_unknown_session_id_is_rejected():
    guard = SessionFixationGuard()
    result = guard.validate_session("never-registered", "203.0.113.7", "curl/8.0")
    assert result.valid is False
    assert result.regenerate is True
    assert result.drift_score == 100


def test_ip_range_change_alone_is_minor_drift():
    guard = SessionFixationGuard()
    session_id = guard.register_session("203.0.113.7", "curl/8.0")
    result = guard.validate_session(session_id, "198.51.100.1", "curl/8.0")
    assert result.valid is True
    assert result.regenerate is False
    assert result.drift_score == 40


def test_ip_range_and_user_agent_change_together_is_fixation_suspected():
    guard = SessionFixationGuard()
    session_id = guard.register_session("203.0.113.7", "curl/8.0")
    result = guard.validate_session(session_id, "198.51.100.1", "python-requests/2.0")
    assert result.valid is False
    assert result.regenerate is True
    assert result.drift_score == 80
    assert "hijack suspected" in result.reason


def test_old_session_is_removed_when_registering_a_replacement():
    guard = SessionFixationGuard()
    old_id = guard.register_session("203.0.113.7", "curl/8.0")
    guard.register_session("203.0.113.7", "curl/8.0", old_session_id=old_id)
    result = guard.validate_session(old_id, "203.0.113.7", "curl/8.0")
    assert result.valid is False
    assert result.reason == "Unknown session ID"


def test_remove_session_drops_it():
    guard = SessionFixationGuard()
    session_id = guard.register_session("203.0.113.7", "curl/8.0")
    guard.remove_session(session_id)
    result = guard.validate_session(session_id, "203.0.113.7", "curl/8.0")
    assert result.valid is False


def test_get_stats_counts_active_sessions():
    guard = SessionFixationGuard()
    guard.register_session("203.0.113.7", "curl/8.0")
    guard.register_session("203.0.113.8", "curl/8.0")
    assert guard.get_stats() == {"active_sessions": 2}


def test_disabling_ip_binding_ignores_ip_change():
    guard = SessionFixationGuard(bind_to_ip_range=False)
    session_id = guard.register_session("203.0.113.7", "curl/8.0")
    result = guard.validate_session(session_id, "198.51.100.1", "curl/8.0")
    assert result.valid is True
    assert result.drift_score == 0
