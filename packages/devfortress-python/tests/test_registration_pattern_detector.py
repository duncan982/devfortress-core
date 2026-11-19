from devfortress.registration_pattern_detector import RegistrationEvent, RegistrationPatternDetector


def test_single_clean_registration_allowed():
    d = RegistrationPatternDetector()
    result = d.evaluate(RegistrationEvent(ip="1.1.1.1", email="alice@example.com"))
    assert result.allowed is True
    assert result.severity == "LOW"
    assert result.action == "allow"
    assert result.risk_score == 0


def test_ip_velocity_over_threshold_flagged():
    d = RegistrationPatternDetector(max_per_ip=3)
    result = None
    for i in range(5):
        result = d.evaluate(RegistrationEvent(ip="2.2.2.2", email=f"user{i}@example.com"))
    assert any("IP velocity" in s for s in result.signals)
    assert result.risk_score >= 30


def test_domain_velocity_over_threshold_flagged():
    d = RegistrationPatternDetector(max_per_domain=2)
    result = None
    for i in range(4):
        result = d.evaluate(RegistrationEvent(ip=f"3.3.3.{i}", email=f"person{i}@samedomain.com"))
    assert any("Domain velocity" in s for s in result.signals)


def test_disposable_email_domain_flagged():
    d = RegistrationPatternDetector()
    result = d.evaluate(RegistrationEvent(ip="4.4.4.4", email="bob@mailinator.com"))
    assert any("Disposable email domain" in s for s in result.signals)
    assert result.risk_score >= 25


def test_honeypot_trigger_flagged_high_score():
    d = RegistrationPatternDetector()
    result = d.evaluate(
        RegistrationEvent(ip="5.5.5.5", email="carol@example.com", honeypot_triggered=True)
    )
    assert any("Honeypot" in s for s in result.signals)
    assert result.risk_score >= 40


def test_fast_form_fill_flagged():
    d = RegistrationPatternDetector()
    result = d.evaluate(
        RegistrationEvent(ip="6.6.6.6", email="dave@example.com", form_fill_duration_ms=500)
    )
    assert any("Suspiciously fast form fill" in s for s in result.signals)
    assert result.risk_score >= 30


def test_moderately_fast_form_fill_flagged_lower_score():
    d = RegistrationPatternDetector()
    result = d.evaluate(
        RegistrationEvent(ip="6.6.6.7", email="dave2@example.com", form_fill_duration_ms=3000)
    )
    assert any("Fast form fill" in s for s in result.signals)


def test_generated_email_pattern_flagged():
    d = RegistrationPatternDetector()
    result = d.evaluate(RegistrationEvent(ip="7.7.7.7", email="user123@example.com"))
    assert any("generated/sequential pattern" in s for s in result.signals)


def test_identical_user_agent_across_registrations_flagged():
    d = RegistrationPatternDetector(max_per_ip=100)
    result = None
    for i in range(3):
        result = d.evaluate(
            RegistrationEvent(ip="8.8.8.8", email=f"eve{i}@example.com", user_agent="same-ua")
        )
    assert any("Identical user-agent" in s for s in result.signals)


def test_high_risk_score_triggers_captcha():
    # Disposable (25) + honeypot (40) = 65 -> HIGH band -> captcha.
    d = RegistrationPatternDetector()
    result = d.evaluate(
        RegistrationEvent(ip="9.9.9.9", email="frank@mailinator.com", honeypot_triggered=True)
    )
    assert result.severity == "HIGH"
    assert result.action == "captcha"
    assert result.allowed is True


def test_critical_risk_score_blocks():
    # Disposable (25) + honeypot (40) + fast fill (30) + generated pattern (15) = 100 -> CRITICAL -> block.
    d = RegistrationPatternDetector()
    result = d.evaluate(
        RegistrationEvent(
            ip="9.9.9.10",
            email="bot123@mailinator.com",
            honeypot_triggered=True,
            form_fill_duration_ms=500,
        )
    )
    assert result.severity == "CRITICAL"
    assert result.action == "block"
    assert result.allowed is False


def test_get_stats_reports_tracked_ips_and_domains():
    d = RegistrationPatternDetector()
    d.evaluate(RegistrationEvent(ip="10.10.10.10", email="grace@example.com"))
    d.evaluate(RegistrationEvent(ip="10.10.10.11", email="heidi@otherdomain.com"))
    stats = d.get_stats()
    assert stats["tracked_ips"] == 2
    assert stats["tracked_domains"] == 2


def test_destroy_cancels_cleanup_timer():
    d = RegistrationPatternDetector()
    assert d._cleanup_timer is not None
    d.destroy()
    assert d._cleanup_timer is None
