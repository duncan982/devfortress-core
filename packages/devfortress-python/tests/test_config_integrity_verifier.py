"""ConfigIntegrityVerifier (Invention A9, TODO 419/426): seals an
HMAC-SHA256 digest of a config snapshot and flags drift, ported from
config-integrity-verifier.ts.
"""

from devfortress import ConfigIntegrityVerifier


def test_unmodified_config_verifies_clean():
    verifier = ConfigIntegrityVerifier()
    config = {"mode": "external", "blockThreshold": 80}
    verifier.seal(config)
    result = verifier.verify(config)
    assert result.valid is True
    assert result.violations == []
    assert result.check_count == 1


def test_tampered_critical_field_is_flagged_critical():
    verifier = ConfigIntegrityVerifier()
    original = {"mode": "external", "blockThreshold": 80}
    verifier.seal(original)
    tampered = {"mode": "internal", "blockThreshold": 80}
    result = verifier.verify(tampered)
    assert result.valid is False
    assert len(result.violations) == 1
    assert result.violations[0].field == "mode"
    assert result.violations[0].severity == "CRITICAL"


def test_tampered_non_critical_field_is_flagged_high():
    verifier = ConfigIntegrityVerifier()
    original = {"debug": False}
    verifier.seal(original)
    tampered = {"debug": True}
    result = verifier.verify(tampered)
    assert result.valid is False
    assert result.violations[0].severity == "HIGH"


def test_nested_config_drift_is_found_with_dotted_field_path():
    verifier = ConfigIntegrityVerifier()
    original = {"limits": {"rateLimitMax": 100}}
    verifier.seal(original)
    tampered = {"limits": {"rateLimitMax": 999}}
    result = verifier.verify(tampered)
    assert result.valid is False
    assert result.violations[0].field == "limits.rateLimitMax"
    assert result.violations[0].severity == "CRITICAL"


def test_on_violation_callback_fires_for_each_violation():
    seen = []
    verifier = ConfigIntegrityVerifier(on_violation=lambda v: seen.append(v.field))
    verifier.seal({"a": 1, "b": 2})
    verifier.verify({"a": 9, "b": 9})
    assert sorted(seen) == ["a", "b"]


def test_violations_accumulate_across_multiple_verify_calls():
    verifier = ConfigIntegrityVerifier()
    verifier.seal({"a": 1})
    verifier.verify({"a": 2})
    verifier.verify({"a": 3})
    status = verifier.get_status()
    assert status.check_count == 2
    assert len(status.violations) == 2


def test_get_status_without_verifying_is_clean_after_seal():
    verifier = ConfigIntegrityVerifier()
    verifier.seal({"a": 1})
    status = verifier.get_status()
    assert status.valid is True
    assert status.check_count == 0
