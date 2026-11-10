from devfortress.api_key_aliasing import APIKeyAliasingService


def test_create_and_resolve_alias():
    svc = APIKeyAliasingService(vault_secret="secret123")
    result = svc.create_alias("primary-hash", "agent", "my-key")
    assert result.success is True
    assert svc.resolve(result.alias.alias_id) == result.alias_key


def test_resolve_revoked_alias_returns_none():
    svc = APIKeyAliasingService(vault_secret="secret123")
    result = svc.create_alias("primary-hash", "agent", "my-key")
    svc.revoke_alias(result.alias.alias_id)
    assert svc.resolve(result.alias.alias_id) is None


def test_rotate_alias_marks_old_as_rotating():
    svc = APIKeyAliasingService(vault_secret="secret123")
    result = svc.create_alias("primary-hash", "agent", "my-key")
    rotation = svc.rotate_alias(result.alias.alias_id)
    assert rotation.success is True
    assert rotation.new_alias.alias_id != result.alias.alias_id
    assert svc._aliases[result.alias.alias_id].state == "rotating"


def test_validate_alias_key_detects_fingerprint_mismatch():
    svc = APIKeyAliasingService(vault_secret="secret123")
    result = svc.create_alias("primary-hash", "agent", "my-key", fingerprint="fp-1")
    validation = svc.validate_alias_key(result.alias_key, fingerprint="fp-2")
    assert validation.anomaly_detected is True
    assert validation.valid is False


def test_creation_burst_detected():
    svc = APIKeyAliasingService(vault_secret="secret123", creation_burst_threshold=2)
    for _ in range(3):
        svc.create_alias("primary-hash", "agent", "key")
    result = svc.create_alias("primary-hash", "agent", "key")
    assert result.success is False
    assert "burst" in result.error.lower()


def test_max_aliases_per_key_enforced():
    svc = APIKeyAliasingService(vault_secret="secret123", max_aliases_per_key=1, anomaly_detection=False)
    svc.create_alias("primary-hash", "agent", "key-1")
    result = svc.create_alias("primary-hash", "agent", "key-2")
    assert result.success is False
