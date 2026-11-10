import pytest

from devfortress.credential_isolation import CredentialIsolationManager


@pytest.fixture
def manager():
    return CredentialIsolationManager(encryption_key="a" * 64)


def test_requires_encryption_key():
    with pytest.raises(ValueError):
        CredentialIsolationManager(encryption_key=None)


def test_rejects_malformed_key():
    with pytest.raises(ValueError):
        CredentialIsolationManager(encryption_key="not-hex")


@pytest.mark.asyncio
async def test_create_and_resolve_alias(manager):
    alias = await manager.create_alias("real-token-1", "user-1")
    assert alias.startswith("df_sid_")
    resolved = await manager.resolve_alias(alias)
    assert resolved.real_token == "real-token-1"
    assert resolved.user_id == "user-1"


@pytest.mark.asyncio
async def test_create_alias_is_idempotent_for_same_token(manager):
    a1 = await manager.create_alias("real-token-2", "user-1")
    a2 = await manager.create_alias("real-token-2", "user-1")
    assert a1 == a2


@pytest.mark.asyncio
async def test_revoke_by_alias_removes_mapping(manager):
    alias = await manager.create_alias("real-token-3", "user-1")
    resolved = await manager.revoke_by_alias(alias, "active_threat")
    assert resolved.real_token == "real-token-3"
    assert await manager.resolve_alias(alias) is None
    assert await manager.is_revoked(alias) is True


@pytest.mark.asyncio
async def test_revoke_unknown_alias_triggers_fallback(manager):
    seen = []

    async def fallback(subject_id, reason):
        seen.append((subject_id, reason))

    m = CredentialIsolationManager(encryption_key="a" * 64, on_fallback_revocation=fallback)
    result = await m.revoke_by_alias("df_sid_unknown", "active_threat", subject_id="user-9")
    assert result is None
    assert seen[0][0] == "user-9"


@pytest.mark.asyncio
async def test_rotate_alias_keeps_old_resolvable_during_grace_period(manager):
    old_alias = await manager.create_alias("real-token-4", "user-1")
    new_alias = await manager.rotate_alias(old_alias)
    assert new_alias != old_alias
    # Old alias remains resolvable for revocation purposes during the grace period.
    old_resolved = await manager.resolve_alias(old_alias)
    assert old_resolved.real_token == "real-token-4"
    new_resolved = await manager.resolve_alias(new_alias)
    assert new_resolved.real_token == "real-token-4"


@pytest.mark.asyncio
async def test_revoke_on_logout(manager):
    alias = await manager.create_alias("real-token-5", "user-1")
    await manager.revoke_on_logout("real-token-5")
    assert await manager.resolve_alias(alias) is None
    details = await manager.get_revocation_details(alias)
    assert details["reason"] == "logout"
