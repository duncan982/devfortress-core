import pytest

from devfortress.credential_vault import CredentialVault, decrypt, derive_vault_key, encrypt


def test_derive_vault_key_is_32_bytes_and_deterministic():
    k1 = derive_vault_key("secret", "ctx")
    k2 = derive_vault_key("secret", "ctx")
    assert len(k1) == 32
    assert k1 == k2


def test_derive_vault_key_differs_by_context():
    k1 = derive_vault_key("secret", "ctx-a")
    k2 = derive_vault_key("secret", "ctx-b")
    assert k1 != k2


def test_encrypt_decrypt_roundtrip():
    key = derive_vault_key("secret", "ctx")
    record = encrypt("hello world", key)
    assert decrypt(record, key) == "hello world"


def test_decrypt_raises_on_auth_tag_mismatch():
    key = derive_vault_key("secret", "ctx")
    other_key = derive_vault_key("other", "ctx")
    record = encrypt("hello world", key)
    with pytest.raises(Exception):
        decrypt(record, other_key)


def test_vault_register_resolve_revoke():
    vault = CredentialVault()
    key = derive_vault_key("secret", "ctx")
    vault.register("alias1", "real-value", key)
    assert vault.resolve("alias1") == "real-value"
    assert vault.has("alias1") is True
    assert vault.revoke("alias1") is True
    assert vault.resolve("alias1") is None
    assert vault.has("alias1") is False


def test_vault_resolve_unknown_alias_returns_none():
    vault = CredentialVault()
    assert vault.resolve("nope") is None


def test_vault_evicts_oldest_when_full():
    vault = CredentialVault(max_entries=2)
    key = derive_vault_key("secret", "ctx")
    vault.register("a", "1", key)
    vault.register("b", "2", key)
    vault.register("c", "3", key)
    assert vault.has("a") is False
    assert vault.has("b") is True
    assert vault.has("c") is True
