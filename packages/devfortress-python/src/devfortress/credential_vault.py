"""Shared AES-256-GCM reversible-encryption primitive.

Port of the Node SDK's ``credential-vault.ts``. Generic reversible-encryption
primitive used by ``api_key_aliasing.py`` and other alias-keyed stores
built on top of this.

Key derivation: HKDF-SHA256 from an application secret, zero salt, and a
namespaced info string — same call shape as ``agent_identity/alias_generator.py``'s
``hkdf_alias``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAX_TRACKED_RECORDS = 50_000


@dataclass(frozen=True)
class VaultEncryptedRecord:
    ciphertext: str  # hex
    iv: str  # hex
    auth_tag: str  # hex


def derive_vault_key(application_secret: Union[str, bytes], context: str) -> bytes:
    """Derive a 32-byte AES-256 key from an application secret + context via HKDF-SHA256."""
    secret_bytes = (
        application_secret
        if isinstance(application_secret, bytes)
        else application_secret.encode("utf-8")
    )
    info = f"devfortress.credential-vault.{context}".encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(32),
        info=info,
    ).derive(secret_bytes)


def encrypt(real_credential: str, key: bytes) -> VaultEncryptedRecord:
    """Pure primitive: encrypt a real credential with an explicit key."""
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    # cryptography's AESGCM appends the 16-byte auth tag to the ciphertext.
    sealed = aesgcm.encrypt(iv, real_credential.encode("utf-8"), None)
    ciphertext, auth_tag = sealed[:-16], sealed[-16:]
    return VaultEncryptedRecord(
        ciphertext=ciphertext.hex(), iv=iv.hex(), auth_tag=auth_tag.hex()
    )


def decrypt(record: VaultEncryptedRecord, key: bytes) -> str:
    """Pure primitive: decrypt a ciphertext bundle. Raises on auth-tag mismatch
    (never returns garbage plaintext)."""
    aesgcm = AESGCM(key)
    sealed = bytes.fromhex(record.ciphertext) + bytes.fromhex(record.auth_tag)
    iv = bytes.fromhex(record.iv)
    return aesgcm.decrypt(iv, sealed, None).decode("utf-8")


@dataclass
class _StoredRecord:
    record: VaultEncryptedRecord
    key: bytes


class CredentialVault:
    """A self-contained, in-memory vault: encrypts + stores real credentials
    under an alias, later resolves the alias back to plaintext. Used wherever
    a class needs its own alias-keyed encrypted store."""

    def __init__(self, max_entries: int = MAX_TRACKED_RECORDS):
        self._max_entries = max_entries
        self._store: "Dict[str, _StoredRecord]" = {}

    def register(self, alias: str, real_credential: str, key: bytes) -> VaultEncryptedRecord:
        record = encrypt(real_credential, key)
        if alias in self._store:
            del self._store[alias]
        elif len(self._store) >= self._max_entries:
            oldest = next(iter(self._store), None)
            if oldest is not None:
                del self._store[oldest]
        self._store[alias] = _StoredRecord(record=record, key=key)
        return record

    def resolve(self, alias: str) -> Optional[str]:
        """Returns None only for an unknown alias. Raises on auth-tag mismatch
        (does not return garbage plaintext) — matches the Node port exactly:
        no try/except here, decrypt()'s exception propagates to the caller."""
        stored = self._store.get(alias)
        if stored is None:
            return None
        return decrypt(stored.record, stored.key)

    def revoke(self, alias: str) -> bool:
        if alias in self._store:
            del self._store[alias]
            return True
        return False

    def has(self, alias: str) -> bool:
        return alias in self._store
