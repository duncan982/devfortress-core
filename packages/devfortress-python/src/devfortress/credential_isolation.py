"""Credential Isolation Security — Session Indirection (Hardened).

Port of the Node SDK's ``credential-isolation.ts``.

Replaces real session tokens with opaque, random aliases before they leave
the client app's trust boundary. DevFortress only ever sees the alias —
never the real token.

Uses CSPRNG — the alias has no mathematical relationship to the real token.

Security hardening:
- AES-256-GCM encryption of forward mapping values
- SHA-256 hashed reverse mapping keys
- SubjectId-level fallback revocation on cache failure
- Local emergency blocklist — synchronous, pre-webhook
- Alias rotation grace period — old aliases remain resolvable
- In-memory LRU fallback cache — survives Redis outages

For production use with Redis, implement the ``CacheAdapter`` protocol.
Falls back to in-memory storage for development/testing.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Literal, Optional, Protocol, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RevocationReason = Literal["active_threat", "rotation_expired", "logout"]

ENCRYPTED_PREFIX = "enc:v1:"


# ── Cache Adapter Protocol ──────────────────────────────────


class CacheAdapter(Protocol):
    async def get(self, key: str) -> Optional[str]: ...
    async def set(self, key: str, value: str, ttl_seconds: int) -> None: ...
    async def delete(self, key: str) -> None: ...


# ── AES-256-GCM Encryption Helpers ──────────────────────────


def _encrypt(plaintext: str, key_hex: str) -> str:
    key = bytes.fromhex(key_hex)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    sealed = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    encrypted, auth_tag = sealed[:-16], sealed[-16:]
    return ENCRYPTED_PREFIX + iv.hex() + ":" + encrypted.hex() + ":" + auth_tag.hex()


def _decrypt(ciphertext: str, key_hex: str) -> str:
    if not ciphertext.startswith(ENCRYPTED_PREFIX):
        # Legacy unencrypted format — return as-is (rolling migration)
        return ciphertext
    parts = ciphertext[len(ENCRYPTED_PREFIX):].split(":")
    if len(parts) != 3:
        raise ValueError("Invalid encrypted format")
    iv = bytes.fromhex(parts[0])
    encrypted = bytes.fromhex(parts[1])
    auth_tag = bytes.fromhex(parts[2])
    key = bytes.fromhex(key_hex)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, encrypted + auth_tag, None).decode("utf-8")


def _hash_token(real_token: str) -> str:
    return hashlib.sha256(real_token.encode("utf-8")).hexdigest()


# ── In-Memory LRU Cache — Fallback for Redis ───────────────


class _LRUCache:
    def __init__(self, max_entries: int = 1000, default_ttl_seconds: int = 60):
        self._max_entries = max_entries
        self._default_ttl = default_ttl_seconds
        self._cache: "Dict[str, tuple]" = {}  # key -> (value, expires_at_ms)

    def get(self, key: str) -> Optional[str]:
        entry = self._cache.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.time() * 1000 > expires_at:
            del self._cache[key]
            return None
        # Move to end (most recently used)
        del self._cache[key]
        self._cache[key] = (value, expires_at)
        return value

    def set(self, key: str, value: str, ttl_seconds: Optional[float] = None) -> None:
        if key in self._cache:
            del self._cache[key]
        elif len(self._cache) >= self._max_entries:
            oldest = next(iter(self._cache), None)
            if oldest is not None:
                del self._cache[oldest]
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        self._cache[key] = (value, time.time() * 1000 + ttl * 1000)

    def delete(self, key: str) -> None:
        self._cache.pop(key, None)

    def has(self, key: str) -> bool:
        return self.get(key) is not None


# ── In-Memory Cache (development fallback) ──────────────────


class _MemoryAdapter:
    def __init__(self):
        self._store: "Dict[str, tuple]" = {}

    async def get(self, key: str) -> Optional[str]:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.time() * 1000 > expires_at:
            del self._store[key]
            return None
        return value

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self._store[key] = (value, time.time() * 1000 + ttl_seconds * 1000)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)


_memory_adapter = _MemoryAdapter()


# ── Emergency Blocklist ─────────────────────────────────────


class ThreatInterceptor:
    """Local emergency blocklist — synchronous-fast, pre-webhook IP blocking.
    When a critical event fires, the IP is written here BEFORE the webhook is
    sent, ensuring the IP is blocked even if the webhook receiver is down."""

    def __init__(self, cache: Optional[CacheAdapter] = None, ttl_seconds: int = 900):
        self._cache: CacheAdapter = cache or _memory_adapter
        self._lru = _LRUCache(5000, ttl_seconds)
        self._default_ttl_seconds = ttl_seconds

    async def block_ip(self, ip: str, reason: str = "critical_event") -> None:
        value = json.dumps({"reason": reason, "blockedAt": time.time() * 1000})
        self._lru.set(f"emergency:block:{ip}", value, self._default_ttl_seconds)
        try:
            await self._cache.set(f"emergency:block:{ip}", value, self._default_ttl_seconds)
        except Exception:
            pass  # LRU cache is already set — Redis failure doesn't prevent blocking

    async def is_blocked(self, ip: str) -> bool:
        if self._lru.has(f"emergency:block:{ip}"):
            return True
        try:
            val = await self._cache.get(f"emergency:block:{ip}")
            return val is not None
        except Exception:
            return False  # On Redis failure, LRU was already checked

    async def unblock_ip(self, ip: str) -> None:
        self._lru.delete(f"emergency:block:{ip}")
        try:
            await self._cache.delete(f"emergency:block:{ip}")
        except Exception:
            pass


# ── Credential Isolation Manager (Hardened) ────────────────


@dataclass
class IsolatedCredentialData:
    real_token: str
    user_id: str
    created_at: float


class CredentialIsolationManager:
    def __init__(
        self,
        cache_adapter: Optional[CacheAdapter] = None,
        *,
        encryption_key: Optional[str] = None,
        lru_max_entries: int = 1000,
        lru_ttl_seconds: int = 60,
        rotation_grace_period_seconds: int = 1200,
        on_fallback_revocation: Optional[Callable[[str, str], Union[Awaitable[None], None]]] = None,
    ):
        self._cache: CacheAdapter = cache_adapter or _memory_adapter
        self._lru = _LRUCache(lru_max_entries, lru_ttl_seconds)
        self._rotation_grace_period = rotation_grace_period_seconds
        self._on_fallback_revocation = on_fallback_revocation

        # Encryption is mandatory: credentials must never be cached in plaintext.
        # Fail loudly at construction time rather than silently no-op'ing.
        key = encryption_key or os.environ.get("DEVFORTRESS_REDIS_ENCRYPTION_KEY")
        if not key:
            raise ValueError(
                "DEVFORTRESS_REDIS_ENCRYPTION_KEY is required — CredentialIsolationManager "
                "refuses to store credentials without encryption. Set this env var to a "
                "32-byte hex string (64 hex characters), e.g. `openssl rand -hex 32`, or "
                "pass encryption_key explicitly."
            )
        if len(key) != 64:
            raise ValueError(
                "DEVFORTRESS_REDIS_ENCRYPTION_KEY must be a 32-byte hex string (64 hex characters)"
            )
        self._encryption_key = key

    def _encrypt_value(self, plaintext: str) -> str:
        return _encrypt(plaintext, self._encryption_key)

    def _decrypt_value(self, ciphertext: str) -> str:
        return _decrypt(ciphertext, self._encryption_key)

    async def _cache_get(self, key: str) -> Optional[str]:
        try:
            value = await self._cache.get(key)
            if value is not None:
                self._lru.set(key, value)  # backfill LRU on successful read
                return value
        except Exception:
            pass  # Redis failure — fall back to LRU
        return self._lru.get(key)

    async def _cache_set(self, key: str, value: str, ttl_seconds: int) -> None:
        self._lru.set(key, value, ttl_seconds)  # always write to LRU first
        try:
            await self._cache.set(key, value, ttl_seconds)
        except Exception:
            pass  # LRU is set — Redis failure is survivable

    async def _cache_del(self, key: str) -> None:
        self._lru.delete(key)
        try:
            await self._cache.delete(key)
        except Exception:
            pass

    async def create_alias(self, real_token: str, user_id: str, ttl_seconds: int = 3600) -> str:
        """Generate a cryptographically random alias for a real session token.
        The alias has NO mathematical relationship to the real token.

        Forward mapping value is AES-256-GCM encrypted. Reverse mapping key
        uses SHA-256(realToken) instead of plaintext. Writes to both Redis
        and LRU cache for fallback resilience.
        """
        token_hash = _hash_token(real_token)

        existing_alias = await self._cache_get(f"cred:alias:{token_hash}")
        if existing_alias:
            return existing_alias

        alias = "df_sid_" + secrets.token_hex(16)

        data = {
            "realToken": real_token,
            "userId": user_id,
            "createdAt": time.time() * 1000,
        }

        encrypted_data = self._encrypt_value(json.dumps(data))
        await self._cache_set(f"alias:{alias}", encrypted_data, ttl_seconds)
        await self._cache_set(f"cred:alias:{token_hash}", alias, ttl_seconds)

        return alias

    async def resolve_alias(self, alias: str) -> Optional[IsolatedCredentialData]:
        """Resolve an alias back to the real token and user.
        Called ONLY when a revocation webhook arrives from DevFortress.

        Decrypts AES-256-GCM encrypted values. Returns data even for
        aliases in "rotating" status. Falls back to LRU cache on Redis
        failure.
        """
        raw = await self._cache_get(f"alias:{alias}")
        if not raw:
            return None
        try:
            decrypted = self._decrypt_value(raw)
            data = json.loads(decrypted)
            # alias is valid for revocation even if rotating
            return IsolatedCredentialData(
                real_token=data["realToken"],
                user_id=data["userId"],
                created_at=data["createdAt"],
            )
        except Exception:
            return None

    async def revoke_by_alias(
        self,
        alias: str,
        reason: RevocationReason = "active_threat",
        subject_id: Optional[str] = None,
    ) -> Optional[IsolatedCredentialData]:
        """Revoke a session by alias. The real token is resolved within the
        client app — DevFortress never touches the real token.

        On cache failure, falls back to subjectId-level revocation.
        Records revocation_reason in audit marker.
        """
        try:
            resolved = await self.resolve_alias(alias)
            if not resolved:
                if subject_id and self._on_fallback_revocation:
                    result = self._on_fallback_revocation(
                        subject_id,
                        f"[DF] alias resolution failed for {alias} — falling back to subjectId revocation",
                    )
                    if result is not None:
                        await result
                return None

            token_hash = _hash_token(resolved.real_token)
            await self._cache_del(f"alias:{alias}")
            await self._cache_del(f"cred:alias:{token_hash}")

            revocation_marker = json.dumps(
                {
                    "revoked": True,
                    "reason": reason,
                    "revokedAt": time.time() * 1000,
                    "revocation_scope": "precise",
                }
            )
            await self._cache_set(f"revoked:alias:{alias}", revocation_marker, 86400)

            return resolved
        except Exception as error:
            fallback_subject = subject_id or "unknown"
            if self._on_fallback_revocation:
                result = self._on_fallback_revocation(
                    fallback_subject,
                    f"[DF] cache error during revoke_by_alias({alias}) — falling back to "
                    f"subjectId revocation. Error: {error}",
                )
                if result is not None:
                    await result
            try:
                revocation_marker = json.dumps(
                    {
                        "revoked": True,
                        "reason": reason,
                        "revokedAt": time.time() * 1000,
                        "revocation_scope": "broad",
                    }
                )
                await self._cache_set(f"revoked:alias:{alias}", revocation_marker, 86400)
            except Exception:
                pass
            return None

    async def rotate_alias(self, old_alias: str, ttl_seconds: int = 3600) -> Optional[str]:
        """Rotate alias — replaces the alias for a live session.

        Old alias is NOT deleted immediately. Instead, it gets a grace
        period TTL and is marked with status "rotating". The old alias
        remains resolvable for revocation purposes, but canCreateNewEvents
        is set to false.
        """
        resolved = await self.resolve_alias(old_alias)
        if not resolved:
            return None

        rotating_data = {
            "realToken": resolved.real_token,
            "userId": resolved.user_id,
            "createdAt": resolved.created_at,
            "status": "rotating",
            "canCreateNewEvents": False,
        }
        encrypted_rotating = self._encrypt_value(json.dumps(rotating_data))
        await self._cache_set(f"alias:{old_alias}", encrypted_rotating, self._rotation_grace_period)

        token_hash = _hash_token(resolved.real_token)
        await self._cache_del(f"cred:alias:{token_hash}")

        return await self.create_alias(resolved.real_token, resolved.user_id, ttl_seconds)

    async def revoke_on_logout(self, real_token: str) -> None:
        """Clean up alias when user logs out normally.
        Always call this on logout — don't wait for TTL expiry."""
        token_hash = _hash_token(real_token)
        alias = await self._cache_get(f"cred:alias:{token_hash}")
        if not alias:
            return

        revocation_marker = json.dumps(
            {
                "revoked": True,
                "reason": "logout",
                "revokedAt": time.time() * 1000,
                "revocation_scope": "precise",
            }
        )
        await self._cache_set(f"revoked:alias:{alias}", revocation_marker, 86400)
        await self._cache_del(f"alias:{alias}")
        await self._cache_del(f"cred:alias:{token_hash}")

    async def is_revoked(self, alias: str) -> bool:
        """Idempotency check for webhook retries."""
        revoked = await self._cache_get(f"revoked:alias:{alias}")
        return revoked is not None

    async def get_revocation_details(self, alias: str) -> Optional[Dict[str, Any]]:
        raw = await self._cache_get(f"revoked:alias:{alias}")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return {
                "reason": "active_threat",
                "revokedAt": time.time() * 1000,
                "revocation_scope": "precise",
            }
