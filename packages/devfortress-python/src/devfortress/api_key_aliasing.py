"""DevFortress SDK — API Key Aliasing Service.

Port of the Node SDK's ``api-key-aliasing.ts``.

Provides alias lifecycle management for API keys: create, rotate, revoke,
inspect, and audit. Each alias is scoped to a workload (CI, agent, browser,
server) with fingerprint and scope binding.

Key features:
  - Per-integration alias families (CI, agents, plugins, browser, server)
  - Fingerprint-bound alias enforcement
  - Selective alias revocation without primary key rotation
  - Zero-downtime rotation with overlap window
  - Anomaly detection for alias misuse patterns

Forward-map storage uses the shared ``credential_vault`` primitive: real
AES-256-GCM, genuinely reversible (unlike an HMAC digest, which is one-way).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Set

from .credential_vault import VaultEncryptedRecord, decrypt, derive_vault_key, encrypt

AliasWorkload = Literal["ci", "agent", "plugin", "browser", "server", "custom"]
AliasState = Literal["active", "rotating", "revoked", "expired"]


@dataclass
class AliasRecord:
    alias_id: str
    alias_key: str  # encrypted-in-storage JSON bundle; '[REDACTED]' once returned to callers
    primary_key_hash: str
    workload: AliasWorkload
    label: str
    state: AliasState
    created_at: float
    last_used_at: float
    usage_count: int = 0
    fingerprint: Optional[str] = None
    scope: Optional[List[str]] = None
    expires_at: Optional[float] = None
    rotated_from_id: Optional[str] = None
    rotated_to_id: Optional[str] = None


@dataclass
class AliasAuditEvent:
    type: Literal[
        "alias_created", "alias_rotated", "alias_revoked",
        "alias_misuse_detected", "alias_expired", "alias_used",
    ]
    alias_id: str
    primary_key_hash: str
    workload: AliasWorkload
    timestamp: float
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AliasCreationResult:
    success: bool
    alias: Optional[AliasRecord] = None
    alias_key: Optional[str] = None  # only returned on creation
    error: Optional[str] = None


@dataclass
class AliasRotationResult:
    success: bool
    old_alias_id: Optional[str] = None
    new_alias: Optional[AliasRecord] = None
    new_alias_key: Optional[str] = None
    overlap_expires_at: Optional[float] = None
    error: Optional[str] = None


@dataclass
class AliasValidationResult:
    valid: bool
    reason: str
    alias_id: Optional[str] = None
    workload: Optional[AliasWorkload] = None
    primary_key_hash: Optional[str] = None
    anomaly_detected: Optional[bool] = None


@dataclass
class AliasStats:
    total_aliases: int
    active_aliases: int
    rotating_aliases: int
    revoked_aliases: int
    by_workload: Dict[str, int]
    recent_anomalies: int


class APIKeyAliasingService:
    def __init__(
        self,
        *,
        max_aliases_per_key: int = 50,
        rotation_overlap_ms: int = 300_000,
        max_primary_keys: int = 10_000,
        anomaly_detection: bool = True,
        creation_burst_threshold: int = 10,
        vault_secret: Optional[str] = None,
        debug: bool = False,
    ):
        self._max_aliases_per_key = max_aliases_per_key
        self._rotation_overlap_ms = rotation_overlap_ms
        self._max_primary_keys = max_primary_keys
        self._anomaly_detection = anomaly_detection
        self._creation_burst_threshold = creation_burst_threshold
        self._debug = debug

        self._aliases: "Dict[str, AliasRecord]" = {}
        self._alias_key_index: "Dict[str, str]" = {}  # aliasKeyHash -> aliasId
        self._primary_key_aliases: "Dict[str, Set[str]]" = {}
        self._audit_log: "List[AliasAuditEvent]" = []
        self._creation_timestamps: "List[float]" = []

        self._vault_key = (
            derive_vault_key(vault_secret, "api-key-aliasing") if vault_secret else os.urandom(32)
        )

    def create_alias(
        self,
        primary_key_hash: str,
        workload: AliasWorkload,
        label: str,
        *,
        fingerprint: Optional[str] = None,
        scope: Optional[List[str]] = None,
        expires_in_ms: Optional[int] = None,
    ) -> AliasCreationResult:
        now = time.time() * 1000

        existing = self._primary_key_aliases.get(primary_key_hash)
        if existing and len(existing) >= self._max_aliases_per_key:
            return AliasCreationResult(
                success=False,
                error=f"Maximum aliases ({self._max_aliases_per_key}) reached for this key",
            )

        if self._anomaly_detection:
            self._creation_timestamps.append(now)
            recent_creations = [t for t in self._creation_timestamps if now - t <= 3_600_000]
            if len(recent_creations) > self._creation_burst_threshold:
                self._emit_audit(
                    AliasAuditEvent(
                        type="alias_misuse_detected",
                        alias_id="N/A",
                        primary_key_hash=primary_key_hash,
                        workload=workload,
                        timestamp=now,
                        metadata={"reason": "creation_burst", "count": len(recent_creations)},
                    )
                )
                return AliasCreationResult(
                    success=False,
                    error=f"Alias creation burst detected: {len(recent_creations)} in 1 hour",
                )

        alias_id = f"alias_{secrets.token_hex(16)}"
        alias_key = f"vx_alias_{secrets.token_hex(24)}"
        alias_key_hash = hashlib.sha256(alias_key.encode("utf-8")).hexdigest()

        record = AliasRecord(
            alias_id=alias_id,
            alias_key=self._encrypt_alias_key(alias_key, primary_key_hash),
            primary_key_hash=primary_key_hash,
            workload=workload,
            label=label,
            state="active",
            fingerprint=fingerprint,
            scope=scope,
            created_at=now,
            expires_at=(now + expires_in_ms) if expires_in_ms else None,
            last_used_at=now,
        )

        self._aliases[alias_id] = record
        self._alias_key_index[alias_key_hash] = alias_id
        self._primary_key_aliases.setdefault(primary_key_hash, set()).add(alias_id)

        self._emit_audit(
            AliasAuditEvent(
                type="alias_created",
                alias_id=alias_id,
                primary_key_hash=primary_key_hash,
                workload=workload,
                timestamp=now,
                metadata={"label": label, "hasFingerprint": bool(fingerprint), "scope": scope},
            )
        )

        redacted = AliasRecord(**{**record.__dict__, "alias_key": "[REDACTED]"})
        return AliasCreationResult(success=True, alias=redacted, alias_key=alias_key)

    def rotate_alias(self, alias_id: str) -> AliasRotationResult:
        now = time.time() * 1000
        old_alias = self._aliases.get(alias_id)
        if not old_alias or old_alias.state != "active":
            return AliasRotationResult(success=False, error=f"Alias {alias_id} not found or not active")

        old_alias.state = "rotating"
        old_alias.expires_at = now + self._rotation_overlap_ms

        result = self.create_alias(
            old_alias.primary_key_hash,
            old_alias.workload,
            f"{old_alias.label} (rotated)",
            fingerprint=old_alias.fingerprint,
            scope=old_alias.scope,
        )

        if not result.success or not result.alias:
            old_alias.state = "active"  # rollback
            return AliasRotationResult(success=False, error=result.error)

        old_alias.rotated_to_id = result.alias.alias_id
        # Update the stored (non-redacted) record's lineage pointer too.
        stored_new = self._aliases.get(result.alias.alias_id)
        if stored_new:
            stored_new.rotated_from_id = alias_id

        self._emit_audit(
            AliasAuditEvent(
                type="alias_rotated",
                alias_id=alias_id,
                primary_key_hash=old_alias.primary_key_hash,
                workload=old_alias.workload,
                timestamp=now,
                metadata={"newAliasId": result.alias.alias_id, "overlapMs": self._rotation_overlap_ms},
            )
        )

        return AliasRotationResult(
            success=True,
            old_alias_id=alias_id,
            new_alias=result.alias,
            new_alias_key=result.alias_key,
            overlap_expires_at=old_alias.expires_at,
        )

    def revoke_alias(self, alias_id: str, reason: Optional[str] = None) -> bool:
        alias = self._aliases.get(alias_id)
        if not alias:
            return False

        alias.state = "revoked"
        self._emit_audit(
            AliasAuditEvent(
                type="alias_revoked",
                alias_id=alias_id,
                primary_key_hash=alias.primary_key_hash,
                workload=alias.workload,
                timestamp=time.time() * 1000,
                metadata={"reason": reason or "manual_revocation"},
            )
        )
        return True

    def validate_alias_key(
        self, alias_key: str, fingerprint: Optional[str] = None
    ) -> AliasValidationResult:
        alias_key_hash = hashlib.sha256(alias_key.encode("utf-8")).hexdigest()
        alias_id = self._alias_key_index.get(alias_key_hash)
        if not alias_id:
            return AliasValidationResult(valid=False, reason="Unknown alias key")

        alias = self._aliases.get(alias_id)
        if not alias:
            return AliasValidationResult(valid=False, reason="Alias record not found")

        now = time.time() * 1000

        if alias.state == "revoked":
            return AliasValidationResult(
                valid=False, alias_id=alias_id, workload=alias.workload, reason="Alias has been revoked"
            )

        if alias.expires_at and now > alias.expires_at:
            alias.state = "expired"
            self._emit_audit(
                AliasAuditEvent(
                    type="alias_expired",
                    alias_id=alias_id,
                    primary_key_hash=alias.primary_key_hash,
                    workload=alias.workload,
                    timestamp=now,
                )
            )
            return AliasValidationResult(
                valid=False, alias_id=alias_id, workload=alias.workload, reason="Alias has expired"
            )

        anomaly_detected = False
        if alias.fingerprint and fingerprint and alias.fingerprint != fingerprint:
            anomaly_detected = True
            self._emit_audit(
                AliasAuditEvent(
                    type="alias_misuse_detected",
                    alias_id=alias_id,
                    primary_key_hash=alias.primary_key_hash,
                    workload=alias.workload,
                    timestamp=now,
                    metadata={
                        "reason": "fingerprint_mismatch",
                        "expectedFingerprint": alias.fingerprint[:8],
                    },
                )
            )

        alias.last_used_at = now
        alias.usage_count += 1
        self._emit_audit(
            AliasAuditEvent(
                type="alias_used",
                alias_id=alias_id,
                primary_key_hash=alias.primary_key_hash,
                workload=alias.workload,
                timestamp=now,
            )
        )

        return AliasValidationResult(
            valid=not anomaly_detected,
            alias_id=alias_id,
            workload=alias.workload,
            primary_key_hash=alias.primary_key_hash,
            reason="Fingerprint mismatch detected" if anomaly_detected else "Valid alias",
            anomaly_detected=anomaly_detected,
        )

    def list_aliases(self, primary_key_hash: str) -> List[AliasRecord]:
        alias_ids = self._primary_key_aliases.get(primary_key_hash)
        if not alias_ids:
            return []
        out = []
        for aid in alias_ids:
            a = self._aliases.get(aid)
            if a:
                out.append(AliasRecord(**{**a.__dict__, "alias_key": "[REDACTED]"}))
        return out

    def get_stats(self) -> AliasStats:
        by_workload = {w: 0 for w in ("ci", "agent", "plugin", "browser", "server", "custom")}
        active = rotating = revoked = 0
        for alias in self._aliases.values():
            if alias.state == "active":
                active += 1
            elif alias.state == "rotating":
                rotating += 1
            elif alias.state == "revoked":
                revoked += 1
            by_workload[alias.workload] += 1

        one_hour_ago = time.time() * 1000 - 3_600_000
        recent_anomalies = sum(
            1 for e in self._audit_log if e.type == "alias_misuse_detected" and e.timestamp > one_hour_ago
        )

        return AliasStats(
            total_aliases=len(self._aliases),
            active_aliases=active,
            rotating_aliases=rotating,
            revoked_aliases=revoked,
            by_workload=by_workload,
            recent_anomalies=recent_anomalies,
        )

    def get_audit_log(self, limit: int = 100) -> List[AliasAuditEvent]:
        return self._audit_log[-limit:]

    def _encrypt_alias_key(self, alias_key: str, primary_key_hash: str) -> str:
        """AES-256-GCM encrypt the alias key for forward-map storage.
        Returns a JSON-serialized {ciphertext, iv, authTag} bundle — genuinely
        reversible via resolve()."""
        import json

        record = encrypt(f"{primary_key_hash}:{alias_key}", self._vault_key)
        return json.dumps({"ciphertext": record.ciphertext, "iv": record.iv, "authTag": record.auth_tag})

    def resolve(self, alias_id: str) -> Optional[str]:
        """Resolve a stored alias back to its real alias key. Returns None for
        an unknown/revoked/expired alias, or if the stored ciphertext fails
        auth-tag verification (tampered/corrupted)."""
        import json

        alias = self._aliases.get(alias_id)
        if not alias:
            return None
        if alias.state in ("revoked", "expired"):
            return None

        try:
            raw = json.loads(alias.alias_key)
            record = VaultEncryptedRecord(
                ciphertext=raw["ciphertext"], iv=raw["iv"], auth_tag=raw["authTag"]
            )
        except Exception:
            return None

        try:
            decrypted = decrypt(record, self._vault_key)
            separator_index = decrypted.find(":")
            return decrypted if separator_index == -1 else decrypted[separator_index + 1 :]
        except Exception:
            return None  # Auth-tag verification failed — do not return garbage plaintext.

    def _emit_audit(self, event: AliasAuditEvent) -> None:
        self._audit_log.append(event)
        if len(self._audit_log) > 10_000:
            del self._audit_log[: len(self._audit_log) - 10_000]
        if self._debug:
            print(f"[AliasAudit] {event.type}: {event.alias_id} ({event.workload})")
