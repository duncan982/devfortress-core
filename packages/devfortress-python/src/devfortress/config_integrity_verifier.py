"""DevFortress SDK — Config Integrity Verifier (Invention A9).

Port of the Node SDK's ``config-integrity-verifier.ts`` ``ConfigIntegrityVerifier``
(TODO 419/426 — one of the 20 Node-only claims identified by the
2026-11-02 patent audit).

Seals an HMAC-SHA256 digest of a configuration snapshot at initialization
and flags drift (tampered thresholds, disabled features, injected
configuration) when re-verified later.

Node's own class also starts a periodic background timer that calls
``verify()`` automatically; this port deliberately does not start a
background thread for that, since an SDK silently spawning background
timers is a bigger surprise in Python than in Node's event loop — call
:meth:`ConfigIntegrityVerifier.verify` yourself on whatever cadence suits
your application. The actual patented mechanism (seal, hash, compare,
locate the specific violating fields) is unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

__all__ = [
    "ConfigViolation",
    "ConfigIntegrityResult",
    "ConfigIntegrityVerifier",
]

_CRITICAL_FIELDS = (
    "mode",
    "failClosed",
    "tier",
    "apiKey",
    "blockThreshold",
    "rateLimitMax",
    "rateLimitWindowMs",
)


@dataclass(frozen=True)
class ConfigViolation:
    field: str
    expected: str
    actual: str
    severity: str  # "HIGH" | "CRITICAL"
    timestamp: float
    reason: str


@dataclass
class ConfigIntegrityResult:
    valid: bool
    violations: List[ConfigViolation] = field(default_factory=list)
    last_verified: float = 0.0
    check_count: int = 0


def _now_ms() -> float:
    return time.time() * 1000


class ConfigIntegrityVerifier:
    """Seals a config snapshot's HMAC digest and verifies it against drift."""

    def __init__(
        self,
        hmac_secret: Optional[str] = None,
        on_violation: Optional[Callable[[ConfigViolation], None]] = None,
    ) -> None:
        self._hmac_secret = hmac_secret or os.urandom(32).hex()
        self._on_violation = on_violation or (lambda _v: None)
        self._original_hash = ""
        self._original_snapshot: Dict[str, Any] = {}
        self._check_count = 0
        self._last_verified = 0.0
        self._violations: List[ConfigViolation] = []

    def seal(self, sdk_config: Dict[str, Any]) -> str:
        """Seal the SDK configuration. Call once at initialization."""
        self._original_snapshot = json.loads(json.dumps(sdk_config))
        self._original_hash = self._compute_hmac(self._original_snapshot)
        self._last_verified = _now_ms()
        self._check_count = 0
        self._violations = []
        return self._original_hash

    def verify(self, current_config: Dict[str, Any]) -> ConfigIntegrityResult:
        """Verify the current configuration against the sealed snapshot."""
        self._check_count += 1
        self._last_verified = _now_ms()

        current_hash = self._compute_hmac(current_config)
        valid = current_hash == self._original_hash

        if not valid:
            new_violations = self._find_violations(self._original_snapshot, current_config)
            self._violations.extend(new_violations)
            for violation in new_violations:
                self._on_violation(violation)

        return ConfigIntegrityResult(
            valid=valid,
            violations=list(self._violations),
            last_verified=self._last_verified,
            check_count=self._check_count,
        )

    def get_status(self) -> ConfigIntegrityResult:
        """Get the current integrity status without re-checking."""
        return ConfigIntegrityResult(
            valid=len(self._violations) == 0,
            violations=list(self._violations),
            last_verified=self._last_verified,
            check_count=self._check_count,
        )

    def _compute_hmac(self, obj: Dict[str, Any]) -> str:
        serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        return hmac.new(
            self._hmac_secret.encode("utf-8"), serialized.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _find_violations(
        self, original: Dict[str, Any], current: Dict[str, Any], prefix: str = ""
    ) -> List[ConfigViolation]:
        violations: List[ConfigViolation] = []
        now = _now_ms()

        for key in set(original.keys()) | set(current.keys()):
            field_name = f"{prefix}.{key}" if prefix else key
            orig_val = original.get(key)
            curr_val = current.get(key)

            if orig_val == curr_val:
                continue

            severity = (
                "CRITICAL" if any(f in field_name for f in _CRITICAL_FIELDS) else "HIGH"
            )

            if (
                isinstance(orig_val, dict)
                and isinstance(curr_val, dict)
            ):
                violations.extend(self._find_violations(orig_val, curr_val, field_name))
            elif json.dumps(orig_val, sort_keys=True) != json.dumps(curr_val, sort_keys=True):
                violations.append(
                    ConfigViolation(
                        field=field_name,
                        expected=str(orig_val),
                        actual=str(curr_val),
                        severity=severity,
                        timestamp=now,
                        reason=f"Config field '{field_name}' changed from '{orig_val}' to '{curr_val}'",
                    )
                )

        return violations
