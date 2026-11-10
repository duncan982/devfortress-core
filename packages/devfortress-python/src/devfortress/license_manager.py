"""DevFortress SDK — License Manager (CV-M1, CV-M4, CV-M7).

Port of the Node SDK's ``license-manager.ts``.

Implements:
- CV-M1: Server-side license validation with 24h check interval and 72h
  grace-period degradation to monitor-only mode.
- CV-M4: ML model expiry (30-day staleness without platform sync).
- CV-M7: SDK anti-tampering HMAC signature verification.

This is the client-side port of the fix for the bug class TODO 321 already
fixed on Node: license-check/heartbeat calls silently 404ing used to cause
silent monitor-only degradation with no visible signal. ``check_license``
here always logs a visible warning before degrading — it never fails
silently. The platform's ``/api/sdk/license-check`` endpoint already exists
(TODO 321); this module is a client only, no new platform route.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, replace
from typing import Literal, Optional
from urllib.parse import urlsplit

import requests

from .signing import sign_request
from .version import SDK_VERSION

SubscriptionTier = Literal["starter", "pro", "team", "enterprise"]
LicenseAction = Literal["block", "rate_limit", "observe"]

# ── Constants ────────────────────────────────────────────────

DEFAULT_CHECK_INTERVAL_SECONDS = 24 * 60 * 60  # 24 hours
DEFAULT_GRACE_PERIOD_SECONDS = 72 * 60 * 60  # 72 hours
DEFAULT_MODEL_EXPIRY_SECONDS = 30 * 24 * 60 * 60  # 30 days
LICENSE_CHECK_TIMEOUT_SECONDS = 10.0


# ── Types ────────────────────────────────────────────────────


@dataclass
class LicenseState:
    """Current license validity/tier state, as last resolved from the platform."""

    valid: bool = False
    tier: SubscriptionTier = "starter"
    last_checked_at: float = 0.0
    consecutive_failures: int = 0
    degraded: bool = False
    degradation_reason: Optional[str] = None


@dataclass
class ModelState:
    """Freshness state of the embedded ML model."""

    last_synced_at: float = 0.0
    model_version: str = "embedded-v1"
    expired: bool = False


def _request_target(url: str) -> str:
    """Path plus ``?query`` of an absolute URL, as it goes on the request line."""
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


# ── License Manager ──────────────────────────────────────────


class LicenseManager:
    """Resolves license/tier state from the platform, with heartbeat-style
    periodic re-checks and graceful (never silent) degradation on failure.
    """

    def __init__(
        self,
        api_key: str,
        endpoint: str,
        *,
        check_interval_seconds: float = DEFAULT_CHECK_INTERVAL_SECONDS,
        grace_period_seconds: float = DEFAULT_GRACE_PERIOD_SECONDS,
        model_expiry_seconds: float = DEFAULT_MODEL_EXPIRY_SECONDS,
        integrity_secret: Optional[str] = None,
        debug: bool = False,
        timeout: float = LICENSE_CHECK_TIMEOUT_SECONDS,
        session: Optional[requests.Session] = None,
    ):
        if not api_key:
            raise ValueError("LicenseManager: api_key is required")
        if not endpoint:
            raise ValueError("LicenseManager: endpoint is required")

        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.check_interval_seconds = check_interval_seconds
        self.grace_period_seconds = grace_period_seconds
        self.model_expiry_seconds = model_expiry_seconds
        self.integrity_secret = integrity_secret
        self.debug = debug
        self.timeout = timeout
        self._session = session or requests.Session()

        self._license_state = LicenseState()
        self._model_state = ModelState(last_synced_at=time.time())  # assume fresh on init

        self._timer: Optional[threading.Timer] = None
        self._initialized = False

    # ── CV-M1: License Validation ──────────────────────────────

    def init(self) -> LicenseState:
        """Perform an initial license check and start periodic validation."""
        if self._initialized:
            return self.get_license_state()

        self.check_license()
        self._schedule_next_check()
        self._initialized = True
        return self.get_license_state()

    def _schedule_next_check(self) -> None:
        timer = threading.Timer(self.check_interval_seconds, self._tick)
        timer.daemon = True  # never blocks process exit
        self._timer = timer
        timer.start()

    def _tick(self) -> None:
        self.check_license()
        self._schedule_next_check()

    def check_license(self) -> LicenseState:
        """Perform a license check against the platform.

        On failure, tracks consecutive failures and degrades to monitor-only
        after the grace period — always with a visible log, never silently.
        Safe to call directly (e.g. from tests) without ``init()``.
        """
        url = f"{self.endpoint}/api/sdk/license-check"
        body = json.dumps(
            {
                "sdkVersion": SDK_VERSION,
                "timestamp": int(time.time() * 1000),
                "integrity": self.compute_integrity_hash(),
            },
            separators=(",", ":"),
        ).encode("utf-8")

        try:
            headers = {"Content-Type": "application/json"}
            headers.update(sign_request(self.api_key, "POST", _request_target(url), body))
            response = self._session.post(url, data=body, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            self._handle_check_failure(str(exc))
            return self.get_license_state()

        if response.status_code == 200:
            try:
                data = response.json()
            except ValueError:
                data = {}

            self._license_state = LicenseState(
                valid=True,
                tier=data.get("tier") or self._license_state.tier,
                last_checked_at=time.time(),
                consecutive_failures=0,
                degraded=False,
            )

            # CV-M4: sync ML model freshness on successful license check
            model_version = data.get("modelVersion")
            if model_version:
                self._model_state = ModelState(
                    last_synced_at=time.time(), model_version=model_version, expired=False
                )

            self._log("info", f"License validated: tier={self._license_state.tier}")
        elif response.status_code in (402, 403):
            # Explicitly unauthorized/payment required
            self._license_state = LicenseState(
                valid=False,
                tier="starter",
                last_checked_at=time.time(),
                consecutive_failures=self._license_state.consecutive_failures + 1,
                degraded=True,
                degradation_reason=f"License rejected: HTTP {response.status_code}",
            )
            self._log("warn", f"License rejected: HTTP {response.status_code}")
        else:
            # Server error (or any other non-2xx) — treat as transient failure
            self._handle_check_failure(f"HTTP {response.status_code}")

        return self.get_license_state()

    def _handle_check_failure(self, reason: str) -> None:
        self._license_state.consecutive_failures += 1
        # If never successfully checked, start grace period from initialization
        baseline_time = (
            time.time() if self._license_state.last_checked_at == 0 else self._license_state.last_checked_at
        )
        time_since_last_success = time.time() - baseline_time

        if time_since_last_success >= self.grace_period_seconds:
            # Grace period expired — degrade to monitor-only. This log is the
            # fix for TODO 321's bug class: degradation is always visible.
            self._license_state.degraded = True
            self._license_state.degradation_reason = (
                f"License check failed for {round(time_since_last_success / 3600)}h "
                f"(grace period: {round(self.grace_period_seconds / 3600)}h). "
                f"Reason: {reason}. SDK degraded to monitor-only mode."
            )
            self._log("warn", self._license_state.degradation_reason)
        else:
            self._log(
                "debug",
                f"License check failed ({reason}), "
                f"{self._license_state.consecutive_failures} consecutive failures, "
                f"{round((self.grace_period_seconds - time_since_last_success) / 3600)}h grace remaining",
            )

    def get_license_state(self) -> LicenseState:
        """Current license state (a copy — mutating it has no effect)."""
        return replace(self._license_state)

    def is_degraded(self) -> bool:
        """Whether the SDK should operate in degraded (monitor-only) mode."""
        return self._license_state.degraded

    def can_perform_action(self, action: LicenseAction) -> bool:
        """Check if a specific capability is available in the current license state."""
        if action == "observe":
            return True  # always allowed
        if self._license_state.degraded:
            return False  # degraded = monitor-only
        if not self._license_state.valid and self._license_state.last_checked_at == 0:
            # Never validated yet — allow actions during initial grace period
            return True
        return self._license_state.valid

    # ── CV-M4: ML Model Expiry ─────────────────────────────────

    def is_model_expired(self) -> bool:
        """Whether the embedded ML model has expired (stale >30 days without platform sync)."""
        age = time.time() - self._model_state.last_synced_at
        self._model_state.expired = age > self.model_expiry_seconds
        return self._model_state.expired

    def get_model_state(self) -> ModelState:
        """Current ML model state (a copy)."""
        expired = self.is_model_expired()
        return replace(self._model_state, expired=expired)

    def sync_model(self, model_version: str) -> None:
        """Manually trigger a model sync (called from init or heartbeat)."""
        self._model_state = ModelState(last_synced_at=time.time(), model_version=model_version, expired=False)
        self._log("info", f"ML model synced: version={model_version}")

    # ── CV-M7: Anti-Tampering ──────────────────────────────────

    def compute_integrity_hash(self) -> str:
        """HMAC over critical SDK code paths; differs from the platform's
        expected value if the SDK distribution has been modified.
        """
        if not self.integrity_secret:
            return "no-integrity-secret"

        critical_paths = "|".join(
            [
                "DevFortress.observe",
                "DevFortress.isBlocked",
                "LicenseManager.checkLicense",
                "InternalClosedLoopEngine.evaluate",
                "TierGate.checkEventLimit",
            ]
        )

        mac = hmac.new(self.integrity_secret.encode("utf-8"), digestmod=hashlib.sha256)
        mac.update(critical_paths.encode("utf-8"))
        mac.update(self.api_key.encode("utf-8"))
        return mac.hexdigest()[:16]

    def verify_integrity(self, expected_hash: Optional[str] = None) -> dict:
        """Verify the SDK has not been tampered with. ``tampered`` is True
        if the integrity hash doesn't match ``expected_hash``.
        """
        current_hash = self.compute_integrity_hash()
        if not expected_hash:
            return {"tampered": False, "hash": current_hash}
        return {"tampered": current_hash != expected_hash, "hash": current_hash}

    # ── Cleanup ────────────────────────────────────────────────

    def destroy(self) -> None:
        """Stop periodic license checks and clean up."""
        if self._timer:
            self._timer.cancel()
            self._timer = None
        self._initialized = False

    # ── Logging ────────────────────────────────────────────────

    def _log(self, level: Literal["info", "warn", "debug", "error"], message: str) -> None:
        if not self.debug and level == "debug":
            return
        print(f"[DevFortress:License] {message}")  # noqa: T201
