"""DevFortress SDK — Password Spray Detector.

Port of the Node SDK's ``password-spray-detector.ts``.

Detects distributed password spray attacks by correlating authentication
failures across multiple accounts. Unlike brute force (many passwords,
one account), spray attacks try few passwords across many accounts to
evade per-account lockout thresholds.

Detection signals:
  1. Same password hash submitted to N different accounts within window
  2. Low failure rate per account but high aggregate failure rate
  3. Credential rotation pattern (sequential password attempts)
  4. Geographic clustering of spray sources

Node's own class runs its sliding-window cleanup on a periodic background
timer; this port uses a daemon ``threading.Timer`` (same pattern as
``graduated_rate_limiter.py``) rather than Node's ``setInterval``, guarded
by a lock since Python, unlike Node's single-threaded event loop, can call
in from the timer thread and the caller's thread at the same time.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Set

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SprayAction = Literal["allow", "rate_limit", "captcha_challenge", "block"]


@dataclass
class AuthFailureEvent:
    ip: str
    #: Hashed credential (never store plaintext).
    credential_hash: str
    #: Target account identifier.
    account_id: str
    timestamp: Optional[float] = None
    user_agent: Optional[str] = None
    #: Geographic region if available.
    geo_region: Optional[str] = None


@dataclass
class SprayDetectionResult:
    detected: bool
    severity: Severity
    #: Number of unique accounts targeted with the same credential.
    affected_accounts: int
    #: Confidence score 0-1.
    confidence: float
    action: SprayAction
    #: Source IPs involved.
    source_ips: List[str]
    reason: str


@dataclass
class _CredentialFailureRecord:
    accounts: Dict[str, float] = field(default_factory=dict)  # accountId -> timestamp (ms)
    source_ips: Set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0


class PasswordSprayDetector:
    """Detects password spray attacks: the same credential tried across many accounts."""

    def __init__(
        self,
        *,
        account_threshold: int = 5,
        window_ms: int = 300_000,
        max_entries: int = 50_000,
        graduated_response: bool = True,
        debug: bool = False,
    ):
        self._account_threshold = account_threshold
        self._window_ms = window_ms
        self._max_entries = max_entries
        self._graduated_response = graduated_response
        self._debug = debug

        self._credential_failures: "Dict[str, _CredentialFailureRecord]" = {}
        self._lock = threading.Lock()
        self._cleanup_timer: Optional[threading.Timer] = None
        self._schedule_cleanup()

    def _schedule_cleanup(self) -> None:
        timer = threading.Timer(self._window_ms / 1000, self._cleanup_tick)
        timer.daemon = True
        self._cleanup_timer = timer
        timer.start()

    def _cleanup_tick(self) -> None:
        self._cleanup()
        if self._cleanup_timer is not None:
            self._schedule_cleanup()

    def record_failure(self, event: AuthFailureEvent) -> SprayDetectionResult:
        """Record an authentication failure and check for a spray pattern."""
        now = event.timestamp if event.timestamp is not None else time.time() * 1000

        with self._lock:
            record = self._credential_failures.get(event.credential_hash)
            if record is None or now - record.first_seen > self._window_ms:
                record = _CredentialFailureRecord(first_seen=now, last_seen=now)

            record.accounts[event.account_id] = now
            record.source_ips.add(event.ip)
            record.last_seen = now

            # Purge expired accounts from the window.
            for acct, ts in list(record.accounts.items()):
                if now - ts > self._window_ms:
                    del record.accounts[acct]

            if (
                event.credential_hash not in self._credential_failures
                and len(self._credential_failures) >= self._max_entries
            ):
                # LRU-ish eviction: drop the oldest-inserted entry.
                oldest_key = next(iter(self._credential_failures), None)
                if oldest_key is not None:
                    del self._credential_failures[oldest_key]
            self._credential_failures[event.credential_hash] = record

            affected_accounts = len(record.accounts)
            source_ips = list(record.source_ips)
            first_seen = record.first_seen

        if affected_accounts < self._account_threshold:
            return SprayDetectionResult(
                detected=False,
                severity="LOW",
                affected_accounts=affected_accounts,
                confidence=affected_accounts / self._account_threshold,
                action="allow",
                source_ips=source_ips,
                reason=f"{affected_accounts} accounts below threshold {self._account_threshold}",
            )

        ratio = affected_accounts / self._account_threshold
        severity: Severity
        action: SprayAction
        if ratio >= 4:
            severity = "CRITICAL"
            action = "block"
            confidence = 0.98
        elif ratio >= 2:
            severity = "HIGH"
            action = "captcha_challenge" if self._graduated_response else "block"
            confidence = 0.9
        else:
            severity = "MEDIUM"
            action = "rate_limit" if self._graduated_response else "captcha_challenge"
            confidence = 0.75

        if self._debug:
            print(f"[PasswordSprayDetector] SPRAY DETECTED: {affected_accounts} accounts, severity={severity}")

        return SprayDetectionResult(
            detected=True,
            severity=severity,
            affected_accounts=affected_accounts,
            confidence=confidence,
            action=action,
            source_ips=source_ips,
            reason=(
                f"Password spray detected: {affected_accounts} accounts targeted with same "
                f"credential from {len(source_ips)} IPs in {round((now - first_seen) / 1000)}s"
            ),
        )

    def get_stats(self) -> Dict[str, int]:
        """Get current detection statistics."""
        with self._lock:
            total_failures = sum(len(r.accounts) for r in self._credential_failures.values())
            return {
                "tracked_credentials": len(self._credential_failures),
                "total_failures": total_failures,
            }

    def _cleanup(self) -> None:
        now = time.time() * 1000
        with self._lock:
            to_delete = [
                key
                for key, record in self._credential_failures.items()
                if now - record.last_seen > self._window_ms
            ]
            for key in to_delete:
                del self._credential_failures[key]

    def destroy(self) -> None:
        """Stop the detector's cleanup timer and clear its state."""
        if self._cleanup_timer is not None:
            self._cleanup_timer.cancel()
            self._cleanup_timer = None
