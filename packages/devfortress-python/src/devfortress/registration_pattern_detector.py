"""DevFortress SDK — Registration Pattern Detector.

Port of the Node SDK's ``registration-pattern-detector.ts``.

Detects mass registration campaigns, bot armies, and credential-stuffing
setup by analyzing registration metadata patterns.

Signals: timing patterns, email domain clustering, IP velocity,
user-agent consistency, honeypot correlation.

Node's own class runs its sliding-window cleanup on a periodic background
timer; this port uses a daemon ``threading.Timer`` (same pattern as
``graduated_rate_limiter.py``) rather than Node's ``setInterval``, guarded
by a lock since Python, unlike Node's single-threaded event loop, can call
in from the timer thread and the caller's thread at the same time.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Set

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RegistrationAction = Literal["allow", "captcha", "delay", "block"]

# Common disposable email domains.
DEFAULT_DISPOSABLE_DOMAINS: Set[str] = {
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwaway.email",
    "yopmail.com",
    "10minutemail.com",
    "trashmail.com",
    "dispostable.com",
    "sharklasers.com",
    "guerrillamailblock.com",
    "grr.la",
    "temp-mail.org",
    "fakeinbox.com",
    "getnada.com",
    "maildrop.cc",
    "inboxbear.com",
}

_GENERATED_EMAIL_RE = re.compile(r"^[a-z]+\d{3,}@")
_SEQUENTIAL_EMAIL_RE = re.compile(r"^(test|user|admin|bot)\d+@")


@dataclass
class RegistrationEvent:
    ip: str
    email: str
    user_agent: Optional[str] = None
    timestamp: Optional[float] = None
    #: Whether a honeypot field was filled.
    honeypot_triggered: bool = False
    #: Time from page load to form submit (ms).
    form_fill_duration_ms: Optional[float] = None


@dataclass
class RegistrationResult:
    allowed: bool
    risk_score: int
    severity: Severity
    action: RegistrationAction
    signals: List[str]
    reason: str


@dataclass
class _IPRecord:
    registrations: List[float] = field(default_factory=list)
    emails: Set[str] = field(default_factory=set)
    user_agents: Set[str] = field(default_factory=set)


@dataclass
class _DomainRecord:
    registrations: List[float] = field(default_factory=list)
    ips: Set[str] = field(default_factory=set)


class RegistrationPatternDetector:
    def __init__(
        self,
        *,
        max_per_ip: int = 3,
        max_per_domain: int = 10,
        window_ms: int = 3_600_000,
        max_entries: int = 100_000,
        disposable_domains: Optional[Set[str]] = None,
        debug: bool = False,
    ):
        self._max_per_ip = max_per_ip
        self._max_per_domain = max_per_domain
        self._window_ms = window_ms
        self._max_entries = max_entries
        self._disposable_domains = (
            disposable_domains if disposable_domains is not None else DEFAULT_DISPOSABLE_DOMAINS
        )
        self._debug = debug

        self._ip_records: "Dict[str, _IPRecord]" = {}
        self._domain_records: "Dict[str, _DomainRecord]" = {}
        self._lock = threading.Lock()
        self._cleanup_timer: Optional[threading.Timer] = None
        self._schedule_cleanup()

    def _schedule_cleanup(self) -> None:
        timer = threading.Timer(self._window_ms / 2 / 1000, self._cleanup_tick)
        timer.daemon = True
        self._cleanup_timer = timer
        timer.start()

    def _cleanup_tick(self) -> None:
        self._cleanup()
        if self._cleanup_timer is not None:
            self._schedule_cleanup()

    def evaluate(self, event: RegistrationEvent) -> RegistrationResult:
        now = event.timestamp if event.timestamp is not None else time.time() * 1000
        signals: List[str] = []
        risk_score = 0

        email_domain = event.email.split("@")[1].lower() if "@" in event.email else ""

        with self._lock:
            # ── IP velocity check ──
            ip_rec = self._ip_records.get(event.ip)
            if ip_rec is None:
                ip_rec = _IPRecord()
                self._ip_records[event.ip] = ip_rec
            ip_rec.registrations = [t for t in ip_rec.registrations if now - t <= self._window_ms]
            ip_rec.registrations.append(now)
            ip_rec.emails.add(event.email)
            if event.user_agent:
                ip_rec.user_agents.add(event.user_agent)

            if len(ip_rec.registrations) > self._max_per_ip:
                risk_score += 30
                signals.append(f"IP velocity: {len(ip_rec.registrations)} registrations from {event.ip}")

            # ── Domain velocity check ──
            domain_rec = self._domain_records.get(email_domain)
            if domain_rec is None:
                domain_rec = _DomainRecord()
                self._domain_records[email_domain] = domain_rec
            domain_rec.registrations = [t for t in domain_rec.registrations if now - t <= self._window_ms]
            domain_rec.registrations.append(now)
            domain_rec.ips.add(event.ip)

            if len(domain_rec.registrations) > self._max_per_domain:
                risk_score += 20
                signals.append(
                    f"Domain velocity: {len(domain_rec.registrations)} registrations for @{email_domain}"
                )

            ip_registration_count = len(ip_rec.registrations)
            ip_ua_count = len(ip_rec.user_agents)

            # Enforce max entries with (insertion-order) LRU-ish eviction.
            if len(self._ip_records) > self._max_entries:
                oldest = next(iter(self._ip_records), None)
                if oldest is not None:
                    del self._ip_records[oldest]

        # ── Disposable email check ──
        if email_domain in self._disposable_domains:
            risk_score += 25
            signals.append(f"Disposable email domain: @{email_domain}")

        # ── Honeypot trigger ──
        if event.honeypot_triggered:
            risk_score += 40
            signals.append("Honeypot field filled (bot indicator)")

        # ── Form fill speed (bot detection) ──
        if event.form_fill_duration_ms is not None:
            if event.form_fill_duration_ms < 2000:
                risk_score += 30
                signals.append(f"Suspiciously fast form fill: {event.form_fill_duration_ms}ms")
            elif event.form_fill_duration_ms < 5000:
                risk_score += 10
                signals.append(f"Fast form fill: {event.form_fill_duration_ms}ms")

        # ── Same UA for all registrations from IP ──
        if ip_registration_count > 2 and ip_ua_count == 1:
            risk_score += 10
            signals.append("Identical user-agent across multiple registrations")

        # ── Email pattern: sequential or generated ──
        if _GENERATED_EMAIL_RE.match(event.email) or _SEQUENTIAL_EMAIL_RE.match(event.email):
            risk_score += 15
            signals.append("Email matches generated/sequential pattern")

        # Cap and determine result.
        risk_score = min(100, risk_score)

        severity: Severity
        action: RegistrationAction
        if risk_score >= 70:
            severity = "CRITICAL"
            action = "block"
            allowed = False
        elif risk_score >= 50:
            severity = "HIGH"
            action = "captcha"
            allowed = True
        elif risk_score >= 25:
            severity = "MEDIUM"
            action = "delay"
            allowed = True
        else:
            severity = "LOW"
            action = "allow"
            allowed = True

        reason = (
            f"Registration risk (score={risk_score}): {'; '.join(signals)}"
            if signals
            else f"Registration allowed (score={risk_score})"
        )

        return RegistrationResult(
            allowed=allowed,
            risk_score=risk_score,
            severity=severity,
            action=action,
            signals=signals,
            reason=reason,
        )

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "tracked_ips": len(self._ip_records),
                "tracked_domains": len(self._domain_records),
            }

    def _cleanup(self) -> None:
        now = time.time() * 1000
        with self._lock:
            for key in list(self._ip_records.keys()):
                rec = self._ip_records[key]
                rec.registrations = [t for t in rec.registrations if now - t <= self._window_ms]
                if not rec.registrations:
                    del self._ip_records[key]
            for key in list(self._domain_records.keys()):
                rec = self._domain_records[key]
                rec.registrations = [t for t in rec.registrations if now - t <= self._window_ms]
                if not rec.registrations:
                    del self._domain_records[key]

    def destroy(self) -> None:
        """Stop the detector's cleanup timer and clear its state."""
        if self._cleanup_timer is not None:
            self._cleanup_timer.cancel()
            self._cleanup_timer = None
