"""DevFortress SDK — Internal Closed-Loop Protection Engine.

Port of the Node SDK's ``internal-closed-loop-engine.ts``.

Three tiers:

  Tier 1: Deterministic rule engine (<1ms) — regex, scanner signature,
          sensitive-file, credential-stuffing, and agent-tool rules.
  Tier 2: Optional custom scorer — a callable the caller supplies.
          Unimplemented by default: no scorer is wired in unless the
          caller passes one; ``evaluate()`` simply skips Tier 2 in that
          case (same as Node's behaviour when ``tier2_scorer`` is unset).
  Tier 3: Async relay — fires ``on_relay`` for non-'allow' decisions when
          ``enable_external_relay`` is true (hybrid mode only). This
          engine has no HTTP client or platform credentials of its own by
          design; the caller's relay callback does the actual platform
          call, same as Node's ``onRelay``/``relayInternalDecisionToPlatform``.

State (blocked IPs/users/sessions, quarantined agents, rate-limiter
entries, audit log) is bounded in-memory, lives for the engine instance's
lifetime, and is never persisted — matching Node's ``BoundedMap``-backed
design exactly (reusing this SDK's own :class:`BoundedMap`, already
ported for other modules).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional, Union

from .bounded_map import BoundedMap

CLDecision = Literal["allow", "block", "rate_limit", "challenge", "quarantine"]

__all__ = [
    "InternalCLConfig",
    "InternalCLRequest",
    "InternalCLResult",
    "InternalCLAction",
    "InternalCLAuditEntry",
    "InternalCLRule",
    "InternalClosedLoopEngine",
    "matches_known_attack_pattern",
]

# ── Default Attack Pattern Rules (Tier 1) — byte-for-byte port of Node's ──

_SQL_INJECTION_STRICT = [
    re.compile(
        r"(?:^|\s)(?:UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+[a-zA-Z0-9_]+\s+SET|DELETE\s+FROM)(?:\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:'|")\s*OR\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|"[^"]*"\s*=\s*"[^"]*")""",
        re.IGNORECASE,
    ),
    re.compile(r"""(?:'|")\s*;\s*(?:--|/\*)"""),
    re.compile(r"(\bxp_\w+)", re.IGNORECASE),
]
_SQL_INJECTION_MODERATE = [
    re.compile(r"(/\*.*\*/)"),
    re.compile(r"(\bEXEC\b|\bEXECUTE\b)\s*\(", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(load|error|click|mouseover|submit|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"(<iframe|<object|<embed|<applet)", re.IGNORECASE),
    re.compile(r"(document\.(cookie|write|location))", re.IGNORECASE),
    re.compile(r"(window\.(location|open))", re.IGNORECASE),
]

_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.%2[fF]"),
    re.compile(r"\.\.\\$"),
    re.compile(r"%2e%2e[%/\\]", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|hosts)"),
    re.compile(r"/proc/self"),
    re.compile(r"(/\.env|/\.git|/\.ssh)"),
]

_SCANNER_SIGNATURES = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"sqlmap",
        r"nikto",
        r"nmap",
        r"dirbuster",
        r"gobuster",
        r"wpscan",
        r"burp\s*suite",
        r"acunetix",
        r"nessus",
        r"masscan",
        r"zgrab",
        r"nuclei",
    )
]

_SENSITIVE_FILE_PATTERNS = [
    re.compile(p)
    for p in (
        r"/\.env",
        r"/\.git",
        r"/\.ssh",
        r"/wp-admin",
        r"/wp-login",
        r"/phpmyadmin",
        r"/admin\.php",
        r"/\.htaccess",
        r"/\.htpasswd",
        r"/server-status",
        r"/actuator",
        r"/debug/",
    )
]
_SENSITIVE_FILE_PATTERNS[5] = re.compile(r"/phpmyadmin", re.IGNORECASE)

_AUTH_PATHS = ("/login", "/signin", "/auth", "/api/auth", "/api/login", "/oauth/token")
_DANGEROUS_TOOLS = {"shell_exec", "eval", "exec", "rm", "sudo", "chmod", "kill"}


def matches_known_attack_pattern(path: Optional[str] = None, user_agent: Optional[str] = None) -> bool:
    """Lightweight, synchronous, zero-network content check reusing the same
    Tier 1 patterns as :meth:`InternalClosedLoopEngine._register_default_rules`.

    Mirrors Node's ``matchesKnownAttackPattern`` (Option B, 2026-08-27):
    external mode's own local behavioral preflight (A1 cold-start / A2 LSH
    campaign / A3 rate limit) is purely statistical and cannot flag a
    single, first-ever malicious request from a fresh entity — there is no
    deviation/campaign/rate signal yet on request #1. This gives external
    mode a content check of its own for exactly that case.
    """
    if path:
        if any(p.search(path) for p in _SQL_INJECTION_STRICT):
            return True
        if any(p.search(path) for p in _SQL_INJECTION_MODERATE):
            return True
        if any(p.search(path) for p in _XSS_PATTERNS):
            return True
        if any(p.search(path) for p in _PATH_TRAVERSAL_PATTERNS):
            return True
    if user_agent and any(p.search(user_agent) for p in _SCANNER_SIGNATURES):
        return True
    return False


# ── Configuration ───────────────────────────────────────────


@dataclass
class InternalCLConfig:
    fail_mode: Literal["closed", "open"] = "closed"
    enable_external_relay: bool = False
    max_blocked_entries: int = 10_000
    max_rate_limit_entries: int = 50_000
    max_audit_entries: int = 100_000
    default_block_ttl_seconds: int = 3600
    # Tier 2 — unimplemented/pass-through by default. `evaluate()` skips
    # Tier 2 entirely when this is None, exactly as Node does when
    # `tier2Scorer` is unset in the config.
    tier2_scorer: Optional[Callable[["InternalCLRequest"], Union[Awaitable[float], float]]] = None
    block_threshold: float = 85
    rate_limit_threshold: float = 60
    rate_limit_max: int = 100
    rate_limit_window_seconds: float = 60.0
    debug: bool = False
    on_action: Optional[Callable[["InternalCLAction"], None]] = None
    on_relay: Optional[Callable[["InternalCLResult", "InternalCLRequest"], Union[Awaitable[None], None]]] = None


# ── Request / Result models ─────────────────────────────────


@dataclass
class InternalCLRequest:
    ip: str
    method: str
    path: str
    user_agent: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    body: Optional[str] = None
    query: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None
    timestamp: Optional[float] = None  # seconds since epoch; defaults to time.time()


@dataclass
class InternalCLAction:
    type: str  # block_ip | rate_limit | block_session | block_user | quarantine_agent | log
    target: str
    reason: str
    ttl_seconds: int
    timestamp: float
    event_id: str


@dataclass
class InternalCLResult:
    decision: CLDecision
    score: float
    tier: Literal[1, 2, 3]
    matched_rules: List[str]
    evaluation_time_us: float
    actions: List[InternalCLAction]
    event_id: str


@dataclass
class InternalCLAuditEntry:
    event_id: str
    timestamp: float
    ip: str
    decision: CLDecision
    score: float
    tier: int
    matched_rules: List[str]
    user_id: Optional[str]
    agent_id: Optional[str]
    path: str
    method: str


@dataclass
class InternalCLRule:
    name: str
    description: str
    severity: str
    score: float
    decision: CLDecision
    match: Callable[[InternalCLRequest], bool]
    enabled: bool = True


@dataclass
class _BlockEntry:
    expires_at: float
    reason: str


@dataclass
class _QuarantineEntry:
    reason: str
    timestamp: float


@dataclass
class _RateLimitEntry:
    timestamps: List[float] = field(default_factory=list)
    blocked: bool = False


# ── Internal Closed-Loop Engine ─────────────────────────────


class InternalClosedLoopEngine:
    def __init__(self, config: Optional[InternalCLConfig] = None):
        self.config = config or InternalCLConfig()

        self._blocked_ips: BoundedMap[str, _BlockEntry] = BoundedMap(self.config.max_blocked_entries)
        self._blocked_users: BoundedMap[str, _BlockEntry] = BoundedMap(self.config.max_blocked_entries)
        self._blocked_sessions: BoundedMap[str, _BlockEntry] = BoundedMap(self.config.max_blocked_entries)
        self._quarantined_agents: BoundedMap[str, _QuarantineEntry] = BoundedMap(self.config.max_blocked_entries)
        self._rate_limiter: BoundedMap[str, _RateLimitEntry] = BoundedMap(self.config.max_rate_limit_entries)
        self._audit_log: List[InternalCLAuditEntry] = []
        self._rules: List[InternalCLRule] = []
        self._event_counter = 0

        self._register_default_rules()
        self._log("info", f"Internal Closed-Loop Engine initialized (fail_mode={self.config.fail_mode})")

    # ── Public API ──────────────────────────────────────────

    async def evaluate(self, req: InternalCLRequest) -> InternalCLResult:
        """Evaluate a request through the 3-tier engine. Call this for every
        inbound request, before it reaches the application — the defining
        behaviour of internal mode is that this never needs a platform
        round-trip to produce a decision.
        """
        start = time.perf_counter()
        now = req.timestamp if req.timestamp is not None else time.time()
        event_id = self._generate_event_id()

        try:
            pre_check = self._check_blocked(req, now)
            if pre_check is not None:
                decision, reason = pre_check
                elapsed_us = (time.perf_counter() - start) * 1_000_000
                result = InternalCLResult(
                    decision=decision,
                    score=100,
                    tier=1,
                    matched_rules=[reason],
                    evaluation_time_us=elapsed_us,
                    actions=[],
                    event_id=event_id,
                )
                self._record_audit(result, req)
                return result

            tier1_decision, tier1_score, tier1_rules = self._evaluate_tier1(req)
            if tier1_decision != "allow":
                elapsed_us = (time.perf_counter() - start) * 1_000_000
                actions = self._execute_actions(tier1_decision, tier1_rules, req, event_id, now)
                result = InternalCLResult(
                    decision=tier1_decision,
                    score=tier1_score,
                    tier=1,
                    matched_rules=tier1_rules,
                    evaluation_time_us=elapsed_us,
                    actions=actions,
                    event_id=event_id,
                )
                self._record_audit(result, req)
                if self.config.enable_external_relay:
                    await self._relay_to_external(result, req)
                return result

            if self._check_rate_limit(req.ip, now):
                elapsed_us = (time.perf_counter() - start) * 1_000_000
                actions = self._execute_actions("rate_limit", ["rate_limit_exceeded"], req, event_id, now)
                result = InternalCLResult(
                    decision="rate_limit",
                    score=65,
                    tier=1,
                    matched_rules=["rate_limit_exceeded"],
                    evaluation_time_us=elapsed_us,
                    actions=actions,
                    event_id=event_id,
                )
                self._record_audit(result, req)
                return result

            self._record_request(req.ip, now)

            # ─── Tier 2: optional custom scorer — unimplemented/pass-through
            # by default. Skipped entirely when no scorer is configured. ───
            if self.config.tier2_scorer is not None:
                score = self.config.tier2_scorer(req)
                if hasattr(score, "__await__"):
                    score = await score  # type: ignore[assignment]
                score = float(score)  # type: ignore[arg-type]

                if score >= self.config.block_threshold:
                    elapsed_us = (time.perf_counter() - start) * 1_000_000
                    actions = self._execute_actions("block", ["tier2_ml_score"], req, event_id, now)
                    result = InternalCLResult(
                        decision="block",
                        score=score,
                        tier=2,
                        matched_rules=["tier2_ml_score"],
                        evaluation_time_us=elapsed_us,
                        actions=actions,
                        event_id=event_id,
                    )
                    self._record_audit(result, req)
                    if self.config.enable_external_relay:
                        await self._relay_to_external(result, req)
                    return result
                elif score >= self.config.rate_limit_threshold:
                    elapsed_us = (time.perf_counter() - start) * 1_000_000
                    result = InternalCLResult(
                        decision="rate_limit",
                        score=score,
                        tier=2,
                        matched_rules=["tier2_ml_elevated"],
                        evaluation_time_us=elapsed_us,
                        actions=[],
                        event_id=event_id,
                    )
                    self._record_audit(result, req)
                    return result

            elapsed_us = (time.perf_counter() - start) * 1_000_000
            return InternalCLResult(
                decision="allow",
                score=0,
                tier=1,
                matched_rules=[],
                evaluation_time_us=elapsed_us,
                actions=[],
                event_id=event_id,
            )
        except Exception as error:  # fail-closed or fail-open per config
            elapsed_us = (time.perf_counter() - start) * 1_000_000
            self._log("error", f"Evaluation error: {error}")
            if self.config.fail_mode == "closed":
                return InternalCLResult(
                    decision="block",
                    score=100,
                    tier=1,
                    matched_rules=["fail_closed_error"],
                    evaluation_time_us=elapsed_us,
                    actions=[],
                    event_id=event_id,
                )
            return InternalCLResult(
                decision="allow",
                score=0,
                tier=1,
                matched_rules=["fail_open_error"],
                evaluation_time_us=elapsed_us,
                actions=[],
                event_id=event_id,
            )

    def block_ip(self, ip: str, reason: str, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self.config.default_block_ttl_seconds
        self._blocked_ips.set(ip, _BlockEntry(expires_at=time.time() + ttl, reason=reason))
        self._log("info", f"IP blocked: {ip} — {reason} (TTL: {ttl}s)")

    def unblock_ip(self, ip: str) -> bool:
        existed = self._blocked_ips.has(ip)
        self._blocked_ips.delete(ip)
        if existed:
            self._log("info", f"IP unblocked: {ip}")
        return existed

    def block_user(self, user_id: str, reason: str, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self.config.default_block_ttl_seconds
        self._blocked_users.set(user_id, _BlockEntry(expires_at=time.time() + ttl, reason=reason))
        self._log("info", f"User blocked: {user_id} — {reason}")

    def block_session(self, session_id: str, reason: str, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self.config.default_block_ttl_seconds
        self._blocked_sessions.set(session_id, _BlockEntry(expires_at=time.time() + ttl, reason=reason))
        self._log("info", f"Session blocked: {session_id} — {reason}")

    def quarantine_agent(self, agent_id: str, reason: str) -> None:
        self._quarantined_agents.set(agent_id, _QuarantineEntry(reason=reason, timestamp=time.time()))
        self._log("info", f"Agent quarantined: {agent_id} — {reason}")

    def unquarantine_agent(self, agent_id: str) -> bool:
        existed = self._quarantined_agents.has(agent_id)
        self._quarantined_agents.delete(agent_id)
        if existed:
            self._log("info", f"Agent unquarantined: {agent_id}")
        return existed

    def is_ip_blocked(self, ip: str) -> bool:
        entry = self._blocked_ips.get(ip)
        if entry is None:
            return False
        if time.time() > entry.expires_at:
            self._blocked_ips.delete(ip)
            return False
        return True

    def is_agent_quarantined(self, agent_id: str) -> bool:
        return self._quarantined_agents.has(agent_id)

    def add_rule(self, rule: InternalCLRule) -> None:
        self._rules.append(rule)
        self._log("debug", f"Rule added: {rule.name}")

    def remove_rule(self, name: str) -> bool:
        for i, rule in enumerate(self._rules):
            if rule.name == name:
                del self._rules[i]
                self._log("debug", f"Rule removed: {name}")
                return True
        return False

    def get_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "score": r.score,
                "decision": r.decision,
                "enabled": r.enabled,
            }
            for r in self._rules
        ]

    def get_audit_log(self, limit: int = 100) -> List[InternalCLAuditEntry]:
        return self._audit_log[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "blocked_ips": self._blocked_ips.size,
            "blocked_users": self._blocked_users.size,
            "blocked_sessions": self._blocked_sessions.size,
            "quarantined_agents": self._quarantined_agents.size,
            "rate_limit_entries": self._rate_limiter.size,
            "audit_log_size": len(self._audit_log),
            "rules_count": len(self._rules),
            "fail_mode": self.config.fail_mode,
        }

    def import_blocked_ips(self, entries: List[Dict[str, Any]]) -> int:
        count = 0
        for entry in entries:
            self.block_ip(entry["ip"], entry["reason"], entry.get("ttl_seconds"))
            count += 1
        return count

    def _reset(self) -> None:
        """Reset all state (for testing)."""
        self._blocked_ips.clear()
        self._blocked_users.clear()
        self._blocked_sessions.clear()
        self._quarantined_agents.clear()
        self._rate_limiter.clear()
        self._audit_log = []
        self._event_counter = 0

    # ── Private: pre-check / Tier 1 / rate limit ─────────────

    def _check_blocked(self, req: InternalCLRequest, now: float) -> Optional[tuple]:
        ip_block = self._blocked_ips.get(req.ip)
        if ip_block is not None:
            if now > ip_block.expires_at:
                self._blocked_ips.delete(req.ip)
            else:
                return ("block", f"ip_blocked:{ip_block.reason}")

        if req.user_id:
            user_block = self._blocked_users.get(req.user_id)
            if user_block is not None:
                if now > user_block.expires_at:
                    self._blocked_users.delete(req.user_id)
                else:
                    return ("block", f"user_blocked:{user_block.reason}")

        if req.session_id:
            session_block = self._blocked_sessions.get(req.session_id)
            if session_block is not None:
                if now > session_block.expires_at:
                    self._blocked_sessions.delete(req.session_id)
                else:
                    return ("block", f"session_blocked:{session_block.reason}")

        if req.agent_id and self._quarantined_agents.has(req.agent_id):
            return ("quarantine", f"agent_quarantined:{req.agent_id}")

        return None

    def _evaluate_tier1(self, req: InternalCLRequest) -> tuple:
        matched_rules: List[str] = []
        max_score = 0.0
        decision: CLDecision = "allow"

        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                if rule.match(req):
                    matched_rules.append(rule.name)
                    if rule.score > max_score:
                        max_score = rule.score
                        decision = rule.decision
            except Exception:
                self._log("error", f"Rule {rule.name} raised an error")

        return decision, max_score, matched_rules

    def _check_rate_limit(self, ip: str, now: float) -> bool:
        entry = self._rate_limiter.get(ip)
        if entry is None:
            return False
        window_start = now - self.config.rate_limit_window_seconds
        entry.timestamps = [t for t in entry.timestamps if t > window_start]
        if len(entry.timestamps) >= self.config.rate_limit_max:
            entry.blocked = True
            return True
        return False

    def _record_request(self, ip: str, now: float) -> None:
        entry = self._rate_limiter.get(ip)
        if entry is None:
            entry = _RateLimitEntry()
        entry.timestamps.append(now)
        self._rate_limiter.set(ip, entry)

    def _execute_actions(
        self, decision: CLDecision, matched_rules: List[str], req: InternalCLRequest, event_id: str, now: float
    ) -> List[InternalCLAction]:
        actions: List[InternalCLAction] = []
        ttl = self.config.default_block_ttl_seconds
        reason = ", ".join(matched_rules)

        if decision in ("block", "quarantine"):
            self._blocked_ips.set(req.ip, _BlockEntry(expires_at=now + ttl, reason=reason))
            actions.append(
                InternalCLAction(type="block_ip", target=req.ip, reason=reason, ttl_seconds=ttl, timestamp=now, event_id=event_id)
            )

            if req.session_id:
                self._blocked_sessions.set(req.session_id, _BlockEntry(expires_at=now + ttl, reason=reason))
                actions.append(
                    InternalCLAction(
                        type="block_session", target=req.session_id, reason=reason, ttl_seconds=ttl, timestamp=now, event_id=event_id
                    )
                )

            if req.agent_id:
                self._quarantined_agents.set(req.agent_id, _QuarantineEntry(reason=reason, timestamp=now))
                actions.append(
                    InternalCLAction(
                        type="quarantine_agent", target=req.agent_id, reason=reason, ttl_seconds=0, timestamp=now, event_id=event_id
                    )
                )

        if self.config.on_action:
            for action in actions:
                try:
                    self.config.on_action(action)
                except Exception:
                    self._log("error", f"on_action callback error for {action.type}")

        return actions

    def _record_audit(self, result: InternalCLResult, req: InternalCLRequest) -> None:
        if len(self._audit_log) >= self.config.max_audit_entries:
            del self._audit_log[: max(1, int(self.config.max_audit_entries * 0.1))]

        self._audit_log.append(
            InternalCLAuditEntry(
                event_id=result.event_id,
                timestamp=req.timestamp if req.timestamp is not None else time.time(),
                ip=req.ip,
                decision=result.decision,
                score=result.score,
                tier=result.tier,
                matched_rules=result.matched_rules,
                user_id=req.user_id,
                agent_id=req.agent_id,
                path=req.path,
                method=req.method,
            )
        )

    async def _relay_to_external(self, result: InternalCLResult, req: InternalCLRequest) -> None:
        # Tier 3: relay via the caller-supplied on_relay callback. This
        # engine has no HTTP client or platform credentials of its own by
        # design — the caller does the actual platform call.
        self._log("debug", f"Tier 3 relay: {result.event_id} -> external platform")
        if self.config.on_relay is None:
            return
        try:
            maybe = self.config.on_relay(result, req)
            if hasattr(maybe, "__await__"):
                await maybe  # type: ignore[misc]
        except Exception as e:
            self._log("error", f"on_relay callback error for {result.event_id}: {e}")

    def _generate_event_id(self) -> str:
        self._event_counter += 1
        ts = format(int(time.time() * 1000), "x")
        counter = format(self._event_counter, "x").rjust(4, "0")
        rand = format(int(time.time() * 1_000_000) % 0xFFFF, "x").rjust(4, "0")
        return f"icl_{ts}_{counter}_{rand}"

    def _register_default_rules(self) -> None:
        def sql_injection(req: InternalCLRequest) -> bool:
            strict_targets = [t for t in (req.path, req.query) if t]
            if any(p.search(t) for t in strict_targets for p in _SQL_INJECTION_STRICT):
                return True
            if any(p.search(t) for t in strict_targets for p in _SQL_INJECTION_MODERATE):
                return True
            body_targets = [t for t in [req.body, *req.headers.values()] if t]
            return any(p.search(t) for t in body_targets for p in _SQL_INJECTION_STRICT)

        self._rules.append(
            InternalCLRule(
                name="sql_injection",
                description="Detects SQL injection patterns context-aware (strict on path/query, moderate on body)",
                severity="critical",
                score=95,
                decision="block",
                match=sql_injection,
            )
        )

        def xss_attempt(req: InternalCLRequest) -> bool:
            targets = [t for t in (req.path, req.query, req.body) if t]
            return any(p.search(t) for t in targets for p in _XSS_PATTERNS)

        self._rules.append(
            InternalCLRule(
                name="xss_attempt",
                description="Detects cross-site scripting patterns",
                severity="high",
                score=90,
                decision="block",
                match=xss_attempt,
            )
        )

        def path_traversal(req: InternalCLRequest) -> bool:
            targets = [t for t in (req.path, req.query) if t]
            return any(p.search(t) for t in targets for p in _PATH_TRAVERSAL_PATTERNS)

        self._rules.append(
            InternalCLRule(
                name="path_traversal",
                description="Detects directory traversal attempts",
                severity="high",
                score=90,
                decision="block",
                match=path_traversal,
            )
        )

        def scanner_detected(req: InternalCLRequest) -> bool:
            if not req.user_agent:
                return False
            return any(p.search(req.user_agent) for p in _SCANNER_SIGNATURES)

        self._rules.append(
            InternalCLRule(
                name="scanner_detected",
                description="Detects known vulnerability scanner user agents",
                severity="medium",
                score=75,
                decision="block",
                match=scanner_detected,
            )
        )

        def sensitive_file_access(req: InternalCLRequest) -> bool:
            return any(p.search(req.path) for p in _SENSITIVE_FILE_PATTERNS)

        self._rules.append(
            InternalCLRule(
                name="sensitive_file_access",
                description="Detects access to sensitive files (.env, .git, wp-admin, etc.)",
                severity="high",
                score=85,
                decision="block",
                match=sensitive_file_access,
            )
        )

        def credential_stuffing_pattern(req: InternalCLRequest) -> bool:
            if req.method != "POST":
                return False
            path_lower = req.path.lower()
            return any(p in path_lower for p in _AUTH_PATHS)

        self._rules.append(
            InternalCLRule(
                name="credential_stuffing_pattern",
                description="Detects credential stuffing via POST to auth endpoints",
                severity="high",
                score=80,
                decision="rate_limit",
                match=credential_stuffing_pattern,
            )
        )

        def agent_unsanctioned_tool(req: InternalCLRequest) -> bool:
            if not req.agent_id or not req.tool_name:
                return False
            return req.tool_name.lower() in _DANGEROUS_TOOLS

        self._rules.append(
            InternalCLRule(
                name="agent_unsanctioned_tool",
                description="Detects agent attempting to use dangerous tools",
                severity="critical",
                score=95,
                decision="quarantine",
                match=agent_unsanctioned_tool,
            )
        )

    def _log(self, level: str, message: str) -> None:
        if not self.config.debug and level == "debug":
            return
        prefix = "[DevFortress ICL]"
        if level in ("error", "warn") or self.config.debug:
            print(f"{prefix} {message}")  # noqa: T201
