"""DevFortress SDK — Unified Audit Trail (CL-M3).

Port of packages/devfortress-sdk/src/unified-audit.ts.

Merges internal and external closed-loop audit events into a single
in-memory timeline with consistent fields regardless of source.

NOTE on tamper-evidence: this is an in-memory log only — it is not
cryptographically signed or hash-chained, and neither is Node's own
``UnifiedAuditTrail``. The HMAC-signed, hash-chained tamper-evident audit
trail (TODO 265/266/272) is a separate, server-side Next.js module
(``lib/audit-trail-signer.ts``) operating directly on the ``LiveThreatEvent``
Postgres table. It has no SDK-side analog in any language, including Node,
so this port does not and cannot provide tamper-evidence either.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional

AuditSource = Literal["internal", "external", "hybrid"]
ThreatSeverity = Literal["low", "medium", "high", "critical"]

DEDUP_WINDOW_MS = 5_000
DEFAULT_MAX_ENTRIES = 100_000
_DEDUP_MAP_CAP = 10_000


@dataclass
class UnifiedAuditEntry:
    event_id: str
    timestamp: float
    source: AuditSource
    tier: int
    decision: str
    score: float
    severity: ThreatSeverity
    latency_ms: float
    ip: str
    path: str
    method: str
    matched_rules: List[str] = field(default_factory=list)
    user_id: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    fallback_mode: Optional[bool] = None
    meta: Optional[Dict[str, Any]] = None


class UnifiedAuditTrail:
    """In-memory audit sink merging internal/external/hybrid closed-loop
    decisions into a single timeline. Mirrors Node's ``UnifiedAuditTrail``
    (unified-audit.ts) feature-for-feature: bounded storage, the S27 dedup
    window for hybrid mode, aggregated stats, decision distribution,
    latency histogram, and JSON export. Thread-safe.
    """

    def __init__(
        self,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        on_entry: Optional[Callable[[UnifiedAuditEntry], None]] = None,
        debug: bool = False,
    ):
        self._max_entries = max_entries
        self._on_entry = on_entry
        self._debug = debug
        self._lock = threading.Lock()
        self._entries: List[UnifiedAuditEntry] = []
        self._recent_event_ids: Dict[str, float] = {}
        self._stats = {
            "internal_decisions": 0,
            "external_decisions": 0,
            "hybrid_decisions": 0,
            "fallback_events": 0,
            "total_blocks": 0,
            "total_allows": 0,
            "total_rate_limits": 0,
            "internal_latency_sum": 0.0,
            "external_latency_sum": 0.0,
        }

    def record(self, entry: UnifiedAuditEntry) -> None:
        """Record an audit entry from any source. S27: same eventId within
        the 5s dedup window is merged (external overrides internal), not
        duplicated."""
        fire_entry: Optional[UnifiedAuditEntry] = None

        with self._lock:
            now_ms = time.time() * 1000
            existing = self._recent_event_ids.get(entry.event_id)
            if existing is not None and now_ms - existing < DEDUP_WINDOW_MS:
                if entry.source == "external":
                    for i, e in enumerate(self._entries):
                        if e.event_id == entry.event_id and e.source == "internal":
                            merged = {**asdict(e), **asdict(entry), "source": "hybrid"}
                            self._entries[i] = UnifiedAuditEntry(**merged)
                            if self._debug:
                                print(
                                    f"[DF Audit] DEDUP: merged {entry.event_id} "
                                    "(external overrides internal)"
                                )
                            break
                return

            self._recent_event_ids[entry.event_id] = now_ms
            if len(self._recent_event_ids) > _DEDUP_MAP_CAP:
                cutoff = now_ms - DEDUP_WINDOW_MS
                for eid, ts in list(self._recent_event_ids.items()):
                    if ts < cutoff:
                        del self._recent_event_ids[eid]

            if len(self._entries) >= self._max_entries:
                del self._entries[: int(self._max_entries * 0.1)]

            self._entries.append(entry)
            self._update_stats(entry)
            fire_entry = entry

        if fire_entry is not None and self._on_entry is not None:
            try:
                self._on_entry(fire_entry)
            except Exception:
                pass

        if self._debug and fire_entry is not None:
            print(
                f"[DF Audit] {entry.source}:tier{entry.tier} {entry.decision} "
                f"score={entry.score} {entry.ip} {entry.method} {entry.path} "
                f"({entry.latency_ms}ms)"
            )

    def query(
        self,
        source: Optional[AuditSource] = None,
        decision: Optional[str] = None,
        ip: Optional[str] = None,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        min_score: Optional[float] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> List[UnifiedAuditEntry]:
        """Query audit entries with filters."""
        with self._lock:
            result = list(self._entries)

        if source is not None:
            result = [e for e in result if e.source == source]
        if decision is not None:
            result = [e for e in result if e.decision == decision]
        if ip is not None:
            result = [e for e in result if e.ip == ip]
        if user_id is not None:
            result = [e for e in result if e.user_id == user_id]
        if agent_id is not None:
            result = [e for e in result if e.agent_id == agent_id]
        if min_score is not None:
            result = [e for e in result if e.score >= min_score]
        if since is not None:
            result = [e for e in result if e.timestamp >= since]

        return result[-limit:] if limit else result

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregated statistics."""
        with self._lock:
            stats = dict(self._stats)
            total = len(self._entries)

        avg_internal = (
            round(stats["internal_latency_sum"] / stats["internal_decisions"])
            if stats["internal_decisions"] > 0
            else 0
        )
        avg_external = (
            round(stats["external_latency_sum"] / stats["external_decisions"])
            if stats["external_decisions"] > 0
            else 0
        )

        return {
            "total": total,
            "internal_decisions": stats["internal_decisions"],
            "external_decisions": stats["external_decisions"],
            "hybrid_decisions": stats["hybrid_decisions"],
            "fallback_events": stats["fallback_events"],
            "total_blocks": stats["total_blocks"],
            "total_allows": stats["total_allows"],
            "total_rate_limits": stats["total_rate_limits"],
            "avg_internal_latency_ms": avg_internal,
            "avg_external_latency_ms": avg_external,
        }

    def get_decision_distribution(self) -> Dict[str, int]:
        """Get decision distribution for dashboard visualization."""
        dist: Dict[str, int] = {}
        with self._lock:
            entries = list(self._entries)
        for e in entries:
            key = f"{e.source}:{e.decision}"
            dist[key] = dist.get(key, 0) + 1
        return dist

    def get_latency_histogram(self) -> Dict[str, int]:
        """Get latency histogram buckets."""
        hist = {
            "under_1ms": 0,
            "under_5ms": 0,
            "under_50ms": 0,
            "under_200ms": 0,
            "under_1s": 0,
            "over_1s": 0,
        }
        with self._lock:
            entries = list(self._entries)
        for e in entries:
            if e.latency_ms < 1:
                hist["under_1ms"] += 1
            elif e.latency_ms < 5:
                hist["under_5ms"] += 1
            elif e.latency_ms < 50:
                hist["under_50ms"] += 1
            elif e.latency_ms < 200:
                hist["under_200ms"] += 1
            elif e.latency_ms < 1000:
                hist["under_1s"] += 1
            else:
                hist["over_1s"] += 1
        return hist

    def export_json(self, since: Optional[float] = None) -> str:
        """Export entries as JSON (for compliance/archival)."""
        with self._lock:
            entries = list(self._entries)
        if since is not None:
            entries = [e for e in entries if e.timestamp >= since]
        return json.dumps([asdict(e) for e in entries], indent=2)

    def reset(self) -> None:
        """Reset the audit trail (for testing). @internal"""
        with self._lock:
            self._entries = []
            self._recent_event_ids = {}
            self._stats = {key: 0 for key in self._stats}

    def _update_stats(self, entry: UnifiedAuditEntry) -> None:
        if entry.source == "internal":
            self._stats["internal_decisions"] += 1
            self._stats["internal_latency_sum"] += entry.latency_ms
        elif entry.source == "external":
            self._stats["external_decisions"] += 1
            self._stats["external_latency_sum"] += entry.latency_ms
        else:
            self._stats["hybrid_decisions"] += 1
            if entry.tier > 0:
                self._stats["internal_latency_sum"] += entry.latency_ms
            else:
                self._stats["external_latency_sum"] += entry.latency_ms

        if entry.fallback_mode:
            self._stats["fallback_events"] += 1

        if entry.decision == "block":
            self._stats["total_blocks"] += 1
        elif entry.decision == "allow":
            self._stats["total_allows"] += 1
        elif entry.decision == "rate_limit":
            self._stats["total_rate_limits"] += 1
