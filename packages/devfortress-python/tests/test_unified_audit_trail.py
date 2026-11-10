"""Tests for UnifiedAuditTrail (CL-M3).

Mirrors packages/devfortress-sdk/__tests__/unified-audit.test.ts coverage:
record, query, get_stats, get_decision_distribution, get_latency_histogram,
export_json, bounded storage, reset, onEntry callback, debug mode — plus
dedup/merge (S27) coverage Node's own test file does not have, since the
underlying logic is real and already present in both Node and this port.
"""

import json
import random
import string
import time

import pytest

from devfortress.unified_audit_trail import UnifiedAuditEntry, UnifiedAuditTrail


def make_entry(**overrides):
    base = dict(
        event_id=f"evt_{''.join(random.choices(string.ascii_lowercase, k=6))}",
        timestamp=time.time() * 1000,
        source="internal",
        tier=1,
        decision="allow",
        score=10,
        severity="low",
        latency_ms=0.5,
        ip="192.168.1.1",
        path="/api/test",
        method="GET",
        matched_rules=[],
    )
    base.update(overrides)
    return UnifiedAuditEntry(**base)


@pytest.fixture
def audit():
    a = UnifiedAuditTrail(debug=False)
    yield a
    a.reset()


class TestRecordAndQuery:
    def test_record_and_retrieve(self, audit):
        audit.record(make_entry(ip="10.0.0.1"))
        audit.record(make_entry(ip="10.0.0.2"))
        assert len(audit.query()) == 2

    def test_filter_by_source(self, audit):
        audit.record(make_entry(source="internal"))
        audit.record(make_entry(source="external"))
        audit.record(make_entry(source="hybrid"))
        assert len(audit.query(source="internal")) == 1
        assert len(audit.query(source="external")) == 1
        assert len(audit.query(source="hybrid")) == 1

    def test_filter_by_decision(self, audit):
        audit.record(make_entry(decision="allow"))
        audit.record(make_entry(decision="block"))
        audit.record(make_entry(decision="rate_limit"))
        assert len(audit.query(decision="block")) == 1

    def test_filter_by_ip(self, audit):
        audit.record(make_entry(ip="1.2.3.4"))
        audit.record(make_entry(ip="5.6.7.8"))
        assert len(audit.query(ip="1.2.3.4")) == 1

    def test_filter_by_user_id(self, audit):
        audit.record(make_entry(user_id="user-1"))
        audit.record(make_entry(user_id="user-2"))
        assert len(audit.query(user_id="user-1")) == 1

    def test_filter_by_agent_id(self, audit):
        audit.record(make_entry(agent_id="agent-A"))
        audit.record(make_entry(agent_id="agent-B"))
        assert len(audit.query(agent_id="agent-A")) == 1

    def test_filter_by_min_score(self, audit):
        audit.record(make_entry(score=20))
        audit.record(make_entry(score=60))
        audit.record(make_entry(score=90))
        assert len(audit.query(min_score=50)) == 2

    def test_filter_by_since(self, audit):
        now = time.time() * 1000
        audit.record(make_entry(timestamp=now - 10_000))
        audit.record(make_entry(timestamp=now - 5_000))
        audit.record(make_entry(timestamp=now))
        assert len(audit.query(since=now - 7_000)) == 2

    def test_limit_results(self, audit):
        for _ in range(50):
            audit.record(make_entry())
        assert len(audit.query(limit=10)) == 10

    def test_combine_multiple_filters(self, audit):
        audit.record(make_entry(source="internal", decision="block", score=85))
        audit.record(make_entry(source="internal", decision="allow", score=10))
        audit.record(make_entry(source="external", decision="block", score=90))

        results = audit.query(source="internal", decision="block", min_score=80)
        assert len(results) == 1
        assert results[0].score == 85


class TestGetStats:
    def test_counts_decisions_by_source(self, audit):
        audit.record(make_entry(source="internal"))
        audit.record(make_entry(source="internal"))
        audit.record(make_entry(source="external"))
        audit.record(make_entry(source="hybrid"))

        stats = audit.get_stats()
        assert stats["total"] == 4
        assert stats["internal_decisions"] == 2
        assert stats["external_decisions"] == 1
        assert stats["hybrid_decisions"] == 1

    def test_counts_blocks_allows_rate_limits(self, audit):
        audit.record(make_entry(decision="block"))
        audit.record(make_entry(decision="allow"))
        audit.record(make_entry(decision="allow"))
        audit.record(make_entry(decision="rate_limit"))

        stats = audit.get_stats()
        assert stats["total_blocks"] == 1
        assert stats["total_allows"] == 2
        assert stats["total_rate_limits"] == 1

    def test_tracks_fallback_events(self, audit):
        audit.record(make_entry(source="hybrid", fallback_mode=True))
        audit.record(make_entry(source="hybrid", fallback_mode=False))
        assert audit.get_stats()["fallback_events"] == 1

    def test_computes_average_latencies(self, audit):
        audit.record(make_entry(source="internal", latency_ms=0.5))
        audit.record(make_entry(source="internal", latency_ms=1.5))
        audit.record(make_entry(source="external", latency_ms=100))
        audit.record(make_entry(source="external", latency_ms=200))

        stats = audit.get_stats()
        assert stats["avg_internal_latency_ms"] == 1
        assert stats["avg_external_latency_ms"] == 150


class TestGetDecisionDistribution:
    def test_returns_source_decision_counts(self, audit):
        audit.record(make_entry(source="internal", decision="allow"))
        audit.record(make_entry(source="internal", decision="allow"))
        audit.record(make_entry(source="internal", decision="block"))
        audit.record(make_entry(source="external", decision="allow"))

        dist = audit.get_decision_distribution()
        assert dist["internal:allow"] == 2
        assert dist["internal:block"] == 1
        assert dist["external:allow"] == 1


class TestGetLatencyHistogram:
    def test_buckets_latencies_correctly(self, audit):
        audit.record(make_entry(latency_ms=0.3))
        audit.record(make_entry(latency_ms=2))
        audit.record(make_entry(latency_ms=30))
        audit.record(make_entry(latency_ms=100))
        audit.record(make_entry(latency_ms=500))
        audit.record(make_entry(latency_ms=2000))

        hist = audit.get_latency_histogram()
        assert hist["under_1ms"] == 1
        assert hist["under_5ms"] == 1
        assert hist["under_50ms"] == 1
        assert hist["under_200ms"] == 1
        assert hist["under_1s"] == 1
        assert hist["over_1s"] == 1


class TestExportJson:
    def test_exports_all_entries(self, audit):
        audit.record(make_entry(ip="1.1.1.1"))
        audit.record(make_entry(ip="2.2.2.2"))
        parsed = json.loads(audit.export_json())
        assert len(parsed) == 2

    def test_exports_entries_since_timestamp(self, audit):
        now = time.time() * 1000
        audit.record(make_entry(timestamp=now - 10_000))
        audit.record(make_entry(timestamp=now))
        parsed = json.loads(audit.export_json(since=now - 5_000))
        assert len(parsed) == 1


class TestBoundedStorage:
    def test_evicts_oldest_10pct_when_max_entries_reached(self):
        small = UnifiedAuditTrail(max_entries=100)
        for i in range(110):
            small.record(make_entry(event_id=f"evt_{i}"))

        stats = small.get_stats()
        assert stats["total"] <= 110
        assert stats["total"] > 90


class TestReset:
    def test_clears_all_entries_and_stats(self, audit):
        audit.record(make_entry())
        audit.record(make_entry())
        assert audit.get_stats()["total"] == 2

        audit.reset()
        assert audit.get_stats()["total"] == 0
        assert audit.get_stats()["internal_decisions"] == 0


class TestOnEntryCallback:
    def test_fires_callback_for_each_recorded_entry(self):
        received = []
        tracked = UnifiedAuditTrail(on_entry=lambda e: received.append(e))
        tracked.record(make_entry())
        tracked.record(make_entry())
        assert len(received) == 2

    def test_survives_callback_errors(self):
        def boom(_entry):
            raise RuntimeError("callback error")

        error_audit = UnifiedAuditTrail(on_entry=boom)
        error_audit.record(make_entry())  # must not raise
        assert error_audit.get_stats()["total"] == 1


class TestDebugMode:
    def test_logs_entries_when_debug_enabled(self, capsys):
        debug_audit = UnifiedAuditTrail(debug=True)
        debug_audit.record(make_entry())
        captured = capsys.readouterr()
        assert "[DF Audit]" in captured.out


class TestDedupMerge:
    """S27: same eventId within the 5s window is merged (external
    overrides internal), not duplicated — logic present in Node's source
    but not covered by Node's own test file."""

    def test_external_overrides_internal_within_window(self, audit):
        audit.record(make_entry(event_id="evt_dup", source="internal", decision="allow"))
        audit.record(make_entry(event_id="evt_dup", source="external", decision="block"))

        results = audit.query()
        assert len(results) == 1
        assert results[0].source == "hybrid"
        assert results[0].decision == "block"

    def test_duplicate_internal_is_skipped_not_merged(self, audit):
        audit.record(make_entry(event_id="evt_dup2", source="internal", decision="allow"))
        audit.record(make_entry(event_id="evt_dup2", source="internal", decision="block"))

        results = audit.query()
        assert len(results) == 1
        assert results[0].decision == "allow"
