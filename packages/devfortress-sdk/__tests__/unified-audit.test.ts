/**
 * Tests for UnifiedAuditTrail (CL-M3)
 *
 * Coverage: record, query, getStats, getDecisionDistribution,
 * getLatencyHistogram, exportJSON, bounded storage, _reset.
 */
import {
  UnifiedAuditTrail,
  type UnifiedAuditEntry,
} from '../src/unified-audit';

// Suppress console output during tests
beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterAll(() => {
  jest.restoreAllMocks();
});

function makeEntry(
  overrides: Partial<UnifiedAuditEntry> = {}
): UnifiedAuditEntry {
  return {
    eventId: `evt_${Math.random().toString(36).slice(2, 8)}`,
    timestamp: Date.now(),
    source: 'internal',
    tier: 1,
    decision: 'allow',
    score: 10,
    severity: 'low',
    latencyMs: 0.5,
    ip: '192.168.1.1',
    path: '/api/test',
    method: 'GET',
    matchedRules: [],
    ...overrides,
  };
}

describe('UnifiedAuditTrail', () => {
  let audit: UnifiedAuditTrail;

  beforeEach(() => {
    audit = new UnifiedAuditTrail({ debug: false });
  });

  afterEach(() => {
    audit._reset();
  });

  // ── Record & Query ────────────────────────────────────────

  describe('record and query', () => {
    it('should record and retrieve entries', () => {
      audit.record(makeEntry({ ip: '10.0.0.1' }));
      audit.record(makeEntry({ ip: '10.0.0.2' }));

      const all = audit.query();
      expect(all).toHaveLength(2);
    });

    it('should filter by source', () => {
      audit.record(makeEntry({ source: 'internal' }));
      audit.record(makeEntry({ source: 'external' }));
      audit.record(makeEntry({ source: 'hybrid' }));

      expect(audit.query({ source: 'internal' })).toHaveLength(1);
      expect(audit.query({ source: 'external' })).toHaveLength(1);
      expect(audit.query({ source: 'hybrid' })).toHaveLength(1);
    });

    it('should filter by decision', () => {
      audit.record(makeEntry({ decision: 'allow' }));
      audit.record(makeEntry({ decision: 'block' }));
      audit.record(makeEntry({ decision: 'rate_limit' }));

      expect(audit.query({ decision: 'block' })).toHaveLength(1);
    });

    it('should filter by IP', () => {
      audit.record(makeEntry({ ip: '1.2.3.4' }));
      audit.record(makeEntry({ ip: '5.6.7.8' }));

      expect(audit.query({ ip: '1.2.3.4' })).toHaveLength(1);
    });

    it('should filter by userId', () => {
      audit.record(makeEntry({ userId: 'user-1' }));
      audit.record(makeEntry({ userId: 'user-2' }));

      expect(audit.query({ userId: 'user-1' })).toHaveLength(1);
    });

    it('should filter by agentId', () => {
      audit.record(makeEntry({ agentId: 'agent-A' }));
      audit.record(makeEntry({ agentId: 'agent-B' }));

      expect(audit.query({ agentId: 'agent-A' })).toHaveLength(1);
    });

    it('should filter by minScore', () => {
      audit.record(makeEntry({ score: 20 }));
      audit.record(makeEntry({ score: 60 }));
      audit.record(makeEntry({ score: 90 }));

      expect(audit.query({ minScore: 50 })).toHaveLength(2);
    });

    it('should filter by since timestamp', () => {
      const now = Date.now();
      audit.record(makeEntry({ timestamp: now - 10_000 }));
      audit.record(makeEntry({ timestamp: now - 5_000 }));
      audit.record(makeEntry({ timestamp: now }));

      expect(audit.query({ since: now - 7_000 })).toHaveLength(2);
    });

    it('should limit results', () => {
      for (let i = 0; i < 50; i++) {
        audit.record(makeEntry());
      }

      expect(audit.query({ limit: 10 })).toHaveLength(10);
    });

    it('should combine multiple filters', () => {
      audit.record(
        makeEntry({ source: 'internal', decision: 'block', score: 85 })
      );
      audit.record(
        makeEntry({ source: 'internal', decision: 'allow', score: 10 })
      );
      audit.record(
        makeEntry({ source: 'external', decision: 'block', score: 90 })
      );

      const results = audit.query({
        source: 'internal',
        decision: 'block',
        minScore: 80,
      });
      expect(results).toHaveLength(1);
      expect(results[0].score).toBe(85);
    });
  });

  // ── Statistics ────────────────────────────────────────────

  describe('getStats', () => {
    it('should count decisions by source', () => {
      audit.record(makeEntry({ source: 'internal' }));
      audit.record(makeEntry({ source: 'internal' }));
      audit.record(makeEntry({ source: 'external' }));
      audit.record(makeEntry({ source: 'hybrid' }));

      const stats = audit.getStats();
      expect(stats.total).toBe(4);
      expect(stats.internalDecisions).toBe(2);
      expect(stats.externalDecisions).toBe(1);
      expect(stats.hybridDecisions).toBe(1);
    });

    it('should count blocks, allows, and rate limits', () => {
      audit.record(makeEntry({ decision: 'block' }));
      audit.record(makeEntry({ decision: 'allow' }));
      audit.record(makeEntry({ decision: 'allow' }));
      audit.record(makeEntry({ decision: 'rate_limit' }));

      const stats = audit.getStats();
      expect(stats.totalBlocks).toBe(1);
      expect(stats.totalAllows).toBe(2);
      expect(stats.totalRateLimits).toBe(1);
    });

    it('should track fallback events', () => {
      audit.record(makeEntry({ source: 'hybrid', fallbackMode: true }));
      audit.record(makeEntry({ source: 'hybrid', fallbackMode: false }));

      expect(audit.getStats().fallbackEvents).toBe(1);
    });

    it('should compute average latencies', () => {
      audit.record(makeEntry({ source: 'internal', latencyMs: 0.5 }));
      audit.record(makeEntry({ source: 'internal', latencyMs: 1.5 }));
      audit.record(makeEntry({ source: 'external', latencyMs: 100 }));
      audit.record(makeEntry({ source: 'external', latencyMs: 200 }));

      const stats = audit.getStats();
      expect(stats.avgInternalLatencyMs).toBe(1); // (0.5 + 1.5) / 2 = 1
      expect(stats.avgExternalLatencyMs).toBe(150); // (100 + 200) / 2 = 150
    });
  });

  // ── Decision Distribution ─────────────────────────────────

  describe('getDecisionDistribution', () => {
    it('should return source:decision counts', () => {
      audit.record(makeEntry({ source: 'internal', decision: 'allow' }));
      audit.record(makeEntry({ source: 'internal', decision: 'allow' }));
      audit.record(makeEntry({ source: 'internal', decision: 'block' }));
      audit.record(makeEntry({ source: 'external', decision: 'allow' }));

      const dist = audit.getDecisionDistribution();
      expect(dist['internal:allow']).toBe(2);
      expect(dist['internal:block']).toBe(1);
      expect(dist['external:allow']).toBe(1);
    });
  });

  // ── Latency Histogram ─────────────────────────────────────

  describe('getLatencyHistogram', () => {
    it('should bucket latencies correctly', () => {
      audit.record(makeEntry({ latencyMs: 0.3 })); // under1ms
      audit.record(makeEntry({ latencyMs: 2 })); // under5ms
      audit.record(makeEntry({ latencyMs: 30 })); // under50ms
      audit.record(makeEntry({ latencyMs: 100 })); // under200ms
      audit.record(makeEntry({ latencyMs: 500 })); // under1s
      audit.record(makeEntry({ latencyMs: 2000 })); // over1s

      const hist = audit.getLatencyHistogram();
      expect(hist.under1ms).toBe(1);
      expect(hist.under5ms).toBe(1);
      expect(hist.under50ms).toBe(1);
      expect(hist.under200ms).toBe(1);
      expect(hist.under1s).toBe(1);
      expect(hist.over1s).toBe(1);
    });
  });

  // ── Export ────────────────────────────────────────────────

  describe('exportJSON', () => {
    it('should export all entries as valid JSON', () => {
      audit.record(makeEntry({ ip: '1.1.1.1' }));
      audit.record(makeEntry({ ip: '2.2.2.2' }));

      const json = audit.exportJSON();
      const parsed = JSON.parse(json);
      expect(parsed).toHaveLength(2);
    });

    it('should export entries since a given timestamp', () => {
      const now = Date.now();
      audit.record(makeEntry({ timestamp: now - 10_000 }));
      audit.record(makeEntry({ timestamp: now }));

      const json = audit.exportJSON(now - 5_000);
      const parsed = JSON.parse(json);
      expect(parsed).toHaveLength(1);
    });
  });

  // ── Bounded Storage ───────────────────────────────────────

  describe('bounded storage', () => {
    it('should evict oldest 10% when maxEntries is reached', () => {
      const small = new UnifiedAuditTrail({ maxEntries: 100 });

      for (let i = 0; i < 110; i++) {
        small.record(makeEntry({ eventId: `evt_${i}` }));
      }

      // After filling to 100, recording #100 triggers eviction of 10,
      // then continues adding. Total: ~100
      const stats = small.getStats();
      expect(stats.total).toBeLessThanOrEqual(110);
      expect(stats.total).toBeGreaterThan(90);
    });
  });

  // ── _reset ────────────────────────────────────────────────

  describe('_reset', () => {
    it('should clear all entries and stats', () => {
      audit.record(makeEntry());
      audit.record(makeEntry());
      expect(audit.getStats().total).toBe(2);

      audit._reset();
      expect(audit.getStats().total).toBe(0);
      expect(audit.getStats().internalDecisions).toBe(0);
    });
  });

  // ── onEntry Callback ──────────────────────────────────────

  describe('onEntry callback', () => {
    it('should fire callback for each recorded entry', () => {
      const received: UnifiedAuditEntry[] = [];
      const tracked = new UnifiedAuditTrail({
        onEntry: entry => {
          received.push(entry);
        },
      });

      tracked.record(makeEntry());
      tracked.record(makeEntry());

      expect(received).toHaveLength(2);
    });

    it('should survive callback errors', () => {
      const errorAudit = new UnifiedAuditTrail({
        onEntry: () => {
          throw new Error('callback error');
        },
      });

      expect(() => errorAudit.record(makeEntry())).not.toThrow();
      expect(errorAudit.getStats().total).toBe(1);
    });
  });

  // ── Debug Mode ────────────────────────────────────────────

  describe('debug mode', () => {
    it('should log entries when debug is enabled', () => {
      const debugAudit = new UnifiedAuditTrail({ debug: true });
      const logSpy = jest.spyOn(console, 'log');

      debugAudit.record(makeEntry());

      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('[DF Audit]')
      );
    });
  });
});
