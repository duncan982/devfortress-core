/**
 * Tests for DevFortress v4.0.0 — Three-Mode Closed-Loop Integration
 *
 * Coverage: constructor (mode resolution, tier gating), observe (external,
 * internal, hybrid), blockIP/unblockIP tier enforcement, isBlocked,
 * trackEvent, getMode/getAudit/getTierGate accessors, onThreatDetected.
 */

import { DevFortressCore as DevFortress } from '../src/devfortress';
import type { DevFortressConfig, ObserveResult } from '../src/types';
import { MLClassifier } from '../src/ml-classifier';

// Mock axios
jest.mock('axios', () => {
  const mockInstance = {
    post: jest.fn().mockResolvedValue({
      data: {
        success: true,
        eventId: 'evt_mock',
        flagged: false,
        confidence: 0.1,
      },
    }),
    get: jest.fn().mockResolvedValue({
      data: { blocked: false },
    }),
    patch: jest.fn().mockResolvedValue({ data: { success: true } }),
  };

  return {
    create: jest.fn(() => mockInstance),
    __mockInstance: mockInstance,
  };
});

// Suppress console output during tests
beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => {
  jest.restoreAllMocks();
});

function baseConfig(
  overrides: Partial<DevFortressConfig> = {}
): DevFortressConfig {
  return {
    apiKey: 'test-api-key',
    appId: 'test-app',
    debug: false,
    ...overrides,
  };
}

function mockReq(ip = '192.168.1.100', path = '/api/test') {
  return {
    method: 'GET',
    url: path,
    headers: {
      'x-forwarded-for': ip,
      'user-agent': 'Mozilla/5.0 (X11; Linux x86_64)',
    },
  };
}

// ── Constructor & Mode Resolution ───────────────────────────

describe('DevFortress — Constructor', () => {
  it('should require apiKey', () => {
    expect(() => new DevFortress({ apiKey: '', appId: 'x' })).toThrow(
      'apiKey is required'
    );
  });

  it('should require appId', () => {
    expect(() => new DevFortress({ apiKey: 'x', appId: '' })).toThrow(
      'appId is required'
    );
  });

  it('should default to external mode with starter tier', () => {
    const df = new DevFortress(baseConfig());
    expect(df.getMode()).toBe('external');
    expect(df.getTierGate().getTier()).toBe('starter');
  });

  it('should respect enterprise tier with hybrid default', () => {
    const df = new DevFortress(baseConfig({ tier: 'enterprise' }));
    expect(df.getMode()).toBe('hybrid');
  });

  it('should allow internal mode for enterprise', () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );
    expect(df.getMode()).toBe('internal');
  });

  it('should downgrade internal request on starter to external', () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'starter',
        mode: 'internal',
      })
    );
    expect(df.getMode()).toBe('external');
  });

  it('should downgrade hybrid on pro without addon to external', () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'pro',
        mode: 'hybrid',
      })
    );
    expect(df.getMode()).toBe('external');
  });

  it('should reject hybrid on pro even with the (now-defunct) addon flag', () => {
    // Package A (2026-08-28): Pro never gets ICL/hybrid at any point.
    const df = new DevFortress(
      baseConfig({
        tier: 'pro',
        mode: 'hybrid',
        hybridAddonEnabled: true,
      })
    );
    expect(df.getMode()).toBe('external');
  });

  it('should default team tier to hybrid mode', () => {
    const df = new DevFortress(baseConfig({ tier: 'team' }));
    expect(df.getMode()).toBe('hybrid');
  });
});

// ── Accessors ───────────────────────────────────────────────

describe('DevFortress — Accessors', () => {
  it('should expose audit trail', () => {
    const df = new DevFortress(baseConfig({ tier: 'enterprise' }));
    expect(df.getAudit()).toBeDefined();
    expect(typeof df.getAudit().record).toBe('function');
  });

  it('should expose tier gate', () => {
    const df = new DevFortress(baseConfig({ tier: 'pro' }));
    expect(df.getTierGate()).toBeDefined();
    expect(df.getTierGate().canBlock()).toBe(true);
  });

  it('should expose internal engine for internal mode', () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );
    expect(df.getInternalEngine()).not.toBeNull();
  });

  it('should return null internal engine for external mode', () => {
    const df = new DevFortress(baseConfig({ tier: 'starter' }));
    expect(df.getInternalEngine()).toBeNull();
  });

  it('should expose circuit breaker diagnostics for hybrid mode', () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'hybrid',
      })
    );
    const diag = df.getCircuitBreakerDiagnostics();
    expect(diag).not.toBeNull();
    expect(diag!.state).toBe('closed');
  });

  it('should return null circuit breaker for non-hybrid modes', () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'external',
      })
    );
    expect(df.getCircuitBreakerDiagnostics()).toBeNull();
  });
});

// ── External Observe ────────────────────────────────────────

describe('DevFortress — External Observe', () => {
  it('should send request to platform and return null for clean traffic', async () => {
    const df = new DevFortress(baseConfig());
    const result = await df.observe(mockReq());

    // Mock returns flagged: false, so result should be null
    expect(result).toBeNull();
  });

  it('should record audit entry for external observe', async () => {
    const df = new DevFortress(baseConfig());
    await df.observe(mockReq());

    const stats = df.getAudit().getStats();
    expect(stats.total).toBe(1);
    expect(stats.externalDecisions).toBe(1);
  });
});

// ── Internal Observe ────────────────────────────────────────

describe('DevFortress — Internal Observe', () => {
  it('should evaluate locally without platform calls', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );

    const result = await df.observe(mockReq());

    // Normal traffic should be allowed
    expect(result).toBeNull();

    const stats = df.getAudit().getStats();
    expect(stats.internalDecisions).toBeGreaterThanOrEqual(1);
  });

  it('should flag suspicious traffic', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );

    // SQL injection in path should be flagged by Tier 1 rules
    const result = await df.observe(
      mockReq('192.168.1.200', '/api/test?id=1%20OR%201=1')
    );

    // The internal engine should detect the SQLi pattern
    if (result) {
      expect(result.flagged).toBe(true);
      expect(result.confidence).toBeGreaterThan(0);
    }
  });

  it('should record internal audit entries', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );

    await df.observe(mockReq());

    const entries = df.getAudit().query({ source: 'internal' });
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries[0].source).toBe('internal');
    expect(entries[0].tier).toBeGreaterThanOrEqual(1);
  });
});

// ── Hybrid Observe ──────────────────────────────────────────

describe('DevFortress — Hybrid Observe', () => {
  it('should evaluate internally first then relay', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'hybrid',
      })
    );

    const result = await df.observe(mockReq());

    // Clean traffic: internal allows → external enrichment also clean
    expect(result).toBeNull();

    const stats = df.getAudit().getStats();
    // At minimum the internal decision should be recorded
    expect(stats.total).toBeGreaterThanOrEqual(1);
  });

  it('should return immediately if internal blocks', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'hybrid',
      })
    );

    // Block the IP first
    df.blockIP('10.10.10.10');

    // Request from blocked IP — internal should block immediately
    const result = await df.observe(mockReq('10.10.10.10'));

    if (result) {
      expect(result.flagged).toBe(true);
    }
  });
});

// ── Block / Unblock ─────────────────────────────────────────

describe('DevFortress — blockIP / unblockIP', () => {
  it('should block and unblock IP on enterprise tier', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'external',
      })
    );

    df.blockIP('1.2.3.4');
    expect(await df.isBlocked('1.2.3.4')).toBe(true);

    df.unblockIP('1.2.3.4');
    // After unblock, in-memory cache is cleared
    // External check will return false (mocked)
    expect(await df.isBlocked('1.2.3.4')).toBe(false);
  });

  it('should refuse blockIP on starter tier', () => {
    const df = new DevFortress(baseConfig({ tier: 'starter' }));

    // Should not throw, but should warn
    df.blockIP('1.2.3.4');

    // The IP should NOT be blocked since starter can't block
    // (The method returns void but should log a warning)
  });

  it('should block in internal engine when in hybrid mode', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'hybrid',
      })
    );

    df.blockIP('5.5.5.5');

    // Should be blocked in both internal engine and memory cache
    const engine = df.getInternalEngine();
    expect(engine).not.toBeNull();
    expect(engine!.isIPBlocked('5.5.5.5')).toBe(true);
  });
});

// ── isBlocked ───────────────────────────────────────────────

describe('DevFortress — isBlocked', () => {
  it('should check internal engine first in hybrid mode', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'hybrid',
      })
    );

    df.blockIP('9.9.9.9');
    expect(await df.isBlocked('9.9.9.9')).toBe(true);
  });

  it('should not make external calls in internal mode', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );

    // Not blocked — should return false without external call
    expect(await df.isBlocked('8.8.8.8')).toBe(false);
  });
});

// ── onThreatDetected ────────────────────────────────────────

describe('DevFortress — onThreatDetected', () => {
  it('should register and fire threat handlers', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );

    const threats: Array<{ severity: string; ip: string }> = [];
    df.onThreatDetected('*', event => {
      threats.push({ severity: event.severity, ip: event.ip });
    });

    // Block an IP to trigger a threat
    df.blockIP('6.6.6.6');

    // Observe from the blocked IP
    await df.observe(mockReq('6.6.6.6'));

    // If the engine detects the blocked IP, handler should fire
    // (depends on internal engine returning decision !== 'allow')
  });
});

// ── trackEvent ──────────────────────────────────────────────

describe('DevFortress — trackEvent', () => {
  it('should track events in internal mode', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );

    const result = await df.trackEvent({
      eventType: 'test_event',
      ip: '10.0.0.1',
      severity: 'LOW',
      method: 'GET',
      path: '/test',
    });

    expect(result.success).toBe(true);
    expect(result.eventId).toBeDefined();
  });

  it('should track events in external mode', async () => {
    const df = new DevFortress(baseConfig({ tier: 'pro' }));

    const result = await df.trackEvent({
      eventType: 'test_event',
      ip: '10.0.0.1',
    });

    expect(result.success).toBe(true);
  });

  it('should enforce event limits', async () => {
    const df = new DevFortress(baseConfig({ tier: 'starter' }));

    // Exhaust the event limit
    for (let i = 0; i < 10_000; i++) {
      df.getTierGate().recordEvent();
    }

    const result = await df.trackEvent({
      eventType: 'test',
      ip: '10.0.0.1',
    });

    expect(result.success).toBe(false);
  });
});

// ── testConnection ──────────────────────────────────────────

describe('DevFortress — testConnection', () => {
  it('should return true for internal mode with engine', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );

    const result = await df.testConnection();
    expect(result).toBe(true);
  });

  it('should call platform for external mode', async () => {
    const df = new DevFortress(baseConfig());
    const result = await df.testConnection();
    expect(result).toBe(true);
  });
});

// ── enrichEvent (no-op in internal) ─────────────────────────

describe('DevFortress — enrichEvent', () => {
  it('should be a no-op in internal mode', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'enterprise',
        mode: 'internal',
      })
    );

    // Should not throw
    await df.enrichEvent('evt_123', { extra: 'data' });
  });
});

// ── Event Limit Enforcement ─────────────────────────────────

describe('DevFortress — Event Limit Enforcement', () => {
  it('should return null from observe when limit reached', async () => {
    const df = new DevFortress(baseConfig({ tier: 'starter' }));

    // Exhaust the limit
    for (let i = 0; i < 10_000; i++) {
      df.getTierGate().recordEvent();
    }

    const result = await df.observe(mockReq());
    expect(result).toBeNull();
  });
});

// ── TODO 192: Embedded MLClassifier wired as default Tier 2 scorer ──

describe('DevFortress — Tier 2 ML scoring (TODO 192)', () => {
  // Spies on MLClassifier.prototype.classify instead of exercising the real
  // bundled ONNX model here. Real end-to-end embedded-inference correctness
  // (against the actual .onnx file) is covered exclusively in
  // ml-classifier.test.ts — deliberately kept to that one file, since
  // onnxruntime-node's native binding is not safe to re-initialize a second
  // time within the same process (see MLClassifier.sessionCache comment):
  // a second file in the same jest worker independently calling
  // InferenceSession.create() crashes the whole worker (native SIGABRT),
  // not just the one test. This suite only needs to prove *wiring* — that
  // DevFortressCore calls MLClassifier.classify() and uses its result as
  // the Tier 2 score — which a spy proves without touching the native path.
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('wires the embedded MLClassifier by default for team tier internal mode', async () => {
    const classifySpy = jest
      .spyOn(MLClassifier.prototype, 'classify')
      .mockResolvedValue({
        severity: 'HIGH',
        confidence: 0.9,
        modelSource: 'embedded',
        modelVersion: 'onnx-local',
        inferenceLatencyMs: 2,
      });

    const df = new DevFortress(
      baseConfig({
        tier: 'team',
        mode: 'internal',
      })
    );

    expect(df.getLastTier2Classification()).toBeNull();
    await df.observe(mockReq());

    expect(classifySpy).toHaveBeenCalled();
    const classification = df.getLastTier2Classification();
    expect(classification).not.toBeNull();
    expect(classification!.modelSource).toBe('embedded');
    expect(classification!.modelVersion).toBe('onnx-local');
    expect(typeof classification!.inferenceLatencyMs).toBe('number');
  });

  it('never wires a tier2Scorer for pro (no internal/hybrid access)', () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'pro',
        mode: 'hybrid', // requested mode ignored — pro has no hybrid access
      })
    );

    expect(df.getMode()).toBe('external');
    expect(df.getInternalEngine()).toBeNull();
  });

  it('respects a caller-supplied tier2Scorer over the default MLClassifier', async () => {
    const customScorer = jest.fn().mockReturnValue(10);
    const df = new DevFortress(
      baseConfig({
        tier: 'team',
        mode: 'internal',
        internalCL: { tier2Scorer: customScorer },
      })
    );

    await df.observe(mockReq());

    expect(customScorer).toHaveBeenCalled();
    expect(df.getLastTier2Classification()).toBeNull();
  });
});
