/**
 * Security Module Tests — IP-S1, IP-S2, IP-S3, IP-S4, IP-S6
 *
 * Tests for:
 * - IP classification (ASN/ISP category signal)
 * - Scoring configuration (post-auth threshold reduction)
 * - Cross-customer velocity blocklist
 * - Cross-application event correlation
 * - Internal closed-loop engine (air-gap mode)
 */

// ── IP-S2: Scoring Configuration ────────────────────────────

import {
  configureScoringThresholds,
  getEffectiveCriticalThreshold,
  classifyThreatSeverity,
  getScoringConfig,
} from '@core/lib/security/scoring-config';

describe('IP-S2: Scoring Configuration', () => {
  beforeEach(() => {
    // Reset to defaults
    configureScoringThresholds({
      criticalThreshold: 85,
      postAuthThreshold: 70,
      highThreshold: 60,
      mediumThreshold: 40,
    });
  });

  test('default critical threshold is 85 for pre-auth', () => {
    expect(getEffectiveCriticalThreshold(null)).toBe(85);
    expect(getEffectiveCriticalThreshold(undefined)).toBe(85);
  });

  test('post-auth threshold is 70 for logged-in users', () => {
    expect(getEffectiveCriticalThreshold('user-123')).toBe(70);
  });

  test('classifies severity correctly for pre-auth', () => {
    expect(classifyThreatSeverity(90)).toBe('critical');
    expect(classifyThreatSeverity(85)).toBe('critical');
    expect(classifyThreatSeverity(84)).toBe('high');
    expect(classifyThreatSeverity(60)).toBe('high');
    expect(classifyThreatSeverity(50)).toBe('medium');
    expect(classifyThreatSeverity(40)).toBe('medium');
    expect(classifyThreatSeverity(30)).toBe('low');
  });

  test('classifies with lower threshold for post-auth (IP-S2)', () => {
    // Score of 75 is "high" for pre-auth but "critical" for post-auth
    expect(classifyThreatSeverity(75, null)).toBe('high');
    expect(classifyThreatSeverity(75, 'user-123')).toBe('critical');
  });

  test('custom thresholds work', () => {
    configureScoringThresholds({
      criticalThreshold: 95,
      postAuthThreshold: 80,
    });
    expect(getEffectiveCriticalThreshold(null)).toBe(95);
    expect(getEffectiveCriticalThreshold('user-1')).toBe(80);
  });

  test('getScoringConfig returns current config', () => {
    const config = getScoringConfig();
    expect(config.criticalThreshold).toBe(85);
    expect(config.postAuthThreshold).toBe(70);
  });
});

// ── IP-S3 + IP-S4: Cross-Customer Correlation ──────────────

import {
  recordCriticalEvent,
  isOnCrossCustomerBlocklist,
  getCrossCustomerBlocklist,
  onPlatformIncident,
  cleanupExpiredEntries,
  type PlatformIncident,
} from '@core/lib/security/cross-customer-correlation';

describe('IP-S3: Cross-Customer Velocity Blocklist', () => {
  test('adds IP to blocklist after 3 distinct apps in 1 hour', async () => {
    const now = Date.now();

    await recordCriticalEvent({
      ip: '198.51.100.1',
      appId: 'app-1',
      eventId: 'evt-1',
      timestamp: now,
    });
    expect(isOnCrossCustomerBlocklist('198.51.100.1')).toBe(false);

    await recordCriticalEvent({
      ip: '198.51.100.1',
      appId: 'app-2',
      eventId: 'evt-2',
      timestamp: now + 1000,
    });
    expect(isOnCrossCustomerBlocklist('198.51.100.1')).toBe(false);

    await recordCriticalEvent({
      ip: '198.51.100.1',
      appId: 'app-3',
      eventId: 'evt-3',
      timestamp: now + 2000,
    });
    expect(isOnCrossCustomerBlocklist('198.51.100.1')).toBe(true);
  });

  test('same app does not count as distinct', async () => {
    const now = Date.now();

    // 3 events from the same app — should NOT trigger
    await recordCriticalEvent({
      ip: '198.51.100.2',
      appId: 'app-1',
      eventId: 'evt-1',
      timestamp: now,
    });
    await recordCriticalEvent({
      ip: '198.51.100.2',
      appId: 'app-1',
      eventId: 'evt-2',
      timestamp: now + 1000,
    });
    await recordCriticalEvent({
      ip: '198.51.100.2',
      appId: 'app-1',
      eventId: 'evt-3',
      timestamp: now + 2000,
    });
    expect(isOnCrossCustomerBlocklist('198.51.100.2')).toBe(false);
  });

  test('getCrossCustomerBlocklist returns blocked IPs', async () => {
    const now = Date.now();

    await recordCriticalEvent({
      ip: '198.51.100.3',
      appId: 'app-a',
      eventId: 'evt-a',
      timestamp: now,
    });
    await recordCriticalEvent({
      ip: '198.51.100.3',
      appId: 'app-b',
      eventId: 'evt-b',
      timestamp: now + 100,
    });
    await recordCriticalEvent({
      ip: '198.51.100.3',
      appId: 'app-c',
      eventId: 'evt-c',
      timestamp: now + 200,
    });

    const blocklist = getCrossCustomerBlocklist();
    const entry = blocklist.find(e => e.ip === '198.51.100.3');
    expect(entry).toBeDefined();
    expect(entry!.reason).toContain('cross_customer_velocity');
  });
});

describe('IP-S4: Cross-Application Event Correlation', () => {
  test('detects cross-application incident with 2+ apps in 60s', async () => {
    const incidents: PlatformIncident[] = [];
    onPlatformIncident(incident => {
      incidents.push(incident);
    });

    const now = Date.now();

    await recordCriticalEvent({
      ip: '203.0.113.1',
      appId: 'app-x',
      eventId: 'evt-x',
      timestamp: now,
    });
    await recordCriticalEvent({
      ip: '203.0.113.1',
      appId: 'app-y',
      eventId: 'evt-y',
      timestamp: now + 500,
    });

    // At least one incident should be cross_application
    const crossApp = incidents.find(i => i.type === 'cross_application');
    expect(crossApp).toBeDefined();
    expect(crossApp!.affectedAppIds).toContain('app-x');
    expect(crossApp!.affectedAppIds).toContain('app-y');
  });

  test('cleanupExpiredEntries does not throw', () => {
    expect(() => cleanupExpiredEntries()).not.toThrow();
  });
});

// ── IP-S6: Internal Closed-Loop Engine ──────────────────────

import {
  InternalClosedLoopEngine,
  type RequestContext,
} from '@core/lib/security/internal-closed-loop-engine';

describe('IP-S6: Internal Closed-Loop Engine', () => {
  const makeContext = (
    overrides?: Partial<RequestContext>
  ): RequestContext => ({
    ip: '192.0.2.1',
    method: 'GET',
    path: '/api/data',
    userAgent: 'Mozilla/5.0',
    userId: null,
    sessionId: null,
    compositeScore: 0,
    headers: {},
    ...overrides,
  });

  test('allows clean requests', () => {
    const engine = new InternalClosedLoopEngine();
    const decision = engine.evaluate(makeContext());
    expect(decision.action).toBe('allow');
    expect(decision.tier).toBe(1);
  });

  test('blocks IPs on blocklist (Tier 1)', () => {
    const engine = new InternalClosedLoopEngine({
      blocklist: new Set(['198.51.100.100']),
    });
    const decision = engine.evaluate(makeContext({ ip: '198.51.100.100' }));
    expect(decision.action).toBe('block_ip');
    expect(decision.tier).toBe(1);
    expect(decision.ruleName).toBe('blocklist_match');
    expect(decision.confidence).toBe(1.0);
  });

  test('blocks honeypot paths (Tier 1)', () => {
    const engine = new InternalClosedLoopEngine({
      honeypotPaths: ['/admin-backup', '/.env'],
    });
    const decision = engine.evaluate(
      makeContext({ path: '/admin-backup/db.sql' })
    );
    expect(decision.action).toBe('block_ip');
    expect(decision.ruleName).toBe('honeypot_triggered');
  });

  test('rate limits excessive requests (Tier 1)', () => {
    const engine = new InternalClosedLoopEngine({
      rateLimitMax: 3,
      rateLimitWindowSeconds: 60,
    });

    const ctx = makeContext({ ip: '10.0.0.50' });
    engine.evaluate(ctx); // 1
    engine.evaluate(ctx); // 2
    engine.evaluate(ctx); // 3
    const decision = engine.evaluate(ctx); // 4 — exceeds limit
    expect(decision.action).toBe('rate_limit');
    expect(decision.tier).toBe(1);
  });

  test('detects SQL injection patterns (Tier 1)', () => {
    const engine = new InternalClosedLoopEngine();
    const decision = engine.evaluate(
      makeContext({
        path: "/api/users?id=1' OR '1'='1",
      })
    );
    expect(decision.action).toBe('block_ip');
    expect(decision.ruleName).toBe('sql_injection_pattern');
  });

  test('blocks critical composite scores (Tier 2)', () => {
    const engine = new InternalClosedLoopEngine();
    const decision = engine.evaluate(makeContext({ compositeScore: 90 }));
    expect(decision.action).toBe('block_ip');
    expect(decision.tier).toBe(2);
  });

  test('post-auth high score triggers session revocation (Tier 2, IP-S2)', () => {
    const engine = new InternalClosedLoopEngine();
    const decision = engine.evaluate(
      makeContext({
        compositeScore: 75,
        userId: 'user-123',
      })
    );
    expect(decision.action).toBe('revoke_session');
    expect(decision.tier).toBe(2);
    expect(decision.ruleName).toBe('post_auth_high_score');
  });

  test('escalates to platform in non-air-gap mode (Tier 3)', () => {
    const engine = new InternalClosedLoopEngine({ airGap: false });
    const decision = engine.evaluate(makeContext({ compositeScore: 45 }));
    expect(decision.action).toBe('escalate');
    expect(decision.tier).toBe(3);
  });

  test('does NOT escalate in air-gap mode', () => {
    const engine = new InternalClosedLoopEngine({ airGap: true });
    const decision = engine.evaluate(makeContext({ compositeScore: 45 }));
    // Should not escalate — air-gap mode
    expect(decision.action).toBe('allow');
  });

  test('custom deterministic rules (Tier 1)', () => {
    const engine = new InternalClosedLoopEngine({
      customRules: [
        {
          name: 'block_user_agent_bot',
          evaluate: ctx => {
            if (ctx.userAgent?.includes('ScannerBot')) return 'block_ip';
            return null;
          },
        },
      ],
    });
    const decision = engine.evaluate(
      makeContext({ userAgent: 'ScannerBot/1.0' })
    );
    expect(decision.action).toBe('block_ip');
    expect(decision.ruleName).toBe('block_user_agent_bot');
  });

  test('runtime blocklist management', () => {
    const engine = new InternalClosedLoopEngine();

    engine.blockIP('192.0.2.99');
    expect(engine.evaluate(makeContext({ ip: '192.0.2.99' })).action).toBe(
      'block_ip'
    );

    engine.unblockIP('192.0.2.99');
    expect(engine.evaluate(makeContext({ ip: '192.0.2.99' })).action).toBe(
      'allow'
    );
  });

  test('processing time is tracked', () => {
    const engine = new InternalClosedLoopEngine();
    const decision = engine.evaluate(makeContext());
    expect(decision.processingTimeMs).toBeGreaterThanOrEqual(0);
    expect(decision.processingTimeMs).toBeLessThan(10); // Should be <1ms
  });

  test('isAirGapped returns correct value', () => {
    expect(new InternalClosedLoopEngine({ airGap: true }).isAirGapped()).toBe(
      true
    );
    expect(new InternalClosedLoopEngine({ airGap: false }).isAirGapped()).toBe(
      false
    );
    expect(new InternalClosedLoopEngine().isAirGapped()).toBe(false);
  });
});
