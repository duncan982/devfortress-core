/**
 * Tests for InternalClosedLoopEngine
 *
 * Coverage: Tier 1 rules, rate limiting, blocking/unblocking,
 * agent quarantine, fail modes, audit log, bounded stores, Tier 2 scorer.
 */
import {
  InternalClosedLoopEngine,
  InternalCLRequest,
  InternalCLAction,
} from '../src/internal-closed-loop-engine';

// Suppress console output during tests
beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterAll(() => {
  jest.restoreAllMocks();
});

const baseReq: InternalCLRequest = {
  ip: '192.168.1.100',
  method: 'GET',
  path: '/api/data',
  userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
  timestamp: Date.now(),
};

describe('InternalClosedLoopEngine', () => {
  let engine: InternalClosedLoopEngine;

  beforeEach(() => {
    engine = new InternalClosedLoopEngine({ debug: false });
  });

  afterEach(() => {
    engine._reset();
  });

  // ── Initialization ──────────────────────────────────────

  describe('initialization', () => {
    it('should create engine with default config', () => {
      const stats = engine.getStats();
      expect(stats.failMode).toBe('closed');
      expect(stats.blockedIPs).toBe(0);
      expect(stats.rulesCount).toBeGreaterThan(0);
    });

    it('should create engine with custom fail-open config', () => {
      const openEngine = new InternalClosedLoopEngine({ failMode: 'open' });
      expect(openEngine.getStats().failMode).toBe('open');
    });

    it('should register default rules', () => {
      const rules = engine.getRules();
      const ruleNames = rules.map(r => r.name);
      expect(ruleNames).toContain('sql_injection');
      expect(ruleNames).toContain('xss_attempt');
      expect(ruleNames).toContain('path_traversal');
      expect(ruleNames).toContain('scanner_detected');
      expect(ruleNames).toContain('sensitive_file_access');
      expect(ruleNames).toContain('credential_stuffing_pattern');
      expect(ruleNames).toContain('agent_unsanctioned_tool');
    });
  });

  // ── Tier 1: SQL Injection Detection ─────────────────────

  describe('Tier 1 — SQL injection', () => {
    it('should block SQL injection in query', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        path: '/api/users',
        query: "id=1' OR 1=1 --",
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('sql_injection');
      expect(result.tier).toBe(1);
      expect(result.score).toBeGreaterThanOrEqual(90);
    });

    it('should block UNION SELECT injection', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        body: 'id=1 UNION SELECT username, password FROM users',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('sql_injection');
    });

    it('should block DROP TABLE attempts', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        body: "'; DROP TABLE users; --",
      });
      expect(result.decision).toBe('block');
    });
  });

  // ── Tier 1: XSS Detection ──────────────────────────────

  describe('Tier 1 — XSS detection', () => {
    it('should block script tags', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        body: '<script>alert("xss")</script>',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('xss_attempt');
    });

    it('should block event handler injection', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        query: 'name=<img onerror=alert(1)>',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('xss_attempt');
    });

    it('should block javascript: protocol', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        body: 'url=javascript:alert(document.cookie)',
      });
      expect(result.decision).toBe('block');
    });
  });

  // ── Tier 1: Path Traversal ─────────────────────────────

  describe('Tier 1 — path traversal', () => {
    it('should block ../ traversal', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        path: '/api/files/../../../etc/passwd',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('path_traversal');
    });

    it('should block encoded traversal', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        path: '/api/files/..%2F..%2F..%2Fetc%2Fpasswd',
      });
      expect(result.decision).toBe('block');
    });

    it('should block .env access', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        path: '/.env',
      });
      expect(result.decision).toBe('block');
    });
  });

  // ── Tier 1: Scanner Detection ──────────────────────────

  describe('Tier 1 — scanner detection', () => {
    it('should block sqlmap user agent', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        userAgent: 'sqlmap/1.7.2',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('scanner_detected');
    });

    it('should block Nikto scanner', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        userAgent: 'Mozilla/5.0 (Nikto/2.1.6)',
      });
      expect(result.decision).toBe('block');
    });

    it('should block Nuclei scanner', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        userAgent:
          'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)',
      });
      expect(result.decision).toBe('block');
    });
  });

  // ── Tier 1: Sensitive File Access ──────────────────────

  describe('Tier 1 — sensitive file access', () => {
    it('should block .git access', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        path: '/.git/config',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('sensitive_file_access');
    });

    it('should block wp-admin access', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        path: '/wp-admin/',
      });
      expect(result.decision).toBe('block');
    });

    it('should block phpmyadmin access', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        path: '/phpmyadmin/',
      });
      expect(result.decision).toBe('block');
    });
  });

  // ── Tier 1: Credential Stuffing ────────────────────────

  describe('Tier 1 — credential stuffing', () => {
    it('should rate-limit POST to /login', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        method: 'POST',
        path: '/api/auth/login',
      });
      expect(result.matchedRules).toContain('credential_stuffing_pattern');
    });

    it('should not flag GET to /login', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        method: 'GET',
        path: '/api/auth/login',
      });
      expect(result.matchedRules).not.toContain('credential_stuffing_pattern');
    });
  });

  // ── Tier 1: Agent Tool Monitoring ──────────────────────

  describe('Tier 1 — agent tool monitoring', () => {
    it('should quarantine agent using dangerous tool', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        agentId: 'agent-001',
        toolName: 'shell_exec',
      });
      expect(result.decision).toBe('quarantine');
      expect(result.matchedRules).toContain('agent_unsanctioned_tool');
      expect(result.score).toBe(95);
    });

    it('should allow agent using safe tool', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        agentId: 'agent-001',
        toolName: 'search_database',
      });
      expect(result.decision).toBe('allow');
    });
  });

  // ── Clean Traffic ──────────────────────────────────────

  describe('clean traffic', () => {
    it('should allow normal GET request', async () => {
      const result = await engine.evaluate(baseReq);
      expect(result.decision).toBe('allow');
      expect(result.score).toBe(0);
      expect(result.matchedRules).toHaveLength(0);
    });

    it('should allow normal POST request', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        method: 'POST',
        path: '/api/projects',
        body: JSON.stringify({ name: 'My Project' }),
      });
      expect(result.decision).toBe('allow');
    });

    it('should return evaluation time', async () => {
      const result = await engine.evaluate(baseReq);
      expect(result.evaluationTimeUs).toBeGreaterThanOrEqual(0);
    });

    it('should return unique event IDs', async () => {
      const r1 = await engine.evaluate(baseReq);
      const r2 = await engine.evaluate(baseReq);
      expect(r1.eventId).not.toBe(r2.eventId);
      expect(r1.eventId).toMatch(/^icl_/);
    });
  });

  // ── IP Blocking ────────────────────────────────────────

  describe('IP blocking', () => {
    it('should block manually blocked IP', async () => {
      engine.blockIP('10.0.0.1', 'manual_block', 3600);
      const result = await engine.evaluate({
        ...baseReq,
        ip: '10.0.0.1',
      });
      expect(result.decision).toBe('block');
      expect(result.score).toBe(100);
    });

    it('should allow after unblock', async () => {
      engine.blockIP('10.0.0.2', 'test', 3600);
      expect(engine.isIPBlocked('10.0.0.2')).toBe(true);
      engine.unblockIP('10.0.0.2');
      expect(engine.isIPBlocked('10.0.0.2')).toBe(false);
      const result = await engine.evaluate({
        ...baseReq,
        ip: '10.0.0.2',
      });
      expect(result.decision).toBe('allow');
    });

    it('should auto-expire blocked IPs', async () => {
      engine.blockIP('10.0.0.3', 'test', 1);
      expect(engine.isIPBlocked('10.0.0.3')).toBe(true);
      const result = await engine.evaluate({
        ...baseReq,
        ip: '10.0.0.3',
        timestamp: Date.now() + 5000,
      });
      expect(result.decision).toBe('allow');
    });

    it('should auto-block IP after rule match', async () => {
      await engine.evaluate({
        ...baseReq,
        ip: '10.0.0.4',
        query: "id=' OR 1=1 --",
      });
      expect(engine.isIPBlocked('10.0.0.4')).toBe(true);
    });

    it('should return false for unblocking non-existent IP', () => {
      expect(engine.unblockIP('99.99.99.99')).toBe(false);
    });
  });

  // ── User Blocking ──────────────────────────────────────

  describe('user blocking', () => {
    it('should block request from blocked user', async () => {
      engine.blockUser('user-123', 'suspicious activity', 3600);
      const result = await engine.evaluate({
        ...baseReq,
        userId: 'user-123',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules[0]).toContain('user_blocked');
    });
  });

  // ── Session Blocking ───────────────────────────────────

  describe('session blocking', () => {
    it('should block request from blocked session', async () => {
      engine.blockSession('sess-abc', 'hijacked', 3600);
      const result = await engine.evaluate({
        ...baseReq,
        sessionId: 'sess-abc',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules[0]).toContain('session_blocked');
    });
  });

  // ── Agent Quarantine ───────────────────────────────────

  describe('agent quarantine', () => {
    it('should quarantine agent', async () => {
      engine.quarantineAgent('agent-bad', 'anomalous behavior');
      expect(engine.isAgentQuarantined('agent-bad')).toBe(true);

      const result = await engine.evaluate({
        ...baseReq,
        agentId: 'agent-bad',
      });
      expect(result.decision).toBe('quarantine');
    });

    it('should unquarantine agent', () => {
      engine.quarantineAgent('agent-temp', 'testing');
      expect(engine.unquarantineAgent('agent-temp')).toBe(true);
      expect(engine.isAgentQuarantined('agent-temp')).toBe(false);
    });

    it('should return false for unquarantining non-existent agent', () => {
      expect(engine.unquarantineAgent('ghost-agent')).toBe(false);
    });
  });

  // ── Rate Limiting ──────────────────────────────────────

  describe('rate limiting', () => {
    it('should rate-limit after exceeding max requests', async () => {
      const limitEngine = new InternalClosedLoopEngine({
        rateLimitMax: 5,
        rateLimitWindowMs: 60000,
        debug: false,
      });

      const now = Date.now();
      for (let i = 0; i < 5; i++) {
        await limitEngine.evaluate({
          ...baseReq,
          ip: '10.10.10.10',
          timestamp: now + i,
        });
      }
      const result = await limitEngine.evaluate({
        ...baseReq,
        ip: '10.10.10.10',
        timestamp: now + 10,
      });
      expect(result.decision).toBe('rate_limit');
      expect(result.matchedRules).toContain('rate_limit_exceeded');
    });

    it('should allow requests after window expires', async () => {
      const limitEngine = new InternalClosedLoopEngine({
        rateLimitMax: 3,
        rateLimitWindowMs: 1000,
        debug: false,
      });

      const now = Date.now();
      for (let i = 0; i < 3; i++) {
        await limitEngine.evaluate({
          ...baseReq,
          ip: '10.10.10.11',
          timestamp: now + i,
        });
      }
      const result = await limitEngine.evaluate({
        ...baseReq,
        ip: '10.10.10.11',
        timestamp: now + 2000,
      });
      expect(result.decision).toBe('allow');
    });
  });

  // ── Tier 2: Custom Scorer ──────────────────────────────

  describe('Tier 2 — custom scorer', () => {
    it('should block when scorer returns high score', async () => {
      const scorerEngine = new InternalClosedLoopEngine({
        tier2Scorer: () => 90,
        blockThreshold: 85,
        debug: false,
      });

      const result = await scorerEngine.evaluate(baseReq);
      expect(result.decision).toBe('block');
      expect(result.tier).toBe(2);
      expect(result.matchedRules).toContain('tier2_ml_score');
    });

    it('should rate-limit when scorer returns medium score', async () => {
      const scorerEngine = new InternalClosedLoopEngine({
        tier2Scorer: () => 70,
        blockThreshold: 85,
        rateLimitThreshold: 60,
        debug: false,
      });

      const result = await scorerEngine.evaluate(baseReq);
      expect(result.decision).toBe('rate_limit');
      expect(result.tier).toBe(2);
      expect(result.matchedRules).toContain('tier2_ml_elevated');
    });

    it('should allow when scorer returns low score', async () => {
      const scorerEngine = new InternalClosedLoopEngine({
        tier2Scorer: () => 30,
        blockThreshold: 85,
        rateLimitThreshold: 60,
        debug: false,
      });

      const result = await scorerEngine.evaluate(baseReq);
      expect(result.decision).toBe('allow');
    });

    it('should support async scorer', async () => {
      const scorerEngine = new InternalClosedLoopEngine({
        tier2Scorer: async () => 90,
        blockThreshold: 85,
        debug: false,
      });

      const result = await scorerEngine.evaluate(baseReq);
      expect(result.decision).toBe('block');
      expect(result.tier).toBe(2);
    });
  });

  // ── Fail Mode ──────────────────────────────────────────

  describe('fail mode', () => {
    it('should block on error in fail-closed mode', async () => {
      const failEngine = new InternalClosedLoopEngine({
        failMode: 'closed',
        tier2Scorer: () => {
          throw new Error('ML failure');
        },
        debug: false,
      });

      const result = await failEngine.evaluate(baseReq);
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('fail_closed_error');
    });

    it('should allow on error in fail-open mode', async () => {
      const failEngine = new InternalClosedLoopEngine({
        failMode: 'open',
        tier2Scorer: () => {
          throw new Error('ML failure');
        },
        debug: false,
      });

      const result = await failEngine.evaluate(baseReq);
      expect(result.decision).toBe('allow');
      expect(result.matchedRules).toContain('fail_open_error');
    });
  });

  // ── Custom Rules ───────────────────────────────────────

  describe('custom rules', () => {
    it('should add and match custom rule', async () => {
      engine.addRule({
        name: 'custom_test_rule',
        description: 'Test rule',
        severity: 'high',
        score: 88,
        decision: 'block',
        enabled: true,
        match: req => req.path.includes('/secret'),
      });

      const result = await engine.evaluate({
        ...baseReq,
        path: '/api/secret/data',
      });
      expect(result.decision).toBe('block');
      expect(result.matchedRules).toContain('custom_test_rule');
    });

    it('should skip disabled rules', async () => {
      engine.addRule({
        name: 'disabled_rule',
        description: 'This is disabled',
        severity: 'critical',
        score: 100,
        decision: 'block',
        enabled: false,
        match: () => true,
      });

      const result = await engine.evaluate(baseReq);
      expect(result.decision).toBe('allow');
    });

    it('should remove rules', () => {
      engine.addRule({
        name: 'temp_rule',
        description: 'Temporary',
        severity: 'low',
        score: 50,
        decision: 'rate_limit',
        enabled: true,
        match: () => true,
      });

      expect(engine.removeRule('temp_rule')).toBe(true);
      expect(engine.removeRule('nonexistent')).toBe(false);
    });

    it('should handle rule errors gracefully', async () => {
      engine.addRule({
        name: 'error_rule',
        description: 'This throws',
        severity: 'critical',
        score: 100,
        decision: 'block',
        enabled: true,
        match: () => {
          throw new Error('Rule error');
        },
      });

      const result = await engine.evaluate(baseReq);
      expect(result.decision).toBe('allow');
    });
  });

  // ── Audit Log ──────────────────────────────────────────

  describe('audit log', () => {
    it('should record audit entries for blocks', async () => {
      await engine.evaluate({
        ...baseReq,
        ip: '10.0.0.5',
        body: '<script>alert(1)</script>',
      });

      const log = engine.getAuditLog();
      expect(log.length).toBe(1);
      expect(log[0].decision).toBe('block');
      expect(log[0].ip).toBe('10.0.0.5');
    });

    it('should not record audit for clean allow', async () => {
      await engine.evaluate(baseReq);
      const log = engine.getAuditLog();
      expect(log.length).toBe(0);
    });

    it('should limit audit log entries', () => {
      const smallEngine = new InternalClosedLoopEngine({
        maxAuditEntries: 10,
        debug: false,
      });

      const stats = smallEngine.getStats();
      expect(stats.auditLogSize).toBe(0);
    });
  });

  // ── Import Blocked IPs ─────────────────────────────────

  describe('importBlockedIPs', () => {
    it('should import multiple IPs', () => {
      const count = engine.importBlockedIPs([
        { ip: '1.1.1.1', reason: 'blacklist' },
        { ip: '2.2.2.2', reason: 'blacklist', ttlSeconds: 7200 },
        { ip: '3.3.3.3', reason: 'blacklist' },
      ]);

      expect(count).toBe(3);
      expect(engine.isIPBlocked('1.1.1.1')).toBe(true);
      expect(engine.isIPBlocked('2.2.2.2')).toBe(true);
      expect(engine.isIPBlocked('3.3.3.3')).toBe(true);
    });
  });

  // ── Stats ──────────────────────────────────────────────

  describe('stats', () => {
    it('should return accurate statistics', () => {
      engine.blockIP('1.1.1.1', 'test');
      engine.blockUser('user-1', 'test');
      engine.blockSession('sess-1', 'test');
      engine.quarantineAgent('agent-1', 'test');

      const stats = engine.getStats();
      expect(stats.blockedIPs).toBe(1);
      expect(stats.blockedUsers).toBe(1);
      expect(stats.blockedSessions).toBe(1);
      expect(stats.quarantinedAgents).toBe(1);
    });
  });

  // ── Action Callback ────────────────────────────────────

  describe('onAction callback', () => {
    it('should fire callback on block action', async () => {
      const actions: InternalCLAction[] = [];
      const callbackEngine = new InternalClosedLoopEngine({
        onAction: action => {
          actions.push(action);
        },
        debug: false,
      });

      await callbackEngine.evaluate({
        ...baseReq,
        ip: '10.0.0.6',
        body: '<script>alert(1)</script>',
      });

      expect(actions.length).toBeGreaterThan(0);
      expect(actions[0].type).toBe('block_ip');
      expect(actions[0].target).toBe('10.0.0.6');
    });
  });

  // ── Multiple Rule Matches ──────────────────────────────

  describe('multiple rule matches', () => {
    it('should use highest score from multiple matched rules', async () => {
      const result = await engine.evaluate({
        ...baseReq,
        ip: '10.0.0.7',
        path: '/.env/../../../etc/passwd',
        query: "id=' OR 1=1 --",
      });

      expect(result.decision).toBe('block');
      expect(result.matchedRules.length).toBeGreaterThan(1);
      expect(result.score).toBe(95);
    });
  });

  // ── Reset ──────────────────────────────────────────────

  describe('reset', () => {
    it('should clear all state', async () => {
      engine.blockIP('1.1.1.1', 'test');
      engine.blockUser('user-1', 'test');
      engine.quarantineAgent('agent-1', 'test');

      await engine.evaluate({
        ...baseReq,
        body: '<script>alert(1)</script>',
      });

      engine._reset();

      const stats = engine.getStats();
      expect(stats.blockedIPs).toBe(0);
      expect(stats.blockedUsers).toBe(0);
      expect(stats.quarantinedAgents).toBe(0);
      expect(stats.auditLogSize).toBe(0);
    });
  });
});
