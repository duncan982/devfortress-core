/**
 * Agent Security — Tests (IP-C2, IP-C3, IP-C4, IP-C5)
 *
 * Tests for AgentCredentialManager, AgentBaselineEngine,
 * AgentAnomalyDetector, and AgentScopeEnforcer.
 */

import crypto from 'crypto';
import {
  AgentCredentialManager,
  AgentBaselineEngine,
  AgentAnomalyDetector,
  AgentScopeEnforcer,
  _resetAgentSecurityStores,
  type AgentSessionRecord,
  type AgentAnomalySignal,
} from '../src/agent-security';
import {
  CredentialIsolationManager,
  type CacheAdapter,
} from '../src/credential-isolation';

// ── Test Helpers ────────────────────────────────────────────

function generateEncryptionKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

function createTestCache(): CacheAdapter & {
  store: Map<string, { value: string; ttl: number }>;
} {
  const store = new Map<string, { value: string; ttl: number }>();
  return {
    store,
    async get(key: string) {
      const entry = store.get(key);
      return entry ? entry.value : null;
    },
    async set(key: string, value: string, ttlSeconds: number) {
      store.set(key, { value, ttl: ttlSeconds });
    },
    async del(key: string) {
      store.delete(key);
    },
  };
}

function createTokenManager(cache?: CacheAdapter): CredentialIsolationManager {
  return new CredentialIsolationManager(cache, {
    encryptionKey: generateEncryptionKey(),
    lruMaxEntries: 100,
    lruTtlSeconds: 60,
  });
}

function createSessionRecord(
  agentId: string,
  tools: string[],
  opts?: Partial<AgentSessionRecord>
): AgentSessionRecord {
  const now = Date.now();
  return {
    sessionId: `ses-${Math.random().toString(36).substring(7)}`,
    agentId,
    toolCalls: tools.map(t => ({ tool: t, durationMs: 100, dataBytes: 1024 })),
    startedAt: now - 60000,
    endedAt: now,
    totalDataBytes: tools.length * 1024,
    ...opts,
  };
}

// ═══════════════════════════════════════════════════════════
// IP-C2: Agent Credential Aliasing
// ═══════════════════════════════════════════════════════════

// Reset shared in-memory stores before each test
beforeEach(() => {
  _resetAgentSecurityStores();
});

describe('AgentCredentialManager (IP-C2)', () => {
  describe('createAgentAlias', () => {
    it('should create an alias for an agent API key', async () => {
      const cache = createTestCache();
      const tm = createTokenManager(cache);
      const acm = new AgentCredentialManager(tm, cache);

      const alias = await acm.createAgentAlias(
        'real-api-key-123',
        'agent-1',
        'agent_api_key'
      );

      expect(alias).toBeDefined();
      expect(typeof alias).toBe('string');
      expect(alias.length).toBeGreaterThan(0);

      const creds = acm.getAgentCredentials('agent-1');
      expect(creds).toHaveLength(1);
      expect(creds[0].agentId).toBe('agent-1');
      expect(creds[0].credentialType).toBe('agent_api_key');
      expect(creds[0].quarantined).toBe(false);
    });

    it('should create aliases for different credential types', async () => {
      const tm = createTokenManager();
      const acm = new AgentCredentialManager(tm);

      await acm.createAgentAlias('key-1', 'agent-1', 'agent_api_key');
      await acm.createAgentAlias('token-1', 'agent-1', 'agent_oauth_token');
      await acm.createAgentAlias('sa-1', 'agent-1', 'service_account');

      const creds = acm.getAgentCredentials('agent-1');
      expect(creds).toHaveLength(3);
      expect(creds.map(c => c.credentialType)).toEqual([
        'agent_api_key',
        'agent_oauth_token',
        'service_account',
      ]);
    });
  });

  describe('revokeAgentAccess', () => {
    it('should revoke all credentials for an agent', async () => {
      const cache = createTestCache();
      const tm = createTokenManager(cache);
      const acm = new AgentCredentialManager(tm, cache);

      await acm.createAgentAlias('key-1', 'agent-1', 'agent_api_key');
      await acm.createAgentAlias('key-2', 'agent-1', 'agent_oauth_token');

      const count = await acm.revokeAgentAccess('agent-1', 'active_threat');
      expect(count).toBe(2);

      const creds = acm.getAgentCredentials('agent-1');
      expect(creds).toHaveLength(0);
    });

    it('should return 0 for unknown agent', async () => {
      const tm = createTokenManager();
      const acm = new AgentCredentialManager(tm);

      const count = await acm.revokeAgentAccess('unknown-agent');
      expect(count).toBe(0);
    });
  });

  describe('quarantineAgent', () => {
    it('should quarantine an agent preserving session data', async () => {
      const tm = createTokenManager();
      const acm = new AgentCredentialManager(tm);

      await acm.createAgentAlias('key-1', 'agent-1', 'agent_api_key');

      expect(acm.isQuarantined('agent-1')).toBe(false);

      await acm.quarantineAgent('agent-1', 'Suspicious activity detected');

      expect(acm.isQuarantined('agent-1')).toBe(true);
      const details = acm.getQuarantineDetails('agent-1');
      expect(details).not.toBeNull();
      expect(details!.reason).toBe('Suspicious activity detected');
      expect(details!.at).toBeGreaterThan(0);

      // Credentials are still there (for forensics) but marked quarantined
      const creds = acm.getAgentCredentials('agent-1');
      expect(creds).toHaveLength(1);
      expect(creds[0].quarantined).toBe(true);
      expect(creds[0].quarantineReason).toBe('Suspicious activity detected');
    });

    it('should allow unquarantine', async () => {
      const tm = createTokenManager();
      const acm = new AgentCredentialManager(tm);

      await acm.createAgentAlias('key-1', 'agent-1', 'agent_api_key');
      await acm.quarantineAgent('agent-1', 'Testing');

      expect(acm.isQuarantined('agent-1')).toBe(true);

      await acm.unquarantineAgent('agent-1');

      expect(acm.isQuarantined('agent-1')).toBe(false);
      const creds = acm.getAgentCredentials('agent-1');
      expect(creds[0].quarantined).toBe(false);
    });

    it('should persist quarantine to cache when available', async () => {
      const cache = createTestCache();
      const tm = createTokenManager(cache);
      const acm = new AgentCredentialManager(tm, cache);

      await acm.createAgentAlias('key-1', 'agent-1', 'agent_api_key');
      await acm.quarantineAgent('agent-1', 'Cache test');

      expect(cache.store.has('agent:quarantine:agent-1')).toBe(true);

      await acm.unquarantineAgent('agent-1');
      expect(cache.store.has('agent:quarantine:agent-1')).toBe(false);
    });
  });
});

// ═══════════════════════════════════════════════════════════
// IP-C3: Agent Behavioral Baseline
// ═══════════════════════════════════════════════════════════

describe('AgentBaselineEngine (IP-C3)', () => {
  describe('recordSession', () => {
    it('should record sessions and build baseline after minimum sessions', () => {
      const engine = new AgentBaselineEngine();

      // Record 5 sessions (minimum for baseline)
      for (let i = 0; i < 5; i++) {
        engine.recordSession(
          createSessionRecord('agent-1', ['search', 'calculate', 'format'])
        );
      }

      const baseline = engine.getBaseline('agent-1');
      expect(baseline).not.toBeNull();
      expect(baseline!.totalSessions).toBe(5);
      expect(baseline!.avgToolsPerSession).toBe(3);
      expect(baseline!.topTools).toContain('search');
      expect(baseline!.topTools).toContain('calculate');
    });

    it('should not create baseline with fewer than 5 sessions', () => {
      const engine = new AgentBaselineEngine();

      for (let i = 0; i < 4; i++) {
        engine.recordSession(createSessionRecord('agent-1', ['search']));
      }

      const baseline = engine.getBaseline('agent-1');
      expect(baseline).toBeNull();
    });
  });

  describe('agentBaseline', () => {
    it('should return null when not enough data', () => {
      const engine = new AgentBaselineEngine();
      const result = engine.agentBaseline('new-agent', 'Search task');
      expect(result).toBeNull();
    });

    it('should return baseline with task definition', () => {
      const engine = new AgentBaselineEngine();

      for (let i = 0; i < 6; i++) {
        engine.recordSession(
          createSessionRecord('agent-1', ['search', 'summarize'])
        );
      }

      const baseline = engine.agentBaseline('agent-1', 'Content research');
      expect(baseline).not.toBeNull();
      expect(baseline!.taskDefinition).toBe('Content research');
      expect(baseline!.totalSessions).toBe(6);
    });

    it('should update task definition on existing baseline', () => {
      const engine = new AgentBaselineEngine();

      for (let i = 0; i < 5; i++) {
        engine.recordSession(createSessionRecord('agent-1', ['search']));
      }

      engine.agentBaseline('agent-1', 'Task v1');
      const updated = engine.agentBaseline('agent-1', 'Task v2');
      expect(updated!.taskDefinition).toBe('Task v2');
    });
  });

  describe('metrics calculation', () => {
    it('should calculate tool diversity entropy correctly', () => {
      const engine = new AgentBaselineEngine();

      // All same tool = 0 entropy
      for (let i = 0; i < 5; i++) {
        engine.recordSession(
          createSessionRecord('agent-mono', ['search', 'search', 'search'])
        );
      }

      const monoBaseline = engine.getBaseline('agent-mono');
      expect(monoBaseline!.toolDiversityEntropy).toBe(0);

      // Diverse tools = higher entropy
      for (let i = 0; i < 5; i++) {
        engine.recordSession(
          createSessionRecord('agent-diverse', [
            'search',
            'calculate',
            'format',
            'write',
          ])
        );
      }

      const diverseBaseline = engine.getBaseline('agent-diverse');
      expect(diverseBaseline!.toolDiversityEntropy).toBeGreaterThan(0);
      expect(diverseBaseline!.toolDiversityEntropy).toBe(2); // log2(4) = 2 for uniform distribution
    });

    it('should calculate average data volume', () => {
      const engine = new AgentBaselineEngine();

      for (let i = 0; i < 5; i++) {
        engine.recordSession(
          createSessionRecord('agent-1', ['a', 'b'], { totalDataBytes: 5000 })
        );
      }

      const baseline = engine.getBaseline('agent-1');
      expect(baseline!.avgDataVolumeBytes).toBe(5000);
    });

    it('should calculate session duration', () => {
      const engine = new AgentBaselineEngine();
      const now = Date.now();

      for (let i = 0; i < 5; i++) {
        engine.recordSession(
          createSessionRecord('agent-1', ['a'], {
            startedAt: now - 10000,
            endedAt: now,
          })
        );
      }

      const baseline = engine.getBaseline('agent-1');
      expect(baseline!.avgSessionDurationMs).toBe(10000);
    });
  });

  describe('3σ deviation detection', () => {
    it('should detect 3σ deviations', () => {
      const engine = new AgentBaselineEngine();
      // Normal values: all around 100
      const values = [100, 102, 98, 101, 99, 100, 101, 100, 99, 100];

      // Value within range
      expect(engine.is3SigmaDeviation(values, 103)).toBe(false);

      // Value far outside range
      expect(engine.is3SigmaDeviation(values, 200)).toBe(true);
      expect(engine.is3SigmaDeviation(values, 0)).toBe(true);
    });

    it('should handle insufficient data', () => {
      const engine = new AgentBaselineEngine();
      expect(engine.is3SigmaDeviation([100], 200)).toBe(false);
      expect(engine.is3SigmaDeviation([], 200)).toBe(false);
    });
  });
});

// ═══════════════════════════════════════════════════════════
// IP-C4: Agent Anomaly Detection
// ═══════════════════════════════════════════════════════════

describe('AgentAnomalyDetector (IP-C4)', () => {
  function buildDetector(): {
    engine: AgentBaselineEngine;
    detector: AgentAnomalyDetector;
    enforcer: AgentScopeEnforcer;
  } {
    const engine = new AgentBaselineEngine();
    const detector = new AgentAnomalyDetector(engine);
    const enforcer = new AgentScopeEnforcer();
    return { engine, detector, enforcer };
  }

  function populateBaseline(
    engine: AgentBaselineEngine,
    agentId: string,
    tools: string[] = ['search', 'calculate', 'format'],
    count: number = 10
  ): void {
    for (let i = 0; i < count; i++) {
      engine.recordSession(createSessionRecord(agentId, tools));
    }
  }

  describe('scope deviation detection', () => {
    it('should flag tool not in baseline', () => {
      const { engine, detector } = buildDetector();
      populateBaseline(engine, 'agent-1', ['search', 'calculate']);

      const signals = detector.analyzeToolCall('agent-1', 'delete_database');

      expect(signals.length).toBeGreaterThan(0);
      const scopeSignal = signals.find(s => s.type === 'scope_deviation');
      expect(scopeSignal).toBeDefined();
      expect(scopeSignal!.severity).toBe('medium');
      expect(scopeSignal!.description).toContain('delete_database');
    });

    it('should not flag tools within baseline', () => {
      const { engine, detector } = buildDetector();
      populateBaseline(engine, 'agent-1', ['search', 'calculate']);

      const signals = detector.analyzeToolCall('agent-1', 'search');
      const scopeSignal = signals.find(s => s.type === 'scope_deviation');
      expect(scopeSignal).toBeUndefined();
    });
  });

  describe('data volume anomaly (3σ)', () => {
    it('should flag extreme data volume', () => {
      const { engine, detector } = buildDetector();

      // Build baseline with ~3KB per session
      for (let i = 0; i < 10; i++) {
        engine.recordSession(
          createSessionRecord('agent-1', ['a', 'b', 'c'], {
            totalDataBytes: 3072,
          })
        );
      }

      // Send a tool call with massive data
      const signals = detector.analyzeToolCall('agent-1', 'a', 1_000_000);

      const volumeSignal = signals.find(s => s.type === 'data_volume_anomaly');
      expect(volumeSignal).toBeDefined();
      expect(volumeSignal!.severity).toBe('high');
    });

    it('should not flag normal data volume', () => {
      const { engine, detector } = buildDetector();

      // Build baseline with some natural variation around 3000
      const volumes = [
        2900, 3100, 2950, 3050, 2980, 3020, 3000, 2960, 3040, 2990,
      ];
      for (let i = 0; i < 10; i++) {
        engine.recordSession(
          createSessionRecord('agent-1', ['a', 'b', 'c'], {
            totalDataBytes: volumes[i],
          })
        );
      }

      // Value well within normal range
      const signals = detector.analyzeToolCall('agent-1', 'a', 3050);
      const volumeSignal = signals.find(s => s.type === 'data_volume_anomaly');
      expect(volumeSignal).toBeUndefined();
    });
  });

  describe('cross-agent credential sharing', () => {
    it('should flag when same credential used by multiple agents', () => {
      const { engine, detector } = buildDetector();
      populateBaseline(engine, 'agent-1', ['search']);
      populateBaseline(engine, 'agent-2', ['search']);

      const alias = 'shared-cred-alias-123';

      // First agent uses credential — no problem
      let signals = detector.analyzeToolCall('agent-1', 'search', 0, alias);
      const shareSignal1 = signals.find(
        s => s.type === 'cross_agent_credential_sharing'
      );
      expect(shareSignal1).toBeUndefined();

      // Second agent uses SAME credential — critical!
      signals = detector.analyzeToolCall('agent-2', 'search', 0, alias);
      const shareSignal2 = signals.find(
        s => s.type === 'cross_agent_credential_sharing'
      );
      expect(shareSignal2).toBeDefined();
      expect(shareSignal2!.severity).toBe('critical');
      expect(shareSignal2!.description).toContain('agent-1');
      expect(shareSignal2!.description).toContain('agent-2');
    });
  });

  describe('session entropy anomaly', () => {
    it('should flag sessions with entropy deviation > 50%', () => {
      const { engine, detector } = buildDetector();

      // Build baseline with diverse tools (high entropy)
      for (let i = 0; i < 10; i++) {
        engine.recordSession(
          createSessionRecord('agent-1', ['a', 'b', 'c', 'd', 'e'])
        );
      }

      // Submit a session with very low entropy (all same tool)
      const anomalousSession = createSessionRecord('agent-1', [
        'a',
        'a',
        'a',
        'a',
        'a',
        'a',
        'a',
      ]);

      const signals = detector.analyzeSession(anomalousSession);
      const entropySignal = signals.find(
        s => s.type === 'sequence_entropy_anomaly'
      );
      expect(entropySignal).toBeDefined();
      expect(entropySignal!.severity).toBe('high');
    });

    it('should not flag sessions with normal entropy', () => {
      const { engine, detector } = buildDetector();

      // Build baseline with simple tool set
      for (let i = 0; i < 10; i++) {
        engine.recordSession(
          createSessionRecord('agent-1', ['search', 'calculate'])
        );
      }

      // Submit similar session
      const normalSession = createSessionRecord('agent-1', [
        'search',
        'calculate',
      ]);
      const signals = detector.analyzeSession(normalSession);
      const entropySignal = signals.find(
        s => s.type === 'sequence_entropy_anomaly'
      );
      expect(entropySignal).toBeUndefined();
    });
  });

  describe('anomaly handler', () => {
    it('should invoke registered handlers on anomaly detection', () => {
      const { engine, detector } = buildDetector();
      populateBaseline(engine, 'agent-1', ['search']);

      const handler = jest.fn();
      detector.onAnomaly(handler);

      detector.analyzeToolCall('agent-1', 'unknown_tool');

      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'scope_deviation' })
      );
    });

    it('should not crash when handler throws', () => {
      const { engine, detector } = buildDetector();
      populateBaseline(engine, 'agent-1', ['search']);

      detector.onAnomaly(() => {
        throw new Error('Handler error');
      });

      // Should not throw
      expect(() => {
        detector.analyzeToolCall('agent-1', 'unknown_tool');
      }).not.toThrow();
    });
  });

  describe('integration with scope enforcer (IP-C5)', () => {
    it('should detect unsanctioned tool via anomaly detector', () => {
      const { engine, detector, enforcer } = buildDetector();
      populateBaseline(engine, 'agent-1', ['search', 'calculate']);

      // Define strict scope
      enforcer.defineAgentScope('agent-1', ['search', 'calculate'], true);

      // The detector also checks scope (integrated)
      const signals = detector.analyzeToolCall('agent-1', 'delete_all_data');
      const scopeSignal = signals.find(s => s.type === 'unsanctioned_tool');
      expect(scopeSignal).toBeDefined();
      expect(scopeSignal!.severity).toBe('critical');
    });
  });
});

// ═══════════════════════════════════════════════════════════
// IP-C5: Agent Scope Enforcement
// ═══════════════════════════════════════════════════════════

describe('AgentScopeEnforcer (IP-C5)', () => {
  describe('defineAgentScope', () => {
    it('should define and retrieve agent scope', () => {
      const enforcer = new AgentScopeEnforcer();
      const scope = enforcer.defineAgentScope(
        'agent-1',
        ['search', 'calculate', 'format'],
        true
      );

      expect(scope.agentId).toBe('agent-1');
      expect(scope.allowedTools).toEqual(['search', 'calculate', 'format']);
      expect(scope.strictMode).toBe(true);
      expect(scope.createdAt).toBeGreaterThan(0);
    });
  });

  describe('isToolAllowed', () => {
    it('should allow tools in scope', () => {
      const enforcer = new AgentScopeEnforcer();
      enforcer.defineAgentScope('agent-1', ['search', 'calculate']);

      expect(enforcer.isToolAllowed('agent-1', 'search')).toBe(true);
      expect(enforcer.isToolAllowed('agent-1', 'calculate')).toBe(true);
    });

    it('should block tools not in scope (strict mode)', () => {
      const enforcer = new AgentScopeEnforcer();
      enforcer.defineAgentScope('agent-1', ['search'], true);

      expect(enforcer.isToolAllowed('agent-1', 'delete_database')).toBe(false);
    });

    it('should allow all tools when no scope defined', () => {
      const enforcer = new AgentScopeEnforcer();
      expect(enforcer.isToolAllowed('unknown-agent', 'anything')).toBe(true);
    });

    it('should allow all tools in non-strict mode', () => {
      const enforcer = new AgentScopeEnforcer();
      enforcer.defineAgentScope('agent-1', ['search'], false);

      expect(enforcer.isToolAllowed('agent-1', 'anything')).toBe(true);
    });
  });

  describe('scope management', () => {
    it('should add tools to scope', () => {
      const enforcer = new AgentScopeEnforcer();
      enforcer.defineAgentScope('agent-1', ['search']);

      enforcer.addAllowedTools('agent-1', ['calculate', 'format']);

      const scope = enforcer.getScope('agent-1');
      expect(scope!.allowedTools).toContain('search');
      expect(scope!.allowedTools).toContain('calculate');
      expect(scope!.allowedTools).toContain('format');
    });

    it('should not duplicate tools when adding', () => {
      const enforcer = new AgentScopeEnforcer();
      enforcer.defineAgentScope('agent-1', ['search', 'calculate']);

      enforcer.addAllowedTools('agent-1', ['search', 'format']);

      const scope = enforcer.getScope('agent-1');
      expect(scope!.allowedTools).toHaveLength(3);
    });

    it('should remove tools from scope', () => {
      const enforcer = new AgentScopeEnforcer();
      enforcer.defineAgentScope('agent-1', ['search', 'calculate', 'format']);

      enforcer.removeAllowedTools('agent-1', ['calculate']);

      const scope = enforcer.getScope('agent-1');
      expect(scope!.allowedTools).toEqual(['search', 'format']);
    });

    it('should remove scope entirely', () => {
      const enforcer = new AgentScopeEnforcer();
      enforcer.defineAgentScope('agent-1', ['search']);

      enforcer.removeScope('agent-1');

      expect(enforcer.getScope('agent-1')).toBeNull();
      expect(enforcer.isToolAllowed('agent-1', 'anything')).toBe(true);
    });

    it('should create scope when adding tools to non-existent agent', () => {
      const enforcer = new AgentScopeEnforcer();
      enforcer.addAllowedTools('new-agent', ['tool1', 'tool2']);

      const scope = enforcer.getScope('new-agent');
      expect(scope).not.toBeNull();
      expect(scope!.allowedTools).toEqual(['tool1', 'tool2']);
    });
  });
});
