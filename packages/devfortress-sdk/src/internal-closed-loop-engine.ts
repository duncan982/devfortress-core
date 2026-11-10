/**
 * DevFortress SDK v3.3.0 — Internal Closed-Loop Protection Engine
 *
 * Implements the 3-tier internal protection architecture described in the
 * DevFortress patent disclosures (§5 of arXiv paper).
 *
 * Architecture:
 *   Tier 1: Deterministic rule engine (<1ms) — regex, IP blocklist, rate limits
 *   Tier 2: ML scoring placeholder (1-5ms) — extensible via custom scorer
 *   Tier 3: Async platform relay — deferred forwarding to external platform
 *
 * Design principles:
 *   - Zero external dependencies in the critical path (Tier 1 + 2)
 *   - Fail-closed by default (configurable to fail-open for backward compat)
 *   - Bounded in-memory storage with configurable max entries
 *   - Works in air-gap mode (no network required for Tier 1 + 2)
 *   - Agent-aware: extends to AI agent tool call monitoring
 *
 * Weaknesses addressed:
 *   - W1: Configurable fail-closed/fail-open via `failMode`
 *   - W2: Bounded Maps with LRU eviction via `maxEntries`
 *   - W3: Rate limiter with sliding window
 *   - W4: Composite scoring integrated with AbuseIPDB cache
 *   - W5: Audit trail for all actions
 *   - W6: Agent tool call inline blocking (not just flag)
 *
 * @packageDocumentation
 */

import type { ThreatSeverity, EventType, ThreatEvent } from './types';

// ── Configuration ───────────────────────────────────────────

export interface InternalCLConfig {
  /** Fail-closed (block on error) or fail-open (allow on error). Default: 'closed' */
  failMode?: 'closed' | 'open';
  /** Enable Tier 3 async relay to external platform. Default: false (air-gap) */
  enableExternalRelay?: boolean;
  /** Maximum entries in blocking cache. Default: 10_000 */
  maxBlockedEntries?: number;
  /** Maximum entries in rate limiter. Default: 50_000 */
  maxRateLimitEntries?: number;
  /** Maximum entries in audit log. Default: 100_000 */
  maxAuditEntries?: number;
  /** Default block TTL in seconds. Default: 3600 */
  defaultBlockTtlSeconds?: number;
  /** Custom Tier 2 scorer function. Returns 0-100 threat score. */
  tier2Scorer?: (request: InternalCLRequest) => Promise<number> | number;
  /** Score threshold for auto-block. Default: 85 */
  blockThreshold?: number;
  /** Score threshold for rate-limiting. Default: 60 */
  rateLimitThreshold?: number;
  /** Rate limit: max requests per window. Default: 100 */
  rateLimitMax?: number;
  /** Rate limit: window size in ms. Default: 60_000 (1 minute) */
  rateLimitWindowMs?: number;
  /** Debug logging. Default: false */
  debug?: boolean;
  /** Callback when action is taken (for external relay in Tier 3) */
  onAction?: (action: InternalCLAction) => Promise<void> | void;
  /**
   * Option B (2026-08-27): Tier 3 relay callback — fired from
   * `relayToExternal()` for every non-'allow' decision when
   * `enableExternalRelay` is true (hybrid mode only). Receives the full
   * `InternalCLResult` and `InternalCLRequest` so the caller can forward to
   * the platform via its own client (e.g. `DevFortress.trackEvent()`)
   * without this engine needing any HTTP client or platform credentials of
   * its own — it stays deliberately air-gapped otherwise. Deliberately a
   * separate field from `onAction`: `InternalCLAction` (type/target/reason)
   * doesn't carry `ip`/`method`/`path`/`userAgent`/`score`/`decision`, which
   * a platform-ingest payload needs and this callback's parameters already
   * have in scope.
   */
  onRelay?: (
    result: InternalCLResult,
    req: InternalCLRequest
  ) => Promise<void> | void;
}

// ── Request Model ───────────────────────────────────────────

export interface InternalCLRequest {
  /** Client IP address */
  ip: string;
  /** HTTP method */
  method: string;
  /** Request path */
  path: string;
  /** User agent string */
  userAgent?: string;
  /** Authenticated user ID (null for pre-auth) */
  userId?: string | null;
  /** Session ID */
  sessionId?: string | null;
  /** Request body (for pattern matching — optional) */
  body?: string;
  /** Query string (for pattern matching — optional) */
  query?: string;
  /** Request headers (selective — for pattern detection) */
  headers?: Record<string, string>;
  /** Agent ID (for AI agent monitoring) */
  agentId?: string;
  /** Tool name (for AI agent tool call monitoring) */
  toolName?: string;
  /** Timestamp override (defaults to Date.now()) */
  timestamp?: number;
}

// ── Decision Model ──────────────────────────────────────────

export type InternalCLDecision =
  | 'allow'
  | 'block'
  | 'rate_limit'
  | 'challenge'
  | 'quarantine';

export interface InternalCLResult {
  /** Final decision */
  decision: InternalCLDecision;
  /** Combined threat score (0-100) */
  score: number;
  /** Which tier made the decision */
  tier: 1 | 2 | 3;
  /** Matched rule names (Tier 1) */
  matchedRules: string[];
  /** Time taken for evaluation in microseconds */
  evaluationTimeUs: number;
  /** Actions taken */
  actions: InternalCLAction[];
  /** Event ID for audit trail */
  eventId: string;
}

export interface InternalCLAction {
  type:
    | 'block_ip'
    | 'rate_limit'
    | 'block_session'
    | 'block_user'
    | 'quarantine_agent'
    | 'log';
  target: string;
  reason: string;
  ttlSeconds: number;
  timestamp: number;
  eventId: string;
}

// ── Audit Entry ─────────────────────────────────────────────

export interface InternalCLAuditEntry {
  eventId: string;
  timestamp: number;
  ip: string;
  decision: InternalCLDecision;
  score: number;
  tier: 1 | 2 | 3;
  matchedRules: string[];
  userId?: string | null;
  agentId?: string;
  path: string;
  method: string;
}

// ── Rule Definition ─────────────────────────────────────────

export interface InternalCLRule {
  /** Unique rule name */
  name: string;
  /** Rule description */
  description: string;
  /** What severity to assign if matched */
  severity: ThreatSeverity;
  /** Score to assign (0-100) */
  score: number;
  /** Decision if matched */
  decision: InternalCLDecision;
  /** The match function */
  match: (req: InternalCLRequest) => boolean;
  /** Whether rule is enabled */
  enabled: boolean;
}

// ── Bounded Map utility ─────────────────────────────────────

export class BoundedMap<K, V> {
  private map = new Map<K, V>();
  private maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = maxSize;
  }

  get(key: K): V | undefined {
    const val = this.map.get(key);
    if (val !== undefined) {
      // Move to end (LRU)
      this.map.delete(key);
      this.map.set(key, val);
    }
    return val;
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.maxSize) {
      // Evict oldest entry (first key)
      const first = this.map.keys().next().value;
      if (first !== undefined) this.map.delete(first);
    }
    this.map.set(key, value);
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }

  get size(): number {
    return this.map.size;
  }

  clear(): void {
    this.map.clear();
  }

  values(): IterableIterator<V> {
    return this.map.values();
  }

  keys(): IterableIterator<K> {
    return this.map.keys();
  }

  entries(): IterableIterator<[K, V]> {
    return this.map.entries();
  }

  forEach(callback: (value: V, key: K) => void): void {
    for (const [key, value] of this.map) {
      callback(value, key);
    }
  }
}

// ── Sliding Window Rate Limiter ─────────────────────────────

interface RateLimitEntry {
  timestamps: number[];
  blocked: boolean;
}

// ── Default Attack Pattern Rules (Tier 1) ───────────────────

const SQL_INJECTION_PATTERNS = {
  strict: [
    /(?:^|\s)(?:UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+[a-zA-Z0-9_]+\s+SET|DELETE\s+FROM)(?:\s|$)/i,
    /(?:'|")\s*OR\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|"[^"]*"\s*=\s*"[^"]*")/i,
    /(?:'|")\s*;\s*(?:--|\/\*)/,
    /(\bxp_\w+)/i,
  ],
  moderate: [/(\/\*.*\*\/)/, /(\bEXEC\b|\bEXECUTE\b)\s*\(/i],
};

const XSS_PATTERNS = [
  /<script[\s>]/i,
  /javascript\s*:/i,
  /on(load|error|click|mouseover|submit|focus|blur)\s*=/i,
  /(<iframe|<object|<embed|<applet)/i,
  /(document\.(cookie|write|location))/i,
  /(window\.(location|open))/i,
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\//,
  /\.\.%2[fF]/,
  /\.\.\\$/,
  /%2e%2e[%\/\\]/i,
  /\/etc\/(passwd|shadow|hosts)/,
  /\/proc\/self/,
  /(\/\.env|\/\.git|\/\.ssh)/,
];

const SCANNER_SIGNATURES = [
  /sqlmap/i,
  /nikto/i,
  /nmap/i,
  /dirbuster/i,
  /gobuster/i,
  /wpscan/i,
  /burp\s*suite/i,
  /acunetix/i,
  /nessus/i,
  /masscan/i,
  /zgrab/i,
  /nuclei/i,
];

/**
 * Option B (2026-08-27): lightweight, synchronous, zero-network content
 * check reusing the same Tier 1 patterns as registerDefaultRules() below.
 *
 * Why this exists: external mode's own local behavioral preflight (A1
 * cold-start / A2 LSH campaign / A3 rate limit — see
 * DevFortress.runBehavioralPreflight) is purely statistical and needs
 * accumulated history to flag anything — it cannot flag a single, first-ever
 * malicious request (e.g. one-off SQL injection) from a fresh IP, since
 * there's no deviation/campaign/rate signal yet on request #1. External mode
 * otherwise has no content inspection of its own (that's normally the
 * platform's job, server-side, after relay). Without this check, Option B's
 * anomaly gate in observeExternal() would misclassify a genuine one-off
 * attack as "clean" and route it to the non-billed rollup path instead of
 * relaying it — silently losing detection, not just billing, for exactly
 * the traffic this whole system exists to catch.
 */
export function matchesKnownAttackPattern(req: {
  path?: string;
  userAgent?: string;
}): boolean {
  const target = req.path;
  if (target) {
    if (SQL_INJECTION_PATTERNS.strict.some(p => p.test(target))) return true;
    if (SQL_INJECTION_PATTERNS.moderate.some(p => p.test(target))) return true;
    if (XSS_PATTERNS.some(p => p.test(target))) return true;
    if (PATH_TRAVERSAL_PATTERNS.some(p => p.test(target))) return true;
  }
  if (req.userAgent && SCANNER_SIGNATURES.some(p => p.test(req.userAgent!))) {
    return true;
  }
  return false;
}

// ── Internal Closed-Loop Engine ─────────────────────────────

export class InternalClosedLoopEngine {
  private config: Required<
    Omit<InternalCLConfig, 'tier2Scorer' | 'onAction' | 'onRelay'>
  > & {
    tier2Scorer?: InternalCLConfig['tier2Scorer'];
    onAction?: InternalCLConfig['onAction'];
    onRelay?: InternalCLConfig['onRelay'];
  };

  // Bounded data stores
  private blockedIPs: BoundedMap<string, { expiresAt: number; reason: string }>;
  private blockedUsers: BoundedMap<
    string,
    { expiresAt: number; reason: string }
  >;
  private blockedSessions: BoundedMap<
    string,
    { expiresAt: number; reason: string }
  >;
  private quarantinedAgents: BoundedMap<
    string,
    { reason: string; timestamp: number }
  >;
  private rateLimiter: BoundedMap<string, RateLimitEntry>;
  private auditLog: InternalCLAuditEntry[] = [];
  private rules: InternalCLRule[] = [];
  private eventCounter = 0;

  constructor(config: InternalCLConfig = {}) {
    this.config = {
      failMode: config.failMode ?? 'closed',
      enableExternalRelay: config.enableExternalRelay ?? false,
      maxBlockedEntries: config.maxBlockedEntries ?? 10_000,
      maxRateLimitEntries: config.maxRateLimitEntries ?? 50_000,
      maxAuditEntries: config.maxAuditEntries ?? 100_000,
      defaultBlockTtlSeconds: config.defaultBlockTtlSeconds ?? 3600,
      tier2Scorer: config.tier2Scorer,
      blockThreshold: config.blockThreshold ?? 85,
      rateLimitThreshold: config.rateLimitThreshold ?? 60,
      rateLimitMax: config.rateLimitMax ?? 100,
      rateLimitWindowMs: config.rateLimitWindowMs ?? 60_000,
      debug: config.debug ?? false,
      onAction: config.onAction,
      onRelay: config.onRelay,
    };

    this.blockedIPs = new BoundedMap(this.config.maxBlockedEntries);
    this.blockedUsers = new BoundedMap(this.config.maxBlockedEntries);
    this.blockedSessions = new BoundedMap(this.config.maxBlockedEntries);
    this.quarantinedAgents = new BoundedMap(this.config.maxBlockedEntries);
    this.rateLimiter = new BoundedMap(this.config.maxRateLimitEntries);

    // Register default rules
    this.registerDefaultRules();

    this.log(
      'info',
      `Internal Closed-Loop Engine initialized (failMode=${this.config.failMode})`
    );
  }

  // ── Public API ──────────────────────────────────────────

  /**
   * Evaluate a request through the 3-tier engine.
   * This is the main entry point — call this for every inbound request.
   *
   * Returns the decision synchronously (Tier 1) or with minimal latency (Tier 2).
   * Tier 3 (async relay) is non-blocking.
   */
  async evaluate(req: InternalCLRequest): Promise<InternalCLResult> {
    const startTime = performance.now();
    const now = req.timestamp ?? Date.now();
    const eventId = this.generateEventId();

    try {
      // ─── Pre-check: is IP/user/session/agent already blocked? ───
      const preCheck = this.checkBlocked(req, now);
      if (preCheck) {
        const elapsed = Math.round((performance.now() - startTime) * 1000);
        const result: InternalCLResult = {
          decision: preCheck.decision,
          score: 100,
          tier: 1,
          matchedRules: [preCheck.reason],
          evaluationTimeUs: elapsed,
          actions: [],
          eventId,
        };
        this.recordAudit(result, req);
        return result;
      }

      // ─── Tier 1: Deterministic Rules (<1ms target) ───
      const tier1Result = this.evaluateTier1(req);
      if (tier1Result.decision !== 'allow') {
        const elapsed = Math.round((performance.now() - startTime) * 1000);
        const actions = this.executeActions(tier1Result, req, eventId, now);
        const result: InternalCLResult = {
          ...tier1Result,
          evaluationTimeUs: elapsed,
          actions,
          eventId,
        };
        this.recordAudit(result, req);

        // Tier 3: async relay
        if (this.config.enableExternalRelay) {
          this.relayToExternal(result, req).catch(() => {});
        }

        return result;
      }

      // ─── Rate limit check ───
      const rateLimited = this.checkRateLimit(req.ip, now);
      if (rateLimited) {
        const elapsed = Math.round((performance.now() - startTime) * 1000);
        const actions = this.executeActions(
          {
            decision: 'rate_limit',
            score: 65,
            tier: 1,
            matchedRules: ['rate_limit_exceeded'],
          },
          req,
          eventId,
          now
        );
        const result: InternalCLResult = {
          decision: 'rate_limit',
          score: 65,
          tier: 1,
          matchedRules: ['rate_limit_exceeded'],
          evaluationTimeUs: elapsed,
          actions,
          eventId,
        };
        this.recordAudit(result, req);
        return result;
      }

      // Record request for rate limiting
      this.recordRequest(req.ip, now);

      // ─── Tier 2: ML/Custom Scoring (1-5ms target) ───
      if (this.config.tier2Scorer) {
        const tier2Score = await this.config.tier2Scorer(req);
        if (tier2Score >= this.config.blockThreshold) {
          const elapsed = Math.round((performance.now() - startTime) * 1000);
          const tier2Decision: Omit<
            InternalCLResult,
            'evaluationTimeUs' | 'actions' | 'eventId'
          > = {
            decision: 'block',
            score: tier2Score,
            tier: 2,
            matchedRules: ['tier2_ml_score'],
          };
          const actions = this.executeActions(tier2Decision, req, eventId, now);
          const result: InternalCLResult = {
            ...tier2Decision,
            evaluationTimeUs: elapsed,
            actions,
            eventId,
          };
          this.recordAudit(result, req);

          if (this.config.enableExternalRelay) {
            this.relayToExternal(result, req).catch(() => {});
          }

          return result;
        } else if (tier2Score >= this.config.rateLimitThreshold) {
          const elapsed = Math.round((performance.now() - startTime) * 1000);
          const result: InternalCLResult = {
            decision: 'rate_limit',
            score: tier2Score,
            tier: 2,
            matchedRules: ['tier2_ml_elevated'],
            evaluationTimeUs: elapsed,
            actions: [],
            eventId,
          };
          this.recordAudit(result, req);
          return result;
        }
      }

      // ─── Allow ───
      const elapsed = Math.round((performance.now() - startTime) * 1000);
      const result: InternalCLResult = {
        decision: 'allow',
        score: 0,
        tier: 1,
        matchedRules: [],
        evaluationTimeUs: elapsed,
        actions: [],
        eventId,
      };
      return result;
    } catch (error) {
      // Fail-closed or fail-open based on config
      const elapsed = Math.round((performance.now() - startTime) * 1000);
      this.log(
        'error',
        `Evaluation error: ${error instanceof Error ? error.message : 'Unknown'}`
      );

      if (this.config.failMode === 'closed') {
        return {
          decision: 'block',
          score: 100,
          tier: 1,
          matchedRules: ['fail_closed_error'],
          evaluationTimeUs: elapsed,
          actions: [],
          eventId,
        };
      }

      return {
        decision: 'allow',
        score: 0,
        tier: 1,
        matchedRules: ['fail_open_error'],
        evaluationTimeUs: elapsed,
        actions: [],
        eventId,
      };
    }
  }

  /**
   * Manually block an IP.
   */
  blockIP(ip: string, reason: string, ttlSeconds?: number): void {
    const ttl = ttlSeconds ?? this.config.defaultBlockTtlSeconds;
    this.blockedIPs.set(ip, {
      expiresAt: Date.now() + ttl * 1000,
      reason,
    });
    this.log('info', `IP blocked: ${ip} — ${reason} (TTL: ${ttl}s)`);
  }

  /**
   * Manually unblock an IP.
   */
  unblockIP(ip: string): boolean {
    const existed = this.blockedIPs.has(ip);
    this.blockedIPs.delete(ip);
    if (existed) this.log('info', `IP unblocked: ${ip}`);
    return existed;
  }

  /**
   * Block a user by ID.
   */
  blockUser(userId: string, reason: string, ttlSeconds?: number): void {
    const ttl = ttlSeconds ?? this.config.defaultBlockTtlSeconds;
    this.blockedUsers.set(userId, {
      expiresAt: Date.now() + ttl * 1000,
      reason,
    });
    this.log('info', `User blocked: ${userId} — ${reason}`);
  }

  /**
   * Block a session.
   */
  blockSession(sessionId: string, reason: string, ttlSeconds?: number): void {
    const ttl = ttlSeconds ?? this.config.defaultBlockTtlSeconds;
    this.blockedSessions.set(sessionId, {
      expiresAt: Date.now() + ttl * 1000,
      reason,
    });
    this.log('info', `Session blocked: ${sessionId} — ${reason}`);
  }

  /**
   * Quarantine an agent.
   */
  quarantineAgent(agentId: string, reason: string): void {
    this.quarantinedAgents.set(agentId, {
      reason,
      timestamp: Date.now(),
    });
    this.log('info', `Agent quarantined: ${agentId} — ${reason}`);
  }

  /**
   * Remove agent quarantine.
   */
  unquarantineAgent(agentId: string): boolean {
    const existed = this.quarantinedAgents.has(agentId);
    this.quarantinedAgents.delete(agentId);
    if (existed) this.log('info', `Agent unquarantined: ${agentId}`);
    return existed;
  }

  /**
   * Check if an IP is currently blocked.
   */
  isIPBlocked(ip: string): boolean {
    const entry = this.blockedIPs.get(ip);
    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      this.blockedIPs.delete(ip);
      return false;
    }
    return true;
  }

  /**
   * Check if an agent is quarantined.
   */
  isAgentQuarantined(agentId: string): boolean {
    return this.quarantinedAgents.has(agentId);
  }

  /**
   * Add a custom rule to Tier 1.
   */
  addRule(rule: InternalCLRule): void {
    this.rules.push(rule);
    this.log('debug', `Rule added: ${rule.name}`);
  }

  /**
   * Remove a rule by name.
   */
  removeRule(name: string): boolean {
    const idx = this.rules.findIndex(r => r.name === name);
    if (idx >= 0) {
      this.rules.splice(idx, 1);
      this.log('debug', `Rule removed: ${name}`);
      return true;
    }
    return false;
  }

  /**
   * Get all rules (for inspection).
   */
  getRules(): ReadonlyArray<Omit<InternalCLRule, 'match'> & { name: string }> {
    return this.rules.map(
      ({ name, description, severity, score, decision, enabled }) => ({
        name,
        description,
        severity,
        score,
        decision,
        enabled,
      })
    );
  }

  /**
   * Get audit log entries.
   */
  getAuditLog(limit: number = 100): ReadonlyArray<InternalCLAuditEntry> {
    return this.auditLog.slice(-limit);
  }

  /**
   * Get engine statistics.
   */
  getStats(): {
    blockedIPs: number;
    blockedUsers: number;
    blockedSessions: number;
    quarantinedAgents: number;
    rateLimitEntries: number;
    auditLogSize: number;
    rulesCount: number;
    failMode: string;
  } {
    return {
      blockedIPs: this.blockedIPs.size,
      blockedUsers: this.blockedUsers.size,
      blockedSessions: this.blockedSessions.size,
      quarantinedAgents: this.quarantinedAgents.size,
      rateLimitEntries: this.rateLimiter.size,
      auditLogSize: this.auditLog.length,
      rulesCount: this.rules.length,
      failMode: this.config.failMode,
    };
  }

  /**
   * Import blocked IPs from an external source (e.g., AbuseIPDB blacklist).
   */
  importBlockedIPs(
    entries: Array<{ ip: string; reason: string; ttlSeconds?: number }>
  ): number {
    let count = 0;
    for (const entry of entries) {
      this.blockIP(entry.ip, entry.reason, entry.ttlSeconds);
      count++;
    }
    return count;
  }

  /**
   * Reset all state (for testing).
   * @internal
   */
  _reset(): void {
    this.blockedIPs.clear();
    this.blockedUsers.clear();
    this.blockedSessions.clear();
    this.quarantinedAgents.clear();
    this.rateLimiter.clear();
    this.auditLog = [];
    this.eventCounter = 0;
  }

  // ── Private Methods ─────────────────────────────────────

  private checkBlocked(
    req: InternalCLRequest,
    now: number
  ): { decision: InternalCLDecision; reason: string } | null {
    // Check IP block
    const ipBlock = this.blockedIPs.get(req.ip);
    if (ipBlock) {
      if (now > ipBlock.expiresAt) {
        this.blockedIPs.delete(req.ip);
      } else {
        return { decision: 'block', reason: `ip_blocked:${ipBlock.reason}` };
      }
    }

    // Check user block
    if (req.userId) {
      const userBlock = this.blockedUsers.get(req.userId);
      if (userBlock) {
        if (now > userBlock.expiresAt) {
          this.blockedUsers.delete(req.userId);
        } else {
          return {
            decision: 'block',
            reason: `user_blocked:${userBlock.reason}`,
          };
        }
      }
    }

    // Check session block
    if (req.sessionId) {
      const sessionBlock = this.blockedSessions.get(req.sessionId);
      if (sessionBlock) {
        if (now > sessionBlock.expiresAt) {
          this.blockedSessions.delete(req.sessionId);
        } else {
          return {
            decision: 'block',
            reason: `session_blocked:${sessionBlock.reason}`,
          };
        }
      }
    }

    // Check agent quarantine
    if (req.agentId) {
      if (this.quarantinedAgents.has(req.agentId)) {
        return {
          decision: 'quarantine',
          reason: `agent_quarantined:${req.agentId}`,
        };
      }
    }

    return null;
  }

  private evaluateTier1(
    req: InternalCLRequest
  ): Omit<InternalCLResult, 'evaluationTimeUs' | 'actions' | 'eventId'> {
    const matchedRules: string[] = [];
    let maxScore = 0;
    let decision: InternalCLDecision = 'allow';

    for (const rule of this.rules) {
      if (!rule.enabled) continue;
      try {
        if (rule.match(req)) {
          matchedRules.push(rule.name);
          if (rule.score > maxScore) {
            maxScore = rule.score;
            decision = rule.decision;
          }
        }
      } catch {
        // Individual rule errors should not crash the engine
        this.log('error', `Rule ${rule.name} threw an error`);
      }
    }

    return {
      decision,
      score: maxScore,
      tier: 1,
      matchedRules,
    };
  }

  private checkRateLimit(ip: string, now: number): boolean {
    const entry = this.rateLimiter.get(ip);
    if (!entry) return false;

    // Clean old timestamps outside window
    const windowStart = now - this.config.rateLimitWindowMs;
    entry.timestamps = entry.timestamps.filter(t => t > windowStart);

    if (entry.timestamps.length >= this.config.rateLimitMax) {
      entry.blocked = true;
      return true;
    }

    return false;
  }

  private recordRequest(ip: string, now: number): void {
    let entry = this.rateLimiter.get(ip);
    if (!entry) {
      entry = { timestamps: [], blocked: false };
    }
    entry.timestamps.push(now);
    this.rateLimiter.set(ip, entry);
  }

  private executeActions(
    result: Omit<InternalCLResult, 'evaluationTimeUs' | 'actions' | 'eventId'>,
    req: InternalCLRequest,
    eventId: string,
    now: number
  ): InternalCLAction[] {
    const actions: InternalCLAction[] = [];
    const ttl = this.config.defaultBlockTtlSeconds;

    if (result.decision === 'block' || result.decision === 'quarantine') {
      // Auto-block IP (for both block and quarantine decisions)
      this.blockedIPs.set(req.ip, {
        expiresAt: now + ttl * 1000,
        reason: result.matchedRules.join(', '),
      });
      actions.push({
        type: 'block_ip',
        target: req.ip,
        reason: result.matchedRules.join(', '),
        ttlSeconds: ttl,
        timestamp: now,
        eventId,
      });

      // Also block session if present
      if (req.sessionId) {
        this.blockedSessions.set(req.sessionId, {
          expiresAt: now + ttl * 1000,
          reason: result.matchedRules.join(', '),
        });
        actions.push({
          type: 'block_session',
          target: req.sessionId,
          reason: result.matchedRules.join(', '),
          ttlSeconds: ttl,
          timestamp: now,
          eventId,
        });
      }

      // Quarantine agent if present
      if (req.agentId) {
        this.quarantinedAgents.set(req.agentId, {
          reason: result.matchedRules.join(', '),
          timestamp: now,
        });
        actions.push({
          type: 'quarantine_agent',
          target: req.agentId,
          reason: result.matchedRules.join(', '),
          ttlSeconds: 0, // Permanent until manual unquarantine
          timestamp: now,
          eventId,
        });
      }
    }

    // Notify via callback
    if (this.config.onAction) {
      for (const action of actions) {
        try {
          const maybePromise = this.config.onAction(action);
          if (
            maybePromise &&
            typeof (maybePromise as Promise<void>).catch === 'function'
          ) {
            (maybePromise as Promise<void>).catch(() => {});
          }
        } catch {
          this.log('error', `onAction callback error for ${action.type}`);
        }
      }
    }

    return actions;
  }

  private recordAudit(result: InternalCLResult, req: InternalCLRequest): void {
    // Bounded audit log — evict oldest when full
    if (this.auditLog.length >= this.config.maxAuditEntries) {
      this.auditLog.splice(0, Math.floor(this.config.maxAuditEntries * 0.1));
    }

    this.auditLog.push({
      eventId: result.eventId,
      timestamp: req.timestamp ?? Date.now(),
      ip: req.ip,
      decision: result.decision,
      score: result.score,
      tier: result.tier,
      matchedRules: result.matchedRules,
      userId: req.userId,
      agentId: req.agentId,
      path: req.path,
      method: req.method,
    });
  }

  private async relayToExternal(
    result: InternalCLResult,
    req: InternalCLRequest
  ): Promise<void> {
    // Tier 3: relay via the caller-supplied onRelay callback (Option B,
    // 2026-08-27). This engine has no HTTP client or platform credentials
    // of its own by design (see InternalCLConfig — deliberately air-gapped);
    // the caller (DevFortress.trackEvent()) does the actual platform call.
    //
    // TODO 210 (2026-08-27): this callback (→ relayInternalDecisionToPlatform
    // → trackEvent()) is now the ONLY relay for a hybrid-mode flagged
    // decision — devfortress.ts's observeHybrid() used to independently
    // relay the same decision a second time via relayToExternalAsync(),
    // producing a duplicate LiveThreatEvent row (double billing) per
    // request. See devfortress.ts's observeHybrid() and relayToExternalAsync()
    // for the fix and its trade-off.
    this.log('debug', `Tier 3 relay: ${result.eventId} → external platform`);
    if (!this.config.onRelay) return;
    try {
      await this.config.onRelay(result, req);
    } catch (e) {
      this.log(
        'error',
        `onRelay callback error for ${result.eventId}: ${e instanceof Error ? e.message : 'Unknown'}`
      );
    }
  }

  private generateEventId(): string {
    this.eventCounter++;
    const ts = Date.now().toString(36);
    const counter = this.eventCounter.toString(36).padStart(4, '0');
    const rand = Math.random().toString(36).substring(2, 6);
    return `icl_${ts}_${counter}_${rand}`;
  }

  private registerDefaultRules(): void {
    // ─── SQL Injection ───
    this.rules.push({
      name: 'sql_injection',
      description:
        'Detects SQL injection patterns context-aware (strict on path/query, moderate on body)',
      severity: 'critical',
      score: 95,
      decision: 'block',
      enabled: true,
      match: req => {
        // Strict patterns for path and query parameters
        const strictTargets = [req.path, req.query].filter(Boolean) as string[];
        if (
          strictTargets.some(t =>
            SQL_INJECTION_PATTERNS.strict.some(p => p.test(t))
          )
        )
          return true;
        if (
          strictTargets.some(t =>
            SQL_INJECTION_PATTERNS.moderate.some(p => p.test(t))
          )
        )
          return true;

        // Body and headers are only checked against strict patterns to reduce false positives
        const bodyTargets = [
          req.body,
          ...Object.values(req.headers || {}),
        ].filter(Boolean) as string[];
        return bodyTargets.some(t =>
          SQL_INJECTION_PATTERNS.strict.some(p => p.test(t))
        );
      },
    });

    // ─── XSS ───
    this.rules.push({
      name: 'xss_attempt',
      description: 'Detects cross-site scripting patterns',
      severity: 'high',
      score: 90,
      decision: 'block',
      enabled: true,
      match: req => {
        const targets = [req.path, req.query, req.body].filter(
          Boolean
        ) as string[];
        return targets.some(t => XSS_PATTERNS.some(p => p.test(t)));
      },
    });

    // ─── Path Traversal ───
    this.rules.push({
      name: 'path_traversal',
      description: 'Detects directory traversal attempts',
      severity: 'high',
      score: 90,
      decision: 'block',
      enabled: true,
      match: req => {
        const targets = [req.path, req.query].filter(Boolean) as string[];
        return targets.some(t => PATH_TRAVERSAL_PATTERNS.some(p => p.test(t)));
      },
    });

    // ─── Scanner Detection ───
    this.rules.push({
      name: 'scanner_detected',
      description: 'Detects known vulnerability scanner user agents',
      severity: 'medium',
      score: 75,
      decision: 'block',
      enabled: true,
      match: req => {
        if (!req.userAgent) return false;
        return SCANNER_SIGNATURES.some(p => p.test(req.userAgent!));
      },
    });

    // ─── Sensitive File Access ───
    this.rules.push({
      name: 'sensitive_file_access',
      description:
        'Detects access to sensitive files (.env, .git, wp-admin, etc.)',
      severity: 'high',
      score: 85,
      decision: 'block',
      enabled: true,
      match: req => {
        const sensitivePatterns = [
          /\/\.env/,
          /\/\.git/,
          /\/\.ssh/,
          /\/wp-admin/,
          /\/wp-login/,
          /\/phpmyadmin/i,
          /\/admin\.php/,
          /\/\.htaccess/,
          /\/\.htpasswd/,
          /\/server-status/,
          /\/actuator/,
          /\/debug\//,
        ];
        return sensitivePatterns.some(p => p.test(req.path));
      },
    });

    // ─── Credential Stuffing Heuristic ───
    this.rules.push({
      name: 'credential_stuffing_pattern',
      description: 'Detects credential stuffing via POST to auth endpoints',
      severity: 'high',
      score: 80,
      decision: 'rate_limit',
      enabled: true,
      match: req => {
        if (req.method !== 'POST') return false;
        const authPaths = [
          '/login',
          '/signin',
          '/auth',
          '/api/auth',
          '/api/login',
          '/oauth/token',
        ];
        return authPaths.some(p => req.path.toLowerCase().includes(p));
      },
    });

    // ─── Agent Unsanctioned Tool ───
    this.rules.push({
      name: 'agent_unsanctioned_tool',
      description: 'Detects agent attempting to use dangerous tools',
      severity: 'critical',
      score: 95,
      decision: 'quarantine',
      enabled: true,
      match: req => {
        if (!req.agentId || !req.toolName) return false;
        const dangerousTools = [
          'shell_exec',
          'eval',
          'exec',
          'rm',
          'sudo',
          'chmod',
          'kill',
        ];
        return dangerousTools.includes(req.toolName.toLowerCase());
      },
    });
  }

  private log(
    level: 'info' | 'warn' | 'error' | 'debug',
    message: string
  ): void {
    if (!this.config.debug && level === 'debug') return;
    const prefix = '[DevFortress ICL]';
    switch (level) {
      case 'error':
        console.error(`${prefix} ${message}`);
        break;
      case 'warn':
        console.warn(`${prefix} ${message}`);
        break;
      case 'info':
      case 'debug':
        if (this.config.debug) {
          console.log(`${prefix} ${message}`);
        }
        break;
    }
  }
}
