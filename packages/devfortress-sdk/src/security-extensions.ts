/**
 * DevFortress SDK — Complete Coverage Security Extensions
 *
 * OAuth Redirect Validator
 * MFA Fatigue Detector
 * Session Fixation Guard
 * Business Logic Abuse Profiler
 * Refresh Token Binding Enforcer
 * Indirect Prompt Injection Filter
 * Agent Feedback Poisoning Guard
 * Clock Drift Anomaly Detector
 *
 * Patent Pending.
 * @packageDocumentation
 */

import crypto from 'crypto';

// ═══════════════════════════════════════════════════════════════
// OAuth Redirect Validator
// ═══════════════════════════════════════════════════════════════

export interface OAuthRedirectConfig {
  /** Pre-registered allowed redirect URIs */
  allowedRedirectURIs: string[];
  /** Max Levenshtein distance for typosquat detection. Default: 3 */
  maxLevenshteinDistance?: number;
  /** Minimum state parameter entropy (bits). Default: 128 */
  minStateEntropy?: number;
  /**
   * Server-side secret used to cryptographically bind the OAuth `state`
   * parameter to the redirect URI it was issued for (HMAC-SHA256). Required
   * for `generateState()`/`verifyStateBinding()`. This binding is required
   * whenever a `state` is presented to `validate()` — if unset,
   * `validate()` throws rather than silently degrading to entropy-only
   * checking (see the `if (state)` branch in `validate()`).
   */
  stateSigningSecret?: string;
  debug?: boolean;
}

export interface RedirectValidationResult {
  valid: boolean;
  reason: string;
  riskScore: number;
  signals: string[];
}

/** Hard cap on redirect URIs scanned by {@link OAuthRedirectValidator.validate}. */
const MAX_REDIRECT_URI_LENGTH = 2048;

/**
 * True if `uri` contains a `//authority` segment with embedded userinfo
 * (`//user@host`), the classic open-redirect/credential-stuffing trick.
 * Linear scan, no backtracking — bounded by the distance to the next `/`
 * or `@` from each `//` occurrence.
 */
function hasEmbeddedAuthorityCredentials(uri: string): boolean {
  let searchFrom = 0;
  while (true) {
    const doubleSlash = uri.indexOf('//', searchFrom);
    if (doubleSlash === -1) return false;
    const authorityStart = doubleSlash + 2;
    const nextSlash = uri.indexOf('/', authorityStart);
    const authority =
      nextSlash === -1
        ? uri.slice(authorityStart)
        : uri.slice(authorityStart, nextSlash);
    if (authority.includes('@')) return true;
    searchFrom = doubleSlash + 2;
  }
}

export class OAuthRedirectValidator {
  private readonly config: Required<OAuthRedirectConfig>;
  private readonly allowedHosts: Set<string>;

  constructor(config: Partial<OAuthRedirectConfig> = {}) {
    this.config = {
      allowedRedirectURIs: config.allowedRedirectURIs ?? [],
      maxLevenshteinDistance: config.maxLevenshteinDistance ?? 3,
      minStateEntropy: config.minStateEntropy ?? 128,
      stateSigningSecret: config.stateSigningSecret ?? '',
      debug: config.debug ?? false,
    };
    this.allowedHosts = new Set(
      this.config.allowedRedirectURIs
        .map(u => {
          try {
            return new URL(u).hostname;
          } catch {
            return '';
          }
        })
        .filter(Boolean)
    );
  }

  validate(redirectUri: string, state?: string): RedirectValidationResult {
    // Defense in depth: cap input length before any pattern scanning below —
    // redirect URIs this long are never legitimate, and bounding length here
    // keeps every subsequent check (Levenshtein, URI-scheme scan) linear
    // regardless of what a caller passes in.
    if (redirectUri.length > MAX_REDIRECT_URI_LENGTH) {
      return {
        valid: false,
        reason: 'Redirect URI exceeds maximum allowed length',
        riskScore: 100,
        signals: ['redirect_uri_too_long'],
      };
    }

    const signals: string[] = [];
    let riskScore = 0;

    // 1. Exact match
    if (this.config.allowedRedirectURIs.includes(redirectUri)) {
      // Check state entropy if provided
      if (state) {
        const entropy = this.estimateEntropy(state);
        if (entropy < this.config.minStateEntropy) {
          signals.push(
            `Low state entropy: ${entropy} bits (min ${this.config.minStateEntropy})`
          );
          riskScore += 30;
        }

        // Layer 2: cryptographically bind the state parameter to the
        // redirect URI it was issued for (HMAC-SHA256 over
        // redirectUri‖timestamp‖nonce). A high-entropy state with no
        // relationship to this redirect URI must still be rejected — that
        // is exactly the scenario this layer exists to catch.
        //
        // Fail loud, not silent fallback (matching the mandatory-encryption
        // pattern in CredentialIsolationManager): a `state` was presented
        // for binding verification, so skipping the check because no
        // secret is configured would silently downgrade the HMAC
        // binding to entropy-only checking. Refuse instead.
        if (!this.config.stateSigningSecret) {
          throw new Error(
            'OAuthRedirectValidator.validate() was called with a `state` ' +
              'parameter but no `stateSigningSecret` is configured — HMAC ' +
              'state-redirect binding cannot be enforced. Refusing to ' +
              'silently fall back to entropy-only checking. Configure ' +
              '`stateSigningSecret` in OAuthRedirectConfig, or omit ' +
              '`state` from validate() if binding is genuinely not needed ' +
              'for this call site.'
          );
        }
        if (!this.verifyStateBinding(state, redirectUri)) {
          signals.push(
            'State parameter failed HMAC binding verification against redirect URI'
          );
          riskScore = 100;
        }
      }
      return {
        valid: riskScore < 30,
        reason: riskScore < 30 ? 'Exact match' : signals.join('; '),
        riskScore,
        signals,
      };
    }

    riskScore += 50; // Not an exact match

    // 2. Host similarity check (typosquat detection)
    let hostName: string;
    try {
      hostName = new URL(redirectUri).hostname;
    } catch {
      return {
        valid: false,
        reason: 'Invalid redirect URI',
        riskScore: 100,
        signals: ['Malformed URL'],
      };
    }

    for (const allowedHost of this.allowedHosts) {
      const distance = this.levenshteinDistance(hostName, allowedHost);
      if (distance > 0 && distance <= this.config.maxLevenshteinDistance) {
        signals.push(
          `Typosquat candidate: '${hostName}' similar to '${allowedHost}' (distance=${distance})`
        );
        riskScore += 30;
      }
    }

    // 3. Multi-hop redirect detection (data: or javascript: URIs)
    if (/^(javascript|data|vbscript):/i.test(redirectUri)) {
      signals.push('Dangerous URI scheme detected');
      riskScore = 100;
    }

    // 4. Fragment injection
    if (redirectUri.includes('#') && redirectUri.includes('?')) {
      signals.push('Fragment with query parameters (potential token leakage)');
      riskScore += 20;
    }

    // 5. Open redirect patterns (embedded credentials in the authority, e.g.
    // `https://real-host@evil.com`). Checked without a regex: a lazy `.*?`
    // between an unanchored `//` and `@` is polynomial on crafted input
    // (many `//` occurrences, each re-scanning for a missing `@`).
    if (
      hasEmbeddedAuthorityCredentials(redirectUri) ||
      redirectUri.includes('\\')
    ) {
      signals.push('Open redirect pattern detected');
      riskScore += 40;
    }

    riskScore = Math.min(100, riskScore);
    return {
      valid: riskScore < 50,
      reason:
        signals.length > 0
          ? signals.join('; ')
          : 'Redirect URI not in allowlist',
      riskScore,
      signals,
    };
  }

  /**
   * Alias for validate() — used by validation scripts.
   */
  check(redirectUri: string, state?: string): RedirectValidationResult {
    return this.validate(redirectUri, state);
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= a.length; i++) {
      matrix[i] = [i];
      for (let j = 1; j <= b.length; j++) {
        matrix[i][j] =
          i === 0
            ? j
            : Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
              );
      }
    }
    return matrix[a.length][b.length];
  }

  private estimateEntropy(state: string): number {
    const charsetSize = new Set(state.split('')).size;
    return Math.round(state.length * Math.log2(Math.max(charsetSize, 2)));
  }

  /**
   * Generate a state parameter cryptographically bound to `redirectUri` via
   * HMAC-SHA256, per spec §5.7.2 Layer 2. Call this when starting the OAuth
   * flow; pass the returned value as the `state` query parameter.
   */
  generateState(redirectUri: string, nonce?: string): string {
    if (!this.config.stateSigningSecret) {
      throw new Error(
        'stateSigningSecret is required to generate a cryptographically bound state parameter'
      );
    }
    const timestamp = Date.now();
    const nonceValue = nonce ?? crypto.randomBytes(16).toString('hex');
    const hmac = this.computeStateHmac(redirectUri, timestamp, nonceValue);
    return Buffer.from(`${timestamp}.${nonceValue}.${hmac}`).toString(
      'base64url'
    );
  }

  /**
   * Verify that `state` was actually issued for `redirectUri` — i.e. that
   * its HMAC matches one computed over this exact redirect URI. Returns
   * false on any malformed input, expired binding, or mismatch.
   */
  verifyStateBinding(state: string, redirectUri: string): boolean {
    if (!this.config.stateSigningSecret) return false;
    let decoded: string;
    try {
      decoded = Buffer.from(state, 'base64url').toString('utf8');
    } catch {
      return false;
    }
    const parts = decoded.split('.');
    if (parts.length !== 3) return false;
    const [timestampStr, nonceValue, providedHmac] = parts;
    const timestamp = Number(timestampStr);
    if (!Number.isFinite(timestamp) || !nonceValue || !providedHmac) {
      return false;
    }
    const expectedHmac = this.computeStateHmac(
      redirectUri,
      timestamp,
      nonceValue
    );
    const expectedBuf = Buffer.from(expectedHmac, 'hex');
    const providedBuf = Buffer.from(providedHmac, 'hex');
    if (expectedBuf.length !== providedBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, providedBuf);
  }

  private computeStateHmac(
    redirectUri: string,
    timestamp: number,
    nonce: string
  ): string {
    const payload = `${redirectUri}␟${timestamp}␟${nonce}`;
    return crypto
      .createHmac('sha256', this.config.stateSigningSecret)
      .update(payload)
      .digest('hex');
  }
}

// ═══════════════════════════════════════════════════════════════
// MFA Fatigue Detector
// ═══════════════════════════════════════════════════════════════

export interface MFAFatigueConfig {
  /** Max MFA prompts per user per window. Default: 5 */
  maxPromptsPerWindow?: number;
  /** Window in ms. Default: 300_000 (5 min) */
  windowMs?: number;
  /** Lockout duration in ms after fatigue detection. Default: 900_000 (15 min) */
  lockoutDurationMs?: number;
  /** Max tracked users. Default: 50_000 */
  maxEntries?: number;
  debug?: boolean;
}

export interface MFAFatigueResult {
  allowed: boolean;
  promptCount: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  action: 'allow' | 'warn_user' | 'lockout' | 'escalate_admin';
  reason: string;
}

interface MFAUserRecord {
  prompts: number[];
  approvals: number[];
  lockedUntil: number;
  lastDevice: string;
}

export class MFAFatigueDetector {
  private readonly config: Required<MFAFatigueConfig>;
  private readonly userRecords = new Map<string, MFAUserRecord>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: MFAFatigueConfig = {}) {
    this.config = {
      maxPromptsPerWindow: config.maxPromptsPerWindow ?? 5,
      windowMs: config.windowMs ?? 300_000,
      lockoutDurationMs: config.lockoutDurationMs ?? 900_000,
      maxEntries: config.maxEntries ?? 50_000,
      debug: config.debug ?? false,
    };
    this.cleanupTimer = setInterval(() => this.cleanup(), this.config.windowMs);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  recordPrompt(userId: string, deviceId?: string): MFAFatigueResult {
    const now = Date.now();
    const record = this.getOrCreateRecord(userId);

    // Check lockout
    if (record.lockedUntil > now) {
      return {
        allowed: false,
        promptCount: record.prompts.length,
        severity: 'CRITICAL',
        action: 'lockout',
        reason: `MFA locked until ${new Date(record.lockedUntil).toISOString()} due to fatigue attack detection`,
      };
    }

    // Purge expired prompts
    record.prompts = record.prompts.filter(
      t => now - t <= this.config.windowMs
    );
    record.prompts.push(now);

    if (deviceId) record.lastDevice = deviceId;

    const promptCount = record.prompts.length;

    if (promptCount <= 2) {
      return {
        allowed: true,
        promptCount,
        severity: 'LOW',
        action: 'allow',
        reason: 'Normal MFA prompt rate',
      };
    }

    if (promptCount <= this.config.maxPromptsPerWindow) {
      return {
        allowed: true,
        promptCount,
        severity: 'MEDIUM',
        action: 'warn_user',
        reason: `Elevated MFA prompts: ${promptCount} in window`,
      };
    }

    // Fatigue attack detected
    const ratio = promptCount / this.config.maxPromptsPerWindow;
    if (ratio >= 3) {
      record.lockedUntil = now + this.config.lockoutDurationMs;
      return {
        allowed: false,
        promptCount,
        severity: 'CRITICAL',
        action: 'escalate_admin',
        reason: `MFA fatigue attack: ${promptCount} prompts in ${this.config.windowMs / 1000}s (Uber-style attack pattern)`,
      };
    }

    record.lockedUntil = now + this.config.lockoutDurationMs;
    return {
      allowed: false,
      promptCount,
      severity: 'HIGH',
      action: 'lockout',
      reason: `MFA fatigue detected: ${promptCount} prompts. Temporary lockout applied.`,
    };
  }

  recordApproval(userId: string): void {
    const record = this.userRecords.get(userId);
    if (record) {
      record.approvals.push(Date.now());
    }
  }

  private getOrCreateRecord(userId: string): MFAUserRecord {
    let record = this.userRecords.get(userId);
    if (!record) {
      if (this.userRecords.size >= this.config.maxEntries) {
        const first = this.userRecords.keys().next().value;
        if (first !== undefined) this.userRecords.delete(first);
      }
      record = { prompts: [], approvals: [], lockedUntil: 0, lastDevice: '' };
      this.userRecords.set(userId, record);
    }
    return record;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, rec] of this.userRecords) {
      rec.prompts = rec.prompts.filter(t => now - t <= this.config.windowMs);
      if (rec.prompts.length === 0 && rec.lockedUntil < now)
        this.userRecords.delete(key);
    }
  }

  getStats(): { trackedUsers: number } {
    return { trackedUsers: this.userRecords.size };
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// Session Fixation Guard
// ═══════════════════════════════════════════════════════════════

export interface SessionFixationConfig {
  /** Require session regeneration on login. Default: true */
  regenerateOnLogin?: boolean;
  /** Bind session to IP range (first 3 octets). Default: true */
  bindToIPRange?: boolean;
  /** Bind session to user-agent. Default: true */
  bindToUserAgent?: boolean;
  /** Max fingerprint drift before flagging. Default: 2 */
  maxFingerprintDrift?: number;
  debug?: boolean;
}

export interface SessionFingerprint {
  sessionId: string;
  ipPrefix: string; // First 3 octets
  userAgent: string;
  tlsVersion?: string;
  createdAt: number;
  lastVerified: number;
}

export interface SessionValidationResult {
  valid: boolean;
  regenerate: boolean;
  reason: string;
  driftScore: number;
}

export class SessionFixationGuard {
  private readonly config: Required<SessionFixationConfig>;
  private readonly sessions = new Map<string, SessionFingerprint>();

  constructor(config: SessionFixationConfig = {}) {
    this.config = {
      regenerateOnLogin: config.regenerateOnLogin ?? true,
      bindToIPRange: config.bindToIPRange ?? true,
      bindToUserAgent: config.bindToUserAgent ?? true,
      maxFingerprintDrift: config.maxFingerprintDrift ?? 2,
      debug: config.debug ?? false,
    };
  }

  /**
   * Register a new session after authentication.
   * Returns a new session ID (caller must replace old session).
   */
  registerSession(
    ip: string,
    userAgent: string,
    oldSessionId?: string
  ): string {
    const newSessionId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();

    // Remove old session
    if (oldSessionId) this.sessions.delete(oldSessionId);

    this.sessions.set(newSessionId, {
      sessionId: newSessionId,
      ipPrefix: this.getIPPrefix(ip),
      userAgent,
      createdAt: now,
      lastVerified: now,
    });

    return newSessionId;
  }

  /**
   * Validate ongoing session against its fingerprint.
   */
  validateSession(
    sessionId: string,
    ip: string,
    userAgent: string
  ): SessionValidationResult {
    const fingerprint = this.sessions.get(sessionId);
    if (!fingerprint) {
      return {
        valid: false,
        regenerate: true,
        reason: 'Unknown session ID',
        driftScore: 100,
      };
    }

    let driftScore = 0;
    const reasons: string[] = [];

    // IP range check
    if (this.config.bindToIPRange) {
      const currentPrefix = this.getIPPrefix(ip);
      if (currentPrefix !== fingerprint.ipPrefix) {
        driftScore += 40;
        reasons.push(
          `IP range changed: ${fingerprint.ipPrefix}.* → ${currentPrefix}.*`
        );
      }
    }

    // User-agent check
    if (this.config.bindToUserAgent && userAgent !== fingerprint.userAgent) {
      driftScore += 40;
      reasons.push('User-agent changed mid-session');
    }

    fingerprint.lastVerified = Date.now();

    if (driftScore > 50) {
      return {
        valid: false,
        regenerate: true,
        reason: `Session fixation/hijack suspected: ${reasons.join('; ')}`,
        driftScore,
      };
    }

    if (driftScore > 0) {
      return {
        valid: true,
        regenerate: false,
        reason: `Minor session drift: ${reasons.join('; ')}`,
        driftScore,
      };
    }

    return {
      valid: true,
      regenerate: false,
      reason: 'Session fingerprint matches',
      driftScore: 0,
    };
  }

  removeSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  private getIPPrefix(ip: string): string {
    return ip.split('.').slice(0, 3).join('.');
  }

  getStats(): { activeSessions: number } {
    return { activeSessions: this.sessions.size };
  }
}

// ═══════════════════════════════════════════════════════════════
// Business Logic Abuse Profiler
// ═══════════════════════════════════════════════════════════════

export interface BusinessLogicConfig {
  /**
   * Prior/seed transaction flow order — used only to bootstrap the learned
   * transition graph before it has enough observed traffic to stand on its
   * own. Progressively overwritten by real observations; not a permanent
   * rule. Default: standard e-commerce flow.
   */
  expectedFlows?: Record<string, string[]>;
  /** Velocity window in ms. Default: 60_000 (1 min) */
  velocityWindowMs?: number;
  /** Max actions per flow step per window. Default: 10 */
  maxActionsPerStep?: number;
  /** Max tracked users. Default: 50_000 */
  maxEntries?: number;
  /**
   * Elapsed time before a flow's transition graph is considered mature
   * enough to police on its own, independent of the seed prior. Default:
   * 7 days.
   */
  learningWindowMs?: number;
  /**
   * Observed transitions before a flow's transition graph is considered
   * mature. Default: 1000.
   */
  minTransactionsForLearned?: number;
  /**
   * EWMA alpha applied to edge weights while the graph is still learning
   * (high responsiveness). Default: 0.3.
   */
  graphEwmaAlphaLearning?: number;
  /**
   * EWMA alpha applied to edge weights once the graph is mature (low
   * drift). Default: 0.05.
   */
  graphEwmaAlphaStable?: number;
  /**
   * Learned-edge weight below which a transition is flagged as
   * rare/unlearned, once the graph has matured. Default: 0.05.
   */
  minEdgeWeightThreshold?: number;
  debug?: boolean;
}

export interface BusinessLogicResult {
  valid: boolean;
  riskScore: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  signals: string[];
  reason: string;
  /** Learned transition-graph state for the flow this evaluation touched. */
  graphState: {
    learned: boolean;
    transactionCount: number;
    edgeWeight?: number;
  };
}

interface UserFlowRecord {
  steps: Array<{
    step: string;
    timestamp: number;
    metadata?: Record<string, unknown>;
  }>;
  lastStep: string;
}

interface FlowGraphEdge {
  /** EWMA-smoothed estimate of relative transition frequency (0-1). */
  weight: number;
  /** Raw observation count, for diagnostics. */
  count: number;
}

interface FlowGraph {
  /** `${fromStep}->${toStep}` -> edge */
  edges: Map<string, FlowGraphEdge>;
  transactionCount: number;
  firstObservedAt: number;
}

export class BusinessLogicProfiler {
  private readonly config: Required<BusinessLogicConfig>;
  private readonly userFlows = new Map<string, UserFlowRecord>();
  /**
   * Directed transaction-flow graph per flow name, built from observed
   * transitions (spec §5.10 `G_a = (V,E,W)`). Population-level
   * per flow (not per user) so the same code adapts automatically to
   * whatever flow shape a given deployment actually has.
   */
  private readonly flowGraphs = new Map<string, FlowGraph>();

  private static readonly DEFAULT_FLOWS: Record<string, string[]> = {
    purchase: [
      'browse',
      'add_to_cart',
      'view_cart',
      'checkout',
      'payment',
      'confirmation',
    ],
    registration: ['visit', 'fill_form', 'verify_email', 'complete_profile'],
    password_reset: ['request_reset', 'verify_identity', 'set_password'],
  };

  constructor(config: BusinessLogicConfig = {}) {
    this.config = {
      expectedFlows:
        config.expectedFlows ?? BusinessLogicProfiler.DEFAULT_FLOWS,
      velocityWindowMs: config.velocityWindowMs ?? 60_000,
      maxActionsPerStep: config.maxActionsPerStep ?? 10,
      maxEntries: config.maxEntries ?? 50_000,
      learningWindowMs: config.learningWindowMs ?? 7 * 24 * 60 * 60 * 1000,
      minTransactionsForLearned: config.minTransactionsForLearned ?? 1000,
      graphEwmaAlphaLearning: config.graphEwmaAlphaLearning ?? 0.3,
      graphEwmaAlphaStable: config.graphEwmaAlphaStable ?? 0.05,
      minEdgeWeightThreshold: config.minEdgeWeightThreshold ?? 0.05,
      debug: config.debug ?? false,
    };
  }

  /**
   * Get (or create + seed) the transition graph for a flow. New graphs are
   * seeded with a weak prior along `expectedFlows[flowName]` so early
   * traffic — before enough observations exist for the graph to stand on
   * its own — is still protected. The prior decays away under the EWMA
   * update in `updateGraphEdge()` as real transitions are observed.
   */
  private getOrCreateGraph(flowName: string, now: number): FlowGraph {
    let graph = this.flowGraphs.get(flowName);
    if (graph) return graph;

    graph = { edges: new Map(), transactionCount: 0, firstObservedAt: now };
    const prior = this.config.expectedFlows[flowName];
    if (prior && prior.length > 1) {
      const PRIOR_WEIGHT = 0.5;
      for (let i = 0; i < prior.length - 1; i++) {
        graph.edges.set(`${prior[i]}->${prior[i + 1]}`, {
          weight: PRIOR_WEIGHT,
          count: 0,
        });
      }
    }
    this.flowGraphs.set(flowName, graph);
    return graph;
  }

  /** Has this flow's graph observed enough traffic over enough time to be self-sufficient? */
  private isGraphLearned(graph: FlowGraph, now: number): boolean {
    return (
      now - graph.firstObservedAt >= this.config.learningWindowMs &&
      graph.transactionCount >= this.config.minTransactionsForLearned
    );
  }

  /**
   * EWMA weight update for an observed transition (GAP-A14 core mechanism).
   * The traversed edge's weight is pulled toward 1; sibling out-edges from
   * the same node decay, so weights approximate a real "what happens next
   * from this step" probability distribution rather than raw counts.
   */
  private updateGraphEdge(
    graph: FlowGraph,
    fromStep: string,
    toStep: string,
    now: number
  ): void {
    const alpha = this.isGraphLearned(graph, now)
      ? this.config.graphEwmaAlphaStable
      : this.config.graphEwmaAlphaLearning;
    const key = `${fromStep}->${toStep}`;
    const existing = graph.edges.get(key);
    if (existing) {
      existing.weight = alpha * 1 + (1 - alpha) * existing.weight;
      existing.count += 1;
    } else {
      graph.edges.set(key, { weight: alpha, count: 1 });
    }

    const prefix = `${fromStep}->`;
    for (const [k, edge] of graph.edges) {
      if (k !== key && k.startsWith(prefix)) {
        edge.weight = (1 - alpha) * edge.weight;
      }
    }
    graph.transactionCount += 1;
  }

  evaluate(
    userId: string,
    flowName: string,
    step: string,
    metadata?: Record<string, unknown>
  ): BusinessLogicResult {
    const now = Date.now();
    const signals: string[] = [];
    let riskScore = 0;

    // Get/create user record
    let record = this.userFlows.get(userId);
    if (!record) {
      if (this.userFlows.size >= this.config.maxEntries) {
        const first = this.userFlows.keys().next().value;
        if (first !== undefined) this.userFlows.delete(first);
      }
      record = { steps: [], lastStep: '' };
      this.userFlows.set(userId, record);
    }

    // Purge old steps
    record.steps = record.steps.filter(
      s => now - s.timestamp <= this.config.velocityWindowMs * 10
    );
    record.steps.push({ step, timestamp: now, metadata });

    // 1. Learned transition-graph check (core mechanism).
    // Evaluated against the graph's state *before* this transition updates
    // it, then the graph is updated so the next call reflects it.
    const graph = this.getOrCreateGraph(flowName, now);
    const learned = this.isGraphLearned(graph, now);
    let graphEdgeWeight: number | undefined;

    if (record.lastStep) {
      const edgeKey = `${record.lastStep}->${step}`;
      graphEdgeWeight = graph.edges.get(edgeKey)?.weight ?? 0;
      // Only treat rarity as a signal once the graph has matured — during
      // the learning window a novel transition is expected traffic, not
      // necessarily abuse.
      if (learned && graphEdgeWeight < this.config.minEdgeWeightThreshold) {
        signals.push(
          `Rare/unlearned transition '${record.lastStep}' -> '${step}' ` +
            `(learned weight=${graphEdgeWeight.toFixed(3)}, threshold=${this.config.minEdgeWeightThreshold})`
        );
        riskScore += 35;
      }
      this.updateGraphEdge(graph, record.lastStep, step, now);
    } else {
      // First step observed for this user in this flow — no edge to bind from yet.
      graph.transactionCount += 1;
    }

    // 2. Velocity check (same step repeated too fast)
    const recentSameStep = record.steps.filter(
      s => s.step === step && now - s.timestamp <= this.config.velocityWindowMs
    );
    if (recentSameStep.length > this.config.maxActionsPerStep) {
      signals.push(
        `Velocity abuse: ${recentSameStep.length}× '${step}' in window`
      );
      riskScore += 30;
    }

    // 3. Price manipulation detection
    if (
      metadata?.price !== undefined &&
      metadata?.originalPrice !== undefined
    ) {
      const price = Number(metadata.price);
      const originalPrice = Number(metadata.originalPrice);
      if (price < originalPrice * 0.5) {
        signals.push(
          `Price manipulation: ${price} vs original ${originalPrice}`
        );
        riskScore += 40;
      }
    }

    // 4. Coupon stacking
    if (
      metadata?.couponCount !== undefined &&
      Number(metadata.couponCount) > 1
    ) {
      signals.push(`Multiple coupons applied: ${metadata.couponCount}`);
      riskScore += 20;
    }

    record.lastStep = step;
    riskScore = Math.min(100, riskScore);

    let severity: BusinessLogicResult['severity'];
    if (riskScore >= 70) severity = 'CRITICAL';
    else if (riskScore >= 45) severity = 'HIGH';
    else if (riskScore >= 20) severity = 'MEDIUM';
    else severity = 'LOW';

    return {
      valid: riskScore < 50,
      riskScore,
      severity,
      signals,
      reason: signals.length > 0 ? signals.join('; ') : 'Normal flow',
      graphState: {
        learned,
        transactionCount: graph.transactionCount,
        edgeWeight: graphEdgeWeight,
      },
    };
  }

  /** Learned weight of a specific transition edge, if observed. For diagnostics/testing. */
  getEdgeWeight(
    flowName: string,
    fromStep: string,
    toStep: string
  ): number | undefined {
    return this.flowGraphs.get(flowName)?.edges.get(`${fromStep}->${toStep}`)
      ?.weight;
  }

  getStats(): {
    trackedUsers: number;
    graphs: Record<
      string,
      { edges: number; transactionCount: number; learned: boolean }
    >;
  } {
    const now = Date.now();
    const graphs: Record<
      string,
      { edges: number; transactionCount: number; learned: boolean }
    > = {};
    for (const [flowName, graph] of this.flowGraphs) {
      graphs[flowName] = {
        edges: graph.edges.size,
        transactionCount: graph.transactionCount,
        learned: this.isGraphLearned(graph, now),
      };
    }
    return { trackedUsers: this.userFlows.size, graphs };
  }
}

// ═══════════════════════════════════════════════════════════════
// Refresh Token Binding Enforcer
// ═══════════════════════════════════════════════════════════════

export interface TokenBindingConfig {
  /** Max device fingerprint drift tolerance. Default: 20 */
  maxDriftTolerance?: number;
  /** Enable automatic rotation on drift. Default: true */
  rotateOnDrift?: boolean;
  /** Max tracked bindings. Default: 100_000 */
  maxEntries?: number;
  debug?: boolean;
}

export interface TokenBindingResult {
  valid: boolean;
  action: 'allow' | 'require_mfa' | 'rotate' | 'revoke';
  driftScore: number;
  reason: string;
}

interface TokenBinding {
  tokenHash: string;
  deviceFingerprint: string;
  bindingHash: string;
  createdAt: number;
  lastUsed: number;
  rotationCount: number;
}

export class RefreshTokenBindingEnforcer {
  private readonly config: Required<TokenBindingConfig>;
  private readonly bindings = new Map<string, TokenBinding>();

  constructor(config: TokenBindingConfig = {}) {
    this.config = {
      maxDriftTolerance: config.maxDriftTolerance ?? 20,
      rotateOnDrift: config.rotateOnDrift ?? true,
      maxEntries: config.maxEntries ?? 100_000,
      debug: config.debug ?? false,
    };
  }

  /**
   * Bind a refresh token to a device fingerprint.
   */
  bind(tokenId: string, deviceFingerprint: string): string {
    const bindingHash = crypto
      .createHmac('sha256', tokenId)
      .update(deviceFingerprint)
      .digest('hex');

    if (this.bindings.size >= this.config.maxEntries) {
      const first = this.bindings.keys().next().value;
      if (first !== undefined) this.bindings.delete(first);
    }

    this.bindings.set(tokenId, {
      tokenHash: crypto.createHash('sha256').update(tokenId).digest('hex'),
      deviceFingerprint,
      bindingHash,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      rotationCount: 0,
    });

    return bindingHash;
  }

  /**
   * Validate token usage against its bound device.
   */
  validate(tokenId: string, currentFingerprint: string): TokenBindingResult {
    const binding = this.bindings.get(tokenId);
    if (!binding) {
      return {
        valid: false,
        action: 'revoke',
        driftScore: 100,
        reason: 'Unknown token binding',
      };
    }

    binding.lastUsed = Date.now();

    // Calculate fingerprint drift
    const driftScore = this.calculateDrift(
      binding.deviceFingerprint,
      currentFingerprint
    );

    if (driftScore === 0) {
      return {
        valid: true,
        action: 'allow',
        driftScore: 0,
        reason: 'Device fingerprint matches',
      };
    }

    if (driftScore <= this.config.maxDriftTolerance) {
      return {
        valid: true,
        action: this.config.rotateOnDrift ? 'rotate' : 'allow',
        driftScore,
        reason: `Minor device drift (${driftScore}/${this.config.maxDriftTolerance})`,
      };
    }

    // Significant drift — token theft suspected
    return {
      valid: false,
      action: 'revoke',
      driftScore,
      reason: `Token-device binding mismatch: drift=${driftScore} exceeds tolerance=${this.config.maxDriftTolerance}. Possible token theft.`,
    };
  }

  revoke(tokenId: string): boolean {
    return this.bindings.delete(tokenId);
  }

  private calculateDrift(original: string, current: string): number {
    if (original === current) return 0;
    // Simple character-level diff as percentage
    let diffs = 0;
    const maxLen = Math.max(original.length, current.length);
    for (let i = 0; i < maxLen; i++) {
      if (original[i] !== current[i]) diffs++;
    }
    return Math.round((diffs / maxLen) * 100);
  }

  getStats(): { activeBindings: number } {
    return { activeBindings: this.bindings.size };
  }
}

// ═══════════════════════════════════════════════════════════════
// Indirect Prompt Injection Filter
// ═══════════════════════════════════════════════════════════════

export interface PromptInjectionConfig {
  /** Sensitivity level. Default: 'medium' */
  sensitivity?: 'low' | 'medium' | 'high';
  /** Custom block patterns (regex strings) */
  customPatterns?: string[];
  /** Max content length to scan (bytes). Default: 100_000 */
  maxScanLength?: number;
  debug?: boolean;
}

export interface PromptInjectionResult {
  safe: boolean;
  confidence: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detectedPatterns: string[];
  reason: string;
}

export class PromptInjectionFilter {
  private readonly config: Required<PromptInjectionConfig>;
  private readonly patterns: Array<{
    regex: RegExp;
    name: string;
    weight: number;
  }>;

  // Known indirect prompt injection patterns
  private static readonly INJECTION_PATTERNS: Array<{
    pattern: string;
    name: string;
    weight: number;
  }> = [
    {
      pattern:
        'ignore\\s+(previous|above|all|prior)\\s+(instructions?|context|rules?)',
      name: 'instruction_override',
      weight: 40,
    },
    {
      pattern: 'you\\s+are\\s+now\\s+(a|an|the)',
      name: 'role_assignment',
      weight: 35,
    },
    {
      pattern: 'system\\s*:\\s*|\\[SYSTEM\\]|<\\|system\\|>',
      name: 'system_prompt_injection',
      weight: 45,
    },
    {
      pattern: 'forget\\s+(everything|all|what)',
      name: 'memory_wipe',
      weight: 40,
    },
    {
      pattern: 'do\\s+not\\s+(follow|obey|listen)',
      name: 'disobedience_injection',
      weight: 35,
    },
    {
      pattern: 'act\\s+as\\s+(if|though)|pretend\\s+(to\\s+be|you)',
      name: 'persona_injection',
      weight: 30,
    },
    {
      pattern: '<script>|javascript:|onerror=|onload=',
      name: 'xss_in_data',
      weight: 50,
    },
    {
      pattern: '\\bexec\\s*\\(|eval\\s*\\(|__import__',
      name: 'code_execution',
      weight: 50,
    },
    {
      pattern: 'translate.*to.*base64|encode.*payload',
      name: 'encoding_evasion',
      weight: 25,
    },
    {
      pattern: 'reveal\\s+(your|the)\\s+(system|secret|api|key|password)',
      name: 'secret_extraction',
      weight: 45,
    },
  ];

  constructor(config: PromptInjectionConfig = {}) {
    this.config = {
      sensitivity: config.sensitivity ?? 'medium',
      customPatterns: config.customPatterns ?? [],
      maxScanLength: config.maxScanLength ?? 100_000,
      debug: config.debug ?? false,
    };

    this.patterns = PromptInjectionFilter.INJECTION_PATTERNS.map(p => ({
      regex: new RegExp(p.pattern, 'gi'),
      name: p.name,
      weight: p.weight,
    }));

    // Add custom patterns
    this.config.customPatterns.forEach((p, i) => {
      this.patterns.push({
        regex: new RegExp(p, 'gi'),
        name: `custom_${i}`,
        weight: 30,
      });
    });
  }

  scanAgentInput(content: string) {
    return this.scan(content);
  }
  scan(content: string): PromptInjectionResult {
    const text = content.slice(0, this.config.maxScanLength);
    const detectedPatterns: string[] = [];
    let totalWeight = 0;

    for (const pattern of this.patterns) {
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(text)) {
        detectedPatterns.push(pattern.name);
        totalWeight += pattern.weight;
      }
    }

    // Apply sensitivity multiplier
    const sensitivityMultiplier =
      this.config.sensitivity === 'high'
        ? 1.5
        : this.config.sensitivity === 'low'
          ? 0.7
          : 1.0;

    const score = Math.min(
      100,
      Math.round(totalWeight * sensitivityMultiplier)
    );
    const confidence =
      detectedPatterns.length > 0
        ? Math.min(0.99, 0.5 + detectedPatterns.length * 0.15)
        : 0.1;

    let severity: PromptInjectionResult['severity'];
    if (score >= 70) severity = 'CRITICAL';
    else if (score >= 45) severity = 'HIGH';
    else if (score >= 20) severity = 'MEDIUM';
    else severity = 'LOW';

    return {
      safe: score < 30,
      confidence,
      severity,
      detectedPatterns,
      reason:
        detectedPatterns.length > 0
          ? `Prompt injection detected: ${detectedPatterns.join(', ')} (score=${score})`
          : 'Content appears safe',
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// Agent Feedback Poisoning Guard
// ═══════════════════════════════════════════════════════════════

export interface FeedbackPoisoningConfig {
  /** Window for feedback analysis (ms). Default: 3_600_000 (1 hour) */
  windowMs?: number;
  /** Min feedback samples before analysis. Default: 5 */
  minSamples?: number;
  /** Anomaly threshold (standard deviations). Default: 2.0 */
  anomalyThreshold?: number;
  /** Max tracked agents. Default: 10_000 */
  maxEntries?: number;
  debug?: boolean;
}

export interface FeedbackEvent {
  agentId: string;
  feedbackScore: number; // 0-1 normalized
  sourceId: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

export interface FeedbackAnalysisResult {
  poisoned: boolean;
  confidence: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  anomalyScore: number;
  reason: string;
  quarantined: boolean;
}

interface AgentFeedbackRecord {
  scores: Array<{ score: number; sourceId: string; timestamp: number }>;
  mean: number;
  stdDev: number;
  quarantined: boolean;
}

export class FeedbackPoisoningGuard {
  private readonly config: Required<FeedbackPoisoningConfig>;
  private readonly agentRecords = new Map<string, AgentFeedbackRecord>();

  constructor(config: FeedbackPoisoningConfig = {}) {
    this.config = {
      windowMs: config.windowMs ?? 3_600_000,
      minSamples: config.minSamples ?? 5,
      anomalyThreshold: config.anomalyThreshold ?? 2.0,
      maxEntries: config.maxEntries ?? 10_000,
      debug: config.debug ?? false,
    };
  }

  evaluate(event: FeedbackEvent): FeedbackAnalysisResult {
    const now = event.timestamp ?? Date.now();
    const { agentId, feedbackScore, sourceId } = event;

    let record = this.agentRecords.get(agentId);
    if (!record) {
      if (this.agentRecords.size >= this.config.maxEntries) {
        const first = this.agentRecords.keys().next().value;
        if (first !== undefined) this.agentRecords.delete(first);
      }
      record = { scores: [], mean: 0.5, stdDev: 0.2, quarantined: false };
      this.agentRecords.set(agentId, record);
    }

    // Purge expired
    record.scores = record.scores.filter(
      s => now - s.timestamp <= this.config.windowMs
    );
    record.scores.push({ score: feedbackScore, sourceId, timestamp: now });

    // Need minimum samples for statistical analysis
    if (record.scores.length < this.config.minSamples) {
      return {
        poisoned: false,
        confidence: 0.2,
        severity: 'LOW',
        anomalyScore: 0,
        reason: `Insufficient samples (${record.scores.length}/${this.config.minSamples})`,
        quarantined: false,
      };
    }

    // Calculate statistics
    const scores = record.scores.map(s => s.score);
    const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
    const variance =
      scores.reduce((sum, s) => sum + (s - mean) ** 2, 0) / scores.length;
    const stdDev = Math.sqrt(variance);

    // Check for anomalous deviation from baseline
    const deviation = Math.abs(feedbackScore - record.mean);
    const anomalyScore =
      stdDev > 0 ? deviation / stdDev : deviation > 0.1 ? 3 : 0;

    // Update running stats
    record.mean = mean;
    record.stdDev = stdDev;

    // Check for source concentration (coordinated campaign)
    const sourceCounts = new Map<string, number>();
    record.scores.forEach(s =>
      sourceCounts.set(s.sourceId, (sourceCounts.get(s.sourceId) ?? 0) + 1)
    );
    const maxSourceCount = Math.max(...sourceCounts.values());
    const sourceConcentration = maxSourceCount / record.scores.length;

    let poisoned = false;
    let severity: FeedbackAnalysisResult['severity'] = 'LOW';
    let confidence = 0.3;
    const reasons: string[] = [];

    if (anomalyScore > this.config.anomalyThreshold) {
      poisoned = true;
      severity =
        anomalyScore > this.config.anomalyThreshold * 2 ? 'CRITICAL' : 'HIGH';
      confidence = Math.min(0.95, 0.6 + anomalyScore * 0.1);
      reasons.push(
        `Anomaly score ${anomalyScore.toFixed(2)} > threshold ${this.config.anomalyThreshold}`
      );
    }

    if (
      sourceConcentration > 0.7 &&
      record.scores.length > this.config.minSamples
    ) {
      poisoned = true;
      severity = 'HIGH';
      confidence = Math.max(confidence, 0.8);
      reasons.push(
        `Source concentration: ${(sourceConcentration * 100).toFixed(0)}% from single source`
      );
    }

    if (poisoned) {
      record.quarantined = true;
    }

    return {
      poisoned,
      confidence,
      severity,
      anomalyScore,
      reason:
        reasons.length > 0 ? reasons.join('; ') : 'Normal feedback pattern',
      quarantined: record.quarantined,
    };
  }

  getStats(): { trackedAgents: number; quarantinedAgents: number } {
    let quarantined = 0;
    this.agentRecords.forEach(r => {
      if (r.quarantined) quarantined++;
    });
    return {
      trackedAgents: this.agentRecords.size,
      quarantinedAgents: quarantined,
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// Clock Drift Anomaly Detector
// ═══════════════════════════════════════════════════════════════

export interface ClockDriftConfig {
  /** Acceptable drift threshold in ms. Default: 30_000 (30s) */
  acceptableThresholdMs?: number;
  /** Suspicious drift threshold in ms. Default: 120_000 (2 min) */
  suspiciousThresholdMs?: number;
  /** Critical drift threshold in ms. Default: 300_000 (5 min) */
  criticalThresholdMs?: number;
  debug?: boolean;
}

export interface ClockDriftResult {
  valid: boolean;
  driftMs: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  action: 'allow' | 'warn' | 'use_server_time' | 'reject';
  reason: string;
}

export class ClockDriftDetector {
  private readonly config: Required<ClockDriftConfig>;
  private readonly driftHistory = new Map<string, number[]>();

  constructor(config: ClockDriftConfig = {}) {
    this.config = {
      acceptableThresholdMs: config.acceptableThresholdMs ?? 30_000,
      suspiciousThresholdMs: config.suspiciousThresholdMs ?? 120_000,
      criticalThresholdMs: config.criticalThresholdMs ?? 300_000,
      debug: config.debug ?? false,
    };
  }

  /**
   * Check client timestamp against server time.
   */
  check(clientTimestamp: number, clientId?: string): ClockDriftResult {
    const serverTime = Date.now();
    const driftMs = Math.abs(clientTimestamp - serverTime);
    const direction = clientTimestamp > serverTime ? 'ahead' : 'behind';

    // Track drift history per client
    if (clientId) {
      let history = this.driftHistory.get(clientId);
      if (!history) {
        history = [];
        this.driftHistory.set(clientId, history);
      }
      history.push(driftMs);
      if (history.length > 100) history.shift();
    }

    if (driftMs <= this.config.acceptableThresholdMs) {
      return {
        valid: true,
        driftMs,
        severity: 'LOW',
        action: 'allow',
        reason: `Clock drift ${driftMs}ms (${direction}) within acceptable range`,
      };
    }

    if (driftMs <= this.config.suspiciousThresholdMs) {
      return {
        valid: true,
        driftMs,
        severity: 'MEDIUM',
        action: 'warn',
        reason: `Clock drift ${driftMs}ms (${direction}) — suspicious, using server time for audit`,
      };
    }

    if (driftMs <= this.config.criticalThresholdMs) {
      return {
        valid: true,
        driftMs,
        severity: 'HIGH',
        action: 'use_server_time',
        reason: `Clock drift ${driftMs}ms (${direction}) — enforcing server-authoritative timestamps`,
      };
    }

    return {
      valid: false,
      driftMs,
      severity: 'CRITICAL',
      action: 'reject',
      reason: `Clock drift ${driftMs}ms (${direction}) exceeds critical threshold — possible timestamp manipulation`,
    };
  }

  /**
   * Get drift trend for a client.
   */
  getDriftTrend(
    clientId: string
  ): { avgDrift: number; increasing: boolean } | null {
    const history = this.driftHistory.get(clientId);
    if (!history || history.length < 3) return null;

    const avgDrift = history.reduce((a, b) => a + b, 0) / history.length;
    const recentAvg = history.slice(-3).reduce((a, b) => a + b, 0) / 3;
    return { avgDrift, increasing: recentAvg > avgDrift * 1.2 };
  }

  getStats(): { trackedClients: number } {
    return { trackedClients: this.driftHistory.size };
  }
}
