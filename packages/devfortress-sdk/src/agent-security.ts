/**
 * Agent Credential Aliasing & Security (IP-C2, IP-C3, IP-C4, IP-C5)
 *
 * Extends the core credential isolation system for AI agent credentials:
 *
 * IP-C2: Agent Credential Aliasing
 *   - createAlias() for credentialType: "agent_api_key" | "agent_oauth_token" | "service_account"
 *   - revokeAgentAccess(agentId, reason) — revoke all credentials for an agent
 *   - quarantineAgent(agentId, reason) — suspend tool access, preserve session for forensics
 *
 * IP-C3: Agent Behavioral Baseline
 *   - agentBaseline(agentId, taskDefinition) — records normal tool patterns for N sessions
 *   - Metrics: avg tools/session, tool diversity entropy, data volumes, session duration
 *   - 30-day rolling update window
 *
 * IP-C4: Agent Anomaly Detection Signals
 *   - API call sequence entropy anomaly
 *   - Tool invocation scope deviation
 *   - Data volume anomaly (3σ deviation)
 *   - Cross-agent credential sharing detection
 *
 * IP-C5: Agent Access Scope Enforcement
 *   - defineAgentScope(agentId, allowedTools[]) — register sanctioned tools
 *   - Unsanctioned tool invocation fires critical event immediately
 *   - Direct defence against prompt injection causing unauthorised tool calls
 *
 * @packageDocumentation
 */

import type { CacheAdapter } from './credential-isolation';
import { CredentialIsolationManager } from './credential-isolation';
import type {
  CredentialIsolationManagerConfig,
  RevocationReason,
} from './credential-isolation';
import { validateAgentId } from './agent';

// ── Agent Credential Types (IP-C2) ─────────────────────────

export type AgentCredentialType =
  | 'agent_api_key'
  | 'agent_oauth_token'
  | 'service_account';

/**
 * CTXFP-P1-03 — execution-context baseline captured at agent alias issuance.
 * Context-capture only in this pass: recorded in-memory (and via the
 * existing CacheAdapter, same as the rest of AgentCredentialAliasData) but
 * not persisted to Postgres and not compared against anything yet. Wiring
 * this into external verification needs the CredentialAlias (Postgres) vs.
 * in-memory/Redis agent-alias-store architecture question resolved first —
 * see the session report.
 */
export interface AgentExecutionContext {
  /** Container or session identifier the alias was issued into. */
  containerId?: string;
  /** Expected outbound network path/host the agent should egress through. */
  expectedEgressPath?: string;
  /** Expected process or agent signature (binary hash, runtime identifier, etc). */
  expectedProcessSignature?: string;
}

export interface AgentCredentialAliasData {
  alias: string;
  agentId: string;
  credentialType: AgentCredentialType;
  createdAt: number;
  /** Whether the agent is quarantined (IP-C2) */
  quarantined: boolean;
  quarantineReason?: string;
  quarantinedAt?: number;
  /** CTXFP-P1-03 execution-context baseline, if provided at issuance. */
  executionContext?: AgentExecutionContext;
}

// ── Agent Behavioral Baseline Types (IP-C3) ─────────────────

export interface AgentBaselineMetrics {
  /** Average number of tool calls per session */
  avgToolsPerSession: number;
  /** Shannon entropy of tool diversity */
  toolDiversityEntropy: number;
  /** Average data volume per session (bytes) */
  avgDataVolumeBytes: number;
  /** Average session duration (milliseconds) */
  avgSessionDurationMs: number;
  /** Most frequently called tools (ordered) */
  topTools: string[];
  /** Total sessions recorded in baseline */
  totalSessions: number;
  /** Baseline creation timestamp */
  createdAt: number;
  /** Last update timestamp */
  lastUpdatedAt: number;
  /** Task definition used to establish baseline */
  taskDefinition?: string;
}

export interface AgentSessionRecord {
  sessionId: string;
  agentId: string;
  toolCalls: { tool: string; durationMs?: number; dataBytes?: number }[];
  startedAt: number;
  endedAt?: number;
  totalDataBytes: number;
}

// ── Agent Anomaly Signal Types (IP-C4) ──────────────────────

export type AgentAnomalyType =
  | 'sequence_entropy_anomaly'
  | 'scope_deviation'
  | 'data_volume_anomaly'
  | 'cross_agent_credential_sharing'
  | 'unsanctioned_tool';

export interface AgentAnomalySignal {
  type: AgentAnomalyType;
  agentId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  detectedAt: number;
  details: Record<string, unknown>;
}

// ── Agent Scope Types (IP-C5) ───────────────────────────────

export interface AgentScopeDefinition {
  agentId: string;
  allowedTools: string[];
  /** If true, any tool not in allowedTools triggers a critical event */
  strictMode: boolean;
  createdAt: number;
  updatedAt: number;
}

// ── In-Memory Stores (replaceable by Redis in production) ───

const agentCredentials = new Map<string, AgentCredentialAliasData[]>();
const agentBaselines = new Map<string, AgentBaselineMetrics>();
const agentSessions = new Map<string, AgentSessionRecord[]>();
const agentScopes = new Map<string, AgentScopeDefinition>();
const agentQuarantines = new Map<string, { reason: string; at: number }>();

/**
 * Reset all in-memory stores. Used for testing only.
 * @internal
 */
export function _resetAgentSecurityStores(): void {
  agentCredentials.clear();
  agentBaselines.clear();
  agentSessions.clear();
  agentScopes.clear();
  agentQuarantines.clear();
}

// ── Shannon Entropy Calculator ──────────────────────────────

function shannonEntropy(items: string[]): number {
  if (items.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const item of items) {
    freq.set(item, (freq.get(item) || 0) + 1);
  }
  let entropy = 0;
  const total = items.length;
  for (const count of freq.values()) {
    const p = count / total;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ── Agent Credential Manager (IP-C2) ────────────────────────

export class AgentCredentialManager {
  private tokenManager: CredentialIsolationManager;
  private cache: CacheAdapter | null;

  constructor(tokenManager: CredentialIsolationManager, cache?: CacheAdapter) {
    this.tokenManager = tokenManager;
    this.cache = cache || null;
  }

  /**
   * Create an alias for an agent credential (API key, OAuth token, etc.).
   * The real credential never leaves the client application.
   */
  async createAgentAlias(
    realCredential: string,
    agentId: string,
    credentialType: AgentCredentialType,
    ttlSeconds: number = 7200,
    executionContext?: AgentExecutionContext
  ): Promise<string> {
    validateAgentId(agentId);
    // Use the underlying credential isolation manager for the crypto
    const alias = await this.tokenManager.createAlias(
      realCredential,
      agentId,
      ttlSeconds
    );

    // Track agent-level credential metadata
    const data: AgentCredentialAliasData = {
      alias,
      agentId,
      credentialType,
      createdAt: Date.now(),
      quarantined: false,
      executionContext,
    };

    if (!agentCredentials.has(agentId)) {
      agentCredentials.set(agentId, []);
    }
    agentCredentials.get(agentId)!.push(data);

    // Persist to cache if available
    if (this.cache) {
      try {
        const existing = await this.cache.get(`agent:creds:${agentId}`);
        const list: AgentCredentialAliasData[] = existing
          ? JSON.parse(existing)
          : [];
        list.push(data);
        await this.cache.set(
          `agent:creds:${agentId}`,
          JSON.stringify(list),
          ttlSeconds
        );
      } catch {
        // In-memory is already set
      }
    }

    return alias;
  }

  /**
   * Revoke ALL credentials for an agent (IP-C2).
   * Used when an agent is compromised or decommissioned.
   */
  async revokeAgentAccess(
    agentId: string,
    reason: RevocationReason = 'active_threat'
  ): Promise<number> {
    const creds = agentCredentials.get(agentId) || [];
    let revokedCount = 0;

    for (const cred of creds) {
      try {
        await this.tokenManager.revokeByAlias(cred.alias, reason, agentId);
        revokedCount++;
      } catch {
        // Continue revoking remaining credentials
      }
    }

    agentCredentials.delete(agentId);
    agentQuarantines.delete(agentId);

    // Clean from cache
    if (this.cache) {
      try {
        await this.cache.del(`agent:creds:${agentId}`);
        await this.cache.del(`agent:quarantine:${agentId}`);
      } catch {
        // Best-effort
      }
    }

    return revokedCount;
  }

  /**
   * Quarantine an agent (IP-C2) — suspend tool access but preserve session for forensics.
   * Unlike revocation, quarantine is reversible and the session data remains intact.
   */
  async quarantineAgent(agentId: string, reason: string): Promise<void> {
    const quarantine = { reason, at: Date.now() };
    agentQuarantines.set(agentId, quarantine);

    // Mark all credentials as quarantined
    const creds = agentCredentials.get(agentId) || [];
    for (const cred of creds) {
      cred.quarantined = true;
      cred.quarantineReason = reason;
      cred.quarantinedAt = quarantine.at;
    }

    if (this.cache) {
      try {
        await this.cache.set(
          `agent:quarantine:${agentId}`,
          JSON.stringify(quarantine),
          86400 // 24h
        );
      } catch {
        // In-memory is set
      }
    }
  }

  /**
   * Lift quarantine for an agent, restoring normal tool access.
   * Rejects if the agent isn't currently quarantined — reinstatement is
   * only meaningful as the reverse of an active quarantine, not a silent no-op.
   */
  async unquarantineAgent(agentId: string): Promise<void> {
    if (!agentQuarantines.has(agentId)) {
      throw new Error(
        `Agent "${agentId}" is not currently quarantined — nothing to reinstate.`
      );
    }

    agentQuarantines.delete(agentId);
    const creds = agentCredentials.get(agentId) || [];
    for (const cred of creds) {
      cred.quarantined = false;
      cred.quarantineReason = undefined;
      cred.quarantinedAt = undefined;
    }

    if (this.cache) {
      try {
        await this.cache.del(`agent:quarantine:${agentId}`);
      } catch {
        // Best-effort
      }
    }
  }

  /**
   * Check if an agent is currently quarantined.
   */
  isQuarantined(agentId: string): boolean {
    return agentQuarantines.has(agentId);
  }

  /**
   * Get quarantine details for an agent.
   */
  getQuarantineDetails(agentId: string): { reason: string; at: number } | null {
    return agentQuarantines.get(agentId) || null;
  }

  /**
   * Get all credential aliases for an agent.
   */
  getAgentCredentials(agentId: string): AgentCredentialAliasData[] {
    return agentCredentials.get(agentId) || [];
  }
}

// ── Agent Behavioral Baseline (IP-C3) ───────────────────────

export class AgentBaselineEngine {
  private readonly BASELINE_WINDOW_DAYS = 30;
  private readonly MIN_SESSIONS_FOR_BASELINE = 5;

  /**
   * Record a completed agent session for baseline building.
   */
  recordSession(record: AgentSessionRecord): void {
    if (!agentSessions.has(record.agentId)) {
      agentSessions.set(record.agentId, []);
    }

    const sessions = agentSessions.get(record.agentId)!;

    // Enforce rolling window
    const windowStart =
      Date.now() - this.BASELINE_WINDOW_DAYS * 24 * 60 * 60 * 1000;
    const filtered = sessions.filter(s => s.startedAt > windowStart);
    filtered.push(record);
    agentSessions.set(record.agentId, filtered);

    // Recalculate baseline if enough sessions
    if (filtered.length >= this.MIN_SESSIONS_FOR_BASELINE) {
      this.recalculateBaseline(record.agentId);
    }
  }

  /**
   * Establish a baseline from a task definition (IP-C3).
   * Call this at the start to register what "normal" looks like.
   */
  agentBaseline(
    agentId: string,
    taskDefinition: string
  ): AgentBaselineMetrics | null {
    const existing = agentBaselines.get(agentId);
    if (existing) {
      // Update task definition on existing baseline
      existing.taskDefinition = taskDefinition;
      existing.lastUpdatedAt = Date.now();
      return existing;
    }

    // No sessions yet — return null until enough data collected
    const sessions = agentSessions.get(agentId) || [];
    if (sessions.length < this.MIN_SESSIONS_FOR_BASELINE) {
      return null;
    }

    return this.recalculateBaseline(agentId, taskDefinition);
  }

  /**
   * Get the current baseline for an agent.
   */
  getBaseline(agentId: string): AgentBaselineMetrics | null {
    return agentBaselines.get(agentId) || null;
  }

  /**
   * Recalculate baseline metrics from recorded sessions.
   */
  private recalculateBaseline(
    agentId: string,
    taskDefinition?: string
  ): AgentBaselineMetrics {
    const sessions = agentSessions.get(agentId) || [];

    const toolsPerSession = sessions.map(s => s.toolCalls.length);
    const avgToolsPerSession =
      toolsPerSession.reduce((a, b) => a + b, 0) / sessions.length;

    const allTools = sessions.flatMap(s => s.toolCalls.map(tc => tc.tool));
    const toolDiversityEntropy = shannonEntropy(allTools);

    const dataVolumes = sessions.map(s => s.totalDataBytes);
    const avgDataVolumeBytes =
      dataVolumes.reduce((a, b) => a + b, 0) / sessions.length;

    const durations = sessions
      .filter(s => s.endedAt)
      .map(s => s.endedAt! - s.startedAt);
    const avgSessionDurationMs =
      durations.length > 0
        ? durations.reduce((a, b) => a + b, 0) / durations.length
        : 0;

    // Top tools by frequency
    const toolFreq = new Map<string, number>();
    for (const tool of allTools) {
      toolFreq.set(tool, (toolFreq.get(tool) || 0) + 1);
    }
    const topTools = [...toolFreq.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([tool]) => tool);

    const baseline: AgentBaselineMetrics = {
      avgToolsPerSession,
      toolDiversityEntropy,
      avgDataVolumeBytes,
      avgSessionDurationMs,
      topTools,
      totalSessions: sessions.length,
      createdAt: agentBaselines.get(agentId)?.createdAt || Date.now(),
      lastUpdatedAt: Date.now(),
      taskDefinition:
        taskDefinition || agentBaselines.get(agentId)?.taskDefinition,
    };

    agentBaselines.set(agentId, baseline);
    return baseline;
  }

  /**
   * Get standard deviation of a number array.
   */
  private stdDev(values: number[]): number {
    if (values.length < 2) return 0;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const sqDiffs = values.map(v => Math.pow(v - mean, 2));
    return Math.sqrt(sqDiffs.reduce((a, b) => a + b, 0) / values.length);
  }

  /**
   * Check if a value is a 3σ deviation from a dataset.
   */
  is3SigmaDeviation(values: number[], newValue: number): boolean {
    if (values.length < 2) return false;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const sd = this.stdDev(values);
    if (sd === 0) return newValue !== mean;
    return Math.abs(newValue - mean) > 3 * sd;
  }
}

// ── Agent Anomaly Detector (IP-C4) ──────────────────────────

export class AgentAnomalyDetector {
  private baselineEngine: AgentBaselineEngine;
  private anomalyHandlers: ((signal: AgentAnomalySignal) => void)[] = [];
  /** Track which agents are using which credentials (for cross-agent detection) */
  private credentialUsage = new Map<string, Set<string>>();

  constructor(baselineEngine: AgentBaselineEngine) {
    this.baselineEngine = baselineEngine;
  }

  /**
   * Register an anomaly handler.
   */
  onAnomaly(handler: (signal: AgentAnomalySignal) => void): void {
    this.anomalyHandlers.push(handler);
  }

  /**
   * Analyze a tool call for anomalies against the agent's baseline.
   * Returns any anomaly signals detected.
   */
  analyzeToolCall(
    agentId: string,
    toolName: string,
    dataBytes: number = 0,
    credentialAlias?: string
  ): AgentAnomalySignal[] {
    const signals: AgentAnomalySignal[] = [];
    const baseline = this.baselineEngine.getBaseline(agentId);

    // IP-C5 scope check (integrated here for convenience)
    const scope = agentScopes.get(agentId);
    if (scope?.strictMode && !scope.allowedTools.includes(toolName)) {
      const signal: AgentAnomalySignal = {
        type: 'unsanctioned_tool',
        agentId,
        severity: 'critical',
        description: `Agent ${agentId} invoked unsanctioned tool "${toolName}". Allowed: [${scope.allowedTools.join(', ')}]`,
        detectedAt: Date.now(),
        details: { tool: toolName, allowedTools: scope.allowedTools },
      };
      signals.push(signal);
      this.emitSignal(signal);
    }

    if (!baseline) return signals;

    // IP-C4.1: Tool invocation scope deviation
    if (baseline.topTools.length > 0 && !baseline.topTools.includes(toolName)) {
      const signal: AgentAnomalySignal = {
        type: 'scope_deviation',
        agentId,
        severity: 'medium',
        description: `Agent ${agentId} invoked tool "${toolName}" outside its baseline tool set`,
        detectedAt: Date.now(),
        details: {
          tool: toolName,
          baselineTools: baseline.topTools,
        },
      };
      signals.push(signal);
      this.emitSignal(signal);
    }

    // IP-C4.3: Data volume anomaly (3σ deviation)
    if (dataBytes > 0) {
      const sessions = agentSessions.get(agentId) || [];
      const volumes = sessions.map(s => s.totalDataBytes);
      if (this.baselineEngine.is3SigmaDeviation(volumes, dataBytes)) {
        const signal: AgentAnomalySignal = {
          type: 'data_volume_anomaly',
          agentId,
          severity: 'high',
          description: `Agent ${agentId} data volume ${dataBytes}B is 3σ deviation from baseline avg ${Math.round(baseline.avgDataVolumeBytes)}B`,
          detectedAt: Date.now(),
          details: {
            dataBytes,
            baselineAvg: baseline.avgDataVolumeBytes,
          },
        };
        signals.push(signal);
        this.emitSignal(signal);
      }
    }

    // IP-C4.4: Cross-agent credential sharing detection
    if (credentialAlias) {
      if (!this.credentialUsage.has(credentialAlias)) {
        this.credentialUsage.set(credentialAlias, new Set());
      }
      const agents = this.credentialUsage.get(credentialAlias)!;
      agents.add(agentId);

      if (agents.size > 1) {
        const signal: AgentAnomalySignal = {
          type: 'cross_agent_credential_sharing',
          agentId,
          severity: 'critical',
          description: `Credential ${credentialAlias.substring(0, 16)}... shared across ${agents.size} agents: [${[...agents].join(', ')}]`,
          detectedAt: Date.now(),
          details: {
            credentialAlias: credentialAlias.substring(0, 16) + '...',
            sharingAgents: [...agents],
          },
        };
        signals.push(signal);
        this.emitSignal(signal);
      }
    }

    return signals;
  }

  /**
   * Analyze a completed session for sequence entropy anomaly (IP-C4.1).
   */
  analyzeSession(record: AgentSessionRecord): AgentAnomalySignal[] {
    const signals: AgentAnomalySignal[] = [];
    const baseline = this.baselineEngine.getBaseline(record.agentId);
    if (!baseline || baseline.totalSessions < 5) return signals;

    // IP-C4.1: API call sequence entropy anomaly
    const sessionTools = record.toolCalls.map(tc => tc.tool);
    const sessionEntropy = shannonEntropy(sessionTools);
    const entropyDeviation = Math.abs(
      sessionEntropy - baseline.toolDiversityEntropy
    );

    // If entropy deviates by more than 50% from baseline, flag it
    if (
      baseline.toolDiversityEntropy > 0 &&
      entropyDeviation / baseline.toolDiversityEntropy > 0.5
    ) {
      const signal: AgentAnomalySignal = {
        type: 'sequence_entropy_anomaly',
        agentId: record.agentId,
        severity: 'high',
        description: `Agent ${record.agentId} session entropy ${sessionEntropy.toFixed(2)} deviates ${((entropyDeviation / baseline.toolDiversityEntropy) * 100).toFixed(0)}% from baseline ${baseline.toolDiversityEntropy.toFixed(2)}`,
        detectedAt: Date.now(),
        details: {
          sessionEntropy,
          baselineEntropy: baseline.toolDiversityEntropy,
          deviationPercent:
            (entropyDeviation / baseline.toolDiversityEntropy) * 100,
        },
      };
      signals.push(signal);
      this.emitSignal(signal);
    }

    return signals;
  }

  private emitSignal(signal: AgentAnomalySignal): void {
    for (const handler of this.anomalyHandlers) {
      try {
        handler(signal);
      } catch {
        // Handler errors don't block detection
      }
    }
  }
}

// ── Agent Scope Enforcer (IP-C5) ────────────────────────────

export class AgentScopeEnforcer {
  /**
   * Define the allowed tool scope for an agent (IP-C5).
   * Any tool invocation outside this scope fires a critical event.
   */
  defineAgentScope(
    agentId: string,
    allowedTools: string[],
    strictMode: boolean = true
  ): AgentScopeDefinition {
    const scope: AgentScopeDefinition = {
      agentId,
      allowedTools,
      strictMode,
      createdAt: agentScopes.get(agentId)?.createdAt || Date.now(),
      updatedAt: Date.now(),
    };
    agentScopes.set(agentId, scope);
    return scope;
  }

  /**
   * Check if a tool invocation is within the agent's defined scope.
   * Returns true if allowed, false if blocked.
   */
  isToolAllowed(agentId: string, toolName: string): boolean {
    const scope = agentScopes.get(agentId);
    if (!scope) return true; // No scope defined — allow by default
    if (!scope.strictMode) return true; // Non-strict mode — log but allow
    return scope.allowedTools.includes(toolName);
  }

  /**
   * Get the scope definition for an agent.
   */
  getScope(agentId: string): AgentScopeDefinition | null {
    return agentScopes.get(agentId) || null;
  }

  /**
   * Remove scope restrictions for an agent.
   */
  removeScope(agentId: string): void {
    agentScopes.delete(agentId);
  }

  /**
   * Add tools to an agent's allowed scope.
   */
  addAllowedTools(agentId: string, tools: string[]): void {
    const scope = agentScopes.get(agentId);
    if (!scope) {
      this.defineAgentScope(agentId, tools, true);
      return;
    }
    const toolSet = new Set([...scope.allowedTools, ...tools]);
    scope.allowedTools = [...toolSet];
    scope.updatedAt = Date.now();
  }

  /**
   * Remove tools from an agent's allowed scope.
   */
  removeAllowedTools(agentId: string, tools: string[]): void {
    const scope = agentScopes.get(agentId);
    if (!scope) return;
    const removeSet = new Set(tools);
    scope.allowedTools = scope.allowedTools.filter(t => !removeSet.has(t));
    scope.updatedAt = Date.now();
  }
}
