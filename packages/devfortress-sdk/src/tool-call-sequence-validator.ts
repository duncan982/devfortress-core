/**
 * DevFortress SDK — A7: Tool-Call Sequence Validator
 *
 * Validates AI agent tool calls against an authorized directed acyclic graph (DAG).
 * Detects out-of-sequence tool calls that indicate prompt injection attacks —
 * e.g., an agent jumping directly to `place_order` without first calling `add_to_cart`.
 *
 * Graduated response: log → rate-limit → block → revoke session.
 *
 * Patent Pending.
 * Author: Duncan Ndungu Ndegwa
 * @packageDocumentation
 */

// ── Types ───────────────────────────────────────────────────

export interface ToolCallGraphNode {
  /** Tools that must have been called before this one is allowed */
  requires: string[];
  /** Maximum times this tool can be called per session. 0 = unlimited */
  maxCalls?: number;
  /** Risk level of this tool (affects response severity) */
  riskLevel?: 'low' | 'medium' | 'high' | 'critical';
}

export interface ToolCallGraph {
  [toolName: string]: ToolCallGraphNode;
}

export interface ToolCallSequenceConfig {
  /** The authorized tool-call DAG */
  graph: ToolCallGraph;
  /** Max violations before session revocation. Default: 3 */
  maxViolations?: number;
  /** Window for violation tracking (ms). Default: 300_000 (5 min) */
  violationWindowMs?: number;
  /** Enable graduated response. Default: true */
  graduatedResponse?: boolean;
  /** Debug logging. Default: false */
  debug?: boolean;
}

export interface ToolCallValidationResult {
  allowed: boolean;
  reason: string;
  /** Recommended action */
  action: 'allow' | 'log' | 'rate_limit' | 'block' | 'revoke_session';
  /** Whether this pattern is likely prompt injection */
  promptInjectionLikely: boolean;
  /** Number of violations in current window */
  violationCount: number;
  /** Tool call history for this session */
  callHistory: string[];
  /** Missing prerequisite tools */
  missingPrerequisites?: string[];
}

// ── Internal session tracking ───────────────────────────────

interface SessionState {
  callHistory: string[];
  callCounts: Map<string, number>;
  violations: Array<{ timestamp: number; tool: string; reason: string }>;
  createdAt: number;
}

// ── Validator ───────────────────────────────────────────────

export class ToolCallSequenceValidator {
  private readonly config: Required<ToolCallSequenceConfig>;
  private readonly sessions = new Map<string, SessionState>();
  private readonly MAX_SESSIONS = 50_000;

  constructor(config: ToolCallSequenceConfig) {
    this.config = {
      graph: config.graph,
      maxViolations: config.maxViolations ?? 3,
      violationWindowMs: config.violationWindowMs ?? 300_000,
      graduatedResponse: config.graduatedResponse ?? true,
      debug: config.debug ?? false,
    };
  }

  /**
   * Validate a tool call against the authorized sequence graph.
   */

  validateToolCall(
    agentId: string,
    toolName: string,
    previousTools: string[] = []
  ) {
    return this.validate(agentId, toolName, { agentId });
  }
  validate(
    sessionId: string,
    toolName: string,
    context?: { agentId?: string; timestamp?: number }
  ): ToolCallValidationResult {
    const session = this.getOrCreateSession(sessionId);
    const now = context?.timestamp ?? Date.now();

    // Prune old violations
    session.violations = session.violations.filter(
      v => now - v.timestamp < this.config.violationWindowMs
    );

    const graphNode = this.config.graph[toolName];

    // Unknown tool — not in graph
    if (!graphNode) {
      const violation = {
        timestamp: now,
        tool: toolName,
        reason: 'unknown_tool',
      };
      session.violations.push(violation);

      return this.buildResult(session, false, 'unknown_tool', toolName, []);
    }

    // Check prerequisites
    const missingPrereqs = graphNode.requires.filter(
      req => !session.callHistory.includes(req)
    );

    if (missingPrereqs.length > 0) {
      const violation = {
        timestamp: now,
        tool: toolName,
        reason: `missing_prerequisites: ${missingPrereqs.join(', ')}`,
      };
      session.violations.push(violation);

      return this.buildResult(
        session,
        false,
        'out_of_sequence',
        toolName,
        missingPrereqs
      );
    }

    // Check max calls
    const currentCalls = session.callCounts.get(toolName) ?? 0;
    if (
      graphNode.maxCalls &&
      graphNode.maxCalls > 0 &&
      currentCalls >= graphNode.maxCalls
    ) {
      const violation = {
        timestamp: now,
        tool: toolName,
        reason: `max_calls_exceeded: ${currentCalls}/${graphNode.maxCalls}`,
      };
      session.violations.push(violation);

      return this.buildResult(
        session,
        false,
        'max_calls_exceeded',
        toolName,
        []
      );
    }

    // Valid — record the call
    session.callHistory.push(toolName);
    session.callCounts.set(toolName, currentCalls + 1);

    if (this.config.debug) {
      console.log(
        `[A7] Session ${sessionId}: ${toolName} ALLOWED (history: ${session.callHistory.join(' → ')})`
      );
    }

    return {
      allowed: true,
      reason: 'valid_sequence',
      action: 'allow',
      promptInjectionLikely: false,
      violationCount: session.violations.length,
      callHistory: [...session.callHistory],
    };
  }

  /**
   * Reset a session's state (e.g., after quarantine release).
   */
  resetSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Get call history for a session (validation-script compatible alias).
   */
  getHistory(sessionId: string): string[] {
    const session = this.sessions.get(sessionId);
    return session ? [...session.callHistory] : [];
  }

  /**
   * Clear a session's state (validation-script compatible alias for resetSession).
   */
  clearSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Get session stats for monitoring.
   */
  getSessionStats(sessionId: string): {
    exists: boolean;
    callCount: number;
    violationCount: number;
    history: string[];
  } {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { exists: false, callCount: 0, violationCount: 0, history: [] };
    }
    return {
      exists: true,
      callCount: session.callHistory.length,
      violationCount: session.violations.length,
      history: [...session.callHistory],
    };
  }

  /**
   * Destroy all sessions and free memory.
   */
  destroy(): void {
    this.sessions.clear();
  }

  // ── Private helpers ───────────────────────────────────────

  private getOrCreateSession(sessionId: string): SessionState {
    let session = this.sessions.get(sessionId);
    if (!session) {
      // LRU eviction
      if (this.sessions.size >= this.MAX_SESSIONS) {
        const firstKey = this.sessions.keys().next().value;
        if (firstKey !== undefined) this.sessions.delete(firstKey);
      }
      session = {
        callHistory: [],
        callCounts: new Map(),
        violations: [],
        createdAt: Date.now(),
      };
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  private buildResult(
    session: SessionState,
    allowed: boolean,
    reason: string,
    toolName: string,
    missingPrerequisites: string[]
  ): ToolCallValidationResult {
    const violationCount = session.violations.length;

    // Graduated response based on violation count
    let action: ToolCallValidationResult['action'] = 'log';
    if (this.config.graduatedResponse) {
      if (violationCount >= this.config.maxViolations) {
        action = 'revoke_session';
      } else if (violationCount >= 2) {
        action = 'block';
      } else if (violationCount >= 1) {
        action = 'rate_limit';
      }
    } else {
      action = 'block';
    }

    // High-risk tools with out-of-sequence = likely prompt injection
    const graphNode = this.config.graph[toolName];
    const promptInjectionLikely =
      reason === 'out_of_sequence' &&
      (graphNode?.riskLevel === 'high' || graphNode?.riskLevel === 'critical');

    if (this.config.debug) {
      console.log(
        `[A7] Session violation: ${toolName} — ${reason} (violations: ${violationCount}, action: ${action})`
      );
    }

    return {
      allowed,
      reason,
      action,
      promptInjectionLikely,
      violationCount,
      callHistory: [...session.callHistory],
      missingPrerequisites:
        missingPrerequisites.length > 0 ? missingPrerequisites : undefined,
    };
  }
}
