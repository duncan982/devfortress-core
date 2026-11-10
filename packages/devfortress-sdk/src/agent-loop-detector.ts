/**
 * DevFortress SDK — A10: Agent Loop Detector
 *
 * Instruments SDK to track agent execution cycles and token consumption.
 * Detects infinite loops via cycle count, time budget, and token budget thresholds.
 * Implements automatic circuit breaker: pause agent, alert owner.
 * Distinguishes legitimate long operations from runaway loops via progress metrics.
 *
 * Patent Pending.
 * Author: Duncan Ndungu Ndegwa
 * @packageDocumentation
 */

// ── Types ───────────────────────────────────────────────────

export interface AgentLoopConfig {
  /** Maximum cycles before circuit break. Default: 20 */
  maxCycles?: number;
  /** Maximum execution time (ms). Default: 120_000 (2 min) */
  maxDurationMs?: number;
  /** Maximum tokens consumed per session. Default: 100_000 */
  maxTokens?: number;
  /** Minimum unique tool names per N cycles to count as progress. Default: 2 tools per 5 cycles */
  progressThreshold?: { uniqueTools: number; windowCycles: number };
  /** Max tracked sessions. Default: 50_000 */
  maxSessions?: number;
  /** Debug logging. Default: false */
  debug?: boolean;
}

export interface LoopCycleContext {
  /** Tokens consumed in this cycle */
  tokensUsed?: number;
  /** Tool called in this cycle */
  toolName?: string;
  /** Arguments passed (for repetition detection) */
  toolArgs?: Record<string, unknown>;
  /** Custom progress indicator (e.g., items processed) */
  progressMetric?: number;
}

export interface LoopDetectionResult {
  /** Whether a loop was detected */
  loop: boolean;
  /** Reason for detection */
  reason: string;
  /** Recommended action */
  action: 'CONTINUE' | 'WARN' | 'PAUSE_AGENT' | 'TERMINATE';
  /** Total cycles executed */
  cycles: number;
  /** Total tokens consumed */
  totalTokens: number;
  /** Elapsed time (ms) */
  elapsedMs: number;
  /** Whether the agent is making progress */
  makingProgress: boolean;
  /** Repetition score (0-1, 1 = fully repetitive) */
  repetitionScore: number;
}

// ── Internal session state ──────────────────────────────────

interface LoopSession {
  agentId: string;
  startedAt: number;
  cycles: number;
  totalTokens: number;
  toolHistory: string[];
  argHashes: string[];
  progressMetrics: number[];
  paused: boolean;
}

// ── Detector ────────────────────────────────────────────────

export class AgentLoopDetector {
  private readonly config: Required<AgentLoopConfig>;
  private readonly sessions = new Map<string, LoopSession>();

  constructor(config: AgentLoopConfig = {}) {
    this.config = {
      maxCycles: config.maxCycles ?? 20,
      maxDurationMs: config.maxDurationMs ?? 120_000,
      maxTokens: config.maxTokens ?? 100_000,
      progressThreshold: config.progressThreshold ?? {
        uniqueTools: 2,
        windowCycles: 5,
      },
      maxSessions: config.maxSessions ?? 50_000,
      debug: config.debug ?? false,
    };
  }

  /**
   * Record a new execution cycle for an agent session.
   * Returns detection result — check `result.loop` and `result.action`.
   */

  detectLoop(agentId: string, toolCallHistory: string[] = []) {
    const toolName =
      toolCallHistory.length > 0
        ? toolCallHistory[toolCallHistory.length - 1]
        : undefined;
    return this.recordCycle(agentId, 'agent_session', { toolName });
  }
  recordCycle(
    agentId: string,
    sessionId: string,
    context: LoopCycleContext = {}
  ): LoopDetectionResult {
    const session = this.getOrCreateSession(agentId, sessionId);
    const now = Date.now();

    // If already paused, reject immediately
    if (session.paused) {
      return this.buildResult(session, now, true, 'agent_paused', 'TERMINATE');
    }

    // Record cycle data
    session.cycles++;
    session.totalTokens += context.tokensUsed ?? 0;

    if (context.toolName) {
      session.toolHistory.push(context.toolName);
    }

    if (context.toolArgs) {
      session.argHashes.push(this.hashArgs(context.toolArgs));
    }

    if (context.progressMetric !== undefined) {
      session.progressMetrics.push(context.progressMetric);
    }

    const elapsedMs = now - session.startedAt;
    const makingProgress = this.checkProgress(session);
    const repetitionScore = this.computeRepetitionScore(session);

    // Check thresholds
    if (session.cycles >= this.config.maxCycles && !makingProgress) {
      session.paused = true;
      return this.buildResult(session, now, true, 'max_cycles', 'PAUSE_AGENT');
    }

    if (elapsedMs >= this.config.maxDurationMs) {
      session.paused = true;
      return this.buildResult(
        session,
        now,
        true,
        'max_duration',
        'PAUSE_AGENT'
      );
    }

    if (session.totalTokens >= this.config.maxTokens) {
      session.paused = true;
      return this.buildResult(session, now, true, 'max_tokens', 'PAUSE_AGENT');
    }

    // High repetition with significant cycles = likely loop
    if (repetitionScore > 0.8 && session.cycles > 5 && !makingProgress) {
      session.paused = true;
      return this.buildResult(
        session,
        now,
        true,
        'repetitive_pattern',
        'PAUSE_AGENT'
      );
    }

    // Warn thresholds (80% of max)
    if (
      session.cycles >= this.config.maxCycles * 0.8 ||
      elapsedMs >= this.config.maxDurationMs * 0.8 ||
      session.totalTokens >= this.config.maxTokens * 0.8
    ) {
      return this.buildResult(session, now, false, 'approaching_limit', 'WARN');
    }

    return this.buildResult(session, now, false, 'within_limits', 'CONTINUE');
  }

  /**
   * Release an agent from paused state (after human review).
   */
  /**
   * Clear a session (validation-script compatible).
   * Accepts (agentId, sessionId) or just (sessionId) as key.
   */
  clearSession(agentIdOrSessionId: string, sessionId?: string): void {
    const key = sessionId
      ? `${agentIdOrSessionId}:${sessionId}`
      : agentIdOrSessionId;
    this.sessions.delete(key);
  }

  releaseAgent(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    session.paused = false;
    session.cycles = 0;
    session.totalTokens = 0;
    session.toolHistory = [];
    session.argHashes = [];
    return true;
  }

  /**
   * Check if an agent is currently paused.
   */
  isPaused(sessionId: string): boolean {
    return this.sessions.get(sessionId)?.paused ?? false;
  }

  /**
   * Get session metrics for monitoring.
   */
  getMetrics(sessionId: string): {
    exists: boolean;
    cycles: number;
    tokens: number;
    elapsedMs: number;
    paused: boolean;
  } {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return {
        exists: false,
        cycles: 0,
        tokens: 0,
        elapsedMs: 0,
        paused: false,
      };
    }
    return {
      exists: true,
      cycles: session.cycles,
      tokens: session.totalTokens,
      elapsedMs: Date.now() - session.startedAt,
      paused: session.paused,
    };
  }

  /**
   * Destroy all sessions.
   */
  destroy(): void {
    this.sessions.clear();
  }

  // ── Private helpers ───────────────────────────────────────

  private getOrCreateSession(agentId: string, sessionId: string): LoopSession {
    let session = this.sessions.get(sessionId);
    if (!session) {
      if (this.sessions.size >= this.config.maxSessions) {
        const firstKey = this.sessions.keys().next().value;
        if (firstKey !== undefined) this.sessions.delete(firstKey);
      }
      session = {
        agentId,
        startedAt: Date.now(),
        cycles: 0,
        totalTokens: 0,
        toolHistory: [],
        argHashes: [],
        progressMetrics: [],
        paused: false,
      };
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  private checkProgress(session: LoopSession): boolean {
    const { uniqueTools, windowCycles } = this.config.progressThreshold;
    const recentTools = session.toolHistory.slice(-windowCycles);
    const uniqueInWindow = new Set(recentTools).size;

    // Progress via tool diversity
    if (uniqueInWindow >= uniqueTools) return true;

    // Progress via increasing progress metric
    if (session.progressMetrics.length >= 2) {
      const recent = session.progressMetrics.slice(-3);
      const increasing = recent.every((v, i) => i === 0 || v > recent[i - 1]);
      if (increasing) return true;
    }

    return false;
  }

  private computeRepetitionScore(session: LoopSession): number {
    if (session.argHashes.length < 3) return 0;

    const recent = session.argHashes.slice(-10);
    const uniqueHashes = new Set(recent).size;
    return 1 - uniqueHashes / recent.length;
  }

  private hashArgs(args: Record<string, unknown>): string {
    // Simple deterministic hash for arg comparison
    const str = JSON.stringify(args, Object.keys(args).sort());
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash + char) | 0;
    }
    return hash.toString(36);
  }

  private buildResult(
    session: LoopSession,
    now: number,
    loop: boolean,
    reason: string,
    action: LoopDetectionResult['action']
  ): LoopDetectionResult {
    const elapsedMs = now - session.startedAt;
    const makingProgress = this.checkProgress(session);
    const repetitionScore = this.computeRepetitionScore(session);

    if (this.config.debug) {
      console.log(
        `[A10] Agent ${session.agentId}: ${reason} — cycles=${session.cycles}, tokens=${session.totalTokens}, elapsed=${elapsedMs}ms, action=${action}`
      );
    }

    return {
      loop,
      reason,
      action,
      cycles: session.cycles,
      totalTokens: session.totalTokens,
      elapsedMs,
      makingProgress,
      repetitionScore,
    };
  }
}
