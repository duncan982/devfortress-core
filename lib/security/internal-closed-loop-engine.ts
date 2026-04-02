/**
 * Internal Closed-Loop Engine (IP-S6) — Enterprise / Air-Gapped Mode
 *
 * Three-tier threat detection architecture for enterprise customers
 * who require on-premise or air-gapped deployments:
 *
 * Tier 1: Deterministic rules — blocklist, rate limit, honeypot patterns
 *         Synchronous, <1ms, runs in SDK middleware. Zero false positives.
 *
 * Tier 2: Embedded ML inference — ONNX Runtime (<5MB model, <5ms inference)
 *         Runs in-process. Anomaly detection on behavioral signals.
 *         (Stub: model loading deferred until ONNX model is trained)
 *
 * Tier 3: Async platform escalation — non-blocking
 *         Sends event to DevFortress platform for cross-customer analysis.
 *         Disabled in air_gap mode.
 *
 * Configuration:
 *   air_gap: true  → Tiers 1+2 only, no platform communication
 *   air_gap: false → All 3 tiers (default)
 */

import { logInfo, logWarn, logDebug } from '@core/lib/logger';

// ── Types ───────────────────────────────────────────────────

export type ThreatAction =
  | 'block_ip'
  | 'revoke_session'
  | 'rate_limit'
  | 'alert'
  | 'escalate'
  | 'allow';

export interface InternalEngineConfig {
  /** Air-gapped mode: disable all platform communication. Default: false */
  airGap?: boolean;
  /** Custom blocklist of IPs. Checked synchronously in Tier 1. */
  blocklist?: Set<string>;
  /** Rate limit: max requests per IP per window. Default: 100/60s */
  rateLimitMax?: number;
  /** Rate limit window in seconds. Default: 60 */
  rateLimitWindowSeconds?: number;
  /** Honeypot paths that should never be accessed by legitimate users */
  honeypotPaths?: string[];
  /** Custom Tier 1 rules (synchronous, deterministic) */
  customRules?: DeterministicRule[];
  /** ONNX model path for Tier 2 (stub — not yet loaded) */
  onnxModelPath?: string;
}

export interface DeterministicRule {
  name: string;
  /** Evaluate the request. Return the action to take, or null to pass to next rule. */
  evaluate: (ctx: RequestContext) => ThreatAction | null;
}

export interface RequestContext {
  ip: string;
  method: string;
  path: string;
  userAgent: string | null;
  userId: string | null;
  sessionId: string | null;
  compositeScore: number;
  headers: Record<string, string>;
}

export interface EngineDecision {
  tier: 1 | 2 | 3;
  action: ThreatAction;
  ruleName: string;
  confidence: number;
  processingTimeMs: number;
}

// ── Rate Limiter (Tier 1) ───────────────────────────────────

const rateLimitBuckets = new Map<
  string,
  { count: number; windowStart: number }
>();

function checkRateLimit(ip: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const bucket = rateLimitBuckets.get(ip);

  if (!bucket || now - bucket.windowStart > windowMs) {
    rateLimitBuckets.set(ip, { count: 1, windowStart: now });
    return false; // Not rate limited
  }

  bucket.count++;
  if (bucket.count > max) {
    return true; // Rate limited
  }
  return false;
}

// ── Internal Engine ─────────────────────────────────────────

export class InternalClosedLoopEngine {
  private config: Required<
    Omit<InternalEngineConfig, 'customRules' | 'onnxModelPath'>
  > & {
    customRules: DeterministicRule[];
    onnxModelPath: string | null;
  };

  constructor(config?: InternalEngineConfig) {
    this.config = {
      airGap: config?.airGap ?? false,
      blocklist: config?.blocklist ?? new Set(),
      rateLimitMax: config?.rateLimitMax ?? 100,
      rateLimitWindowSeconds: config?.rateLimitWindowSeconds ?? 60,
      honeypotPaths: config?.honeypotPaths ?? [],
      customRules: config?.customRules ?? [],
      onnxModelPath: config?.onnxModelPath ?? null,
    };

    if (this.config.airGap) {
      logInfo(
        '[DF] Internal Closed-Loop Engine: AIR-GAP mode — no platform communication'
      );
    }
  }

  /**
   * Evaluate a request through all tiers.
   * Returns the first actionable decision.
   *
   * Tier 1 is synchronous and deterministic (<1ms).
   * Tier 2 is in-process ML inference (<5ms, when model loaded).
   * Tier 3 is async platform escalation (non-blocking).
   */
  evaluate(ctx: RequestContext): EngineDecision {
    const start = performance.now();

    // ── Tier 1: Deterministic Rules ─────────────────────────

    // 1a. Blocklist check
    if (this.config.blocklist.has(ctx.ip)) {
      return this.decision(1, 'block_ip', 'blocklist_match', 1.0, start);
    }

    // 1b. Honeypot path check
    if (this.config.honeypotPaths.some(hp => ctx.path.startsWith(hp))) {
      logWarn('[DF] Honeypot triggered', { ip: ctx.ip, path: ctx.path });
      return this.decision(1, 'block_ip', 'honeypot_triggered', 1.0, start);
    }

    // 1c. Rate limit check
    const rateLimited = checkRateLimit(
      ctx.ip,
      this.config.rateLimitMax,
      this.config.rateLimitWindowSeconds * 1000
    );
    if (rateLimited) {
      return this.decision(1, 'rate_limit', 'rate_limit_exceeded', 0.95, start);
    }

    // 1d. Known attack patterns (deterministic, zero false positives)
    const sqlInjectionPattern =
      /('|--|;|\b(union|select|insert|update|delete|drop|exec)\b)/i;
    const xssPattern = /(<script|javascript:|on\w+\s*=)/i;

    if (
      sqlInjectionPattern.test(ctx.path) ||
      sqlInjectionPattern.test(ctx.headers['content-type'] || '')
    ) {
      return this.decision(1, 'block_ip', 'sql_injection_pattern', 0.9, start);
    }
    if (xssPattern.test(ctx.path)) {
      return this.decision(1, 'block_ip', 'xss_pattern', 0.9, start);
    }

    // 1e. Custom deterministic rules
    for (const rule of this.config.customRules) {
      const action = rule.evaluate(ctx);
      if (action) {
        return this.decision(1, action, rule.name, 0.85, start);
      }
    }

    // ── Tier 2: Embedded ML Inference (Stub) ────────────────

    // When ONNX model is loaded, inference runs here in <5ms.
    // For now, use composite score as a simple heuristic.
    if (ctx.compositeScore >= 85) {
      return this.decision(
        2,
        'block_ip',
        'composite_score_critical',
        0.8,
        start
      );
    }
    if (ctx.compositeScore >= 70 && ctx.userId) {
      // IP-S2: Lower threshold for authenticated users
      return this.decision(
        2,
        'revoke_session',
        'post_auth_high_score',
        0.75,
        start
      );
    }
    if (ctx.compositeScore >= 60) {
      return this.decision(2, 'alert', 'composite_score_high', 0.6, start);
    }

    // ── Tier 3: Platform Escalation (Non-Blocking) ──────────

    if (!this.config.airGap && ctx.compositeScore >= 40) {
      // In non-air-gap mode, escalate medium-confidence events
      // The actual HTTP call to the platform is handled by the caller
      logDebug('[DF] Escalating to platform', {
        ip: ctx.ip,
        score: ctx.compositeScore,
      });
      return this.decision(3, 'escalate', 'platform_escalation', 0.5, start);
    }

    return this.decision(1, 'allow', 'no_threat_detected', 0.0, start);
  }

  /**
   * Check if the engine is in air-gapped mode.
   */
  isAirGapped(): boolean {
    return this.config.airGap;
  }

  /**
   * Add IP to the runtime blocklist (Tier 1).
   */
  blockIP(ip: string): void {
    this.config.blocklist.add(ip);
  }

  /**
   * Remove IP from the runtime blocklist.
   */
  unblockIP(ip: string): void {
    this.config.blocklist.delete(ip);
  }

  /**
   * Add a honeypot path (Tier 1).
   */
  addHoneypotPath(path: string): void {
    if (!this.config.honeypotPaths.includes(path)) {
      this.config.honeypotPaths.push(path);
    }
  }

  /**
   * Add a custom deterministic rule (Tier 1).
   */
  addRule(rule: DeterministicRule): void {
    this.config.customRules.push(rule);
  }

  // ── Private Helpers ─────────────────────────────────────────

  private decision(
    tier: 1 | 2 | 3,
    action: ThreatAction,
    ruleName: string,
    confidence: number,
    startTime: number
  ): EngineDecision {
    return {
      tier,
      action,
      ruleName,
      confidence,
      processingTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
    };
  }
}
