/**
 * DevFortress SDK — A6: Sensitive Action Monitor
 *
 * Monitors high-risk account operations (password change, email change,
 * MFA enrollment/removal, role escalation) with enhanced behavioral
 * deviation scoring and automatic session controls.
 *
 * Patent Pending.
 * @packageDocumentation
 */

export interface SensitiveActionConfig {
  /** Window to track sensitive actions (ms). Default: 600_000 (10 min) */
  windowMs?: number;
  /** Max sensitive actions per user per window before escalation. Default: 3 */
  maxActionsPerWindow?: number;
  /** Score multiplier for sensitive action anomalies. Default: 2.0 */
  scoreMultiplier?: number;
  /** Auto-revoke session on critical pattern. Default: true */
  autoRevoke?: boolean;
  /** Max tracked users. Default: 50_000 */
  maxEntries?: number;
  debug?: boolean;
}

export type SensitiveActionType =
  | 'password_change'
  | 'email_change'
  | 'mfa_enroll'
  | 'mfa_remove'
  | 'role_escalation'
  | 'api_key_create'
  | 'api_key_revoke'
  | 'account_delete'
  | 'payment_method_change'
  | 'session_export';

export interface SensitiveActionEvent {
  userId: string;
  actionType: SensitiveActionType;
  ip: string;
  userAgent?: string;
  sessionId?: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

export interface SensitiveActionResult {
  allowed: boolean;
  riskScore: number; // 0-100
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  action: 'allow' | 'require_mfa' | 'delay' | 'revoke_session' | 'block';
  reason: string;
  actionsInWindow: number;
}

interface UserActionRecord {
  actions: Array<{ type: SensitiveActionType; timestamp: number; ip: string }>;
  lastIp: string;
  lastUserAgent: string;
}

export class SensitiveActionMonitor {
  private readonly config: Required<SensitiveActionConfig>;
  private readonly userActions = new Map<string, UserActionRecord>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  // Action risk weights
  private static readonly ACTION_WEIGHTS: Record<SensitiveActionType, number> =
    {
      password_change: 30,
      email_change: 35,
      mfa_enroll: 20,
      mfa_remove: 40,
      role_escalation: 45,
      api_key_create: 15,
      api_key_revoke: 25,
      account_delete: 50,
      payment_method_change: 30,
      session_export: 20,
    };

  constructor(config: SensitiveActionConfig = {}) {
    this.config = {
      windowMs: config.windowMs ?? 600_000,
      maxActionsPerWindow: config.maxActionsPerWindow ?? 3,
      scoreMultiplier: config.scoreMultiplier ?? 2.0,
      autoRevoke: config.autoRevoke ?? true,
      maxEntries: config.maxEntries ?? 50_000,
      debug: config.debug ?? false,
    };

    this.cleanupTimer = setInterval(() => this.cleanup(), this.config.windowMs);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  /**
   * Evaluate a sensitive action for risk.
   */
  evaluate(event: SensitiveActionEvent): SensitiveActionResult {
    const now = event.timestamp ?? Date.now();
    const { userId, actionType, ip, userAgent, sessionId } = event;

    // Enforce max entries
    if (
      this.userActions.size >= this.config.maxEntries &&
      !this.userActions.has(userId)
    ) {
      const firstKey = this.userActions.keys().next().value;
      if (firstKey !== undefined) this.userActions.delete(firstKey);
    }

    // Get or create user record
    let record = this.userActions.get(userId);
    if (!record) {
      record = { actions: [], lastIp: ip, lastUserAgent: userAgent ?? '' };
      this.userActions.set(userId, record);
    }

    // Purge expired actions
    record.actions = record.actions.filter(
      a => now - a.timestamp <= this.config.windowMs
    );

    // Add current action
    record.actions.push({ type: actionType, timestamp: now, ip });

    const actionsInWindow = record.actions.length;
    const baseWeight = SensitiveActionMonitor.ACTION_WEIGHTS[actionType] ?? 20;

    // Calculate risk score
    let riskScore = baseWeight;

    // Velocity amplifier: more actions → exponentially higher risk
    if (actionsInWindow > 1) {
      riskScore += (actionsInWindow - 1) * 15;
    }

    // IP change during sensitive window
    const uniqueIPs = new Set(record.actions.map(a => a.ip));
    if (uniqueIPs.size > 1) {
      riskScore += 20; // IP switching during sensitive operations
    }

    // Dangerous combinations
    const actionTypes = new Set(record.actions.map(a => a.type));
    if (actionTypes.has('mfa_remove') && actionTypes.has('password_change')) {
      riskScore += 30; // Classic account takeover pattern
    }
    if (actionTypes.has('email_change') && actionTypes.has('password_change')) {
      riskScore += 25; // Account hijack pattern
    }
    if (actionTypes.has('role_escalation') && actionsInWindow > 1) {
      riskScore += 20; // Privilege escalation during rapid changes
    }

    // Apply multiplier and cap
    riskScore = Math.min(
      100,
      Math.round(riskScore * this.config.scoreMultiplier)
    );

    // Determine severity and action
    let severity: SensitiveActionResult['severity'];
    let action: SensitiveActionResult['action'];
    let allowed = true;

    if (riskScore >= 85) {
      severity = 'CRITICAL';
      action = this.config.autoRevoke ? 'revoke_session' : 'block';
      allowed = false;
    } else if (riskScore >= 65) {
      severity = 'HIGH';
      action = 'require_mfa';
      allowed = true; // Allow but require re-verification
    } else if (riskScore >= 40) {
      severity = 'MEDIUM';
      action = 'delay';
      allowed = true;
    } else {
      severity = 'LOW';
      action = 'allow';
      allowed = true;
    }

    // Update record metadata
    record.lastIp = ip;
    record.lastUserAgent = userAgent ?? record.lastUserAgent;

    const reason =
      `Sensitive action '${actionType}' for user ${userId}: ` +
      `${actionsInWindow} actions in window, risk=${riskScore}, ` +
      `${uniqueIPs.size} unique IPs${actionTypes.size > 1 ? `, ${actionTypes.size} action types` : ''}`;

    if (this.config.debug) {
      console.log(`[SensitiveActionMonitor] ${reason}`);
    }

    return { allowed, riskScore, severity, action, reason, actionsInWindow };
  }

  getStats(): { trackedUsers: number } {
    return { trackedUsers: this.userActions.size };
  }

  private cleanup(): void {
    const now = Date.now();
    const toDelete: string[] = [];
    this.userActions.forEach((record, userId) => {
      record.actions = record.actions.filter(
        a => now - a.timestamp <= this.config.windowMs
      );
      if (record.actions.length === 0) toDelete.push(userId);
    });
    toDelete.forEach(key => this.userActions.delete(key));
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}
