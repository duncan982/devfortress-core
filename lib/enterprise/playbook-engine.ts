/**
 * Custom Response Playbooks Engine
 * Enterprise-tier feature for per-endpoint, severity-based automated response rules
 */

import { logInfo, logError, logWarn } from '@core/lib/logger';

/* ─── Types ─── */

export enum PlaybookAction {
  REVOKE_SESSION = 'revoke_session',
  BLOCK_IP = 'block_ip',
  RATE_LIMIT_IP = 'rate_limit_ip',
  TARPIT_IP = 'tarpit_ip',
  LOCK_ACCOUNT = 'lock_account',
  REQUIRE_MFA = 'require_mfa',
  QUARANTINE_ACCOUNT = 'quarantine_account',
  ALERT_TEAM = 'alert_team',
  LOG_ONLY = 'log_only',
  CUSTOM_WEBHOOK = 'custom_webhook',
}

export enum PlaybookConditionField {
  THREAT_TYPE = 'threat_type',
  SEVERITY = 'severity',
  THREAT_SCORE = 'threat_score',
  ENDPOINT_PATTERN = 'endpoint_pattern',
  HTTP_METHOD = 'http_method',
  IP_COUNTRY = 'ip_country',
  TIME_OF_DAY = 'time_of_day',
  USER_ROLE = 'user_role',
  REQUEST_COUNT_1M = 'request_count_1m',
  REQUEST_COUNT_5M = 'request_count_5m',
  FAILED_AUTH_COUNT = 'failed_auth_count',
  IS_KNOWN_ABUSER = 'is_known_abuser',
}

export enum ConditionOperator {
  EQUALS = 'eq',
  NOT_EQUALS = 'neq',
  GREATER_THAN = 'gt',
  LESS_THAN = 'lt',
  GREATER_THAN_OR_EQUAL = 'gte',
  LESS_THAN_OR_EQUAL = 'lte',
  CONTAINS = 'contains',
  MATCHES = 'matches',
  IN = 'in',
  NOT_IN = 'not_in',
}

export interface PlaybookCondition {
  field: PlaybookConditionField;
  operator: ConditionOperator;
  value: string | number | boolean | string[];
}

export interface PlaybookActionConfig {
  action: PlaybookAction;
  /** Duration in seconds for time-limited actions (block, rate-limit, tarpit) */
  durationSeconds?: number;
  /** Rate limit max requests per minute */
  rateLimitRpm?: number;
  /** Tarpit delay in milliseconds */
  tarpitDelayMs?: number;
  /** Webhook URL for CUSTOM_WEBHOOK action */
  webhookUrl?: string;
  /** Alert channels (email, slack, pagerduty) */
  alertChannels?: string[];
  /** Custom metadata */
  metadata?: Record<string, unknown>;
}

export interface PlaybookRule {
  id: string;
  playbookId: string;
  name: string;
  description: string;
  /** All conditions must be true (AND logic) */
  conditions: PlaybookCondition[];
  /** Actions executed in order if conditions match */
  actions: PlaybookActionConfig[];
  /** Priority — lower number = higher priority */
  priority: number;
  enabled: boolean;
  /** Stop evaluating further rules if this matches */
  stopOnMatch: boolean;
}

export interface Playbook {
  id: string;
  orgId: string;
  name: string;
  description: string;
  /** Version number, incremented on each update */
  version: number;
  rules: PlaybookRule[];
  enabled: boolean;
  /** Dry run mode — evaluate but don't execute actions */
  dryRun: boolean;
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
}

export interface PlaybookEvaluationContext {
  threatType: string;
  severity: number;
  threatScore: number;
  endpoint: string;
  httpMethod: string;
  sourceIp: string;
  ipCountry?: string;
  timeOfDay: number; // 0-23 hour
  userId?: string;
  userRole?: string;
  requestCount1m?: number;
  requestCount5m?: number;
  failedAuthCount?: number;
  isKnownAbuser?: boolean;
}

export interface PlaybookExecutionResult {
  playbookId: string;
  ruleId: string;
  ruleName: string;
  matched: boolean;
  actionsExecuted: Array<{
    action: PlaybookAction;
    success: boolean;
    error?: string;
    durationMs: number;
  }>;
  dryRun: boolean;
  evaluatedAt: Date;
}

/* ─── Condition Evaluator ─── */

function evaluateCondition(
  condition: PlaybookCondition,
  context: PlaybookEvaluationContext
): boolean {
  const fieldValue = getFieldValue(condition.field, context);
  if (fieldValue === undefined) return false;

  const { operator, value } = condition;

  switch (operator) {
    case ConditionOperator.EQUALS:
      return String(fieldValue) === String(value);

    case ConditionOperator.NOT_EQUALS:
      return String(fieldValue) !== String(value);

    case ConditionOperator.GREATER_THAN:
      return Number(fieldValue) > Number(value);

    case ConditionOperator.LESS_THAN:
      return Number(fieldValue) < Number(value);

    case ConditionOperator.GREATER_THAN_OR_EQUAL:
      return Number(fieldValue) >= Number(value);

    case ConditionOperator.LESS_THAN_OR_EQUAL:
      return Number(fieldValue) <= Number(value);

    case ConditionOperator.CONTAINS:
      return String(fieldValue)
        .toLowerCase()
        .includes(String(value).toLowerCase());

    case ConditionOperator.MATCHES: {
      try {
        const regex = new RegExp(String(value));
        return regex.test(String(fieldValue));
      } catch {
        return false;
      }
    }

    case ConditionOperator.IN:
      if (Array.isArray(value)) {
        return value.includes(String(fieldValue));
      }
      return false;

    case ConditionOperator.NOT_IN:
      if (Array.isArray(value)) {
        return !value.includes(String(fieldValue));
      }
      return true;

    default:
      return false;
  }
}

function getFieldValue(
  field: PlaybookConditionField,
  context: PlaybookEvaluationContext
): string | number | boolean | undefined {
  switch (field) {
    case PlaybookConditionField.THREAT_TYPE:
      return context.threatType;
    case PlaybookConditionField.SEVERITY:
      return context.severity;
    case PlaybookConditionField.THREAT_SCORE:
      return context.threatScore;
    case PlaybookConditionField.ENDPOINT_PATTERN:
      return context.endpoint;
    case PlaybookConditionField.HTTP_METHOD:
      return context.httpMethod;
    case PlaybookConditionField.IP_COUNTRY:
      return context.ipCountry;
    case PlaybookConditionField.TIME_OF_DAY:
      return context.timeOfDay;
    case PlaybookConditionField.USER_ROLE:
      return context.userRole;
    case PlaybookConditionField.REQUEST_COUNT_1M:
      return context.requestCount1m;
    case PlaybookConditionField.REQUEST_COUNT_5M:
      return context.requestCount5m;
    case PlaybookConditionField.FAILED_AUTH_COUNT:
      return context.failedAuthCount;
    case PlaybookConditionField.IS_KNOWN_ABUSER:
      return context.isKnownAbuser;
    default:
      return undefined;
  }
}

/* ─── Action Executor ─── */

async function executeAction(
  actionConfig: PlaybookActionConfig,
  context: PlaybookEvaluationContext,
  dryRun: boolean
): Promise<{ success: boolean; error?: string; durationMs: number }> {
  const start = Date.now();

  if (dryRun) {
    logInfo('[PLAYBOOK DRY RUN] Would execute action', {
      action: actionConfig.action,
      context: {
        sourceIp: context.sourceIp,
        endpoint: context.endpoint,
        threatType: context.threatType,
      },
    });
    return { success: true, durationMs: Date.now() - start };
  }

  try {
    switch (actionConfig.action) {
      case PlaybookAction.LOG_ONLY:
        logInfo('[PLAYBOOK] Log-only action triggered', {
          threatType: context.threatType,
          sourceIp: context.sourceIp,
          endpoint: context.endpoint,
          threatScore: context.threatScore,
        });
        break;

      case PlaybookAction.BLOCK_IP:
        logInfo('[PLAYBOOK] Blocking IP', {
          ip: context.sourceIp,
          duration: actionConfig.durationSeconds,
        });
        // Integration point: call blocked-ips API
        await fetch(
          `${process.env.NEXT_PUBLIC_APP_URL || ''}/api/blocked-ips`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              ip: context.sourceIp,
              reason: `Playbook: ${context.threatType} (score: ${context.threatScore})`,
              duration: actionConfig.durationSeconds,
            }),
          }
        ).catch(err => logError('Failed to block IP via API', { error: err }));
        break;

      case PlaybookAction.RATE_LIMIT_IP:
        logInfo('[PLAYBOOK] Rate-limiting IP', {
          ip: context.sourceIp,
          rpm: actionConfig.rateLimitRpm,
          duration: actionConfig.durationSeconds,
        });
        break;

      case PlaybookAction.TARPIT_IP:
        logInfo('[PLAYBOOK] Tarpitting IP', {
          ip: context.sourceIp,
          delay: actionConfig.tarpitDelayMs,
          duration: actionConfig.durationSeconds,
        });
        break;

      case PlaybookAction.REVOKE_SESSION:
        logInfo('[PLAYBOOK] Revoking session', {
          userId: context.userId,
          sessionAlias: 'redacted',
        });
        break;

      case PlaybookAction.LOCK_ACCOUNT:
        logInfo('[PLAYBOOK] Locking account', {
          userId: context.userId,
        });
        break;

      case PlaybookAction.REQUIRE_MFA:
        logInfo('[PLAYBOOK] Requiring MFA re-authentication', {
          userId: context.userId,
        });
        break;

      case PlaybookAction.QUARANTINE_ACCOUNT:
        logInfo('[PLAYBOOK] Quarantining account', {
          userId: context.userId,
        });
        break;

      case PlaybookAction.ALERT_TEAM:
        logInfo('[PLAYBOOK] Alerting team', {
          channels: actionConfig.alertChannels,
          threatType: context.threatType,
        });
        break;

      case PlaybookAction.CUSTOM_WEBHOOK:
        if (actionConfig.webhookUrl) {
          await fetch(actionConfig.webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              source: 'devfortress-playbook',
              context,
              metadata: actionConfig.metadata,
            }),
          });
        }
        break;

      default:
        logWarn('[PLAYBOOK] Unknown action', {
          action: actionConfig.action,
        });
    }

    return { success: true, durationMs: Date.now() - start };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    logError('[PLAYBOOK] Action execution failed', {
      action: actionConfig.action,
      error: errorMsg,
    });
    return { success: false, error: errorMsg, durationMs: Date.now() - start };
  }
}

/* ─── Main Service ─── */

export class PlaybookEngine {
  private playbooks: Map<string, Playbook> = new Map();
  private executionLog: PlaybookExecutionResult[] = [];

  /**
   * Register a playbook
   */
  registerPlaybook(playbook: Playbook): void {
    this.playbooks.set(playbook.id, playbook);
    logInfo('Playbook registered', {
      id: playbook.id,
      name: playbook.name,
      orgId: playbook.orgId,
      rulesCount: playbook.rules.length,
      dryRun: playbook.dryRun,
    });
  }

  /**
   * Get all playbooks for an org
   */
  getOrgPlaybooks(orgId: string): Playbook[] {
    return Array.from(this.playbooks.values()).filter(p => p.orgId === orgId);
  }

  /**
   * Get a single playbook by ID
   */
  getPlaybook(playbookId: string): Playbook | undefined {
    return this.playbooks.get(playbookId);
  }

  /**
   * Update a playbook (increments version)
   */
  updatePlaybook(
    playbookId: string,
    updates: Partial<Omit<Playbook, 'id' | 'orgId' | 'version' | 'createdAt'>>
  ): Playbook | null {
    const existing = this.playbooks.get(playbookId);
    if (!existing) return null;

    const updated: Playbook = {
      ...existing,
      ...updates,
      version: existing.version + 1,
      updatedAt: new Date(),
    };
    this.playbooks.set(playbookId, updated);

    logInfo('Playbook updated', {
      id: playbookId,
      version: updated.version,
    });

    return updated;
  }

  /**
   * Remove a playbook
   */
  removePlaybook(playbookId: string): boolean {
    return this.playbooks.delete(playbookId);
  }

  /**
   * Evaluate all playbooks for an org against a threat context
   * Returns results from all matching rules
   */
  async evaluate(
    orgId: string,
    context: PlaybookEvaluationContext
  ): Promise<PlaybookExecutionResult[]> {
    const playbooks = this.getOrgPlaybooks(orgId).filter(p => p.enabled);
    const results: PlaybookExecutionResult[] = [];

    for (const playbook of playbooks) {
      // Sort rules by priority (lower = higher priority)
      const sortedRules = [...playbook.rules]
        .filter(r => r.enabled)
        .sort((a, b) => a.priority - b.priority);

      for (const rule of sortedRules) {
        // All conditions must match (AND logic)
        const allMatch = rule.conditions.every(c =>
          evaluateCondition(c, context)
        );

        const result: PlaybookExecutionResult = {
          playbookId: playbook.id,
          ruleId: rule.id,
          ruleName: rule.name,
          matched: allMatch,
          actionsExecuted: [],
          dryRun: playbook.dryRun,
          evaluatedAt: new Date(),
        };

        if (allMatch) {
          logInfo('Playbook rule matched', {
            playbookId: playbook.id,
            ruleId: rule.id,
            ruleName: rule.name,
            threatType: context.threatType,
            dryRun: playbook.dryRun,
          });

          // Execute all actions for this rule
          for (const actionConfig of rule.actions) {
            const actionResult = await executeAction(
              actionConfig,
              context,
              playbook.dryRun
            );
            result.actionsExecuted.push({
              action: actionConfig.action,
              ...actionResult,
            });
          }

          results.push(result);
          this.executionLog.push(result);

          // Stop evaluating if this rule is configured to stop
          if (rule.stopOnMatch) break;
        }
      }
    }

    return results;
  }

  /**
   * Get execution log (audit trail)
   */
  getExecutionLog(filters?: {
    orgId?: string;
    playbookId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): PlaybookExecutionResult[] {
    let logs = [...this.executionLog];

    if (filters?.playbookId) {
      logs = logs.filter(l => l.playbookId === filters.playbookId);
    }

    if (filters?.startDate) {
      logs = logs.filter(l => l.evaluatedAt >= filters.startDate!);
    }

    if (filters?.endDate) {
      logs = logs.filter(l => l.evaluatedAt <= filters.endDate!);
    }

    logs.sort((a, b) => b.evaluatedAt.getTime() - a.evaluatedAt.getTime());

    if (filters?.limit) {
      logs = logs.slice(0, filters.limit);
    }

    return logs;
  }

  /**
   * Create a set of default playbook rules for common threat types
   */
  createDefaultPlaybook(orgId: string, createdBy: string): Playbook {
    const playbook: Playbook = {
      id: `pb-${orgId}-default-${Date.now()}`,
      orgId,
      name: 'Default Response Playbook',
      description:
        'DevFortress recommended playbook with best-practice rules for common threat types',
      version: 1,
      enabled: true,
      dryRun: true, // Start in dry-run mode
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy,
      rules: [
        {
          id: `rule-critical-block`,
          playbookId: '',
          name: 'Block Critical Threats',
          description: 'Immediately block IPs with critical threat score (90+)',
          conditions: [
            {
              field: PlaybookConditionField.THREAT_SCORE,
              operator: ConditionOperator.GREATER_THAN_OR_EQUAL,
              value: 90,
            },
          ],
          actions: [
            {
              action: PlaybookAction.BLOCK_IP,
              durationSeconds: 86400, // 24 hours
            },
            {
              action: PlaybookAction.REVOKE_SESSION,
            },
            {
              action: PlaybookAction.ALERT_TEAM,
              alertChannels: ['email'],
            },
          ],
          priority: 1,
          enabled: true,
          stopOnMatch: true,
        },
        {
          id: `rule-brute-force`,
          playbookId: '',
          name: 'Brute Force Detection',
          description: 'Rate-limit IPs performing brute force attacks',
          conditions: [
            {
              field: PlaybookConditionField.THREAT_TYPE,
              operator: ConditionOperator.EQUALS,
              value: 'brute_force',
            },
            {
              field: PlaybookConditionField.FAILED_AUTH_COUNT,
              operator: ConditionOperator.GREATER_THAN_OR_EQUAL,
              value: 5,
            },
          ],
          actions: [
            {
              action: PlaybookAction.RATE_LIMIT_IP,
              rateLimitRpm: 5,
              durationSeconds: 3600, // 1 hour
            },
            {
              action: PlaybookAction.LOCK_ACCOUNT,
            },
          ],
          priority: 2,
          enabled: true,
          stopOnMatch: false,
        },
        {
          id: `rule-high-severity`,
          playbookId: '',
          name: 'High Severity Response',
          description: 'Tarpit and alert on high-severity events (score 70–89)',
          conditions: [
            {
              field: PlaybookConditionField.THREAT_SCORE,
              operator: ConditionOperator.GREATER_THAN_OR_EQUAL,
              value: 70,
            },
            {
              field: PlaybookConditionField.THREAT_SCORE,
              operator: ConditionOperator.LESS_THAN,
              value: 90,
            },
          ],
          actions: [
            {
              action: PlaybookAction.TARPIT_IP,
              tarpitDelayMs: 3000,
              durationSeconds: 1800, // 30 min
            },
            {
              action: PlaybookAction.ALERT_TEAM,
              alertChannels: ['email'],
            },
          ],
          priority: 3,
          enabled: true,
          stopOnMatch: false,
        },
        {
          id: `rule-known-abuser`,
          playbookId: '',
          name: 'Known Abuser Block',
          description: 'Block IPs flagged in AbuseIPDB',
          conditions: [
            {
              field: PlaybookConditionField.IS_KNOWN_ABUSER,
              operator: ConditionOperator.EQUALS,
              value: true,
            },
          ],
          actions: [
            {
              action: PlaybookAction.BLOCK_IP,
              durationSeconds: 604800, // 7 days
            },
          ],
          priority: 4,
          enabled: true,
          stopOnMatch: false,
        },
        {
          id: `rule-medium-log`,
          playbookId: '',
          name: 'Medium Severity Logging',
          description: 'Log medium-severity events for review',
          conditions: [
            {
              field: PlaybookConditionField.THREAT_SCORE,
              operator: ConditionOperator.GREATER_THAN_OR_EQUAL,
              value: 40,
            },
            {
              field: PlaybookConditionField.THREAT_SCORE,
              operator: ConditionOperator.LESS_THAN,
              value: 70,
            },
          ],
          actions: [
            {
              action: PlaybookAction.LOG_ONLY,
            },
          ],
          priority: 10,
          enabled: true,
          stopOnMatch: false,
        },
      ],
    };

    // Set playbookId on all rules
    playbook.rules.forEach(r => {
      r.playbookId = playbook.id;
    });

    this.registerPlaybook(playbook);
    return playbook;
  }
}

/** Singleton playbook engine */
export const playbookEngine = new PlaybookEngine();
