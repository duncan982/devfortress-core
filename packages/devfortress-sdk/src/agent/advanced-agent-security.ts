import { createHash } from 'crypto';

export interface AgentConfig {
  enableContentSanitizer: boolean;
  enableAgentGateway: boolean;
  enableToolAuditLogs: boolean;
}

export interface ContentSanitizationOptions {
  stripInstructions: boolean;
  stripRoleplay: boolean;
  allowedSources?: string[];
}

export interface GatewayRequest {
  agentId: string;
  targetEndpoint: string;
  method: string;
  payload: any;
}

export interface ToolAuditLogEntry {
  id: string;
  agentId: string;
  toolName: string;
  inputs: any;
  outputs: any;
  timestamp: number;
  durationMs: number;
  outcome: 'SUCCESS' | 'ERROR' | 'BLOCKED';
  previousHash?: string;
  hash: string;
}

export class AdvancedAgentSecurity {
  private config: AgentConfig;
  private auditLogs: ToolAuditLogEntry[] = [];
  private lastHash: string = createHash('sha256')
    .update('GENESIS')
    .digest('hex');

  // Basic patterns for C26
  private instructionPatterns = [
    /ignore previous instructions/i,
    /new system prompt/i,
    /you are now/i,
  ];
  private roleplayPatterns = [/pretend you are/i, /act as/i, /simulate being/i];

  // Gateway policies for C28
  private gatewayPolicies = new Map<string, string[]>(); // agentId -> allowed endpoints

  constructor(
    config: AgentConfig = {
      enableContentSanitizer: true,
      enableAgentGateway: true,
      enableToolAuditLogs: true,
    }
  ) {
    this.config = config;
  }

  // SPEC-C26: Agent Content Sanitizer
  public sanitizeContent(
    content: string,
    source: string,
    options: ContentSanitizationOptions = {
      stripInstructions: true,
      stripRoleplay: true,
    }
  ): { sanitizedContent: string; modified: boolean } {
    if (!this.config.enableContentSanitizer) {
      return { sanitizedContent: content, modified: false };
    }

    if (options.allowedSources && options.allowedSources.includes(source)) {
      return { sanitizedContent: content, modified: false }; // Trusted source
    }

    let sanitized = content;
    let modified = false;

    if (options.stripInstructions) {
      for (const pattern of this.instructionPatterns) {
        if (pattern.test(sanitized)) {
          sanitized = sanitized.replace(pattern, '[REMOVED_INSTRUCTION]');
          modified = true;
        }
      }
    }

    if (options.stripRoleplay) {
      for (const pattern of this.roleplayPatterns) {
        if (pattern.test(sanitized)) {
          sanitized = sanitized.replace(pattern, '[REMOVED_ROLEPLAY]');
          modified = true;
        }
      }
    }

    return { sanitizedContent: sanitized, modified };
  }

  // SPEC-C28: Agent Gateway
  public setGatewayPolicy(agentId: string, allowedEndpoints: string[]) {
    this.gatewayPolicies.set(agentId, allowedEndpoints);
  }

  public validateGatewayRequest(req: GatewayRequest): {
    allowed: boolean;
    reason?: string;
  } {
    if (!this.config.enableAgentGateway) return { allowed: true };

    const allowed = this.gatewayPolicies.get(req.agentId);
    if (!allowed) {
      return {
        allowed: false,
        reason: `Agent ${req.agentId} has no gateway policies configured.`,
      };
    }

    const isAllowed = allowed.some(endpoint =>
      req.targetEndpoint.startsWith(endpoint)
    );
    if (!isAllowed) {
      return {
        allowed: false,
        reason: `Endpoint ${req.targetEndpoint} is not allowlisted for agent ${req.agentId}.`,
      };
    }

    return { allowed: true };
  }

  // SPEC-C31: Tool Audit Logs
  public appendToolAuditLog(
    agentId: string,
    toolName: string,
    inputs: any,
    outputs: any,
    durationMs: number,
    outcome: 'SUCCESS' | 'ERROR' | 'BLOCKED'
  ): ToolAuditLogEntry | null {
    if (!this.config.enableToolAuditLogs) return null;

    const entryWithoutHash = {
      id: `log_${Date.now()}_${Math.random().toString(36).substring(7)}`,
      agentId,
      toolName,
      inputs,
      outputs,
      timestamp: Date.now(),
      durationMs,
      outcome,
      previousHash: this.lastHash,
    };

    const hashInput = JSON.stringify(entryWithoutHash);
    const hash = createHash('sha256').update(hashInput).digest('hex');

    const entry: ToolAuditLogEntry = {
      ...entryWithoutHash,
      hash,
    };

    this.auditLogs.push(entry);
    this.lastHash = hash;

    return entry;
  }

  public getAuditLogs(): ToolAuditLogEntry[] {
    return [...this.auditLogs];
  }

  public verifyAuditLogIntegrity(): boolean {
    let currentExpectedPrev = createHash('sha256')
      .update('GENESIS')
      .digest('hex');

    for (const log of this.auditLogs) {
      if (log.previousHash !== currentExpectedPrev) {
        return false; // Chain broken
      }

      const entryWithoutHash = {
        id: log.id,
        agentId: log.agentId,
        toolName: log.toolName,
        inputs: log.inputs,
        outputs: log.outputs,
        timestamp: log.timestamp,
        durationMs: log.durationMs,
        outcome: log.outcome,
        previousHash: log.previousHash,
      };
      const hashInput = JSON.stringify(entryWithoutHash);
      const computedHash = createHash('sha256').update(hashInput).digest('hex');

      if (computedHash !== log.hash) {
        return false; // Hash mismatch
      }
      currentExpectedPrev = log.hash;
    }
    return true;
  }
}
