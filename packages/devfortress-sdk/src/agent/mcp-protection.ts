import { z } from 'zod';

export interface McpServerConfig {
  enableRequestValidation: boolean;
  enableToolAcls: boolean;
  enableExfiltrationDetection: boolean;
  maxDataVolumePerCall?: number; // bytes
}

export interface McpRequest {
  jsonrpc: string;
  method: string;
  params?: any;
  id?: string | number;
}

export interface McpToolCall {
  agentId: string;
  toolName: string;
  params: any;
  sessionId: string;
}

export interface McpResult {
  allowed: boolean;
  reason?: string;
}

export class McpProtectionEngine {
  private readonly config: McpServerConfig;
  private readonly toolAcls: Map<string, string[]> = new Map(); // agentId -> allowed tools
  private readonly toolCallHistory: McpToolCall[] = [];

  constructor(
    config: McpServerConfig = {
      enableRequestValidation: true,
      enableToolAcls: true,
      enableExfiltrationDetection: true,
    }
  ) {
    this.config = config;
  }

  public setAgentAcl(agentId: string, allowedTools: string[]) {
    this.toolAcls.set(agentId, allowedTools);
  }

  public validateRequest(request: McpRequest): McpResult {
    if (!this.config.enableRequestValidation) return { allowed: true };

    if (request.jsonrpc !== '2.0') {
      return {
        allowed: false,
        reason: 'Invalid JSON-RPC version. Expected 2.0.',
      };
    }
    if (typeof request.method !== 'string') {
      return { allowed: false, reason: 'Method must be a string.' };
    }

    return { allowed: true };
  }

  public validateToolCall(call: McpToolCall): McpResult {
    // 1. Tool ACL Check
    if (this.config.enableToolAcls) {
      const allowedTools = this.toolAcls.get(call.agentId);
      if (!allowedTools) {
        return {
          allowed: false,
          reason: `Agent ${call.agentId} has no configured ACLs.`,
        };
      }
      if (!allowedTools.includes(call.toolName)) {
        return {
          allowed: false,
          reason: `Agent ${call.agentId} is not authorized to use tool '${call.toolName}'.`,
        };
      }
    }

    // 2. Exfiltration Detection (Basic Volume Check)
    if (
      this.config.enableExfiltrationDetection &&
      this.config.maxDataVolumePerCall
    ) {
      const paramString = JSON.stringify(call.params);
      const bytes = Buffer.byteLength(paramString, 'utf8');

      if (bytes > this.config.maxDataVolumePerCall) {
        return {
          allowed: false,
          reason: `Data volume exceeded limit. (Size: ${bytes} bytes, Max: ${this.config.maxDataVolumePerCall})`,
        };
      }
    }

    // Audit logging
    this.toolCallHistory.push({ ...call, timestamp: Date.now() } as any);

    return { allowed: true };
  }

  public getAuditLogs(): McpToolCall[] {
    return [...this.toolCallHistory];
  }
}
