/**
 * DevFortress Agent Security Adapter (IP-C1)
 *
 * Wraps df.observe() for AI agent tool invocations.
 * Intercepts agent_id, tool_name, and input_summary from:
 *   - LangChain / LangGraph tool calls
 *   - OpenAI function calling (tool_calls)
 *   - Raw HTTP-based agent tool invocations
 *
 * Usage:
 *   import { AgentAdapter } from '@devfortress/sdk';
 *   const agent = new AgentAdapter(df, { agentId: 'my-agent' });
 *   const result = await agent.observeToolCall({ tool: 'search', input: { query: 'test' } });
 *
 * @packageDocumentation
 */

import type { DevFortressCore as DevFortress } from './devfortress';
import type { ObserveResult } from './types';

// ── Agent Event Types ───────────────────────────────────────

export interface AgentToolCall {
  /** The tool being invoked (e.g. 'web_search', 'sql_query', 'file_read') */
  tool: string;
  /** Input parameters passed to the tool (will be summarised, not stored raw) */
  input?: Record<string, unknown>;
  /** Output from the tool (optional — only attach if needed for forensics) */
  output?: unknown;
  /** Duration of the tool call in milliseconds */
  durationMs?: number;
  /** The LLM model that triggered this tool call */
  model?: string;
  /** The framework originating the call */
  framework?:
    | 'langchain'
    | 'langgraph'
    | 'openai'
    | 'anthropic'
    | 'raw_http'
    | 'custom';
  /** Additional metadata */
  meta?: Record<string, unknown>;
}

export interface AgentAdapterConfig {
  /** Unique identifier for this agent instance */
  agentId: string;
  /** Human-readable label */
  agentName?: string;
  /** IP address of the agent host (defaults to '127.0.0.1' for server-side agents) */
  agentIp?: string;
  /** Max characters to include in input_summary (default: 256) */
  maxInputSummaryLength?: number;
  /** Whether to hash sensitive input values before sending (default: true) */
  sanitizeInputs?: boolean;
  /** Callback invoked when a tool call is flagged by DevFortress */
  onFlagged?: (
    toolCall: AgentToolCall,
    result: ObserveResult
  ) => void | Promise<void>;
}

// ── Input Summarizer ────────────────────────────────────────

function summarizeInput(
  input: Record<string, unknown> | undefined,
  maxLen: number,
  sanitize: boolean
): string {
  if (!input) return '{}';
  const keys = Object.keys(input);
  const summary: Record<string, string> = {};

  for (const key of keys) {
    const val = input[key];
    if (val === undefined || val === null) {
      summary[key] = 'null';
    } else if (typeof val === 'string') {
      // Sanitize long strings and potential secrets
      if (
        sanitize &&
        (key.toLowerCase().includes('key') ||
          key.toLowerCase().includes('token') ||
          key.toLowerCase().includes('secret') ||
          key.toLowerCase().includes('password'))
      ) {
        summary[key] = '[REDACTED]';
      } else {
        summary[key] = val.length > 64 ? val.substring(0, 61) + '...' : val;
      }
    } else if (typeof val === 'number' || typeof val === 'boolean') {
      summary[key] = String(val);
    } else if (Array.isArray(val)) {
      summary[key] = `Array(${val.length})`;
    } else {
      summary[key] = '{...}';
    }
  }

  const str = JSON.stringify(summary);
  return str.length > maxLen ? str.substring(0, maxLen - 3) + '...' : str;
}

// ── Validation ──────────────────────────────────────────────

const AGENT_ID_MAX_LENGTH = 128;
const AGENT_ID_PATTERN = /^[a-zA-Z0-9_\-.:@]+$/;

/**
 * Validate agent ID to prevent injection and ensure safe usage as
 * cache keys and pseudo-URL path segments.
 */
function validateAgentId(agentId: string): void {
  if (!agentId || typeof agentId !== 'string') {
    throw new Error('agentId is required and must be a non-empty string');
  }
  if (agentId.length > AGENT_ID_MAX_LENGTH) {
    throw new Error(
      `agentId must be at most ${AGENT_ID_MAX_LENGTH} characters`
    );
  }
  if (!AGENT_ID_PATTERN.test(agentId)) {
    throw new Error(
      'agentId may only contain alphanumeric characters, hyphens, underscores, dots, colons, and @'
    );
  }
}

/** Exported for use by agent-security modules. */
export { validateAgentId };

// ── Agent Adapter (IP-C1) ───────────────────────────────────

export class AgentAdapter {
  private df: DevFortress;
  private agentId: string;
  private agentName: string;
  private agentIp: string;
  private maxInputSummaryLength: number;
  private sanitizeInputs: boolean;
  private onFlagged?: AgentAdapterConfig['onFlagged'];
  private sessionToolCounts = new Map<string, number>();
  private static readonly MAX_TRACKED_SESSIONS = 10_000;

  constructor(df: DevFortress, config: AgentAdapterConfig) {
    validateAgentId(config.agentId);
    this.df = df;
    this.agentId = config.agentId;
    this.agentName = config.agentName || config.agentId;
    this.agentIp = config.agentIp || '127.0.0.1';
    this.maxInputSummaryLength = config.maxInputSummaryLength ?? 256;
    this.sanitizeInputs = config.sanitizeInputs ?? true;
    this.onFlagged = config.onFlagged;
  }

  /**
   * Observe an AI agent tool invocation through DevFortress.
   *
   * Extracts agent_id, tool_name, input_summary and sends as a
   * structured event. The real tool inputs stay local — only the
   * summary is transmitted.
   *
   * Supports LangChain/LangGraph, OpenAI function calling, and raw HTTP.
   */
  async observeToolCall(
    toolCall: AgentToolCall,
    sessionId?: string
  ): Promise<ObserveResult | null> {
    const inputSummary = summarizeInput(
      toolCall.input,
      this.maxInputSummaryLength,
      this.sanitizeInputs
    );

    // Track per-session tool count
    const sid = sessionId || 'default';
    const count = (this.sessionToolCounts.get(sid) || 0) + 1;
    this.sessionToolCounts.set(sid, count);

    // Build the observe request as a pseudo-request object
    const pseudoRequest = {
      method: 'TOOL_CALL',
      url: `/agent/${this.agentId}/tool/${toolCall.tool}`,
      headers: {
        'user-agent': `DevFortress-Agent/${this.agentName}`,
        'x-forwarded-for': this.agentIp,
      },
    };

    const result = await this.df.observe(pseudoRequest, {
      meta: {
        agent_id: this.agentId,
        agent_name: this.agentName,
        tool_name: toolCall.tool,
        input_summary: inputSummary,
        duration_ms: toolCall.durationMs,
        model: toolCall.model,
        framework: toolCall.framework || 'custom',
        session_tool_count: count,
        session_id: sessionId,
        event_category: 'agent_tool_call',
      },
      skipEnrichment: true,
    });

    if (result?.flagged && this.onFlagged) {
      await this.onFlagged(toolCall, result);
    }

    return result;
  }

  /**
   * Observe a LangChain/LangGraph tool call.
   * Convenience wrapper that extracts fields from the LangChain tool call format.
   */
  async observeLangChainTool(
    toolName: string,
    toolInput: Record<string, unknown>,
    options?: { sessionId?: string; model?: string; durationMs?: number }
  ): Promise<ObserveResult | null> {
    return this.observeToolCall(
      {
        tool: toolName,
        input: toolInput,
        framework: 'langchain',
        model: options?.model,
        durationMs: options?.durationMs,
      },
      options?.sessionId
    );
  }

  /**
   * Observe an OpenAI function/tool call.
   * Extracts from the tool_calls array in an OpenAI completion response.
   */
  async observeOpenAIToolCall(
    toolCall: { function: { name: string; arguments: string } },
    options?: { sessionId?: string; model?: string; durationMs?: number }
  ): Promise<ObserveResult | null> {
    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(toolCall.function.arguments);
    } catch {
      parsedArgs = { raw: toolCall.function.arguments };
    }

    return this.observeToolCall(
      {
        tool: toolCall.function.name,
        input: parsedArgs,
        framework: 'openai',
        model: options?.model,
        durationMs: options?.durationMs,
      },
      options?.sessionId
    );
  }

  /**
   * Observe a raw HTTP tool call (e.g. an agent calling an external API).
   */
  async observeHttpToolCall(
    url: string,
    method: string,
    options?: {
      statusCode?: number;
      durationMs?: number;
      sessionId?: string;
      meta?: Record<string, unknown>;
    }
  ): Promise<ObserveResult | null> {
    return this.observeToolCall(
      {
        tool: `http:${method.toUpperCase()}`,
        input: { url, status_code: options?.statusCode },
        framework: 'raw_http',
        durationMs: options?.durationMs,
        meta: options?.meta,
      },
      options?.sessionId
    );
  }

  /**
   * Track the start of an agent session (task/conversation).
   */
  async trackSessionStart(
    sessionId: string,
    taskDescription?: string
  ): Promise<ObserveResult | null> {
    // Evict oldest sessions if map exceeds max size (LRU-style)
    if (this.sessionToolCounts.size >= AgentAdapter.MAX_TRACKED_SESSIONS) {
      const first = this.sessionToolCounts.keys().next().value;
      if (first !== undefined) this.sessionToolCounts.delete(first);
    }
    this.sessionToolCounts.set(sessionId, 0);
    return this.df.observe(
      {
        method: 'SESSION_START',
        url: `/agent/${this.agentId}/session/${sessionId}`,
        headers: {
          'user-agent': `DevFortress-Agent/${this.agentName}`,
          'x-forwarded-for': this.agentIp,
        },
      },
      {
        meta: {
          agent_id: this.agentId,
          session_id: sessionId,
          task_description: taskDescription,
          event_category: 'agent_session_start',
        },
        skipEnrichment: true,
      }
    );
  }

  /**
   * Track the end of an agent session with summary metrics.
   */
  async trackSessionEnd(
    sessionId: string,
    summary?: { totalTools?: number; durationMs?: number; success?: boolean }
  ): Promise<ObserveResult | null> {
    const toolCount = this.sessionToolCounts.get(sessionId) || 0;
    this.sessionToolCounts.delete(sessionId);

    return this.df.observe(
      {
        method: 'SESSION_END',
        url: `/agent/${this.agentId}/session/${sessionId}`,
        headers: {
          'user-agent': `DevFortress-Agent/${this.agentName}`,
          'x-forwarded-for': this.agentIp,
        },
      },
      {
        meta: {
          agent_id: this.agentId,
          session_id: sessionId,
          total_tools: summary?.totalTools ?? toolCount,
          total_duration_ms: summary?.durationMs,
          success: summary?.success,
          event_category: 'agent_session_end',
        },
        skipEnrichment: true,
      }
    );
  }

  /**
   * Get the current session tool count for monitoring.
   */
  getSessionToolCount(sessionId: string): number {
    return this.sessionToolCounts.get(sessionId) || 0;
  }
}
