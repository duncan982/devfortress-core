/**
 * Agent SDK Adapter — Tests (IP-C1)
 *
 * Tests for AgentAdapter class which wraps df.observe() for AI agent
 * tool invocations. Covers LangChain, OpenAI, HTTP, and raw tool calls.
 */

import {
  AgentAdapter,
  validateAgentId,
  type AgentAdapterConfig,
  type AgentToolCall,
} from '../src/agent';
import { type DevFortressCore as DevFortress } from '../src/devfortress';
import { type ObserveResult } from '../src/types';

// ── Mock DevFortress ────────────────────────────────────────

function createMockDF(observeResult?: Partial<ObserveResult>): DevFortress {
  const defaultResult: ObserveResult = {
    event_id: 'evt_test_123',
    flagged: false,
    confidence: 0.1,
  };

  return {
    observe: jest
      .fn()
      .mockResolvedValue({ ...defaultResult, ...observeResult }),
  } as unknown as DevFortress;
}

// ── Basic Construction ──────────────────────────────────────

describe('AgentAdapter — Construction', () => {
  it('should create an adapter with minimal config', () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'test-agent' });
    expect(adapter).toBeDefined();
  });

  it('should accept full config options', () => {
    const df = createMockDF();
    const config: AgentAdapterConfig = {
      agentId: 'my-agent',
      agentName: 'My AI Agent',
      agentIp: '10.0.0.1',
      maxInputSummaryLength: 512,
      sanitizeInputs: false,
      onFlagged: jest.fn(),
    };
    const adapter = new AgentAdapter(df, config);
    expect(adapter).toBeDefined();
  });
});

// ── observeToolCall ─────────────────────────────────────────

describe('AgentAdapter — observeToolCall', () => {
  it('should call df.observe with agent metadata', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, {
      agentId: 'agent-1',
      agentName: 'Search Agent',
    });

    const toolCall: AgentToolCall = {
      tool: 'web_search',
      input: { query: 'test query' },
      durationMs: 150,
      model: 'gpt-4',
      framework: 'langchain',
    };

    const result = await adapter.observeToolCall(toolCall, 'session-1');

    expect(df.observe).toHaveBeenCalledTimes(1);
    const [req, opts] = (df.observe as jest.Mock).mock.calls[0];

    expect(req.method).toBe('TOOL_CALL');
    expect(req.url).toBe('/agent/agent-1/tool/web_search');
    expect(req.headers['user-agent']).toBe('DevFortress-Agent/Search Agent');

    expect(opts.meta.agent_id).toBe('agent-1');
    expect(opts.meta.tool_name).toBe('web_search');
    expect(opts.meta.model).toBe('gpt-4');
    expect(opts.meta.framework).toBe('langchain');
    expect(opts.meta.session_id).toBe('session-1');
    expect(opts.meta.event_category).toBe('agent_tool_call');
    expect(opts.skipEnrichment).toBe(true);

    expect(result).not.toBeNull();
    expect(result?.flagged).toBe(false);
  });

  it('should sanitize sensitive input fields by default', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'agent-1' });

    await adapter.observeToolCall({
      tool: 'db_query',
      input: {
        api_key: 'sk-secret-123',
        query: 'SELECT * FROM users',
        token: 'abc123',
      },
    });

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    const summary = opts.meta.input_summary;

    expect(summary).toContain('[REDACTED]');
    expect(summary).not.toContain('sk-secret-123');
    expect(summary).not.toContain('abc123');
    expect(summary).toContain('SELECT * FROM users');
  });

  it('should not sanitize when sanitizeInputs is false', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, {
      agentId: 'agent-1',
      sanitizeInputs: false,
    });

    await adapter.observeToolCall({
      tool: 'test',
      input: { api_key: 'visible-key' },
    });

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    expect(opts.meta.input_summary).toContain('visible-key');
  });

  it('should truncate long input summaries', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, {
      agentId: 'agent-1',
      maxInputSummaryLength: 50,
    });

    await adapter.observeToolCall({
      tool: 'test',
      input: { data: 'a'.repeat(200) },
    });

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    expect(opts.meta.input_summary.length).toBeLessThanOrEqual(50);
  });

  it('should track session tool counts', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'agent-1' });

    await adapter.observeToolCall({ tool: 'a' }, 'ses-1');
    await adapter.observeToolCall({ tool: 'b' }, 'ses-1');
    await adapter.observeToolCall({ tool: 'c' }, 'ses-1');

    expect(adapter.getSessionToolCount('ses-1')).toBe(3);

    const [, opts] = (df.observe as jest.Mock).mock.calls[2];
    expect(opts.meta.session_tool_count).toBe(3);
  });

  it('should invoke onFlagged callback when result is flagged', async () => {
    const df = createMockDF({ flagged: true, confidence: 0.9 });
    const onFlagged = jest.fn();
    const adapter = new AgentAdapter(df, { agentId: 'agent-1', onFlagged });

    const toolCall: AgentToolCall = { tool: 'dangerous_tool' };
    await adapter.observeToolCall(toolCall);

    expect(onFlagged).toHaveBeenCalledTimes(1);
    expect(onFlagged).toHaveBeenCalledWith(
      toolCall,
      expect.objectContaining({ flagged: true })
    );
  });
});

// ── LangChain Convenience ───────────────────────────────────

describe('AgentAdapter — observeLangChainTool', () => {
  it('should wrap as langchain framework tool call', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'lc-agent' });

    await adapter.observeLangChainTool(
      'calculator',
      { expression: '2+2' },
      { model: 'gpt-4o', sessionId: 'lc-session' }
    );

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    expect(opts.meta.tool_name).toBe('calculator');
    expect(opts.meta.framework).toBe('langchain');
    expect(opts.meta.model).toBe('gpt-4o');
    expect(opts.meta.session_id).toBe('lc-session');
  });
});

// ── OpenAI Function Calling ─────────────────────────────────

describe('AgentAdapter — observeOpenAIToolCall', () => {
  it('should parse OpenAI tool_calls format', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'oai-agent' });

    const openAIToolCall = {
      function: {
        name: 'get_weather',
        arguments: JSON.stringify({ location: 'London', units: 'celsius' }),
      },
    };

    await adapter.observeOpenAIToolCall(openAIToolCall, { model: 'gpt-4' });

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    expect(opts.meta.tool_name).toBe('get_weather');
    expect(opts.meta.framework).toBe('openai');
    expect(opts.meta.input_summary).toContain('London');
  });

  it('should handle invalid JSON arguments gracefully', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'oai-agent' });

    const openAIToolCall = {
      function: {
        name: 'broken_tool',
        arguments: 'not-json{',
      },
    };

    await adapter.observeOpenAIToolCall(openAIToolCall);

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    expect(opts.meta.tool_name).toBe('broken_tool');
    expect(opts.meta.input_summary).toContain('not-json{');
  });
});

// ── HTTP Tool Call ──────────────────────────────────────────

describe('AgentAdapter — observeHttpToolCall', () => {
  it('should format HTTP calls correctly', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'http-agent' });

    await adapter.observeHttpToolCall('https://api.example.com/data', 'POST', {
      statusCode: 200,
      durationMs: 340,
      sessionId: 'http-ses',
    });

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    expect(opts.meta.tool_name).toBe('http:POST');
    expect(opts.meta.framework).toBe('raw_http');
    expect(opts.meta.input_summary).toContain('https://api.example.com/data');
  });
});

// ── Session Tracking ────────────────────────────────────────

describe('AgentAdapter — Session Lifecycle', () => {
  it('should track session start and end', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'session-agent' });

    await adapter.trackSessionStart('ses-42', 'Search task');

    expect(df.observe).toHaveBeenCalledTimes(1);
    const [req1, opts1] = (df.observe as jest.Mock).mock.calls[0];
    expect(req1.method).toBe('SESSION_START');
    expect(opts1.meta.event_category).toBe('agent_session_start');
    expect(opts1.meta.task_description).toBe('Search task');

    // Add some tool calls
    await adapter.observeToolCall({ tool: 'a' }, 'ses-42');
    await adapter.observeToolCall({ tool: 'b' }, 'ses-42');

    expect(adapter.getSessionToolCount('ses-42')).toBe(2);

    await adapter.trackSessionEnd('ses-42', {
      durationMs: 5000,
      success: true,
    });

    const endCall = (df.observe as jest.Mock).mock.calls[3];
    expect(endCall[0].method).toBe('SESSION_END');
    expect(endCall[1].meta.event_category).toBe('agent_session_end');
    expect(endCall[1].meta.total_tools).toBe(2);
    expect(endCall[1].meta.total_duration_ms).toBe(5000);
    expect(endCall[1].meta.success).toBe(true);

    // Session tool count should be cleared after end
    expect(adapter.getSessionToolCount('ses-42')).toBe(0);
  });
});

// ── Input Summarizer Edge Cases ─────────────────────────────

describe('AgentAdapter — Input Edge Cases', () => {
  it('should handle undefined input', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'agent-1' });

    await adapter.observeToolCall({ tool: 'test' });

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    expect(opts.meta.input_summary).toBe('{}');
  });

  it('should summarize arrays and nested objects', async () => {
    const df = createMockDF();
    const adapter = new AgentAdapter(df, { agentId: 'agent-1' });

    await adapter.observeToolCall({
      tool: 'test',
      input: {
        items: [1, 2, 3],
        nested: { deep: true },
        flag: true,
        count: 42,
        nothing: null,
      },
    });

    const [, opts] = (df.observe as jest.Mock).mock.calls[0];
    const summary = opts.meta.input_summary;
    expect(summary).toContain('Array(3)');
    expect(summary).toContain('{...}');
    expect(summary).toContain('true');
    expect(summary).toContain('42');
    expect(summary).toContain('null');
  });
});

// ── Agent ID Validation ─────────────────────────────────────

describe('AgentAdapter — Agent ID Validation (M4)', () => {
  it('should reject empty agentId', () => {
    const df = createMockDF();
    expect(() => new AgentAdapter(df, { agentId: '' })).toThrow(
      'agentId is required and must be a non-empty string'
    );
  });

  it('should reject agentId longer than 128 characters', () => {
    const df = createMockDF();
    expect(() => new AgentAdapter(df, { agentId: 'a'.repeat(129) })).toThrow(
      'agentId must be at most 128 characters'
    );
  });

  it('should reject agentId with path traversal characters', () => {
    const df = createMockDF();
    expect(
      () => new AgentAdapter(df, { agentId: '../../../etc/passwd' })
    ).toThrow('agentId may only contain');
  });

  it('should reject agentId with spaces or special chars', () => {
    const df = createMockDF();
    expect(
      () => new AgentAdapter(df, { agentId: 'agent id with spaces' })
    ).toThrow('agentId may only contain');
    expect(() => new AgentAdapter(df, { agentId: 'agent<script>' })).toThrow(
      'agentId may only contain'
    );
  });

  it('should accept valid agentId patterns', () => {
    const df = createMockDF();
    expect(
      () => new AgentAdapter(df, { agentId: 'my-agent_v2' })
    ).not.toThrow();
    expect(
      () => new AgentAdapter(df, { agentId: 'agent:prod@v1.0' })
    ).not.toThrow();
    expect(() => new AgentAdapter(df, { agentId: 'AGENT-123' })).not.toThrow();
  });

  it('validateAgentId should be callable directly', () => {
    expect(() => validateAgentId('valid-id')).not.toThrow();
    expect(() => validateAgentId('')).toThrow();
  });
});
