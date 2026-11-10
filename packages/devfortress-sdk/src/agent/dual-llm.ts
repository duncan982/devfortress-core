import { z } from 'zod';

export interface DualLlmConfig {
  enableIsolation: boolean;
  blockPlannerDataAccess: boolean;
  blockReaderActionExecution: boolean;
}

export interface LlmMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  name?: string;
  tool_call_id?: string;
}

export interface AgentContext {
  agentId: string;
  sessionId: string;
}

export class DualLlmOrchestrator {
  private config: DualLlmConfig;

  constructor(
    config: DualLlmConfig = {
      enableIsolation: true,
      blockPlannerDataAccess: true,
      blockReaderActionExecution: true,
    }
  ) {
    this.config = config;
  }

  /**
   * The Planner LLM is responsible for decomposing tasks and deciding which tools to call.
   * It should NOT receive raw data contents directly, only metadata or summaries.
   */
  public validatePlannerRequest(
    messages: LlmMessage[],
    context: AgentContext
  ): { allowed: boolean; reason?: string } {
    if (!this.config.enableIsolation || !this.config.blockPlannerDataAccess)
      return { allowed: true };

    // Example simple check: ensure the planner doesn't receive large chunks of raw data.
    // In a real system, this would use an input firewall (like A16).
    const totalContentLength = messages.reduce(
      (acc, msg) => acc + msg.content.length,
      0
    );
    if (totalContentLength > 8000) {
      return {
        allowed: false,
        reason:
          'Planner LLM blocked from accessing potentially raw data (content length exceeded metadata limits).',
      };
    }

    return { allowed: true };
  }

  /**
   * The Reader LLM is responsible for parsing raw data and answering specific questions based on it.
   * It should NOT be allowed to execute state-mutating actions (tool calls).
   */
  public validateReaderResponse(
    responseMessage: LlmMessage,
    context: AgentContext
  ): { allowed: boolean; reason?: string } {
    if (!this.config.enableIsolation || !this.config.blockReaderActionExecution)
      return { allowed: true };

    // Ensure the Reader LLM isn't trying to make a tool call.
    // (Assuming OpenAI-like format where tool_calls are present in the response if it wants to call a tool).
    const hasToolCalls =
      (responseMessage as any).tool_calls &&
      (responseMessage as any).tool_calls.length > 0;

    if (hasToolCalls) {
      return {
        allowed: false,
        reason:
          'Reader LLM blocked from executing actions (tool calls not permitted).',
      };
    }

    return { allowed: true };
  }

  /**
   * Safe communication protocol between Planner and Reader.
   * The Planner asks a question, the Reader answers it based on a data source,
   * and the answer (not the raw data) is returned to the Planner.
   */
  public createReaderTask(
    plannerQuestion: string,
    dataReferenceId: string
  ): string {
    return `TASK_FOR_READER: Extract information from data source ${dataReferenceId} to answer the following: ${plannerQuestion}`;
  }
}
