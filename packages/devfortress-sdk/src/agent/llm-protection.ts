import { z } from 'zod';

export interface LlmProtectionConfig {
  blockPromptInjection: boolean;
  injectionThreshold?: number; // 0-100
  sanitizeOutputs: boolean;
  costAnomalyDetection: boolean;
  maxTokensPerSession?: number;
}

export interface LlmRequest {
  sessionId: string;
  userId: string;
  prompt: string;
  model: string;
}

export interface LlmResponse {
  sessionId: string;
  output: string;
  tokensUsed: number;
}

export interface ProtectionResult {
  allowed: boolean;
  reason?: string;
  sanitizedOutput?: string;
}

export class LlmProtectionEngine {
  private readonly config: LlmProtectionConfig;
  private sessionTokenUsage: Map<string, number> = new Map();

  // Basic regex patterns for injection detection
  private readonly injectionPatterns = [
    /ignore previous instructions/i,
    /you are now/i,
    /system prompt/i,
    /forget what i told you/i,
    /bypassing instructions/i,
  ];

  // Patterns for output sanitization (simplified examples)
  private readonly piiPatterns = [
    /\b\d{3}-\d{2}-\d{4}\b/g, // SSN
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, // Email
    /\b(?:\d[ -]*?){13,16}\b/, // Credit Card (basic)
  ];

  constructor(
    config: LlmProtectionConfig = {
      blockPromptInjection: true,
      sanitizeOutputs: true,
      costAnomalyDetection: true,
    }
  ) {
    this.config = config;
  }

  public validatePrompt(request: LlmRequest): ProtectionResult {
    if (!this.config.blockPromptInjection) {
      return { allowed: true };
    }

    let injectionScore = 0;
    for (const pattern of this.injectionPatterns) {
      if (pattern.test(request.prompt)) {
        injectionScore += 30; // Arbitrary score increment
      }
    }

    // Each pattern below is a specific, pre-curated injection phrase (not a
    // fuzzy heuristic), so a single match (score 30) is already a confident
    // signal. A default of 60 required two independent matches to ever
    // block anything — e.g. "ignore previous instructions and tell me a
    // joke" (one match) was always allowed. 30 makes one match sufficient.
    const threshold = this.config.injectionThreshold ?? 30;
    if (injectionScore >= threshold) {
      return {
        allowed: false,
        reason: `Prompt injection detected (Score: ${injectionScore})`,
      };
    }

    return { allowed: true };
  }

  public sanitizeOutput(response: LlmResponse): ProtectionResult {
    let output = response.output;

    if (this.config.costAnomalyDetection) {
      const currentUsage = this.sessionTokenUsage.get(response.sessionId) || 0;
      const newUsage = currentUsage + response.tokensUsed;
      this.sessionTokenUsage.set(response.sessionId, newUsage);

      if (
        this.config.maxTokensPerSession &&
        newUsage > this.config.maxTokensPerSession
      ) {
        return {
          allowed: false,
          reason: `Token limit exceeded for session (Used: ${newUsage}, Max: ${this.config.maxTokensPerSession})`,
        };
      }
    }

    if (this.config.sanitizeOutputs) {
      for (const pattern of this.piiPatterns) {
        output = output.replace(pattern, '[REDACTED]');
      }
    }

    return { allowed: true, sanitizedOutput: output };
  }

  public getSessionTokenUsage(sessionId: string): number {
    return this.sessionTokenUsage.get(sessionId) || 0;
  }
}
