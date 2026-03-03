/**
 * Prompt Injection Guard
 * Protects LLM-facing endpoints from prompt injection attacks.
 *
 * Detects and sanitizes:
 * 1. System prompt override attempts ("ignore previous instructions")
 * 2. Markdown/HTML injection patterns
 * 3. Excessive token payloads
 * 4. Encoded injection attempts (base64, unicode)
 *
 * @module lib/security/prompt-guard
 */

import { logWarn, logInfo } from '@core/lib/logger';

/** Maximum allowed input length in characters (roughly ~4K tokens) */
const MAX_INPUT_LENGTH = 16_000;

/** Maximum allowed input length for chatbot messages */
const MAX_CHATBOT_LENGTH = 4_000;

/**
 * Patterns that indicate prompt injection attempts.
 * Each pattern has a name (for logging) and a regex.
 */
const INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // System prompt override attempts
  {
    name: 'system_prompt_override',
    pattern:
      /(?:ignore|forget|disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|system|initial)\s+(?:instructions?|prompts?|rules?|directives?|context)/i,
  },
  {
    name: 'role_impersonation',
    pattern:
      /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate|roleplay\s+as|behave\s+as)\s+(?:a\s+)?(?:different|new|unrestricted|jailbroken|evil|hacker)/i,
  },
  {
    name: 'instruction_injection',
    pattern:
      /(?:\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<<SYS>>|<\/SYS>>|###\s*(?:System|Human|Assistant|User)\s*:)/i,
  },
  {
    name: 'delimiter_injection',
    pattern: /(?:---+\s*(?:BEGIN|END|NEW)\s*(?:SYSTEM|PROMPT|INSTRUCTION))/i,
  },
  // Data exfiltration attempts
  {
    name: 'data_exfiltration',
    pattern:
      /(?:print|output|reveal|show|display|tell\s+me|repeat)\s+(?:your\s+)?(?:system\s+prompt|instructions|secret|api\s+key|password|token|credentials)/i,
  },
  // Encoded injection (base64 commands)
  {
    name: 'encoded_injection',
    pattern:
      /(?:base64|atob|btoa|decode)\s*\(\s*['"](?:[A-Za-z0-9+/=]{20,})['"]\s*\)/i,
  },
  // Code execution attempts
  {
    name: 'code_execution',
    pattern:
      /(?:eval|exec|system|subprocess|os\.(?:system|popen)|child_process|require\s*\(\s*['"](?:child_process|fs|net|http))/i,
  },
  // DAN / jailbreak patterns
  {
    name: 'jailbreak_attempt',
    pattern:
      /(?:DAN|Do\s+Anything\s+Now|DEVELOPER\s+MODE|jailbreak|no\s+restrictions|without\s+limits|unrestricted\s+mode)/i,
  },
];

/**
 * HTML/Markdown injection patterns to strip from user input.
 */
const MARKUP_PATTERNS: RegExp[] = [
  /<script[^>]*>[\s\S]*?<\/script>/gi,
  /<iframe[^>]*>[\s\S]*?<\/iframe>/gi,
  /<object[^>]*>[\s\S]*?<\/object>/gi,
  /<embed[^>]*>/gi,
  /<link[^>]*>/gi,
  /javascript:/gi,
  /on\w+\s*=\s*["'][^"']*["']/gi,
  /data:\s*text\/html/gi,
];

/** Result of prompt guard analysis */
export interface PromptGuardResult {
  /** Whether the input is safe to send to the LLM */
  safe: boolean;
  /** Sanitized version of the input (if safe) */
  sanitized: string;
  /** Names of detected injection patterns (if any) */
  detectedPatterns: string[];
  /** Human-readable reason if blocked */
  reason?: string;
}

/**
 * Guard user input before sending to LLM.
 * Detects injection attempts, sanitizes markup, and enforces length limits.
 *
 * @param input - Raw user input string
 * @param options - Optional configuration
 * @returns PromptGuardResult with safety assessment and sanitized input
 *
 * @example
 * ```ts
 * const result = guardPromptInput(userMessage);
 * if (!result.safe) {
 *   return Response.json({ error: result.reason }, { status: 400 });
 * }
 * // Use result.sanitized for the LLM call
 * ```
 */
export function guardPromptInput(
  input: string,
  options: {
    maxLength?: number;
    allowMarkdown?: boolean;
    context?: string;
  } = {}
): PromptGuardResult {
  const {
    maxLength = MAX_INPUT_LENGTH,
    allowMarkdown = false,
    context = 'unknown',
  } = options;

  // Check for empty input
  if (!input || typeof input !== 'string') {
    return {
      safe: false,
      sanitized: '',
      detectedPatterns: ['empty_input'],
      reason: 'Input is required',
    };
  }

  const trimmed = input.trim();

  // Length check
  if (trimmed.length > maxLength) {
    logWarn('Prompt guard: input exceeds maximum length', {
      context,
      inputLength: trimmed.length,
      maxLength,
    });
    return {
      safe: false,
      sanitized: trimmed.slice(0, maxLength),
      detectedPatterns: ['excessive_length'],
      reason: `Input exceeds maximum length of ${maxLength} characters`,
    };
  }

  // Check for injection patterns
  const detectedPatterns: string[] = [];
  for (const { name, pattern } of INJECTION_PATTERNS) {
    if (pattern.test(trimmed)) {
      detectedPatterns.push(name);
    }
  }

  if (detectedPatterns.length > 0) {
    logWarn('Prompt injection attempt detected', {
      context,
      patterns: detectedPatterns,
      inputPreview: trimmed.slice(0, 100),
    });
    return {
      safe: false,
      sanitized: '',
      detectedPatterns,
      reason:
        'Your message contains patterns that are not allowed. Please rephrase your request.',
    };
  }

  // Sanitize markup if not allowed
  let sanitized = trimmed;
  if (!allowMarkdown) {
    for (const pattern of MARKUP_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }
  }

  // Remove null bytes and control characters (except newlines and tabs)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  logInfo('Prompt guard: input passed validation', {
    context,
    originalLength: input.length,
    sanitizedLength: sanitized.length,
  });

  return {
    safe: true,
    sanitized,
    detectedPatterns: [],
  };
}

/**
 * Guard chatbot-specific input with stricter limits.
 *
 * @param input - Raw chatbot message
 * @returns PromptGuardResult
 */
export function guardChatbotInput(input: string): PromptGuardResult {
  return guardPromptInput(input, {
    maxLength: MAX_CHATBOT_LENGTH,
    allowMarkdown: false,
    context: 'chatbot',
  });
}

/**
 * Guard API generation prompts — allows markdown (code blocks) but checks for injection.
 *
 * @param input - Raw API generation prompt
 * @returns PromptGuardResult
 */
export function guardApiGenerationInput(input: string): PromptGuardResult {
  return guardPromptInput(input, {
    maxLength: MAX_INPUT_LENGTH,
    allowMarkdown: true,
    context: 'api-generation',
  });
}
