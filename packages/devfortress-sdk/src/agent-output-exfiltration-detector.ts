/**
 * DevFortress SDK — Agent Output Exfiltration Detector
 *
 * Monitors AI agent outputs for potential data exfiltration patterns.
 * Detects when agent responses contain sensitive data that shouldn't
 * be included in outputs (PII, credentials, internal system info).
 *
 * Patent Pending.
 *
 * @packageDocumentation
 */

export interface ExfiltrationDetectorConfig {
  /** Patterns to detect (regex strings) */
  sensitivePatterns?: string[];
  /** Maximum allowed output size in bytes */
  maxOutputSizeBytes?: number;
  /** Enable entropy-based secret detection */
  entropyDetection?: boolean;
  /** Entropy threshold for secret detection (default: 4.5) */
  entropyThreshold?: number;
}

export interface AgentOutput {
  agentId: string;
  outputContent: string;
  outputType: 'text' | 'json' | 'code' | 'file';
  destinationType: 'user' | 'api' | 'file' | 'log';
  timestamp: number;
}

export interface ExfiltrationResult {
  detected: boolean;
  threatType:
    | 'pii-leak'
    | 'credential-leak'
    | 'system-info-leak'
    | 'high-entropy-secret'
    | 'oversized-output'
    | 'none';
  confidence: number;
  matchedPatterns: string[];
  recommendation: 'block' | 'redact' | 'warn' | 'allow';
  redactedOutput?: string;
}

const DEFAULT_SENSITIVE_PATTERNS = [
  // Credit cards
  '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b',
  // SSN
  '\\b\\d{3}-\\d{2}-\\d{4}\\b',
  // Email addresses in unexpected contexts
  '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z]{2,}\\b',
  // API keys / tokens (high entropy strings)
  '(?:api[_-]?key|token|secret|password|credential)[\\s:=]+["\']?[A-Za-z0-9+/=_-]{20,}["\']?',
  // AWS keys
  '(?:AKIA|ASIA)[A-Z0-9]{16}',
  // Private keys
  '-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
  // Internal IPs
  '\\b(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)[0-9.]+\\b',
];

export class AgentOutputExfiltrationDetector {
  private config: Required<ExfiltrationDetectorConfig>;
  private compiledPatterns: RegExp[];

  constructor(config: ExfiltrationDetectorConfig = {}) {
    this.config = {
      sensitivePatterns: config.sensitivePatterns ?? DEFAULT_SENSITIVE_PATTERNS,
      maxOutputSizeBytes: config.maxOutputSizeBytes ?? 1_048_576,
      entropyDetection: config.entropyDetection ?? true,
      entropyThreshold: config.entropyThreshold ?? 4.5,
    };
    this.compiledPatterns = this.config.sensitivePatterns.map(
      p => new RegExp(p, 'gi')
    );
  }

  analyze(output: AgentOutput): ExfiltrationResult {
    if (process.env.FEATURE_PLATFORM_INTEL === 'false') {
      return {
        detected: false,
        threatType: 'none',
        confidence: 0,
        matchedPatterns: [],
        recommendation: 'allow',
      };
    }

    // Check output size
    if (
      Buffer.byteLength(output.outputContent) > this.config.maxOutputSizeBytes
    ) {
      return {
        detected: true,
        threatType: 'oversized-output',
        confidence: 0.7,
        matchedPatterns: [],
        recommendation: 'warn',
      };
    }

    // Pattern matching
    const matchedPatterns: string[] = [];
    for (let i = 0; i < this.compiledPatterns.length; i++) {
      this.compiledPatterns[i].lastIndex = 0;
      if (this.compiledPatterns[i].test(output.outputContent)) {
        matchedPatterns.push(this.config.sensitivePatterns[i]);
      }
    }

    if (matchedPatterns.length > 0) {
      const threatType = matchedPatterns.some(
        p => p.includes('PRIVATE KEY') || p.includes('AKIA')
      )
        ? ('credential-leak' as const)
        : matchedPatterns.some(p => p.includes('SSN') || p.includes('credit'))
          ? ('pii-leak' as const)
          : ('system-info-leak' as const);

      return {
        detected: true,
        threatType,
        confidence: Math.min(1, 0.5 + matchedPatterns.length * 0.15),
        matchedPatterns,
        recommendation: threatType === 'credential-leak' ? 'block' : 'redact',
        redactedOutput: this.redact(output.outputContent),
      };
    }

    // Entropy detection for unknown secrets
    if (this.config.entropyDetection) {
      const highEntropySegments = this.findHighEntropySegments(
        output.outputContent
      );
      if (highEntropySegments.length > 0) {
        return {
          detected: true,
          threatType: 'high-entropy-secret',
          confidence: 0.6,
          matchedPatterns: highEntropySegments,
          recommendation: 'warn',
        };
      }
    }

    return {
      detected: false,
      threatType: 'none',
      confidence: 0,
      matchedPatterns: [],
      recommendation: 'allow',
    };
  }

  private redact(content: string): string {
    let redacted = content;
    for (const pattern of this.compiledPatterns) {
      pattern.lastIndex = 0;
      redacted = redacted.replace(pattern, '[REDACTED]');
    }
    return redacted;
  }

  private findHighEntropySegments(content: string): string[] {
    const segments: string[] = [];
    // Look for long alphanumeric strings that might be secrets
    const candidates = content.match(/[A-Za-z0-9+/=_-]{32,}/g) || [];
    for (const candidate of candidates) {
      if (this.shannonEntropy(candidate) > this.config.entropyThreshold) {
        segments.push(candidate.slice(0, 20) + '...');
      }
    }
    return segments;
  }

  private shannonEntropy(str: string): number {
    const freq: Record<string, number> = {};
    for (const char of str) freq[char] = (freq[char] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((sum, count) => {
      const p = count / len;
      return sum + p * Math.log2(p);
    }, 0);
  }
}
