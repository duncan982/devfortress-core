<?php


declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Agent Output Exfiltration Detector.
 *
 * Monitors AI agent outputs for potential data exfiltration patterns.
 * Detects when agent responses contain sensitive data that shouldn't
 * be included in outputs (PII, credentials, internal system info).
 * Mirrors packages/devfortress-sdk/src/agent-output-exfiltration-detector.ts.
 *
 * @phpstan-type AgentOutput array{agentId: string, outputContent: string, outputType: string, destinationType: string, timestamp: int}
 * @phpstan-type ExfiltrationResult array{detected: bool, threatType: string, confidence: float, matchedPatterns: list<string>, recommendation: string, redactedOutput?: string}
 */
final class AgentOutputExfiltrationDetector
{
    /** @var list<string> */
    private const DEFAULT_SENSITIVE_PATTERNS = [
        // Credit cards
        '/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/i',
        // SSN
        '/\b\d{3}-\d{2}-\d{4}\b/i',
        // Email addresses in unexpected contexts
        '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/i',
        // API keys / tokens (high entropy strings)
        '/(?:api[_-]?key|token|secret|password|credential)[\s:=]+["\']?[A-Za-z0-9+\/=_-]{20,}["\']?/i',
        // AWS keys
        '/(?:AKIA|ASIA)[A-Z0-9]{16}/i',
        // Private keys
        '/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/i',
        // Internal IPs
        '/\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+\b/i',
    ];

    /** @var list<string> */
    private readonly array $sensitivePatterns;
    private readonly int $maxOutputSizeBytes;
    private readonly bool $entropyDetection;
    private readonly float $entropyThreshold;

    /** @param list<string>|null $sensitivePatterns PCRE patterns, delimiters included (e.g. "/.../i") */
    public function __construct(
        ?array $sensitivePatterns = null,
        ?int $maxOutputSizeBytes = null,
        ?bool $entropyDetection = null,
        ?float $entropyThreshold = null,
    ) {
        $this->sensitivePatterns = $sensitivePatterns ?? self::DEFAULT_SENSITIVE_PATTERNS;
        $this->maxOutputSizeBytes = $maxOutputSizeBytes ?? 1_048_576;
        $this->entropyDetection = $entropyDetection ?? true;
        $this->entropyThreshold = $entropyThreshold ?? 4.5;
    }

    /**
     * @param array{agentId: string, outputContent: string, outputType: string, destinationType: string, timestamp: int} $output
     * @return ExfiltrationResult
     */
    public function analyze(array $output): array
    {
        if (getenv('FEATURE_PLATFORM_INTEL') === 'false') {
            return [
                'detected' => false,
                'threatType' => 'none',
                'confidence' => 0.0,
                'matchedPatterns' => [],
                'recommendation' => 'allow',
            ];
        }

        // Check output size.
        if (strlen($output['outputContent']) > $this->maxOutputSizeBytes) {
            return [
                'detected' => true,
                'threatType' => 'oversized-output',
                'confidence' => 0.7,
                'matchedPatterns' => [],
                'recommendation' => 'warn',
            ];
        }

        // Pattern matching.
        $matchedPatterns = [];
        foreach ($this->sensitivePatterns as $pattern) {
            if (preg_match($pattern, $output['outputContent']) === 1) {
                $matchedPatterns[] = $pattern;
            }
        }

        if ($matchedPatterns !== []) {
            // Faithfully ported from Node: this checks the *pattern source
            // strings themselves* for these substrings, not the matched
            // content. None of DEFAULT_SENSITIVE_PATTERNS' SSN/credit-card
            // entries literally contain "SSN" or "credit", so the
            // 'pii-leak' branch below is effectively unreachable with the
            // defaults, exactly as in agent-output-exfiltration-detector.ts
            // — ported as-is, not fixed, per the faithful-port mandate.
            $threatType = self::anyContains($matchedPatterns, ['PRIVATE KEY', 'AKIA'])
                ? 'credential-leak'
                : (self::anyContains($matchedPatterns, ['SSN', 'credit'])
                    ? 'pii-leak'
                    : 'system-info-leak');

            return [
                'detected' => true,
                'threatType' => $threatType,
                'confidence' => min(1.0, 0.5 + count($matchedPatterns) * 0.15),
                'matchedPatterns' => $matchedPatterns,
                'recommendation' => $threatType === 'credential-leak' ? 'block' : 'redact',
                'redactedOutput' => $this->redact($output['outputContent']),
            ];
        }

        // Entropy detection for unknown secrets.
        if ($this->entropyDetection) {
            $highEntropySegments = $this->findHighEntropySegments($output['outputContent']);
            if ($highEntropySegments !== []) {
                return [
                    'detected' => true,
                    'threatType' => 'high-entropy-secret',
                    'confidence' => 0.6,
                    'matchedPatterns' => $highEntropySegments,
                    'recommendation' => 'warn',
                ];
            }
        }

        return [
            'detected' => false,
            'threatType' => 'none',
            'confidence' => 0.0,
            'matchedPatterns' => [],
            'recommendation' => 'allow',
        ];
    }

    private function redact(string $content): string
    {
        $redacted = $content;
        foreach ($this->sensitivePatterns as $pattern) {
            $replaced = preg_replace($pattern, '[REDACTED]', $redacted);
            if ($replaced !== null) {
                $redacted = $replaced;
            }
        }

        return $redacted;
    }

    /** @return list<string> */
    private function findHighEntropySegments(string $content): array
    {
        $segments = [];
        // Look for long alphanumeric strings that might be secrets.
        preg_match_all('/[A-Za-z0-9+\/=_-]{32,}/', $content, $matches);
        foreach ($matches[0] as $candidate) {
            if (self::shannonEntropy($candidate) > $this->entropyThreshold) {
                $segments[] = substr($candidate, 0, 20) . '...';
            }
        }

        return $segments;
    }

    private static function shannonEntropy(string $str): float
    {
        $freq = [];
        $len = strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $char = $str[$i];
            $freq[$char] = ($freq[$char] ?? 0) + 1;
        }

        $entropy = 0.0;
        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy += $p * log($p, 2);
        }

        return -$entropy;
    }

    /**
     * @param list<string> $patterns
     * @param list<string> $needles
     */
    private static function anyContains(array $patterns, array $needles): bool
    {
        foreach ($patterns as $pattern) {
            foreach ($needles as $needle) {
                if (str_contains($pattern, $needle)) {
                    return true;
                }
            }
        }

        return false;
    }
}
