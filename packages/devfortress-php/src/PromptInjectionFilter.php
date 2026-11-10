<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * A16: Indirect Prompt Injection Filter.
 *
 * Mirrors packages/devfortress-sdk/src/security-extensions.ts's
 * PromptInjectionFilter.
 */
final class PromptInjectionFilter
{
    /** @var list<array{pattern: string, name: string, weight: int}> */
    private const INJECTION_PATTERNS = [
        ['pattern' => 'ignore\s+(previous|above|all|prior)\s+(instructions?|context|rules?)', 'name' => 'instruction_override', 'weight' => 40],
        ['pattern' => 'you\s+are\s+now\s+(a|an|the)', 'name' => 'role_assignment', 'weight' => 35],
        ['pattern' => 'system\s*:\s*|\[SYSTEM\]|<\|system\|>', 'name' => 'system_prompt_injection', 'weight' => 45],
        ['pattern' => 'forget\s+(everything|all|what)', 'name' => 'memory_wipe', 'weight' => 40],
        ['pattern' => 'do\s+not\s+(follow|obey|listen)', 'name' => 'disobedience_injection', 'weight' => 35],
        ['pattern' => 'act\s+as\s+(if|though)|pretend\s+(to\s+be|you)', 'name' => 'persona_injection', 'weight' => 30],
        ['pattern' => '<script>|javascript:|onerror=|onload=', 'name' => 'xss_in_data', 'weight' => 50],
        ['pattern' => '\bexec\s*\(|eval\s*\(|__import__', 'name' => 'code_execution', 'weight' => 50],
        ['pattern' => 'translate.*to.*base64|encode.*payload', 'name' => 'encoding_evasion', 'weight' => 25],
        ['pattern' => 'reveal\s+(your|the)\s+(system|secret|api|key|password)', 'name' => 'secret_extraction', 'weight' => 45],
    ];

    /** @var list<array{regex: string, name: string, weight: int}> */
    private readonly array $patterns;

    /** @param list<string> $customPatterns */
    public function __construct(
        private readonly string $sensitivity = 'medium',
        array $customPatterns = [],
        private readonly int $maxScanLength = 100_000,
    ) {
        $patterns = array_map(
            static fn (array $p) => ['regex' => '/' . $p['pattern'] . '/iu', 'name' => $p['name'], 'weight' => $p['weight']],
            self::INJECTION_PATTERNS,
        );
        foreach ($customPatterns as $i => $pattern) {
            $patterns[] = ['regex' => '/' . $pattern . '/iu', 'name' => "custom_{$i}", 'weight' => 30];
        }
        $this->patterns = $patterns;
    }

    /** @return array{safe: bool, confidence: float, severity: string, detectedPatterns: list<string>, reason: string} */
    public function scan(string $content): array
    {
        $text = substr($content, 0, $this->maxScanLength);
        $detectedPatterns = [];
        $totalWeight = 0;

        foreach ($this->patterns as $pattern) {
            if (@preg_match($pattern['regex'], $text) === 1) {
                $detectedPatterns[] = $pattern['name'];
                $totalWeight += $pattern['weight'];
            }
        }

        $sensitivityMultiplier = match ($this->sensitivity) {
            'high' => 1.5,
            'low' => 0.7,
            default => 1.0,
        };

        $score = min(100, (int) round($totalWeight * $sensitivityMultiplier));
        $confidence = $detectedPatterns === [] ? 0.1 : min(0.99, 0.5 + count($detectedPatterns) * 0.15);

        $severity = match (true) {
            $score >= 70 => 'CRITICAL',
            $score >= 45 => 'HIGH',
            $score >= 20 => 'MEDIUM',
            default => 'LOW',
        };

        return [
            'safe' => $score < 30,
            'confidence' => $confidence,
            'severity' => $severity,
            'detectedPatterns' => $detectedPatterns,
            'reason' => $detectedPatterns !== []
                ? 'Prompt injection detected: ' . implode(', ', $detectedPatterns) . " (score={$score})"
                : 'Content appears safe',
        ];
    }

    /**
     * Alias for scan(), matching Node's scanAgentInput().
     *
     * @return array{safe: bool, confidence: float, severity: string, detectedPatterns: list<string>, reason: string}
     */
    public function scanAgentInput(string $content): array
    {
        return $this->scan($content);
    }
}
