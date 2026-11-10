<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Maps an HTTP response to a DevFortress event. */
final class Classifier
{
    private const SQL = [
        '/(\bor\b.*=.*)/i',
        '/(\bunion\b.*\bselect\b)/i',
        '/(\bdrop\b.*\btable\b)/i',
        '/(\'\s*or\s*\'1\'\s*=\s*\'1)/i',
    ];

    private const XSS = [
        '/<script[^>]*>[\s\S]*?<\/script>/i',
        '/javascript:/i',
        '/onerror\s*=\s*/i',
        '/onload\s*=\s*/i',
    ];

    private const TRAVERSAL = [
        '/\.\.[\/\\\\]/',
        '/\/etc\/passwd/i',
    ];

    /**
     * Names of the suspicious patterns found in $text.
     *
     * Matches the raw text and one percent-decoding pass.
     *
     * @return list<string>
     */
    public static function detectSuspicious(string $text): array
    {
        $candidates = [$text];
        $decoded = urldecode($text);
        if ($decoded !== $text) {
            $candidates[] = $decoded;
        }

        $found = [];
        if (self::hit(self::SQL, $candidates)) {
            $found[] = 'sql_injection';
        }
        if (self::hit(self::XSS, $candidates)) {
            $found[] = 'xss';
        }
        if (self::hit(self::TRAVERSAL, $candidates)) {
            $found[] = 'path_traversal';
        }

        return $found;
    }

    /**
     * An event array, or null when the request is not security-relevant.
     *
     * @return array<string, mixed>|null
     */
    public static function buildEvent(
        string $ip,
        string $method,
        string $path,
        int $statusCode,
        int $latencyMs,
        ?string $userAgent = null,
        string $query = '',
        ?string $userId = null,
    ): ?array {
        $eventType = null;
        $severity = 'LOW';
        $reason = null;
        $action = 'monitored';

        if ($statusCode === 401 || $statusCode === 403) {
            $eventType = 'auth_failure';
            $severity = 'MEDIUM';
            $reason = 'Authentication or authorization failed';
            $action = 'blocked';
        } elseif ($statusCode === 400 || $statusCode === 422) {
            $eventType = 'validation_error';
            $reason = 'Request validation failed';
        } elseif ($statusCode === 429) {
            $eventType = 'rate_limit_exceeded';
            $severity = 'MEDIUM';
            $reason = 'Rate limit exceeded';
            $action = 'rate_limited';
        } elseif ($statusCode >= 500) {
            $eventType = '5xx_error';
            $severity = 'HIGH';
            $reason = 'Server error: ' . $statusCode;
        } elseif ($statusCode >= 400) {
            $eventType = '4xx_error';
            $reason = 'Client error: ' . $statusCode;
        }

        $suspicious = self::detectSuspicious($path . ' ' . $query);
        if ($suspicious !== []) {
            $eventType = 'suspicious_pattern';
            $severity = 'HIGH';
            $reason = 'Suspicious patterns detected: ' . implode(', ', $suspicious);
            $action = 'flagged';
        }

        if ($eventType === null) {
            return null;
        }

        return [
            'eventType' => $eventType,
            'ip' => $ip !== '' ? $ip : '0.0.0.0',
            'method' => $method,
            'path' => $path,
            'userAgent' => $userAgent,
            'statusCode' => $statusCode,
            'severity' => $severity,
            'clMode' => 'external',
            'authPhase' => $userId !== null && $userId !== '' ? 'post_auth' : 'pre_auth',
            'actionTaken' => $action,
            'responseLatencyMs' => $latencyMs,
            'userId' => $userId,
            'metadata' => ['reason' => $reason],
        ];
    }

    /**
     * @param list<string> $patterns
     * @param list<string> $candidates
     */
    private static function hit(array $patterns, array $candidates): bool
    {
        foreach ($candidates as $candidate) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $candidate) === 1) {
                    return true;
                }
            }
        }

        return false;
    }
}
