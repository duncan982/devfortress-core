<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use InvalidArgumentException;

/**
 * Request integrity headers for every SDK-to-platform call (contract v2).
 *
 * Canonical string: "{METHOD}.{requestTarget}.{timestamp}.{nonce}.{payloadHash}"
 * where METHOD is the uppercase HTTP method, requestTarget is the URL path plus
 * "?query" exactly as sent (no host, no re-encoding), and payloadHash is the
 * lowercase hex SHA-256 of the exact body bytes (the empty string for a request
 * with no body). The signature is the lowercase hex HMAC-SHA256 of that string,
 * keyed with the project API key (UTF-8). The timestamp is Unix epoch
 * milliseconds; the nonce is a dashed UUID v4, fresh for every request attempt.
 * Tolerance is 300 seconds.
 *
 * The API key never travels on a signed request. X-DevFortress-Key-Id is a
 * non-secret identifier derived from the key (first 32 hex characters of its
 * SHA-256); the platform verifies the HMAC with the key it has stored.
 */
final class RequestSigner
{
    public const SIGNATURE_VERSION = '2';
    public const TOLERANCE_SECONDS = 300;

    public const KEY_ID_HEADER = 'X-DevFortress-Key-Id';
    public const VERSION_HEADER = 'X-DevFortress-Signature-Version';
    public const NONCE_HEADER = 'X-DevFortress-Nonce';
    public const TIMESTAMP_HEADER = 'X-DevFortress-Timestamp';
    public const PAYLOAD_HASH_HEADER = 'X-DevFortress-Payload-Hash';
    public const SIGNATURE_HEADER = 'X-DevFortress-Signature';

    public function __construct(private readonly string $apiKey)
    {
        if ($apiKey === '') {
            throw new InvalidArgumentException('DevFortress: an API key is required');
        }
    }

    /** Non-secret key ID: first 32 hex characters of SHA-256 over the UTF-8 key. */
    public static function deriveKeyId(string $apiKey): string
    {
        return substr(hash('sha256', $apiKey), 0, 32);
    }

    public function keyId(): string
    {
        return self::deriveKeyId($this->apiKey);
    }

    /**
     * Return the six signing headers (key ID, version, nonce, timestamp, hash, signature).
     *
     * @return array<string, string>
     */
    public function sign(
        string $method,
        string $requestTarget,
        string $body,
        ?string $timestamp = null,
        ?string $nonce = null,
    ): array {
        $ts = $timestamp ?? self::nowMs();
        $n = $nonce ?? self::uuidV4();
        $digest = self::digest($this->apiKey, $method, $requestTarget, $ts, $n, $body);

        return [
            self::KEY_ID_HEADER => $this->keyId(),
            self::VERSION_HEADER => self::SIGNATURE_VERSION,
            self::NONCE_HEADER => $n,
            self::TIMESTAMP_HEADER => $ts,
            self::PAYLOAD_HASH_HEADER => $digest['payloadHash'],
            self::SIGNATURE_HEADER => $digest['signature'],
        ];
    }

    /**
     * Return "valid", "invalid", "expired", "missing" or "unsupported_version".
     *
     * $headers uses the wire header names. Mirrors the platform's check.
     *
     * @param array<string, string|null> $headers
     */
    public static function verify(
        string $apiKey,
        string $method,
        string $requestTarget,
        string $body,
        array $headers,
        ?int $nowMs = null,
    ): string {
        $nonce = $headers[self::NONCE_HEADER] ?? null;
        $ts = $headers[self::TIMESTAMP_HEADER] ?? null;
        $payloadHash = $headers[self::PAYLOAD_HASH_HEADER] ?? null;
        $signature = $headers[self::SIGNATURE_HEADER] ?? null;
        if ($nonce === null || $nonce === '' || $ts === null || $ts === ''
            || $payloadHash === null || $payloadHash === '' || $signature === null || $signature === '') {
            return 'missing';
        }
        if (($headers[self::VERSION_HEADER] ?? null) !== self::SIGNATURE_VERSION) {
            return 'unsupported_version';
        }

        $expected = self::digest($apiKey, $method, $requestTarget, $ts, $nonce, $body);
        $hashOk = hash_equals($expected['payloadHash'], strtolower($payloadHash));
        $sigOk = hash_equals($expected['signature'], strtolower($signature));
        if (!($hashOk && $sigOk)) {
            return 'invalid';
        }

        if (preg_match('/^-?[0-9]+$/D', $ts) !== 1) {
            return 'invalid';
        }
        $now = $nowMs ?? (int) self::nowMs();
        $age = abs($now - (int) $ts);

        return $age > self::TOLERANCE_SECONDS * 1000 ? 'expired' : 'valid';
    }

    /**
     * The request target for a URL: path plus "?query" as written, no scheme,
     * host or fragment, and nothing re-encoded or normalised. An empty path is "/".
     */
    public static function requestTargetFromUrl(string $url): string
    {
        $hash = strpos($url, '#');
        if ($hash !== false) {
            $url = substr($url, 0, $hash);
        }
        $rest = preg_replace('#^[A-Za-z][A-Za-z0-9+.\-]*://[^/?]*#', '', $url) ?? $url;
        if ($rest === '' || $rest[0] === '?') {
            return '/' . $rest;
        }

        return $rest;
    }

    /** A dashed UUID v4 from random_bytes. */
    public static function uuidV4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12),
        );
    }

    /** Unix epoch milliseconds as a decimal string. */
    private static function nowMs(): string
    {
        return (string) (int) floor(microtime(true) * 1000);
    }

    /** @return array{payloadHash: string, signature: string} */
    private static function digest(
        string $apiKey,
        string $method,
        string $requestTarget,
        string $timestamp,
        string $nonce,
        string $body,
    ): array {
        $payloadHash = hash('sha256', $body);
        $canonical = strtoupper($method) . '.' . $requestTarget . '.' . $timestamp . '.' . $nonce . '.' . $payloadHash;

        return [
            'payloadHash' => $payloadHash,
            'signature' => hash_hmac('sha256', $canonical, $apiKey),
        ];
    }
}
