<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use DateTimeInterface;
use InvalidArgumentException;
use stdClass;

/**
 * Inbound webhook signature verification.
 *
 * Contract (platform dispatcher, POST /api/webhooks/deliver):
 *
 * - X-DevFortress-Timestamp: ISO-8601 UTC timestamp of dispatch.
 * - X-DevFortress-Signature: hex HMAC-SHA256, keyed with the project's webhook
 *   secret, over the UTF-8 bytes of "{timestamp}.{rawBody}".
 * - Timestamps older than 300 seconds are rejected.
 * - The body carries a 32-char lowercase-hex "nonce". Replay tracking is left
 *   to the caller through $nonceCheck so the library keeps no state.
 */
final class WebhookVerifier
{
    public const TOLERANCE_SECONDS = 300;
    public const SIGNATURE_HEADER = 'X-DevFortress-Signature';
    public const TIMESTAMP_HEADER = 'X-DevFortress-Timestamp';

    private const ISO_PATTERN = '/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/D';

    /**
     * Verify a DevFortress webhook. Pass the body exactly as received.
     *
     * $nonceCheck($nonce) should return true the first time a nonce is seen and
     * false on replay; when supplied, a missing or malformed nonce fails.
     * $now is for tests: epoch seconds, a DateTimeInterface or an ISO-8601 string.
     *
     * @param (callable(string): bool)|null $nonceCheck
     */
    public static function verify(
        string $rawBody,
        string $signature,
        string $timestamp,
        string $secret,
        int $toleranceSeconds = self::TOLERANCE_SECONDS,
        int|float|DateTimeInterface|string|null $now = null,
        ?callable $nonceCheck = null,
    ): WebhookVerification {
        $tsMs = self::parseIsoMs($timestamp);
        if ($tsMs === null) {
            return new WebhookVerification(false, 'invalid_timestamp');
        }
        $ageMs = self::nowMs($now) - $tsMs;
        if ($ageMs > $toleranceSeconds * 1000) {
            return new WebhookVerification(false, 'timestamp_expired');
        }

        if (preg_match('/^[0-9a-fA-F]{64}$/D', $signature) !== 1) {
            return new WebhookVerification(false, 'invalid_signature');
        }

        $expected = hash_hmac('sha256', $timestamp . '.' . $rawBody, $secret, true);
        $given = hex2bin($signature);
        if ($given === false || !hash_equals($expected, $given)) {
            return new WebhookVerification(false, 'signature_mismatch');
        }

        if ($nonceCheck !== null) {
            $decoded = json_decode($rawBody);
            if (!$decoded instanceof stdClass) {
                return new WebhookVerification(false, 'invalid_body');
            }
            $nonce = $decoded->nonce ?? null;
            if (!is_string($nonce) || preg_match('/^[0-9a-f]{32}$/D', $nonce) !== 1) {
                return new WebhookVerification(false, 'nonce_invalid');
            }
            if (!$nonceCheck($nonce)) {
                return new WebhookVerification(false, 'replay_detected');
            }
        }

        return new WebhookVerification(true);
    }

    /** Epoch milliseconds for an ISO-8601 timestamp with a zone, or null when malformed. */
    private static function parseIsoMs(string $value): ?int
    {
        if (preg_match(self::ISO_PATTERN, $value, $m) !== 1) {
            return null;
        }
        [, $y, $mo, $d, $h, $mi, $s] = $m;
        $frac = $m[7];
        $zone = $m[8];

        $year = (int) $y;
        $month = (int) $mo;
        $day = (int) $d;
        $hour = (int) $h;
        $minute = (int) $mi;
        $second = (int) $s;
        if ($year < 1 || !checkdate($month, $day, $year) || $hour > 23 || $minute > 59 || $second > 59) {
            return null;
        }

        $seconds = gmmktime($hour, $minute, $second, $month, $day, $year);
        $millis = (int) str_pad(substr($frac, 0, 3), 3, '0');
        $ms = $seconds * 1000 + $millis;
        if ($zone !== 'Z') {
            $sign = $zone[0] === '+' ? 1 : -1;
            $offset = ((int) substr($zone, 1, 2)) * 3600 + ((int) substr($zone, 4, 2)) * 60;
            $ms -= $sign * $offset * 1000;
        }

        return $ms;
    }

    private static function nowMs(int|float|DateTimeInterface|string|null $now): int
    {
        if ($now === null) {
            return (int) floor(microtime(true) * 1000);
        }
        if ($now instanceof DateTimeInterface) {
            return $now->getTimestamp() * 1000 + intdiv((int) $now->format('u'), 1000);
        }
        if (is_string($now)) {
            $parsed = self::parseIsoMs($now);
            if ($parsed === null) {
                throw new InvalidArgumentException('now must be an ISO-8601 timestamp');
            }

            return $parsed;
        }

        return (int) floor($now * 1000);
    }
}
