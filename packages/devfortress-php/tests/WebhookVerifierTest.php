<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\Tests\Support\Vectors;
use DevFortress\Sdk\WebhookVerifier;
use PHPUnit\Framework\TestCase;

final class WebhookVerifierTest extends TestCase
{
    public function testEveryWebhookVectorGivesItsExpectedVerdict(): void
    {
        $vectors = Vectors::webhook()['vectors'];
        self::assertIsArray($vectors);
        self::assertGreaterThanOrEqual(15, count($vectors));
        foreach ($vectors as $v) {
            self::assertIsArray($v);
            $result = WebhookVerifier::verify(
                (string) $v['body'],
                (string) $v['signature'],
                (string) $v['timestamp'],
                (string) $v['secret'],
                now: (string) $v['now'],
            );
            self::assertSame($v['expected_valid'], $result->valid, (string) $v['name'] . ': ' . (string) $result->reason);
        }
    }

    private static function sign(string $ts, string $body, string $secret): string
    {
        return hash_hmac('sha256', $ts . '.' . $body, $secret);
    }

    public function testValidTamperedStaleAndWrongSecretCases(): void
    {
        $secret = 'whsec_unit_test_secret';
        $body = '{"event_id":"e1"}';
        $ts = '2026-01-15T12:00:00.000Z';
        $sig = self::sign($ts, $body, $secret);

        self::assertTrue(WebhookVerifier::verify($body, $sig, $ts, $secret, now: $ts)->valid);
        self::assertSame('signature_mismatch', WebhookVerifier::verify($body . ' ', $sig, $ts, $secret, now: $ts)->reason);
        self::assertSame('signature_mismatch', WebhookVerifier::verify($body, self::sign($ts, $body, 'other'), $ts, $secret, now: $ts)->reason);
        self::assertSame('timestamp_expired', WebhookVerifier::verify($body, $sig, $ts, $secret, now: '2026-01-15T12:05:01.000Z')->reason);
        self::assertTrue(WebhookVerifier::verify($body, $sig, $ts, $secret, now: '2026-01-15T12:05:00.000Z')->valid);
        self::assertSame('invalid_timestamp', WebhookVerifier::verify($body, $sig, 'yesterday', $secret, now: $ts)->reason);
        self::assertSame('invalid_signature', WebhookVerifier::verify($body, 'abc', $ts, $secret, now: $ts)->reason);
        self::assertSame('invalid_signature', WebhookVerifier::verify($body, $sig . "\n", $ts, $secret, now: $ts)->reason);
    }

    public function testAnOffsetTimestampIsConvertedToUtc(): void
    {
        $secret = 's';
        $body = '{}';
        $ts = '2026-01-15T14:00:00.000+02:00';
        $sig = self::sign($ts, $body, $secret);
        self::assertTrue(WebhookVerifier::verify($body, $sig, $ts, $secret, now: '2026-01-15T12:00:10.000Z')->valid);
        self::assertSame('timestamp_expired', WebhookVerifier::verify($body, $sig, $ts, $secret, now: '2026-01-15T12:06:00.000Z')->reason);
    }

    public function testNonceReplayIsDetectedThroughTheCallback(): void
    {
        $body = '{"nonce":"a1b2c3d4e5f60718293a4b5c6d7e8f90"}';
        $ts = '2026-01-15T12:00:00.000Z';
        $sig = self::sign($ts, $body, 's');
        $seen = [];
        $check = static function (string $nonce) use (&$seen): bool {
            if (isset($seen[$nonce])) {
                return false;
            }
            $seen[$nonce] = true;

            return true;
        };

        self::assertTrue(WebhookVerifier::verify($body, $sig, $ts, 's', now: $ts, nonceCheck: $check)->valid);
        $second = WebhookVerifier::verify($body, $sig, $ts, 's', now: $ts, nonceCheck: $check);
        self::assertFalse($second->valid);
        self::assertSame('replay_detected', $second->reason);
    }

    public function testAMissingOrMalformedNonceFailsWhenReplayTrackingIsOn(): void
    {
        $ts = '2026-01-15T12:00:00.000Z';
        $always = static fn (string $n): bool => true;
        foreach (['{}' => 'nonce_invalid', '{"nonce":"short"}' => 'nonce_invalid', '[1]' => 'invalid_body', 'not json' => 'invalid_body'] as $body => $reason) {
            $body = (string) $body;
            $result = WebhookVerifier::verify($body, self::sign($ts, $body, 's'), $ts, 's', now: $ts, nonceCheck: $always);
            self::assertSame($reason, $result->reason, $body);
        }
    }
}
