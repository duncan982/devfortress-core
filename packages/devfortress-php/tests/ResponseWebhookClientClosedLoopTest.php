<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\ResponseWebhookClient;
use PHPUnit\Framework\TestCase;

/**
 * Closed-loop local self-enforcement — TODO 358 regression coverage.
 *
 * Node's own external-mode reference (devfortress.ts's handleWebhook/
 * isBlocked pair) and Python's ClosedLoopEngine both self-enforce
 * block/revocation decisions via a local cache, checked unconditionally
 * before any remote fallback. This SDK previously only delivered and
 * verified these commands, leaving every embedding app to implement its
 * own cache. These tests cover the ported local-cache behavior.
 */
final class ResponseWebhookClientClosedLoopTest extends TestCase
{
    private function client(): ResponseWebhookClient
    {
        return new ResponseWebhookClient('https://example.test/webhook', 'secret');
    }

    public function testIpBlockCachedWhenSeverityHighOrCritical(): void
    {
        $client = $this->client();
        self::assertFalse($client->isIPBlocked('1.2.3.4'));

        $client->recordInboundCommand(['type' => 'ip_block', 'ip' => '1.2.3.4', 'severity' => 'high']);

        self::assertTrue($client->isIPBlocked('1.2.3.4'));
    }

    public function testIpBlockNotCachedWhenSeverityLow(): void
    {
        $client = $this->client();
        $client->recordInboundCommand(['type' => 'ip_block', 'ip' => '5.6.7.8', 'severity' => 'low']);

        self::assertFalse($client->isIPBlocked('5.6.7.8'));
    }

    public function testIpBlockDefaultsToCachedWhenSeverityUnset(): void
    {
        $client = $this->client();
        $client->recordInboundCommand(['type' => 'ip_block', 'ip' => '9.9.9.9']);

        self::assertTrue($client->isIPBlocked('9.9.9.9'));
    }

    public function testSessionRevocationCachesUserAndIp(): void
    {
        $client = $this->client();
        self::assertFalse($client->isUserBlocked('user-1'));

        $client->recordInboundCommand(['type' => 'session_revocation', 'user_id' => 'user-1', 'ip' => '10.0.0.1']);

        self::assertTrue($client->isUserBlocked('user-1'));
        self::assertTrue($client->isIPBlocked('10.0.0.1'));
    }

    public function testUnrelatedIpOrUserNotBlocked(): void
    {
        $client = $this->client();
        $client->recordInboundCommand(['type' => 'ip_block', 'ip' => '1.1.1.1', 'severity' => 'critical']);

        self::assertFalse($client->isIPBlocked('2.2.2.2'));
        self::assertFalse($client->isUserBlocked('unrelated-user'));
    }
}
