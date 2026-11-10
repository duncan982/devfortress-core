<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\Classifier;
use PHPUnit\Framework\TestCase;

final class ClassifierTest extends TestCase
{
    public function testEncodedSqlInjectionIsFlagged(): void
    {
        self::assertContains('sql_injection', Classifier::detectSuspicious('/search q=1%27%20OR%20%271%27%3D%271'));
        self::assertContains('sql_injection', Classifier::detectSuspicious('/search q=1+UNION+SELECT+password+FROM+users'));
    }

    public function testEncodedXssAndTraversalAreFlagged(): void
    {
        self::assertContains('xss', Classifier::detectSuspicious('/x q=%3Cscript%3Ealert(1)%3C/script%3E'));
        self::assertContains('path_traversal', Classifier::detectSuspicious('/x f=..%2F..%2Fetc%2Fpasswd'));
    }

    public function testALiteralPercentIsNotFlagged(): void
    {
        self::assertSame([], Classifier::detectSuspicious('/search q=100% organic'));
        self::assertSame([], Classifier::detectSuspicious('/discount code=SAVE20%'));
    }

    public function testDoubleEncodedInputIsHandledWithoutErrorAndNotDetected(): void
    {
        // One decoding pass only: %2527 becomes %27, not a quote. A known limit.
        self::assertSame([], Classifier::detectSuspicious('/x q=%2527%2520OR%2520%25271%2527%253D%25271'));
    }

    public function testRawMatchingIsUnchanged(): void
    {
        self::assertSame(['sql_injection'], Classifier::detectSuspicious("/x q=' or '1'='1"));
        self::assertSame([], Classifier::detectSuspicious('/plain'));
    }

    public function testInvalidUtf8DoesNotThrow(): void
    {
        self::assertSame([], Classifier::detectSuspicious("/x q=\xff\xfe"));
    }

    public function testEventShapeMirrorsThePythonClassifier(): void
    {
        self::assertNull(Classifier::buildEvent('203.0.113.7', 'GET', '/ok', 200, 5));

        $auth = Classifier::buildEvent('203.0.113.7', 'GET', '/secret', 401, 5, 'ua');
        self::assertIsArray($auth);
        self::assertSame('auth_failure', $auth['eventType']);
        self::assertSame('MEDIUM', $auth['severity']);
        self::assertSame('blocked', $auth['actionTaken']);
        self::assertSame('external', $auth['clMode']);
        self::assertSame('pre_auth', $auth['authPhase']);
        self::assertSame(['reason' => 'Authentication or authorization failed'], $auth['metadata']);

        $limit = Classifier::buildEvent('203.0.113.7', 'GET', '/x', 429, 5);
        self::assertIsArray($limit);
        self::assertSame(['rate_limit_exceeded', 'rate_limited'], [$limit['eventType'], $limit['actionTaken']]);

        $server = Classifier::buildEvent('203.0.113.7', 'GET', '/x', 503, 5, userId: 'u1');
        self::assertIsArray($server);
        self::assertSame(['5xx_error', 'HIGH', 'post_auth'], [$server['eventType'], $server['severity'], $server['authPhase']]);

        $notFound = Classifier::buildEvent('', 'GET', '/x', 404, 5);
        self::assertIsArray($notFound);
        self::assertSame(['4xx_error', 'LOW', '0.0.0.0'], [$notFound['eventType'], $notFound['severity'], $notFound['ip']]);

        $bad = Classifier::buildEvent('203.0.113.7', 'POST', '/x', 422, 5);
        self::assertIsArray($bad);
        self::assertSame('validation_error', $bad['eventType']);
    }

    public function testASuspiciousRequestOverridesTheStatusClassification(): void
    {
        $event = Classifier::buildEvent('203.0.113.7', 'GET', '/', 200, 5, query: "q=1%27%20OR%20%271%27=%271");
        self::assertIsArray($event);
        self::assertSame('suspicious_pattern', $event['eventType']);
        self::assertSame('HIGH', $event['severity']);
        self::assertSame('flagged', $event['actionTaken']);
        self::assertSame(['reason' => 'Suspicious patterns detected: sql_injection'], $event['metadata']);
    }
}
