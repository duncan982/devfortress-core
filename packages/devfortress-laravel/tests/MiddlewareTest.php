<?php

declare(strict_types=1);

namespace DevFortress\Laravel\Tests;

use DevFortress\Laravel\Http\Middleware\DevFortressMiddleware;
use DevFortress\Laravel\Tests\Support\RecordingTransport;
use DevFortress\Sdk\RequestSigner;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

final class MiddlewareTest extends TestCase
{
    /** @return array<string, mixed> the first event of the first recorded request */
    private function firstEvent(RecordingTransport $t): array
    {
        self::assertNotSame([], $t->requests, 'no request was recorded');
        $body = json_decode($t->requests[0]['body'], true);
        self::assertIsArray($body);
        self::assertIsArray($body['events']);
        self::assertIsArray($body['events'][0]);

        /** @var array<string, mixed> */
        return $body['events'][0];
    }

    public function testASuccessfulRequestIsNotReported(): void
    {
        $t = $this->useTransport();
        $this->get('/ok')->assertOk();
        self::assertSame([], $t->requests);
    }

    public function testAnAuthFailureIsReportedWithThePythonEventShape(): void
    {
        $t = $this->useTransport();
        $this->get('/secret', ['User-Agent' => 'demo-agent'])->assertStatus(401);

        self::assertCount(1, $t->requests);
        $e = $this->firstEvent($t);
        self::assertSame('auth_failure', $e['eventType']);
        self::assertSame('GET', $e['method']);
        self::assertSame('/secret', $e['path']);
        self::assertSame(401, $e['statusCode']);
        self::assertSame('MEDIUM', $e['severity']);
        self::assertSame('external', $e['clMode']);
        self::assertSame('pre_auth', $e['authPhase']);
        self::assertSame('blocked', $e['actionTaken']);
        self::assertSame('demo-agent', $e['userAgent']);
        self::assertIsInt($e['responseLatencyMs']);
        self::assertSame('adapter-tests', $e['appId']);
        self::assertNull($e['userId']);
        self::assertSame(['reason' => 'Authentication or authorization failed'], $e['metadata']);
    }

    public function testEveryRequestTheAdapterSendsIsSignedAndCarriesNoKey(): void
    {
        $t = $this->useTransport();
        $this->get('/secret');
        $this->get('/boom');

        self::assertCount(2, $t->requests);
        foreach ($t->requests as $request) {
            $wire = $request['headers'];
            self::assertSame('valid', RequestSigner::verify(self::KEY, 'POST', '/api/events/ingest', $request['body'], $wire));
            self::assertSame(RequestSigner::deriveKeyId(self::KEY), $wire[RequestSigner::KEY_ID_HEADER]);
            self::assertFalse(str_contains($request['body'], self::KEY));
            foreach ($request['headers'] as $value) {
                self::assertFalse(str_contains($value, self::KEY));
            }
        }
    }

    public function testAServerErrorAndAValidationErrorAndANotFoundAreReported(): void
    {
        $t = $this->useTransport();
        $this->get('/boom')->assertStatus(500);
        $this->post('/submit')->assertStatus(422);
        $this->get('/missing-thing')->assertNotFound();
        $types = [];
        foreach ($t->requests as $r) {
            $body = json_decode($r['body'], true);
            self::assertIsArray($body);
            self::assertIsArray($body['events']);
            self::assertIsArray($body['events'][0]);
            $types[] = $body['events'][0]['eventType'];
        }
        self::assertSame(['5xx_error', 'validation_error', '4xx_error'], $types);
    }

    public function testEncodedSqlInjectionInTheRawQueryIsFlagged(): void
    {
        $t = $this->useTransport();
        $this->get('/search?q=1%27%20OR%20%271%27=%271&run=a%20b')->assertOk();
        $e = $this->firstEvent($t);
        self::assertSame('suspicious_pattern', $e['eventType']);
        self::assertSame('HIGH', $e['severity']);
        self::assertSame('flagged', $e['actionTaken']);
        self::assertSame('/search', $e['path']);
    }

    public function testALiteralPercentInAQueryIsNotFlagged(): void
    {
        $t = $this->useTransport();
        $this->get('/search?q=100%25+organic')->assertOk();
        self::assertSame([], $t->requests);
    }

    public function testExcludedPathsAreNeverReported(): void
    {
        $t = $this->useTransport();
        $this->get('/health')->assertStatus(500);
        self::assertSame([], $t->requests);
    }

    public function testTheEndUserIpFollowsForwardedForThenRealIpThenTheSocket(): void
    {
        $t = $this->useTransport();
        $this->get('/secret', ['X-Forwarded-For' => '203.0.113.9, 10.0.0.1', 'X-Real-IP' => '198.51.100.1']);
        $this->get('/secret', ['X-Real-IP' => '198.51.100.2']);
        $this->call('GET', '/secret', [], [], [], ['REMOTE_ADDR' => '192.0.2.44']);
        $ips = [];
        foreach ($t->requests as $r) {
            $body = json_decode($r['body'], true);
            self::assertIsArray($body);
            self::assertIsArray($body['events']);
            self::assertIsArray($body['events'][0]);
            $ips[] = $body['events'][0]['ip'];
        }
        self::assertSame(['203.0.113.9', '198.51.100.2', '192.0.2.44'], $ips);
    }

    public function testFiveDistinctEndUsersMakeFiveEvents(): void
    {
        $t = $this->useTransport();
        for ($i = 1; $i <= 5; $i++) {
            $this->get('/secret', ['X-Forwarded-For' => '203.0.113.' . (40 + $i)]);
        }
        self::assertCount(5, $t->requests);
    }

    public function testTheEventIsSentInTerminateNotWhileTheRequestIsHandled(): void
    {
        $t = $this->useTransport();
        $middleware = $this->app->make(DevFortressMiddleware::class);
        $request = Request::create('/secret', 'GET');
        $response = $middleware->handle($request, static fn (): Response => new Response('no', 401));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame([], $t->requests, 'handle() must not send anything');
        self::assertIsInt($request->attributes->get('devfortress.latency_ms'));

        $middleware->terminate($request, $response);
        self::assertCount(1, $t->requests);
    }

    public function testADeliveryFailureNeverChangesTheResponse(): void
    {
        $t = $this->useTransport(RecordingTransport::down());
        $this->get('/secret')->assertStatus(401)->assertSee('no');
        self::assertCount(1, $t->requests);
    }

    public function testWithoutAnApiKeyTheMiddlewareDoesNothing(): void
    {
        config(['devfortress.api_key' => null]);
        $t = $this->useTransport();
        $this->get('/secret')->assertStatus(401);
        self::assertSame([], $t->requests);
    }

    public function testItCanBeSwitchedOffInConfig(): void
    {
        config(['devfortress.enabled' => false]);
        $t = $this->useTransport();
        $this->get('/secret')->assertStatus(401);
        self::assertSame([], $t->requests);
    }
}
