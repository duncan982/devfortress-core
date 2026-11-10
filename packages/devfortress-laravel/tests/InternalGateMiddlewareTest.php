<?php

declare(strict_types=1);

namespace DevFortress\Laravel\Tests;

use DevFortress\Laravel\Tests\Support\RecordingTransport;
use DevFortress\Sdk\Client;

/**
 * Internal/hybrid-mode pre-response gate (TODO 407 port) —
 * DevFortressMiddleware::internalGate(). Adapter-level proof against the
 * real middleware class through a real Laravel route, the same bar as the
 * already-completed Ruby Rails adapter's middleware_test.rb internal-mode
 * tests (not just engine-level unit tests).
 */
final class InternalGateMiddlewareTest extends TestCase
{
    /**
     * Swap the singleton for a client in internal/hybrid mode that records
     * instead of sending. Sets the `devfortress.mode` config key too —
     * DevFortressMiddleware::internalGate() reads the mode from Laravel's
     * config repository (not from the Client instance) as its first,
     * cheap short-circuit before even resolving the Client, so both must
     * agree for the gate to run at all.
     */
    private function useModeTransport(string $mode): RecordingTransport
    {
        config(['devfortress.mode' => $mode]);
        $this->transport = new RecordingTransport();
        $transport = $this->transport;
        $this->app->singleton(Client::class, static fn (): Client => new Client(
            self::KEY,
            self::ENDPOINT,
            2.0,
            1,
            defaults: ['appId' => 'adapter-tests', 'environment' => 'testing'],
            transport: $transport,
            sleeper: static function (float $s): void {
            },
            mode: $mode,
        ));

        return $this->transport;
    }

    public function testInternalModeCleanRequestReachesTheApp(): void
    {
        $this->useModeTransport('internal');
        $this->get('/ok')->assertOk()->assertSee('fine');
    }

    public function testInternalModeScannerUserAgentIsBlockedBeforeReachingTheApp(): void
    {
        $this->useModeTransport('internal');
        $response = $this->get('/ok', ['User-Agent' => 'sqlmap/1.7']);

        $response->assertStatus(403);
        $body = json_decode((string) $response->getContent(), true);
        self::assertIsArray($body);
        self::assertSame('blocked', $body['error']);
        self::assertSame('block', $body['reason']);
    }

    public function testInternalModeBlockedIpStaysBlockedOnALaterCleanRequest(): void
    {
        $this->useModeTransport('internal');
        $this->call('GET', '/ok', [], [], [], [
            'HTTP_USER_AGENT' => 'sqlmap/1.7',
            'REMOTE_ADDR' => '198.51.100.30',
        ])->assertStatus(403);

        $second = $this->call('GET', '/ok', [], [], [], ['REMOTE_ADDR' => '198.51.100.30']);
        $second->assertStatus(403);
    }

    public function testInternalModeSqlInjectionInTheRawQueryIsBlocked(): void
    {
        $this->useModeTransport('internal');
        // Literal (not percent-encoded) special characters, matching this
        // port's documented raw-query-string behavior (same as Python's
        // query_string.decode("latin-1") — the regex requires literal
        // whitespace/quote characters, not their percent-encoded form).
        $response = $this->call('GET', "/search?q=' OR 1=1 --", [], [], [], ['REMOTE_ADDR' => '198.51.100.31']);
        $response->assertStatus(403);
    }

    public function testExternalModeIsUnaffectedByTheInternalGate(): void
    {
        config(['devfortress.mode' => 'external']);
        $this->useTransport();
        $this->get('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk()->assertSee('fine');
    }

    public function testHybridModeBlocksViaInternalFirstSameAsInternalMode(): void
    {
        $this->useModeTransport('hybrid');
        $response = $this->call('GET', '/ok', [], [], [], [
            'HTTP_USER_AGENT' => 'sqlmap/1.7',
            'REMOTE_ADDR' => '198.51.100.32',
        ]);

        $response->assertStatus(403);
        /** @var Client $client */
        $client = $this->app->make(Client::class);
        self::assertSame('closed', $client->circuitBreaker?->getState(),
            'the circuit breaker must stay closed — no second relay/external call for a decision the internal engine already flagged');
    }

    public function testExcludedHealthPathBypassesTheInternalGateEvenInInternalMode(): void
    {
        $this->useModeTransport('internal');
        // /health is in config('devfortress.exclude_paths') default; even
        // though its own route returns a 500 (see TestCase::defineRoutes),
        // an attack-shaped User-Agent here must not trigger the gate at all.
        $this->get('/health', ['User-Agent' => 'sqlmap/1.7'])->assertStatus(500);
    }
}
