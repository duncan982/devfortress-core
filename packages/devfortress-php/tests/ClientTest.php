<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use Closure;
use DevFortress\Sdk\Client;
use DevFortress\Sdk\Event;
use DevFortress\Sdk\LoggerInterface;
use DevFortress\Sdk\RequestSigner;
use DevFortress\Sdk\Tests\Support\RecordingTransport;
use DevFortress\Sdk\Transport\TransportResponse;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Stringable;

final class ClientTest extends TestCase
{
    private const KEY = 'vx_live_test_vector_key_do_not_use';

    private const EVENT = [
        'eventType' => 'auth_failure',
        'ip' => '203.0.113.7',
        'method' => 'POST',
        'path' => '/login',
        'severity' => 'LOW',
    ];

    /** @return array<string, mixed> */
    private static function body(RecordingTransport $t, int $i): array
    {
        $decoded = json_decode($t->requests[$i]['body'], true);
        self::assertIsArray($decoded);
        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param list<TransportResponse|\Throwable> $script
     *
     * @return array{0: Client, 1: RecordingTransport, 2: \ArrayObject<int, float>}
     */
    private static function client(array $script, int $retries = 3, ?object $logger = null, string $privacy = 'standard', int $batch = 25): array
    {
        $transport = new RecordingTransport($script);
        /** @var \ArrayObject<int, float> $sleeps */
        $sleeps = new \ArrayObject();
        $client = new Client(
            self::KEY,
            'http://platform.test/api/events/ingest',
            2.0,
            $retries,
            $logger,
            [],
            $privacy,
            $batch,
            1.0,
            $transport,
            static function (float $s) use ($sleeps): void {
                $sleeps[] = $s;
            },
        );

        return [$client, $transport, $sleeps];
    }

    public function testConstructionRequiresAnApiKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Client('');
    }

    public function testDefaultsMatchThePythonClient(): void
    {
        self::assertSame(15.0, Client::DEFAULT_TIMEOUT);
        self::assertSame(3, Client::DEFAULT_RETRIES);
        self::assertSame(25, Client::DEFAULT_BATCH_SIZE);
        self::assertSame(100, Client::MAX_SERVER_BATCH);
        self::assertSame('https://www.devfortress.net/api/events/ingest', Client::DEFAULT_ENDPOINT);
    }

    public function testEventsAreQueuedUntilFlushAndSentAsABatch(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{"success":true}')]);
        $client->trackEvent(self::EVENT);
        $client->trackEvent(Event::fromArray(self::EVENT));
        $client->trackEvents([self::EVENT]);
        self::assertSame(3, $client->pendingEvents());
        self::assertSame([], $transport->requests);

        $results = $client->flush();
        self::assertCount(1, $results);
        self::assertTrue($results[0]->ok);
        self::assertSame(0, $client->pendingEvents());
        self::assertCount(1, $transport->requests);
        $body = self::body($transport, 0);
        self::assertIsArray($body['events']);
        self::assertCount(3, $body['events']);
        self::assertSame('POST', $transport->request(0)['method']);
        self::assertSame('http://platform.test/api/events/ingest', $transport->request(0)['url']);
    }

    public function testEveryQueuedEventGetsATimestamp(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{}')]);
        $client->trackEvent(self::EVENT);
        $client->flush();
        $events = self::body($transport, 0)['events'];
        self::assertIsArray($events);
        self::assertIsArray($events[0]);
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/D', (string) $events[0]['timestamp']);
    }

    public function testFlushWithNothingQueuedMakesNoRequest(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{}')]);
        self::assertSame([], $client->flush());
        self::assertSame([], $transport->requests);
    }

    public function testTheQueueFlushesAtTheBatchSize(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{}')]);
        for ($i = 0; $i < 24; $i++) {
            $client->trackEvent(self::EVENT);
        }
        self::assertSame([], $transport->requests);
        $client->trackEvent(self::EVENT);
        self::assertCount(1, $transport->requests);
        $events = self::body($transport, 0)['events'];
        self::assertIsArray($events);
        self::assertCount(25, $events);
    }

    public function testFlushSplitsAtTheServerMaximum(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{}')], batch: 1000);
        for ($i = 0; $i < 150; $i++) {
            $client->trackEvent(self::EVENT);
        }
        $client->flush();
        $sizes = [];
        foreach (array_keys($transport->requests) as $i) {
            $events = self::body($transport, $i)['events'];
            self::assertIsArray($events);
            $sizes[] = count($events);
        }
        self::assertSame([100, 50], $sizes);
    }

    public function testStrictPrivacyHashesTheIpAndDropsTheUserAgent(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{}')], privacy: 'strict');
        $client->trackEvent(self::EVENT + ['userAgent' => 'ua']);
        $client->flush();
        $events = self::body($transport, 0)['events'];
        self::assertIsArray($events);
        self::assertIsArray($events[0]);
        self::assertNotSame('203.0.113.7', $events[0]['ip']);
        self::assertArrayNotHasKey('userAgent', $events[0]);
    }

    public function testDefaultsAreMergedUnderTheEvent(): void
    {
        $transport = RecordingTransport::ok();
        $client = new Client(self::KEY, 'http://platform.test/api/events/ingest', defaults: ['appId' => 'a', 'environment' => 'e'], transport: $transport);
        $client->trackEvent(self::EVENT + ['environment' => 'override']);
        $client->flush();
        $events = self::body($transport, 0)['events'];
        self::assertIsArray($events);
        self::assertIsArray($events[0]);
        self::assertSame(['a', 'override'], [$events[0]['appId'], $events[0]['environment']]);
    }

    public function testEveryRequestIsSignedWithAKeyIdAndNeverTheKey(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{"success":true}')]);
        self::assertTrue($client->testConnection());
        $client->trackEvent(self::EVENT);
        $client->trackEvents([self::EVENT, self::EVENT]);
        $client->flush();

        self::assertCount(2, $transport->requests);
        foreach ($transport->requests as $i => $request) {
            $wire = $transport->signingHeaders($i);
            self::assertSame('valid', RequestSigner::verify(self::KEY, 'POST', '/api/events/ingest', $request['body'], $wire), 'request ' . $i);
            self::assertSame('2', $wire[RequestSigner::VERSION_HEADER]);
            self::assertSame(RequestSigner::deriveKeyId(self::KEY), $wire[RequestSigner::KEY_ID_HEADER]);
            self::assertArrayNotHasKey('X-DevFortress-Key', $wire);
            self::assertArrayNotHasKey('X-API-Key', $wire);
            self::assertArrayNotHasKey('Authorization', $wire);
            // Comparison only; nothing is printed.
            $carriesKey = str_contains($request['body'], self::KEY) || str_contains($request['url'], self::KEY);
            foreach ($request['headers'] as $value) {
                $carriesKey = $carriesKey || str_contains($value, self::KEY);
            }
            self::assertFalse($carriesKey, 'request ' . $i . ' carries the API key');
        }
    }

    public function testEachRetryAttemptCarriesAFreshNonceAndTimestamp(): void
    {
        $transport = new RecordingTransport([new TransportResponse(503, '{}'), new TransportResponse(502, '{}'), new TransportResponse(200, '{"success":true}')]);
        $client = new Client(
            self::KEY,
            'http://platform.test/api/events/ingest',
            2.0,
            3,
            transport: $transport,
            sleeper: static function (float $seconds): void {
                usleep(3000); // let the millisecond clock advance between attempts
            },
        );
        $client->trackEvent(self::EVENT);
        $results = $client->flush();

        self::assertTrue($results[0]->ok);
        self::assertSame(3, $results[0]->attempts);
        self::assertCount(3, $transport->requests);
        $nonces = [];
        $stamps = [];
        foreach ($transport->requests as $i => $_) {
            $wire = $transport->signingHeaders($i);
            self::assertSame('valid', RequestSigner::verify(self::KEY, 'POST', '/api/events/ingest', $transport->requests[$i]['body'], $wire));
            $nonces[(string) $wire[RequestSigner::NONCE_HEADER]] = true;
            $stamps[(string) $wire[RequestSigner::TIMESTAMP_HEADER]] = true;
        }
        self::assertCount(3, $nonces, 'each attempt needs its own nonce');
        self::assertCount(3, $stamps, 'each attempt needs its own timestamp');
    }

    public function testFiveHundredsAreRetriedThenGivenUpOnWithoutThrowing(): void
    {
        [$client, $transport, $sleeps] = self::client([new TransportResponse(502, '{"error":"bad gateway"}')]);
        $client->trackEvent(self::EVENT);
        $results = $client->flush();

        self::assertCount(3, $transport->requests);
        self::assertFalse($results[0]->ok);
        self::assertSame(502, $results[0]->statusCode);
        self::assertSame([1.0, 2.0], $sleeps->getArrayCopy());
    }

    /** @return array<int, array{int}> */
    public static function clientErrors(): array
    {
        return ['400' => [400], '401' => [401], '403' => [403], '429' => [429], '301' => [301]];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('clientErrors')]
    public function testNonRetryableStatusesAreSentOnce(int $status): void
    {
        [$client, $transport] = self::client([new TransportResponse($status, '{"error":"nope"}')]);
        $client->trackEvent(self::EVENT);
        $results = $client->flush();
        self::assertCount(1, $transport->requests);
        self::assertFalse($results[0]->ok);
        self::assertSame($status, $results[0]->statusCode);
    }

    public function testNetworkErrorsAreRetriedAndNeverThrown(): void
    {
        [$client, $transport] = self::client([RecordingTransport::down()]);
        $client->trackEvent(self::EVENT);
        $results = $client->flush();
        self::assertCount(3, $transport->requests);
        self::assertFalse($results[0]->ok);
        self::assertNull($results[0]->statusCode);
        self::assertStringContainsString('connection refused', (string) $results[0]->error);
    }

    public function testATransportThatThrowsAnythingNeverReachesTheHost(): void
    {
        [$client] = self::client([new RuntimeException('boom')]);
        $client->trackEvent(self::EVENT);
        $results = $client->flush();
        self::assertFalse($results[0]->ok);
        self::assertFalse($client->testConnection());
    }

    public function testAThrowingLoggerNeverReachesTheHost(): void
    {
        $logger = new class implements LoggerInterface {
            public function log(mixed $level, string|Stringable $message, array $context = []): void
            {
                throw new RuntimeException('logger down');
            }
        };
        [$client] = self::client([new TransportResponse(500, '{}')], 1, $logger);
        $client->trackEvent(self::EVENT);
        self::assertFalse($client->flush()[0]->ok);
    }

    public function testFailuresAreLoggedThroughAPsr3StyleLoggerWithoutTheKey(): void
    {
        $logger = new class {
            /** @var list<string> */
            public array $lines = [];

            /** @param array<string, mixed> $context */
            public function log(mixed $level, string|Stringable $message, array $context = []): void
            {
                $this->lines[] = (is_string($level) ? $level : '?') . ' ' . $message . ' ' . json_encode($context);
            }
        };
        [$client] = self::client([new TransportResponse(401, '{"error":"no"}')], 3, $logger);
        $client->trackEvent(self::EVENT);
        $client->flush();
        self::assertCount(1, $logger->lines);
        self::assertStringStartsWith('warning DevFortress: delivery failed: HTTP 401', $logger->lines[0]);
        self::assertStringNotContainsString(self::KEY, $logger->lines[0]);
    }

    public function testALoggerWithoutLogIsRejectedAtConstruction(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Client(self::KEY, logger: new \stdClass());
    }

    public function testAnUnauthorizedKeyIsSurfacedByTestConnection(): void
    {
        [$client, $transport] = self::client([new TransportResponse(401, '{"error":"no"}')]);
        self::assertFalse($client->testConnection());
        self::assertCount(1, $transport->requests);
        $body = self::body($transport, 0);
        self::assertSame('/__devfortress/test', $body['path']);
        self::assertSame(['test' => true, 'sdk' => 'php'], $body['metadata']);
    }

    public function testAnUnreachablePlatformMakesTestConnectionFalseNotAnException(): void
    {
        [$client] = self::client([RecordingTransport::down()]);
        self::assertFalse($client->testConnection());
    }

    public function testUnencodableEventsAreDroppedWithoutThrowing(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{}')]);
        $client->trackEvent(['eventType' => 'custom', 'metadata' => ['x' => NAN]]);
        self::assertFalse($client->flush()[0]->ok);
        self::assertSame([], $transport->requests);
    }

    public function testInvalidUtf8IsSubstitutedRatherThanFailingTheBatch(): void
    {
        [$client, $transport] = self::client([new TransportResponse(200, '{}')]);
        $client->trackEvent(self::EVENT + ['userAgent' => "bad\xff"]);
        self::assertTrue($client->flush()[0]->ok);
        self::assertCount(1, $transport->requests);
    }

    public function testShutdownFlushRegistersOnce(): void
    {
        [$client] = self::client([new TransportResponse(200, '{}')]);
        $client->registerShutdownFlush();
        $client->registerShutdownFlush();
        self::assertSame(0, $client->pendingEvents());
    }
}
