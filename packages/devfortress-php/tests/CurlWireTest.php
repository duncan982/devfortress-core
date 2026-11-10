<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\Client;
use DevFortress\Sdk\RequestSigner;
use DevFortress\Sdk\Tests\Support\StubServer;
use PHPUnit\Framework\TestCase;

/** The real curl transport against a real HTTP server: what the server receives is what was signed. */
final class CurlWireTest extends TestCase
{
    private const KEY = 'vx_live_test_vector_key_do_not_use';

    private const EVENT = ['eventType' => 'custom', 'ip' => '203.0.113.5', 'method' => 'GET', 'path' => '/x', 'severity' => 'LOW'];

    private ?StubServer $server = null;

    protected function tearDown(): void
    {
        $this->server?->close();
        $this->server = null;
    }

    /** @param list<array{0: int, 1: array<string, mixed>}> $responses */
    private function server(array $responses): StubServer
    {
        return $this->server = new StubServer($responses);
    }

    /** @param array{method: string, target: string, headers: array<string, string>, body: string} $request */
    private static function verdict(array $request): string
    {
        $headers = [];
        foreach ([RequestSigner::NONCE_HEADER, RequestSigner::TIMESTAMP_HEADER, RequestSigner::PAYLOAD_HASH_HEADER, RequestSigner::SIGNATURE_HEADER, RequestSigner::VERSION_HEADER] as $name) {
            $headers[$name] = $request['headers'][$name] ?? null;
        }

        return RequestSigner::verify(self::KEY, $request['method'], $request['target'], $request['body'], $headers);
    }

    public function testTheServerVerifiesWhatArrivedOnTheWire(): void
    {
        $server = $this->server([[200, ['success' => true]]]);
        $client = new Client(self::KEY, $server->url . '/api/events/ingest', 5.0);
        self::assertTrue($client->testConnection());
        $client->trackEvent(self::EVENT);
        $client->trackEvents([self::EVENT, self::EVENT]);
        $client->flush();

        $requests = $server->requests();
        self::assertCount(2, $requests);
        foreach ($requests as $request) {
            self::assertSame('POST', $request['method']);
            self::assertSame('/api/events/ingest', $request['target']);
            self::assertSame('valid', self::verdict($request));
            self::assertSame(RequestSigner::deriveKeyId(self::KEY), $request['headers'][RequestSigner::KEY_ID_HEADER]);
            self::assertFalse(str_contains($request['body'], self::KEY));
            foreach ($request['headers'] as $value) {
                self::assertFalse(str_contains($value, self::KEY));
            }
            self::assertStringStartsWith('devfortress-sdk-php/', $request['headers']['User-Agent']);
        }
    }

    public function testTheSignatureCoversAPathPrefixAndQueryExactlyAsSent(): void
    {
        $server = $this->server([[200, ['success' => true]]]);
        $client = new Client(self::KEY, $server->url . '/gateway/api/events/ingest?v=1&x=a%20b', 5.0);
        $client->trackEvent(self::EVENT);
        $client->flush();

        $request = $server->requests()[0];
        self::assertSame('/gateway/api/events/ingest?v=1&x=a%20b', $request['target']);
        self::assertSame('valid', self::verdict($request));
    }

    public function testARetryOverTheWireCarriesAFreshNonceAndAValidSignature(): void
    {
        $server = $this->server([[503, ['error' => 'x']], [200, ['success' => true]]]);
        $client = new Client(self::KEY, $server->url . '/api/events/ingest', 5.0, 2, backoffBase: 0.01);
        $client->trackEvent(self::EVENT);
        $results = $client->flush();

        self::assertTrue($results[0]->ok);
        $requests = $server->requests();
        self::assertCount(2, $requests);
        self::assertNotSame($requests[0]['headers'][RequestSigner::NONCE_HEADER], $requests[1]['headers'][RequestSigner::NONCE_HEADER]);
        self::assertSame('valid', self::verdict($requests[0]));
        self::assertSame('valid', self::verdict($requests[1]));
    }

    public function testAnUnreachableServerIsAFailureNotAnException(): void
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        self::assertNotFalse($probe);
        $name = (string) stream_socket_get_name($probe, false);
        fclose($probe);
        $port = substr($name, (int) strrpos($name, ':') + 1);

        $client = new Client(self::KEY, 'http://127.0.0.1:' . $port . '/api/events/ingest', 1.0, 2, backoffBase: 0.01);
        $client->trackEvent(self::EVENT);
        $results = $client->flush();
        self::assertFalse($results[0]->ok);
        self::assertNull($results[0]->statusCode);
        self::assertFalse($client->testConnection());
    }

    public function testAnUnauthorizedResponseIsSurfacedByTestConnectionAndNotRetried(): void
    {
        $server = $this->server([[401, ['error' => 'unauthorized']]]);
        $client = new Client(self::KEY, $server->url . '/api/events/ingest', 5.0);
        self::assertFalse($client->testConnection());
        self::assertCount(1, $server->requests());
    }
}
