<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests\Live;

use DevFortress\Sdk\Client;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Live checks against the local platform (default http://localhost:3001) with a
 * throwaway local project. Skipped unless DF_LIVE_API_KEY and DF_LIVE_PROJECT_ID
 * are set; tests/Live/run-live.sh creates and removes the project and sets them.
 */
#[Group('live')]
final class LiveTest extends TestCase
{
    private string $key = '';
    private string $projectId = '';
    private string $base = '';
    private string $cookieJar = '';

    protected function setUp(): void
    {
        $key = getenv('DF_LIVE_API_KEY');
        $project = getenv('DF_LIVE_PROJECT_ID');
        if (!is_string($key) || $key === '' || !is_string($project) || $project === '') {
            self::markTestSkipped('DF_LIVE_API_KEY / DF_LIVE_PROJECT_ID not set (see tests/Live/run-live.sh)');
        }
        $base = getenv('DF_LIVE_BASE_URL');
        $this->key = $key;
        $this->projectId = $project;
        $this->base = is_string($base) && $base !== '' ? rtrim($base, '/') : 'http://localhost:3001';
        $this->cookieJar = tempnam(sys_get_temp_dir(), 'dfjar') ?: '';
    }

    protected function tearDown(): void
    {
        if ($this->cookieJar !== '' && is_file($this->cookieJar)) {
            unlink($this->cookieJar);
        }
    }

    /** @return array{0: int, 1: string} */
    private function http(string $method, string $path, ?string $json = null): array
    {
        $ch = curl_init($this->base . $path);
        self::assertNotFalse($ch);
        $jar = $this->cookieJar;
        if ($jar === '') {
            self::fail('no cookie jar');
        }
        curl_setopt($ch, $method === 'POST' ? CURLOPT_POST : CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 90);
        curl_setopt($ch, CURLOPT_COOKIEJAR, $jar);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $jar);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        if ($json !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
        }
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return [$status, is_string($body) ? $body : ''];
    }

    /** Count of Event Explorer rows for this project whose endpoint is $marker. */
    private function explorerCount(string $marker): int
    {
        [$status, $body] = $this->http('GET', '/api/events/explorer?projectId=' . rawurlencode($this->projectId) . '&limit=100');
        self::assertSame(200, $status, 'Event Explorer API');
        $json = json_decode($body, true);
        self::assertIsArray($json);
        $count = 0;
        foreach ((array) ($json['events'] ?? []) as $event) {
            if (is_array($event) && ($event['endpoint'] ?? null) === $marker) {
                ++$count;
            }
        }

        return $count;
    }

    private function waitForRows(string $marker, int $expected): int
    {
        $count = 0;
        for ($i = 0; $i < 60; $i++) {
            $count = $this->explorerCount($marker);
            if ($count >= $expected) {
                return $count;
            }
            usleep(500_000);
        }

        return $count;
    }

    /** @return array<string, mixed> */
    private static function event(string $path, int $i): array
    {
        return [
            'eventType' => 'custom',
            'ip' => '198.51.100.' . (10 + $i),
            'method' => 'GET',
            'path' => $path,
            'severity' => 'LOW',
            'authPhase' => 'pre_auth',
            'actionTaken' => 'monitored',
            'clMode' => 'external',
            'responseLatencyMs' => 1,
        ];
    }

    private function client(?string $key = null): Client
    {
        return new Client($key ?? $this->key, $this->base . '/api/events/ingest', 90.0, 3, backoffBase: 0.5);
    }

    public function testASignedBatchIsAcceptedAndVisibleThroughTheEventExplorerApi(): void
    {
        [$login] = $this->http('POST', '/api/auth/dev', '{"role":"OWNER"}');
        self::assertSame(200, $login, 'dev login');

        $marker = '/phptest/batch/' . bin2hex(random_bytes(4));
        $client = $this->client();
        $client->trackEvents(array_map(fn (int $i): array => self::event($marker, $i), range(0, 4)));
        $results = $client->flush();

        self::assertCount(1, $results);
        self::assertTrue($results[0]->ok, (string) $results[0]->error);
        self::assertSame(200, $results[0]->statusCode);
        self::assertIsArray($results[0]->body);
        self::assertTrue($results[0]->body['success'] ?? false);
        self::assertSame(5, $results[0]->body['successful'] ?? null);
        self::assertSame(5, $this->waitForRows($marker, 5), 'five distinct end users, five rows');
    }

    public function testAQueuedSingleEventIsAcceptedAndVisible(): void
    {
        [$login] = $this->http('POST', '/api/auth/dev', '{"role":"OWNER"}');
        self::assertSame(200, $login, 'dev login');

        $marker = '/phptest/single/' . bin2hex(random_bytes(4));
        $client = $this->client();
        $client->trackEvent(self::event($marker, 0));
        self::assertTrue($client->flush()[0]->ok);
        self::assertSame(1, $this->waitForRows($marker, 1));
    }

    public function testTestConnectionIsTrueWithAGoodKey(): void
    {
        self::assertTrue($this->client()->testConnection());
    }

    public function testABadKeyGetsA401AndStoresNothing(): void
    {
        [$login] = $this->http('POST', '/api/auth/dev', '{"role":"OWNER"}');
        self::assertSame(200, $login, 'dev login');

        $marker = '/phptest/badkey/' . bin2hex(random_bytes(4));
        $bad = $this->client('vx_live_not_a_real_key_' . bin2hex(random_bytes(4)));
        $bad->trackEvent(self::event($marker, 0));
        $result = $bad->flush()[0];
        self::assertFalse($result->ok);
        self::assertSame(401, $result->statusCode);
        self::assertFalse($bad->testConnection());
        self::assertSame(0, $this->explorerCount($marker));
    }
}
