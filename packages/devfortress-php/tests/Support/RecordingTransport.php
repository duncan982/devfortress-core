<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests\Support;

use DevFortress\Sdk\Transport\TransportException;
use DevFortress\Sdk\Transport\TransportInterface;
use DevFortress\Sdk\Transport\TransportResponse;
use Throwable;

/**
 * A scripted transport that records every request it is given. The script is
 * consumed in order and its last entry repeats.
 */
final class RecordingTransport implements TransportInterface
{
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: string}> */
    public array $requests = [];

    /** @param list<TransportResponse|Throwable> $script */
    public function __construct(private readonly array $script)
    {
    }

    public static function ok(): self
    {
        return new self([new TransportResponse(200, '{"success":true}')]);
    }

    public function send(string $method, string $url, array $headers, string $body, float $timeout): TransportResponse
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];
        $step = $this->script[min(count($this->requests), count($this->script)) - 1];
        if ($step instanceof Throwable) {
            throw $step;
        }

        return $step;
    }

    /** @return array{method: string, url: string, headers: array<string, string>, body: string} */
    public function request(int $i): array
    {
        return $this->requests[$i] ?? throw new \OutOfBoundsException('no request #' . $i);
    }

    public static function down(): TransportException
    {
        return new TransportException('connection refused');
    }

    /** @return array<string, string|null> the signing headers of request $i, by wire name */
    public function signingHeaders(int $i): array
    {
        $out = [];
        foreach ($this->requests[$i]['headers'] as $name => $value) {
            $out[$name] = $value;
        }

        return $out;
    }
}
