<?php

declare(strict_types=1);

namespace DevFortress\Laravel\Tests\Support;

use DevFortress\Sdk\Transport\TransportException;
use DevFortress\Sdk\Transport\TransportInterface;
use DevFortress\Sdk\Transport\TransportResponse;
use Throwable;

/** Records every request the client would put on the wire and answers from a script. */
final class RecordingTransport implements TransportInterface
{
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: string}> */
    public array $requests = [];

    /** @param list<TransportResponse|Throwable> $script */
    public function __construct(private readonly array $script = [new TransportResponse(200, '{"success":true}')])
    {
    }

    public static function down(): self
    {
        return new self([new TransportException('connection refused')]);
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
}
