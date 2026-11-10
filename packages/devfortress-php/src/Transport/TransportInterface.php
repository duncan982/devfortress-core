<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Transport;

interface TransportInterface
{
    /**
     * Send one HTTP request and return the response, whatever its status.
     *
     * The URL and the header/body bytes must go on the wire exactly as given:
     * the request signature covers them.
     *
     * @param array<string, string> $headers
     *
     * @throws TransportException on a network-level failure (no HTTP response)
     */
    public function send(string $method, string $url, array $headers, string $body, float $timeout): TransportResponse;
}
