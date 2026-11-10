<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Transport;

/** The default transport: ext-curl, HTTP/1.1, no redirects, path sent as written. */
final class CurlTransport implements TransportInterface
{
    public function send(string $method, string $url, array $headers, string $body, float $timeout): TransportResponse
    {
        if ($method === '') {
            throw new TransportException('empty HTTP method');
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new TransportException('could not initialise curl');
        }

        $lines = ['Expect:'];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        $timeoutMs = max(1, (int) round($timeout * 1000));
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $lines);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_PATH_AS_IS, true);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $timeoutMs);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, $timeoutMs);
        if ($body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($ch);
        if ($response === false || $response === true) {
            $message = curl_error($ch);
            curl_close($ch);
            throw new TransportException($message !== '' ? $message : 'curl request failed');
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return new TransportResponse($status, $response);
    }
}
