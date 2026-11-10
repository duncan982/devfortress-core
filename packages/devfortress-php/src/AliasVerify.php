<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use Closure;
use DevFortress\Sdk\Transport\CurlTransport;
use DevFortress\Sdk\Transport\TransportException;
use DevFortress\Sdk\Transport\TransportInterface;
use InvalidArgumentException;
use Throwable;

/**
 * Alias binding verification helper.
 *
 * Thin HTTP transport for POST /api/aliases/{id}/verify. All binding
 * checks run server-side; nothing is evaluated locally. Retry behaviour
 * matches Client: exponential backoff on 5xx and network errors only,
 * never on 4xx. Mirrors packages/devfortress-sdk/src/alias-verify.ts.
 */
final class AliasVerify
{
    public const DEFAULT_BASE_URL = 'https://www.devfortress.net';
    public const DEFAULT_TIMEOUT = 15.0;
    public const DEFAULT_RETRIES = 3;

    private function __construct()
    {
    }

    /**
     * Verify an alias's observed context against its recorded binding.
     * Returns the decoded body for 200 and 403 responses (the platform's
     * normal verdicts). Throws AliasVerifyError for 400/401 and for
     * 5xx/network failures once retries are exhausted.
     *
     * @param array<string, mixed> $context
     * @param (Closure(float): void)|null $sleeper
     *
     * @return array<string, mixed>
     */
    public static function verifyAliasBinding(
        string $aliasId,
        string $aliasKey,
        array $context,
        string $baseUrl = self::DEFAULT_BASE_URL,
        float $timeout = self::DEFAULT_TIMEOUT,
        int $retries = self::DEFAULT_RETRIES,
        ?TransportInterface $transport = null,
        ?Closure $sleeper = null,
    ): array {
        if ($aliasId === '') {
            throw new InvalidArgumentException('verifyAliasBinding: aliasId is required');
        }
        if ($aliasKey === '') {
            throw new InvalidArgumentException('verifyAliasBinding: aliasKey is required');
        }

        $base = rtrim($baseUrl, '/');
        $transport ??= new CurlTransport();
        $sleeper ??= static function (float $seconds): void {
            if ($seconds > 0) {
                usleep((int) round($seconds * 1_000_000));
            }
        };
        $url = "{$base}/api/aliases/" . rawurlencode($aliasId) . '/verify';
        $raw = json_encode(['aliasKey' => $aliasKey, 'context' => $context], JSON_THROW_ON_ERROR);
        $headers = ['Content-Type' => 'application/json', 'X-DevFortress-SDK-Version' => Client::VERSION];

        $attempt = 1;
        while (true) {
            try {
                $response = $transport->send('POST', $url, $headers, $raw, $timeout);
                $decoded = $response->body === '' ? [] : json_decode($response->body, true);
                /** @var array<string, mixed> $data */
                $data = is_array($decoded) ? $decoded : [];
                $status = $response->statusCode;

                if ($status === 200 || $status === 403) {
                    return ['httpStatus' => $status, 'violations' => [], ...$data];
                }

                $message = is_string($data['error'] ?? null) ? $data['error'] : "Alias verification failed with status {$status}";
                if ($status < 500 || $attempt >= $retries) {
                    throw new AliasVerifyError($message, $status, $data);
                }
            } catch (TransportException $e) {
                if ($attempt >= $retries) {
                    throw new AliasVerifyError("Alias verification request failed: {$e->getMessage()}");
                }
            } catch (AliasVerifyError $e) {
                throw $e;
            } catch (Throwable $e) {
                if ($attempt >= $retries) {
                    throw new AliasVerifyError("Alias verification request failed: {$e->getMessage()}");
                }
            }

            $sleeper(2 ** $attempt);
            $attempt++;
        }
    }
}
