<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\RequestSigner;
use DevFortress\Sdk\Tests\Support\Vectors;
use PHPUnit\Framework\TestCase;

/**
 * The shared cross-language vectors (contracts/ingest-signature-vectors.json):
 * the platform, the Node SDK, the Python SDK and the open-core route assert the
 * same file.
 */
final class SigningVectorsTest extends TestCase
{
    /** @return list<array<string, mixed>> */
    private static function section(string $name): array
    {
        $section = Vectors::ingest()[$name] ?? null;
        self::assertIsArray($section);
        /** @var list<array<string, mixed>> $section */
        return $section;
    }

    /**
     * @param array<string, mixed> $vector
     *
     * @return array<string, string|null>
     */
    private static function wire(array $vector): array
    {
        $h = $vector['headers'];
        self::assertIsArray($h);
        $get = static fn (string $k): ?string => isset($h[$k]) && is_string($h[$k]) ? $h[$k] : null;

        return [
            RequestSigner::NONCE_HEADER => $get('nonce'),
            RequestSigner::TIMESTAMP_HEADER => $get('timestamp'),
            RequestSigner::PAYLOAD_HASH_HEADER => $get('payload_hash'),
            RequestSigner::SIGNATURE_HEADER => $get('signature'),
            RequestSigner::VERSION_HEADER => $get('version'),
        ];
    }

    public function testEveryVerifierVectorGivesItsExpectedResult(): void
    {
        $vectors = self::section('vectors');
        self::assertGreaterThanOrEqual(26, count($vectors));
        foreach ($vectors as $v) {
            $got = RequestSigner::verify(
                (string) $v['verify_key'],
                (string) $v['method'],
                (string) $v['request_target'],
                (string) $v['body'],
                self::wire($v),
                (int) $v['now_ms'],
            );
            self::assertSame($v['expected'], $got, (string) $v['name']);
        }
    }

    public function testSigningMatchesTheVectorsByteForByte(): void
    {
        $signer = 0;
        foreach (self::section('vectors') as $v) {
            if (!isset($v['sign_input']) || !in_array($v['expected'], ['valid', 'expired'], true)) {
                continue;
            }
            $i = $v['sign_input'];
            self::assertIsArray($i);
            $signed = (new RequestSigner((string) $i['api_key']))->sign(
                (string) $i['method'],
                (string) $i['request_target'],
                (string) $i['body'],
                (string) $i['timestamp'],
                (string) $i['nonce'],
            );
            $want = self::wire($v);
            self::assertSame(strtolower((string) $want[RequestSigner::PAYLOAD_HASH_HEADER]), $signed[RequestSigner::PAYLOAD_HASH_HEADER], (string) $v['name']);
            self::assertSame(strtolower((string) $want[RequestSigner::SIGNATURE_HEADER]), $signed[RequestSigner::SIGNATURE_HEADER], (string) $v['name']);
            self::assertSame($want[RequestSigner::NONCE_HEADER], $signed[RequestSigner::NONCE_HEADER], (string) $v['name']);
            self::assertSame($want[RequestSigner::TIMESTAMP_HEADER], $signed[RequestSigner::TIMESTAMP_HEADER], (string) $v['name']);
            self::assertSame('2', $signed[RequestSigner::VERSION_HEADER]);
            ++$signer;
        }
        self::assertGreaterThanOrEqual(8, $signer);
    }

    public function testNegativeVectorsDoNotMatchWhatTheSignerProduces(): void
    {
        // A signature made for one request must not equal the signature of the
        // request the server actually received (other path, method, query, ...).
        $names = [
            'different_path', 'different_path_same_query', 'different_method', 'changed_query',
            'query_added', 'prefix_stripped', 'tampered_body', 'wrong_key',
        ];
        $seen = 0;
        foreach (self::section('vectors') as $v) {
            if (!in_array($v['name'], $names, true)) {
                continue;
            }
            ++$seen;
            $wire = self::wire($v);
            $signed = (new RequestSigner((string) $v['verify_key']))->sign(
                (string) $v['method'],
                (string) $v['request_target'],
                (string) $v['body'],
                (string) $wire[RequestSigner::TIMESTAMP_HEADER],
                (string) $wire[RequestSigner::NONCE_HEADER],
            );
            self::assertNotSame($wire[RequestSigner::SIGNATURE_HEADER], $signed[RequestSigner::SIGNATURE_HEADER], (string) $v['name']);
        }
        self::assertSame(count($names), $seen);
    }

    public function testKeyIdDerivationMatchesTheVectors(): void
    {
        $derivation = Vectors::ingest()['key_id_derivation'] ?? null;
        self::assertIsArray($derivation);
        $vectors = $derivation['vectors'];
        self::assertIsArray($vectors);
        self::assertGreaterThanOrEqual(3, count($vectors));
        foreach ($vectors as $v) {
            self::assertIsArray($v);
            self::assertSame($v['key_id'], RequestSigner::deriveKeyId((string) $v['api_key']));
            self::assertSame($v['key_id'], (new RequestSigner((string) $v['api_key']))->keyId());
        }
    }

    public function testSignedPathVectorHeadersMatchByteForByte(): void
    {
        $checked = 0;
        foreach (self::section('signed_path_vectors') as $v) {
            if (!isset($v['sign_input'])) {
                continue;
            }
            $i = $v['sign_input'];
            self::assertIsArray($i);
            $signed = (new RequestSigner((string) $i['api_key']))->sign(
                (string) $i['method'],
                (string) $i['request_target'],
                (string) $i['body'],
                (string) $i['timestamp'],
                (string) $i['nonce'],
            );
            $h = $v['headers'];
            self::assertIsArray($h);
            self::assertSame($h['key_id'], $signed[RequestSigner::KEY_ID_HEADER], (string) $v['name']);
            self::assertSame($h['signature'], $signed[RequestSigner::SIGNATURE_HEADER], (string) $v['name']);
            self::assertSame($h['payload_hash'], $signed[RequestSigner::PAYLOAD_HASH_HEADER], (string) $v['name']);
            ++$checked;
        }
        self::assertGreaterThanOrEqual(4, $checked);
    }

    public function testAReferenceServerBuiltOnTheVerifierAgreesWithEverySignedPathVector(): void
    {
        $vectors = self::section('signed_path_vectors');
        self::assertCount(18, $vectors);
        foreach ($vectors as $v) {
            $h = $v['headers'];
            self::assertIsArray($h);
            $knownKeys = $v['known_keys'];
            self::assertIsArray($knownKeys);

            $status = 200;
            $reason = null;
            $keyId = is_string($h['key_id'] ?? null) ? $h['key_id'] : '';
            if ($keyId !== '' && $v['api_key_header'] !== null) {
                [$status, $reason] = [400, 'ambiguous_credentials'];
            } else {
                $key = null;
                foreach ($knownKeys as $candidate) {
                    if (RequestSigner::deriveKeyId((string) $candidate) === $keyId) {
                        $key = (string) $candidate;
                    }
                }
                $result = $key === null
                    ? (self::wire($v)[RequestSigner::SIGNATURE_HEADER] === null ? 'missing' : 'invalid')
                    : RequestSigner::verify($key, (string) $v['method'], (string) $v['request_target'], (string) $v['body'], self::wire($v), (int) $v['now_ms']);
                [$status, $reason] = match ($result) {
                    'valid' => [200, null],
                    'expired' => [400, 'timestamp_expired'],
                    'missing' => [401, 'signature_missing'],
                    'unsupported_version' => [401, 'signature_version_unsupported'],
                    default => [401, 'signature_invalid'],
                };
            }
            $expected = $v['expected'];
            self::assertIsArray($expected);
            self::assertSame($expected['status'], $status, (string) $v['name']);
            self::assertSame($expected['reason'], $reason, (string) $v['name']);
        }
    }

    public function testRequestTargetIsThePathAndQueryAsWritten(): void
    {
        self::assertSame('/api/events/ingest', RequestSigner::requestTargetFromUrl('https://www.devfortress.net/api/events/ingest'));
        self::assertSame('/gateway/api/x?v=1&x=a%20b', RequestSigner::requestTargetFromUrl('http://h:3001/gateway/api/x?v=1&x=a%20b#frag'));
        self::assertSame('/', RequestSigner::requestTargetFromUrl('http://h'));
        self::assertSame('/?a=1', RequestSigner::requestTargetFromUrl('http://h?a=1'));
        self::assertSame('/x?', RequestSigner::requestTargetFromUrl('http://h/x?'));
        self::assertSame('/a/../b', RequestSigner::requestTargetFromUrl('http://h/a/../b'));
    }

    public function testNonceIsADashedV4Uuid(): void
    {
        $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D';
        $seen = [];
        for ($i = 0; $i < 50; $i++) {
            $n = RequestSigner::uuidV4();
            self::assertMatchesRegularExpression($pattern, $n);
            $seen[$n] = true;
        }
        self::assertCount(50, $seen);
    }
}
