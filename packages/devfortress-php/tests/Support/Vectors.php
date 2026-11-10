<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests\Support;

use RuntimeException;

/** Loads the shared cross-language vector files from the repository's contracts/ directory. */
final class Vectors
{
    /** @return array<string, mixed> */
    public static function ingest(): array
    {
        return self::load('ingest-signature-vectors.json');
    }

    /** @return array<string, mixed> */
    public static function webhook(): array
    {
        return self::load('webhook-signature-vectors.json');
    }

    /** @return array<string, mixed> */
    private static function load(string $file): array
    {
        $dir = getenv('DEVFORTRESS_CONTRACTS_DIR');
        $base = is_string($dir) && $dir !== '' ? $dir : dirname(__DIR__, 4) . '/contracts';
        $path = $base . '/' . $file;
        $json = is_file($path) ? file_get_contents($path) : false;
        if ($json === false) {
            throw new RuntimeException('Shared vector file not found: ' . $path . ' (set DEVFORTRESS_CONTRACTS_DIR)');
        }
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new RuntimeException('Unexpected vector file shape: ' . $file);
        }

        /** @var array<string, mixed> $data */
        return $data;
    }
}
