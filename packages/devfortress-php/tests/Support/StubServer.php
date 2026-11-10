<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests\Support;

use RuntimeException;

/**
 * A real HTTP server (PHP's built-in one) that records every request and
 * answers from a script, for tests that must see the bytes on the wire.
 */
final class StubServer
{
    public readonly string $url;

    /** @var resource */
    private $process;
    private readonly string $dir;

    /** @param list<array{0: int, 1: array<string, mixed>}> $responses consumed in order, last repeats */
    public function __construct(array $responses)
    {
        $this->dir = sys_get_temp_dir() . '/df-stub-' . bin2hex(random_bytes(6));
        mkdir($this->dir);
        file_put_contents($this->dir . '/responses.json', json_encode($responses, JSON_THROW_ON_ERROR));
        file_put_contents($this->dir . '/requests.jsonl', '');

        $probe = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($probe === false) {
            throw new RuntimeException('no free port: ' . $errstr);
        }
        $name = (string) stream_socket_get_name($probe, false);
        fclose($probe);
        $port = (int) substr($name, (int) strrpos($name, ':') + 1);

        $cmd = [PHP_BINARY, '-S', '127.0.0.1:' . $port, __DIR__ . '/stub-router.php'];
        $process = proc_open(
            $cmd,
            [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            null,
            ['DF_STUB_DIR' => $this->dir, 'PATH' => (string) getenv('PATH')],
        );
        if (!is_resource($process)) {
            throw new RuntimeException('could not start the stub server');
        }
        $this->process = $process;

        for ($i = 0; $i < 100; $i++) {
            $conn = @fsockopen('127.0.0.1', $port, $e, $s, 0.1);
            if ($conn !== false) {
                fclose($conn);
                $this->url = 'http://127.0.0.1:' . $port;

                return;
            }
            usleep(50_000);
        }
        $this->close();
        throw new RuntimeException('the stub server did not start');
    }

    /** @return list<array{method: string, target: string, headers: array<string, string>, body: string}> */
    public function requests(): array
    {
        $out = [];
        foreach (file($this->dir . '/requests.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            /** @var array{method: string, target: string, headers: array<string, string>, body: string} $row */
            $row = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
            $row['body'] = (string) base64_decode($row['body'], true);
            $out[] = $row;
        }

        return $out;
    }

    public function close(): void
    {
        proc_terminate($this->process);
        proc_close($this->process);
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }
}
