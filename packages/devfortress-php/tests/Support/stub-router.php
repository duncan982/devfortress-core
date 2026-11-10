<?php

declare(strict_types=1);

$dir = (string) getenv('DF_STUB_DIR');
$raw = (string) file_get_contents('php://input');
$headers = [];
foreach (getallheaders() as $name => $value) {
    $headers[(string) $name] = (string) $value;
}
file_put_contents(
    $dir . '/requests.jsonl',
    json_encode([
        'method' => $_SERVER['REQUEST_METHOD'],
        'target' => $_SERVER['REQUEST_URI'],
        'headers' => $headers,
        'body' => base64_encode($raw),
    ]) . "\n",
    FILE_APPEND | LOCK_EX,
);
$seen = count(file($dir . '/requests.jsonl') ?: []);
/** @var list<array{0: int, 1: mixed}> $responses */
$responses = json_decode((string) file_get_contents($dir . '/responses.json'), true);
[$status, $payload] = $responses[min($seen, count($responses)) - 1];
http_response_code($status);
header('Content-Type: application/json');
echo json_encode($payload);
