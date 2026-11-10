# devfortress/sdk-php

Event reporting client for DevFortress (external mode). Pre-release, not published.

Requires PHP 8.2 or newer with `ext-curl`, `ext-json` and `ext-hash`. There are no runtime Composer dependencies.

## Install

Not on Packagist yet. Until it is, use a Composer path repository:

```json
{
  "repositories": [{ "type": "path", "url": "../devfortress-php" }],
  "require": { "devfortress/sdk-php": "@dev" }
}
```

## The DevFortress Textbook

DevFortress implements 34 novel security inventions. Patent Pending.

These 34 inventions are documented in depth across 5 volumes.

**"Credential Isolation Closed-Loop Security"**
_Duncan Ndungu Ndegwa — DevFortress, 2026_

→ Available on Gumroad: [https://devfortress.gumroad.com/l/master-edition]

## Quick start

```php
use DevFortress\Sdk\Client;

$client = new Client(
    apiKey: getenv('DEVFORTRESS_API_KEY'),
    endpoint: 'https://www.devfortress.net/api/events/ingest',
);
$client->registerShutdownFlush(); // sends the queue after the response is finished

$client->trackEvent([
    'eventType' => 'auth_failure',
    'ip' => '203.0.113.7',
    'method' => 'POST',
    'path' => '/login',
    'severity' => 'MEDIUM',
]);
```

`trackEvent()` and `trackEvents()` queue events in memory. `flush()` sends them; the queue also flushes itself once it reaches the batch size. `testConnection()` sends one test event and returns `true` when the platform accepts the key.

The constructor takes `apiKey`, `endpoint`, `timeout` (15 s) and `retries` (3 attempts), plus optional `logger`, `defaults`, `privacy` (`standard` or `strict`), `batchSize` and `mode` (see below).

Delivery never throws into your application. A failed delivery is returned as a `DeliveryResult` from `flush()` and logged through the optional logger (any PSR-3 logger, or anything with a PSR-3 style `log()` method). Failed deliveries are retried automatically. Only a missing API key throws, at construction.

## Closed-loop mode

`mode` selects the closed-loop delivery mode: `'external'` (default — every event ships to the platform, no behavior change for existing callers), `'internal'` (decisions are made locally, nothing leaves your infrastructure), or `'hybrid'` (local-first, with automatic cloud enrichment and failover). Internal/hybrid require Team tier or above.

```php
$client = new Client(
    apiKey: getenv('DEVFORTRESS_API_KEY'),
    mode: getenv('DEVFORTRESS_CL_MODE') ?: 'external',
);
```

Reading the mode from a `DEVFORTRESS_CL_MODE` env var (`external`, `internal`, or `hybrid`) is the convention this SDK's demo apps use so the same code can be started in any mode without a change.

## Request signing

Every request is signed with your API key. The key itself is never sent.

## Webhook verification

```php
use DevFortress\Sdk\WebhookVerifier;

$result = WebhookVerifier::verify(
    file_get_contents('php://input'),           // the body exactly as received
    $_SERVER['HTTP_X_DEVFORTRESS_SIGNATURE'] ?? '',
    $_SERVER['HTTP_X_DEVFORTRESS_TIMESTAMP'] ?? '',
    getenv('DEVFORTRESS_WEBHOOK_SECRET'),
    nonceCheck: fn (string $nonce): bool => rememberNonce($nonce), // true the first time only
);
if (!$result->valid) {
    http_response_code($result->reason === 'replay_detected' ? 409 : 401);
    exit;
}
```

Stale timestamps are rejected. `nonceCheck` is optional; the library keeps no state, so replay tracking is yours.

## Request classification

`Classifier::buildEvent()` turns a response status plus the request path and query into an event array, or `null` when nothing is worth reporting. It flags suspicious patterns in the path and query string.

`ClientIp::resolve()` picks the end-user IP the same way the Laravel middleware does: `X-Forwarded-For`, then `X-Real-IP`, then the socket address.

## Other modules

`DevFortress\Sdk\UnifiedAuditTrail` merges internal and external closed-loop audit events into one in-memory timeline. `DevFortress\Sdk\GraduatedRateLimiter` applies alias-scoped rate limiting with multi-stage escalation (observe, warn, soft-limit, hard-block, revoke).

## Known Limitations

Under PHP's standard per-request execution model (`php artisan serve`, or standard PHP-FPM without a persistent runtime), internal and hybrid closed-loop mode's in-memory state — blocked IPs, users, sessions and agents, the sliding-window rate limiter, and the audit log — does not persist across requests. Each request rebuilds the engine from scratch, so a block decided on one request has no effect on the next. Tier-1 rule matching within a single request is unaffected.

For that stateful guarantee to hold in production, run on a persistent PHP runtime (Laravel Octane on Swoole, RoadRunner, or FrankenPHP), or back the engine's state with an external store (Redis, APCu, or a database). Neither is provided by this SDK today.

## Tests

```
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse
```

The signing and webhook tests read shared test-vector files (set `DEVFORTRESS_CONTRACTS_DIR` to their directory).

## Versioning (Packagist)

This package lives inside the `devfortress-core` monorepo alongside the other language SDKs, not in its own standalone repo. Packagist reads versions from git tags, so a monorepo needs those tags disambiguated per package — **tag releases for this package as `php-v1.0.0`, `php-v1.1.0`, etc., never a bare `v1.0.0`** (a bare tag would be ambiguous against the other SDKs' releases in the same repo).

License: BUSL-1.1
