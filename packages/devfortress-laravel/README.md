# devfortress/sdk-laravel

Laravel adapter for DevFortress (external mode). Pre-release, not published.

It reports security-relevant responses (auth failures, 4xx and 5xx errors, injection-looking
paths and query strings) to your DevFortress project. It needs
[`devfortress/sdk-php`](../devfortress-php) and supports Laravel 12 and 13
(PHP 8.2+ for Laravel 12, PHP 8.3+ for Laravel 13).

## Install

Not on Packagist yet. Until it is, use Composer path repositories for both packages:

```json
{
  "repositories": [
    { "type": "path", "url": "../devfortress-php" },
    { "type": "path", "url": "../devfortress-laravel" }
  ],
  "require": { "devfortress/sdk-laravel": "@dev" }
}
```

The service provider is auto-discovered. Add your settings to `.env`:

```
DEVFORTRESS_API_KEY=
DEVFORTRESS_ENDPOINT=https://www.devfortress.net/api/events/ingest
```

Optional: `php artisan vendor:publish --tag=devfortress-config` copies `config/devfortress.php`
(timeout, retries, app id, environment, privacy, excluded paths, log channel).

## Middleware

Register it globally in `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\DevFortress\Laravel\Http\Middleware\DevFortressMiddleware::class);
})
```

or use the `devfortress` alias on a route group. The middleware measures the request, and
sends the event from `terminate()`, after the response has gone out. Under PHP-FPM the
visitor does not wait for delivery. Requests under `/health` and `/up` are skipped by default.

The end-user IP is the first `X-Forwarded-For` entry, then `X-Real-IP`, then the socket
address. Only put the middleware behind a proxy you control, because those headers are
client-supplied otherwise.

## Facade

```php
use DevFortress\Laravel\Facades\DevFortress;

DevFortress::trackEvent(['eventType' => 'custom', 'ip' => $ip, 'method' => 'GET',
    'path' => '/checkout', 'severity' => 'LOW']);
DevFortress::flush();
```

The facade and the `DevFortress\Sdk\Client` singleton are the Laravel counterpart of the
Python SDK's `init()` / `get_instance()`. Delivery never throws into your application.

## Tests

```
composer install
vendor/bin/phpunit
```

## Versioning (Packagist)

This package lives inside the `devfortress-core` monorepo alongside the other language
SDKs, not in its own standalone repo. Packagist reads versions from git tags, so a
monorepo needs those tags disambiguated per package — **tag releases for this package
as `laravel-v1.0.0`, `laravel-v1.1.0`, etc., never a bare `v1.0.0`** (a bare tag would be
ambiguous against the other SDKs' releases in the same repo).

License: BUSL-1.1
