<?php

declare(strict_types=1);

namespace DevFortress\Laravel\Http\Middleware;

use Closure;
use DevFortress\Sdk\Classifier;
use DevFortress\Sdk\Client;
use DevFortress\Sdk\ClientIp;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Reports security-relevant responses (auth failures, 4xx/5xx, injection-looking
 * paths and queries) to DevFortress (external mode's existing after-response
 * behavior — unchanged).
 *
 * handle() ALSO runs the internal/hybrid closed-loop pre-response gate
 * (TODO 407 port) when `devfortress.mode` is 'internal' or 'hybrid': it
 * evaluates the request through {@see Client::observe()} before the
 * request reaches the application and short-circuits with a 403 JSON
 * response if the internal engine flags it. In 'external' mode (the
 * default), this gate is a no-op and behavior is unchanged from before
 * this port — handle() still just measures the request.
 *
 * The event is built and sent in terminate(), after the response has gone
 * out, so the visitor does not wait for delivery. Nothing in terminate()
 * can change or fail the response; the pre-response gate in handle() is
 * the only part of this middleware that can.
 */
final class DevFortressMiddleware
{
    private const LATENCY_ATTRIBUTE = 'devfortress.latency_ms';

    public function __construct(private readonly Container $container)
    {
    }

    public function handle(Request $request, Closure $next): mixed
    {
        $blocked = $this->internalGate($request);
        if ($blocked !== null) {
            return $blocked;
        }

        $started = hrtime(true);
        $response = $next($request);
        $request->attributes->set(self::LATENCY_ATTRIBUTE, (int) round((hrtime(true) - $started) / 1_000_000));

        return $response;
    }

    /**
     * Internal/hybrid closed-loop pre-response gate (TODO 407 port).
     * Returns a 403 JSON response if the request should be blocked, else
     * null (let the request through). Never throws — any failure to
     * construct the client, build the request shape, or evaluate it falls
     * through to null (request allowed), matching this middleware's
     * existing "reporting must never affect the application" discipline
     * in terminate().
     *
     * Request body: Laravel/Symfony's `Request::getContent()` reads and
     * internally caches the raw body on first access, so calling it here
     * does not consume or break any downstream `->input()`/`->json()`/
     * `->all()` read in the controller — unlike a true streaming ASGI
     * body (see the Python port's FastAPI-vs-Flask distinction for the
     * same question in that SDK), Laravel's request object is not a
     * single-read stream from the framework's own perspective. This was
     * confirmed against Symfony HttpFoundation's actual implementation,
     * not assumed by analogy.
     */
    private function internalGate(Request $request): ?Response
    {
        try {
            $config = $this->container->make(Repository::class);
            if ($config->get('devfortress.enabled', true) === false) {
                return null;
            }
            $apiKey = $config->get('devfortress.api_key');
            if (!is_string($apiKey) || $apiKey === '') {
                return null;
            }
            $mode = $config->get('devfortress.mode', 'external');
            if ($mode !== 'internal' && $mode !== 'hybrid') {
                return null;
            }

            $path = rawurldecode($request->getPathInfo());
            $excluded = $config->get('devfortress.exclude_paths', ['/health', '/up']);
            foreach (is_array($excluded) ? $excluded : [] as $prefix) {
                if (is_string($prefix) && $prefix !== '' && str_starts_with($path, $prefix)) {
                    return null;
                }
            }

            $client = $this->container->make(Client::class);
            if ($client->mode !== 'internal' && $client->mode !== 'hybrid') {
                return null;
            }

            $remote = $request->server->get('REMOTE_ADDR');
            $rawQuery = $request->server->get('QUERY_STRING');
            $headers = [];
            foreach ($request->headers->all() as $name => $values) {
                $headers[$name] = implode(', ', $values);
            }

            $req = [
                'ip' => ClientIp::resolve(
                    $request->headers->get('X-Forwarded-For'),
                    $request->headers->get('X-Real-IP'),
                    is_string($remote) ? $remote : null,
                ),
                'method' => $request->getMethod(),
                'path' => $path,
                'userAgent' => $request->headers->get('User-Agent'),
                'query' => is_string($rawQuery) ? $rawQuery : '',
                'headers' => $headers,
                'body' => $request->getContent() ?: null,
            ];

            $result = $client->observe($req);
            if ($result !== null && ($result['flagged'] ?? false) === true) {
                return new JsonResponse([
                    'error' => 'blocked',
                    'reason' => $result['decision'] ?? 'blocked',
                    'eventId' => $result['eventId'] ?? null,
                ], 403);
            }

            return null;
        } catch (Throwable) {
            // The gate must never break the application either.
            return null;
        }
    }

    public function terminate(Request $request, Response $response): void
    {
        try {
            $config = $this->container->make(Repository::class);
            $apiKey = $config->get('devfortress.api_key');
            if ($config->get('devfortress.enabled', true) === false || !is_string($apiKey) || $apiKey === '') {
                return;
            }

            $path = rawurldecode($request->getPathInfo());
            $excluded = $config->get('devfortress.exclude_paths', ['/health', '/up']);
            foreach (is_array($excluded) ? $excluded : [] as $prefix) {
                if (is_string($prefix) && $prefix !== '' && str_starts_with($path, $prefix)) {
                    return;
                }
            }

            $latency = $request->attributes->get(self::LATENCY_ATTRIBUTE);
            $remote = $request->server->get('REMOTE_ADDR');
            $rawQuery = $request->server->get('QUERY_STRING');
            $event = Classifier::buildEvent(
                ip: ClientIp::resolve(
                    $request->headers->get('X-Forwarded-For'),
                    $request->headers->get('X-Real-IP'),
                    is_string($remote) ? $remote : null,
                ),
                method: $request->getMethod(),
                path: $path,
                statusCode: $response->getStatusCode(),
                latencyMs: is_int($latency) ? $latency : 0,
                userAgent: $request->headers->get('User-Agent'),
                // The raw query string, as sent: getQueryString() would re-order and re-encode it.
                query: is_string($rawQuery) ? $rawQuery : '',
            );
            if ($event === null) {
                return;
            }

            $client = $this->container->make(Client::class);
            $client->trackEvent($event);
            $client->flush();
        } catch (Throwable) {
            // Reporting must never affect the application; the client already logs delivery failures.
        }
    }
}
