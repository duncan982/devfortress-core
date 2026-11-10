<?php

declare(strict_types=1);

namespace DevFortress\Laravel\Tests;

use DevFortress\Laravel\Facades\DevFortress;
use DevFortress\Laravel\Http\Middleware\DevFortressMiddleware;
use DevFortress\Sdk\Client;
use Illuminate\Routing\Router;

final class ProviderTest extends TestCase
{
    public function testTheClientIsASingletonBuiltFromConfig(): void
    {
        $client = $this->app->make(Client::class);
        self::assertInstanceOf(Client::class, $client);
        self::assertSame($client, $this->app->make(Client::class));
        self::assertSame($client, $this->app->make('devfortress'));
    }

    public function testTheConfigIsMergedWithDefaults(): void
    {
        self::assertSame(15.0, config('devfortress.timeout'));
        self::assertSame(3, config('devfortress.retries'));
        self::assertSame(['/health', '/up'], config('devfortress.exclude_paths'));
        self::assertSame('standard', config('devfortress.privacy'));
    }

    public function testTheMiddlewareAliasIsRegistered(): void
    {
        $router = $this->app->make(Router::class);
        self::assertSame(DevFortressMiddleware::class, $router->getMiddleware()['devfortress']);
    }

    public function testTheFacadeResolvesTheSameClient(): void
    {
        $transport = $this->useTransport();
        DevFortress::trackEvent(['eventType' => 'custom', 'ip' => '203.0.113.5', 'method' => 'GET', 'path' => '/x', 'severity' => 'LOW']);
        self::assertSame(1, DevFortress::pendingEvents());
        DevFortress::flush();
        self::assertCount(1, $transport->requests);
    }

    public function testAMissingKeyOnlyFailsWhenTheClientIsResolved(): void
    {
        config(['devfortress.api_key' => null]);
        $this->expectException(\InvalidArgumentException::class);
        $this->app->make(Client::class);
    }

    public function testTheConfigCanBePublished(): void
    {
        $paths = \Illuminate\Support\ServiceProvider::pathsToPublish(\DevFortress\Laravel\DevFortressServiceProvider::class, 'devfortress-config');
        self::assertCount(1, $paths);
        self::assertFileExists((string) array_key_first($paths));
    }
}
