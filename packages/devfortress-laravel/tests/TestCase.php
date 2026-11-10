<?php

declare(strict_types=1);

namespace DevFortress\Laravel\Tests;

use DevFortress\Laravel\DevFortressServiceProvider;
use DevFortress\Laravel\Facades\DevFortress;
use DevFortress\Laravel\Tests\Support\RecordingTransport;
use DevFortress\Sdk\Client;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected const KEY = 'vx_live_test_vector_key_do_not_use';
    protected const ENDPOINT = 'http://platform.test/api/events/ingest';

    protected RecordingTransport $transport;

    /**
     * @param Application $app
     *
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [DevFortressServiceProvider::class];
    }

    /**
     * @param Application $app
     *
     * @return array<string, class-string>
     */
    protected function getPackageAliases($app): array
    {
        return ['DevFortress' => DevFortress::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('devfortress.api_key', self::KEY);
        $app['config']->set('devfortress.endpoint', self::ENDPOINT);
        $app['config']->set('devfortress.app_id', 'adapter-tests');
    }

    /** Swap the singleton for a client that records instead of sending. */
    protected function useTransport(?RecordingTransport $transport = null): RecordingTransport
    {
        $this->transport = $transport ?? new RecordingTransport();
        $transport = $this->transport;
        $this->app->singleton(Client::class, static fn (): Client => new Client(
            self::KEY,
            self::ENDPOINT,
            2.0,
            1,
            defaults: ['appId' => 'adapter-tests', 'environment' => 'testing'],
            transport: $transport,
            sleeper: static function (float $s): void {
            },
        ));

        return $this->transport;
    }

    /** @param Router $router */
    protected function defineRoutes($router): void
    {
        $router->middleware('devfortress')->group(static function (Router $router): void {
            $router->get('/ok', static fn () => response('fine'));
            $router->get('/secret', static fn () => response('no', 401));
            $router->get('/boom', static fn () => response('oops', 500));
            $router->get('/missing-thing', static fn () => response('gone', 404));
            $router->get('/search', static fn () => response('results'));
            $router->get('/health', static fn () => response('up', 500)); // excluded even when failing
            $router->post('/submit', static fn () => response('bad', 422));
        });
    }
}
