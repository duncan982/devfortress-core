<?php

declare(strict_types=1);

namespace DevFortress\Laravel;

use DevFortress\Laravel\Http\Middleware\DevFortressMiddleware;
use DevFortress\Sdk\Client;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Log\LogManager;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

final class DevFortressServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/devfortress.php', 'devfortress');

        // All platform calls go through the core client, so signing lives in one place.
        $this->app->singleton(Client::class, static function (Application $app): Client {
            $repository = $app->make(Repository::class);
            /** @var array<string, mixed> $config */
            $config = (array) $repository->get('devfortress', []);
            $channel = $config['log_channel'] ?? null;
            $log = $app->make(LogManager::class);
            $logger = is_string($channel) && $channel !== '' ? $log->channel($channel) : $log;

            $appId = $config['app_id'] ?? $repository->get('app.name');

            $mode = $config['mode'] ?? 'external';
            $mode = in_array($mode, ['external', 'internal', 'hybrid'], true) ? $mode : 'external';

            return new Client(
                apiKey: is_string($config['api_key'] ?? null) ? $config['api_key'] : '',
                endpoint: is_string($config['endpoint'] ?? null) && $config['endpoint'] !== '' ? $config['endpoint'] : Client::DEFAULT_ENDPOINT,
                timeout: is_numeric($config['timeout'] ?? null) ? (float) $config['timeout'] : Client::DEFAULT_TIMEOUT,
                retries: is_numeric($config['retries'] ?? null) ? (int) $config['retries'] : Client::DEFAULT_RETRIES,
                logger: $logger,
                defaults: [
                    'appId' => is_string($appId) && $appId !== '' ? $appId : 'laravel',
                    'environment' => is_string($config['environment'] ?? null) && $config['environment'] !== '' ? $config['environment'] : $app->environment(),
                ],
                privacy: ($config['privacy'] ?? 'standard') === 'strict' ? 'strict' : 'standard',
                mode: $mode,
            );
        });
        $this->app->alias(Client::class, 'devfortress');
    }

    public function boot(): void
    {
        $this->app->make(Router::class)->aliasMiddleware('devfortress', DevFortressMiddleware::class);

        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__ . '/../config/devfortress.php' => $this->app->configPath('devfortress.php')], 'devfortress-config');
        }
    }
}
