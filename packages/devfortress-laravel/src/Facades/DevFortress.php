<?php

declare(strict_types=1);

namespace DevFortress\Laravel\Facades;

use DevFortress\Sdk\Client;
use DevFortress\Sdk\DeliveryResult;
use DevFortress\Sdk\Event;
use Illuminate\Support\Facades\Facade;

/**
 * @method static void trackEvent(array<string, mixed>|Event $event)
 * @method static void trackEvents(list<array<string, mixed>|Event> $events)
 * @method static list<DeliveryResult> flush()
 * @method static bool testConnection()
 * @method static int pendingEvents()
 *
 * @see Client
 */
final class DevFortress extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return Client::class;
    }
}
