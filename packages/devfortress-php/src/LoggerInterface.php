<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use Stringable;

/**
 * The one logging method the SDK needs, shaped like PSR-3's `log()` so that any
 * PSR-3 logger can be passed to the client directly without a Composer
 * dependency on psr/log.
 */
interface LoggerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function log(mixed $level, string|Stringable $message, array $context = []): void;
}
