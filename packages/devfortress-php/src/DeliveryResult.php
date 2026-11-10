<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** The outcome of one delivery. The client returns this instead of throwing. */
final class DeliveryResult
{
    public function __construct(
        public readonly bool $ok,
        public readonly ?int $statusCode = null,
        public readonly mixed $body = null,
        public readonly ?string $error = null,
        public readonly int $attempts = 1,
    ) {
    }
}
