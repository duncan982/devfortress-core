<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

final class WebhookVerification
{
    public function __construct(
        public readonly bool $valid,
        public readonly ?string $reason = null,
    ) {
    }
}
