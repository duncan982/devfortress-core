<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use RuntimeException;

final class AliasVerifyError extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?int $httpStatus = null,
        public readonly mixed $body = null,
    ) {
        parent::__construct($message);
    }
}
