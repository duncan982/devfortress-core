<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use InvalidArgumentException;

/** Agent ID validation, shared by AgentAdapter and AgentCredentialManager. */
final class AgentId
{
    public const MAX_LENGTH = 128;
    private const PATTERN = '/^[a-zA-Z0-9_\-.:@]+$/D';

    private function __construct()
    {
    }

    /**
     * Validate agent ID to prevent injection and ensure safe usage as cache
     * keys and pseudo-URL path segments.
     */
    public static function validate(string $agentId): void
    {
        if ($agentId === '') {
            throw new InvalidArgumentException('agentId is required and must be a non-empty string');
        }
        if (strlen($agentId) > self::MAX_LENGTH) {
            throw new InvalidArgumentException(sprintf('agentId must be at most %d characters', self::MAX_LENGTH));
        }
        if (preg_match(self::PATTERN, $agentId) !== 1) {
            throw new InvalidArgumentException('agentId may only contain alphanumeric characters, hyphens, underscores, dots, colons, and @');
        }
    }
}
