<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * Picks the end-user IP for an event from what the request shows.
 *
 * Precedence: first X-Forwarded-For entry, then X-Real-IP, then the socket
 * address, then 0.0.0.0. A candidate that is not an IP address is skipped, so a
 * malformed forwarded header cannot poison a batch.
 */
final class ClientIp
{
    public static function resolve(?string $forwardedFor, ?string $realIp, ?string $remoteAddr): string
    {
        $first = $forwardedFor !== null ? trim(explode(',', $forwardedFor)[0]) : '';
        foreach ([$first, trim((string) $realIp), trim((string) $remoteAddr)] as $candidate) {
            if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                return $candidate;
            }
        }

        return '0.0.0.0';
    }
}
