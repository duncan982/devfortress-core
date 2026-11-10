<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * A security event as the ingest endpoint takes it. Field names are the wire
 * names (eventType, ip, method, path, severity, ...); pass a plain array to
 * the client instead if that is easier.
 */
final class Event
{
    /** @param array<string, mixed> $data */
    public function __construct(private readonly array $data)
    {
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self($data);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->data;
    }
}
