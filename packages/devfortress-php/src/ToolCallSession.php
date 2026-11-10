<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Mutable per-session state for ToolCallSequenceValidator. */
final class ToolCallSession
{
    /** @var list<string> */
    public array $callHistory = [];
    /** @var array<string, int> */
    public array $callCounts = [];
    /** @var list<array{timestamp: int, tool: string, reason: string}> */
    public array $violations = [];

    public function __construct(public readonly int $createdAt)
    {
    }
}
