<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\BoundedMap;
use PHPUnit\Framework\TestCase;

final class BoundedMapTest extends TestCase
{
    public function testSetAndGet(): void
    {
        $map = new BoundedMap(3);
        $map->set('a', 1);
        self::assertSame(1, $map->get('a'));
    }

    public function testGetMissingKeyReturnsNull(): void
    {
        $map = new BoundedMap(3);
        self::assertNull($map->get('missing'));
    }

    public function testEvictsOldestOnceAtCapacity(): void
    {
        $map = new BoundedMap(2);
        $map->set('a', 1);
        $map->set('b', 2);
        $map->set('c', 3);

        self::assertFalse($map->has('a'));
        self::assertTrue($map->has('b'));
        self::assertTrue($map->has('c'));
        self::assertSame(2, $map->size());
    }

    public function testSetOnExistingKeyDoesNotEvict(): void
    {
        $map = new BoundedMap(2);
        $map->set('a', 1);
        $map->set('b', 2);
        $map->set('a', 99);

        self::assertSame(2, $map->size());
        self::assertSame(99, $map->get('a'));
    }

    public function testDeleteRemovesEntry(): void
    {
        $map = new BoundedMap(3);
        $map->set('a', 1);

        self::assertTrue($map->delete('a'));
        self::assertFalse($map->has('a'));
        self::assertFalse($map->delete('a'));
    }

    public function testClearRemovesAllEntries(): void
    {
        $map = new BoundedMap(3);
        $map->set('a', 1);
        $map->set('b', 2);
        $map->clear();
        self::assertSame(0, $map->size());
    }

    public function testForEachVisitsAllEntries(): void
    {
        $map = new BoundedMap(3);
        $map->set('a', 1);
        $map->set('b', 2);

        $seen = [];
        $map->forEach(function (int $value, string $key) use (&$seen): void {
            $seen[$key] = $value;
        });

        self::assertSame(['a' => 1, 'b' => 2], $seen);
    }
}
