<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\ClientIp;
use PHPUnit\Framework\TestCase;

final class ClientIpTest extends TestCase
{
    public function testPrecedenceIsForwardedForThenRealIpThenSocket(): void
    {
        self::assertSame('203.0.113.9', ClientIp::resolve('203.0.113.9, 10.0.0.1', '198.51.100.1', '192.0.2.1'));
        self::assertSame('198.51.100.1', ClientIp::resolve(null, '198.51.100.1', '192.0.2.1'));
        self::assertSame('192.0.2.1', ClientIp::resolve('', '', '192.0.2.1'));
        self::assertSame('0.0.0.0', ClientIp::resolve(null, null, null));
    }

    public function testAnEntryThatIsNotAnIpIsSkipped(): void
    {
        self::assertSame('198.51.100.1', ClientIp::resolve('unknown', '198.51.100.1', '192.0.2.1'));
        self::assertSame('2001:db8::1', ClientIp::resolve('2001:db8::1', null, null));
        self::assertSame('0.0.0.0', ClientIp::resolve('<script>', 'nope', 'x'));
    }
}
