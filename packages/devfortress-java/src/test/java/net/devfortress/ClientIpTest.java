package net.devfortress;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClientIpTest {
    @Test
    void prefersFirstForwardedForEntry() {
        assertEquals("203.0.113.7", ClientIp.resolve("203.0.113.7, 10.0.0.1", "10.0.0.2", "10.0.0.3"));
    }

    @Test
    void fallsBackToRealIpWhenForwardedForIsMalformed() {
        assertEquals("203.0.113.9", ClientIp.resolve("not-an-ip", "203.0.113.9", "10.0.0.3"));
    }

    @Test
    void fallsBackToRemoteAddrWhenNeitherHeaderIsAnIp() {
        assertEquals("203.0.113.10", ClientIp.resolve("", "", "203.0.113.10"));
    }

    @Test
    void defaultsToZeroAddressWhenNothingIsAnIp() {
        assertEquals("0.0.0.0", ClientIp.resolve("", "", ""));
        assertEquals("0.0.0.0", ClientIp.resolve(null, null, null));
    }

    @Test
    void acceptsIpv6Literals() {
        assertEquals("::1", ClientIp.resolve("", "", "::1"));
    }

    @Test
    void skipsAMalformedForwardedForEntirely() {
        assertEquals("203.0.113.9", ClientIp.resolve("totally-bogus-header", "203.0.113.9", ""));
    }
}
