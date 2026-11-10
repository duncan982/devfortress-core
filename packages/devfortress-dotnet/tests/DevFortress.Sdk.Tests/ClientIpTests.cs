using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

public class ClientIpTests
{
    [Fact]
    public void PrefersFirstForwardedForEntry()
    {
        Assert.Equal("203.0.113.7", ClientIp.Resolve("203.0.113.7, 10.0.0.1", "10.0.0.2", "10.0.0.3"));
    }

    [Fact]
    public void FallsBackToRealIpWhenForwardedForIsMalformed()
    {
        Assert.Equal("203.0.113.9", ClientIp.Resolve("not-an-ip", "203.0.113.9", "10.0.0.3"));
    }

    [Fact]
    public void FallsBackToRemoteAddrWhenNeitherHeaderIsAnIp()
    {
        Assert.Equal("203.0.113.10", ClientIp.Resolve("", "", "203.0.113.10"));
    }

    [Fact]
    public void DefaultsToZeroAddressWhenNothingIsAnIp()
    {
        Assert.Equal("0.0.0.0", ClientIp.Resolve("", "", ""));
        Assert.Equal("0.0.0.0", ClientIp.Resolve(null, null, null));
    }

    [Fact]
    public void AcceptsIpv6Literals()
    {
        Assert.Equal("::1", ClientIp.Resolve("", "", "::1"));
    }

    [Fact]
    public void SkipsAMalformedForwardedForEntirely()
    {
        Assert.Equal("203.0.113.9", ClientIp.Resolve("totally-bogus-header", "203.0.113.9", ""));
    }
}
