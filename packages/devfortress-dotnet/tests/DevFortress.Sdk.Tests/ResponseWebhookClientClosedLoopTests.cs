using System.Text.Json;
using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// Closed-loop local self-enforcement — TODO 358 regression coverage.
///
/// Node's own external-mode reference (devfortress.ts's handleWebhook/isBlocked pair) and
/// Python's ClosedLoopEngine both self-enforce block/revocation decisions via a local cache,
/// checked unconditionally before any remote fallback. This SDK previously only delivered and
/// verified these commands, leaving every embedding app to implement its own cache. These tests
/// cover the ported local-cache behavior.
/// </summary>
public class ResponseWebhookClientClosedLoopTests
{
    private static JsonElement Command(object value) => JsonSerializer.SerializeToElement(value);

    [Fact]
    public void IpBlock_CachedWhenSeverityHighOrCritical()
    {
        var client = new ResponseWebhookClient("https://example.test/webhook", "secret");
        Assert.False(client.IsIpBlocked("1.2.3.4"));

        client.RecordInboundCommand(Command(new { type = "ip_block", ip = "1.2.3.4", severity = "high" }));

        Assert.True(client.IsIpBlocked("1.2.3.4"));
    }

    [Fact]
    public void IpBlock_NotCachedWhenSeverityLow()
    {
        var client = new ResponseWebhookClient("https://example.test/webhook", "secret");

        client.RecordInboundCommand(Command(new { type = "ip_block", ip = "5.6.7.8", severity = "low" }));

        Assert.False(client.IsIpBlocked("5.6.7.8"));
    }

    [Fact]
    public void IpBlock_DefaultsToCachedWhenSeverityUnset()
    {
        var client = new ResponseWebhookClient("https://example.test/webhook", "secret");

        client.RecordInboundCommand(Command(new { type = "ip_block", ip = "9.9.9.9" }));

        Assert.True(client.IsIpBlocked("9.9.9.9"));
    }

    [Fact]
    public void SessionRevocation_CachesUserAndIp()
    {
        var client = new ResponseWebhookClient("https://example.test/webhook", "secret");
        Assert.False(client.IsUserBlocked("user-1"));

        client.RecordInboundCommand(Command(new { type = "session_revocation", user_id = "user-1", ip = "10.0.0.1" }));

        Assert.True(client.IsUserBlocked("user-1"));
        Assert.True(client.IsIpBlocked("10.0.0.1"));
    }

    [Fact]
    public void UnrelatedIpOrUser_NotBlocked()
    {
        var client = new ResponseWebhookClient("https://example.test/webhook", "secret");
        client.RecordInboundCommand(Command(new { type = "ip_block", ip = "1.1.1.1", severity = "critical" }));

        Assert.False(client.IsIpBlocked("2.2.2.2"));
        Assert.False(client.IsUserBlocked("unrelated-user"));
    }
}
