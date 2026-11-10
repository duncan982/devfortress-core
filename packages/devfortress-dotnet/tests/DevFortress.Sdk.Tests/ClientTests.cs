using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

public class ClientTests
{
    private static Dictionary<string, object?> Event(string path) => new()
    {
        ["eventType"] = "custom",
        ["ip"] = "203.0.113.7",
        ["method"] = "GET",
        ["path"] = path,
        ["severity"] = "LOW",
    };

    [Fact]
    public void QueuesUntilBatchSizeThenAutoFlushes()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).BatchSize(3).Retries(1).Build();

        client.TrackEvent(Event("/a"));
        client.TrackEvent(Event("/b"));
        Assert.Equal(0, transport.CallCount());
        Assert.Equal(2, client.PendingEvents());

        client.TrackEvent(Event("/c"));
        Assert.Equal(1, transport.CallCount());
        Assert.Equal(0, client.PendingEvents());
    }

    [Fact]
    public void ExplicitFlushSendsWhateverIsQueued()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).BatchSize(25).Retries(1).Build();

        client.TrackEvent(Event("/a"));
        var results = client.Flush();
        Assert.Single(results);
        Assert.True(results[0].Ok);
        Assert.Equal(1, transport.CallCount());
    }

    [Fact]
    public void RetriesOn5xxWithExponentialBackoffThenSucceeds()
    {
        var transport = new RecordingTransport().Respond(500, "{}").Respond(500, "{}").Respond(200, "{\"ok\":true}");
        using var client = Client.Create("test-key").Transport(transport).Retries(3).BackoffBase(TimeSpan.FromMilliseconds(1)).Build();

        client.TrackEvent(Event("/a"));
        var result = client.Flush()[0];
        Assert.True(result.Ok);
        Assert.Equal(3, result.Attempts);
        Assert.Equal(3, transport.CallCount());
    }

    [Fact]
    public void NeverRetriesA4xx()
    {
        var transport = new RecordingTransport().Respond(400, "{\"error\":\"bad\"}");
        using var client = Client.Create("test-key").Transport(transport).Retries(3).BackoffBase(TimeSpan.FromMilliseconds(1)).Build();

        client.TrackEvent(Event("/a"));
        var result = client.Flush()[0];
        Assert.False(result.Ok);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal(1, transport.CallCount());
    }

    [Fact]
    public void ExhaustsRetriesOnPersistent5xxAndNeverThrows()
    {
        var transport = new RecordingTransport().Respond(503, "{}").Respond(503, "{}").Respond(503, "{}");
        using var client = Client.Create("test-key").Transport(transport).Retries(3).BackoffBase(TimeSpan.FromMilliseconds(1)).Build();

        client.TrackEvent(Event("/a"));
        var result = client.Flush()[0];
        Assert.False(result.Ok);
        Assert.Equal(3, result.Attempts);
        Assert.Equal(3, transport.CallCount());
    }

    [Fact]
    public void DisposeFlushesWhateverIsStillQueued()
    {
        var transport = new RecordingTransport();
        var client = Client.Create("test-key").Transport(transport).BatchSize(25).Build();
        client.TrackEvent(Event("/a"));
        Assert.Equal(0, transport.CallCount());
        client.Dispose();
        Assert.Equal(1, transport.CallCount());
    }

    [Fact]
    public void EveryAttemptIsSignedWithAFreshNonce()
    {
        var transport = new RecordingTransport().Respond(500, "{}").Respond(200, "{}");
        using var client = Client.Create("test-key").Transport(transport).Retries(2).BackoffBase(TimeSpan.FromMilliseconds(1)).Build();

        client.TrackEvent(Event("/a"));
        client.Flush();
        var calls = transport.Calls.ToArray();
        Assert.Equal(2, calls.Length);
        string nonce1 = calls[0].Headers[Signer.NonceHeader];
        string nonce2 = calls[1].Headers[Signer.NonceHeader];
        Assert.NotEqual(nonce1, nonce2);
    }

    [Fact]
    public void StrictPrivacyHashesIpAndDropsUserAgent()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).Privacy("strict").Build();

        var e = Event("/a");
        e["userAgent"] = "curl/8.0";
        client.TrackEvent(e);
        client.Flush();

        string body = System.Text.Encoding.UTF8.GetString(transport.Calls.First().Body);
        Assert.DoesNotContain("203.0.113.7", body);
        Assert.DoesNotContain("curl/8.0", body);
    }
}
