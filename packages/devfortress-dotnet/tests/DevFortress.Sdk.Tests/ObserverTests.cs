using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// Proves the sparse-traffic delivery guarantee at the point it actually matters:
/// <see cref="Observer.ObserveAndFlush"/> delivers a single observed request even though the
/// client's batch size (25) is never reached, while <see cref="Observer.Observe"/> alone
/// leaves it sitting queued — the exact gap the Go SDK's gin adapter originally shipped with.
/// Every framework adapter (the ASP.NET Core middleware included) must call
/// ObserveAndFlush, not Observe, for exactly this reason.
/// </summary>
public class ObserverTests
{
    private static Observer.Input Input(int statusCode) =>
        new("GET", "/login", "", statusCode, 5, "curl/8.0", "", "", "203.0.113.7");

    [Fact]
    public async Task ObserveAndFlushDeliversASingleSparseEventWithoutWaitingForBatchSize()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).BatchSize(25).Build();

        Observer.ObserveAndFlush(client, Input(401)); // auth_failure: classified, not dropped

        await WaitUntil(() => transport.CallCount() >= 1, TimeSpan.FromSeconds(2));
        Assert.Equal(1, transport.CallCount());
        Assert.Equal(0, client.PendingEvents());
    }

    [Fact]
    public async Task ObserveAloneOnlyQueuesAndDoesNotDeliver()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).BatchSize(25).Build();

        Observer.Observe(client, Input(401));

        await WaitUntil(() => client.PendingEvents() >= 1, TimeSpan.FromSeconds(2));
        await Task.Delay(200);
        Assert.Equal(0, transport.CallCount());
        Assert.Equal(1, client.PendingEvents());
    }

    [Fact]
    public async Task ObserveAndFlushSkipsNonSecurityRelevantRequests()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).BatchSize(25).Build();

        Observer.ObserveAndFlush(client, Input(200));

        await Task.Delay(200);
        Assert.Equal(0, transport.CallCount());
        Assert.Equal(0, client.PendingEvents());
    }

    private static async Task WaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"condition not met within {timeout}");
            }
            await Task.Delay(10);
        }
    }
}
