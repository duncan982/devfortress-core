using System.Diagnostics;
using DevFortress;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace DevFortress.AspNetCore.Tests;

/// <summary>
/// THE regression test this whole adapter exists for: a single sparse request through the
/// real <c>UseDevFortress</c> middleware — far below the client's batch size (25), with no
/// flush interval configured — must still be delivered, and must not add latency to the
/// response. This is the Go SDK gin adapter's original sparse-traffic gap (discovered live,
/// fixed after the fact); this adapter is built against <see cref="Observer.ObserveAndFlush"/>
/// from the start specifically so it never has this gap. If this test ever fails, do not "fix"
/// it by lowering the batch size or adding a flush interval to the demo — that would hide the
/// adapter's own bug instead of fixing it.
/// </summary>
public class SparseDeliveryRegressionTests
{
    private static async Task<IHost> StartHost(Client client, Action<IApplicationBuilder>? terminal = null)
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.Configure(app =>
                {
                    app.UseDevFortress(client);
                    terminal?.Invoke(app);
                });
            })
            .StartAsync();
        return host;
    }

    [Fact]
    public async Task ASingleRequestIsDeliveredWithoutWaitingForBatchSizeOrInterval()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).BatchSize(25).Build();

        using var host = await StartHost(client, app => app.Run(async context =>
        {
            context.Response.StatusCode = 401; // auth_failure: classified
            await context.Response.CompleteAsync();
        }));
        var testClient = host.GetTestClient();

        var sw = Stopwatch.StartNew();
        await testClient.GetAsync("/login");
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < 200, $"the middleware must not block the response on delivery (took {sw.ElapsedMilliseconds}ms)");

        await WaitUntil(() => transport.CallCount() >= 1, TimeSpan.FromSeconds(2));
        Assert.Equal(1, transport.CallCount());
        Assert.Equal(0, client.PendingEvents());
    }

    [Fact]
    public async Task ExcludedPathsAreNeverReported()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).Build();

        using var host = await StartHost(client, app => app.Run(async context =>
        {
            context.Response.StatusCode = 200;
            await context.Response.CompleteAsync();
        }));
        var testClient = host.GetTestClient();

        await testClient.GetAsync("/health");
        await Task.Delay(200);
        Assert.Equal(0, transport.CallCount());
    }

    [Fact]
    public async Task AHandlerExceptionStillPropagatesAndIsStillReported()
    {
        var transport = new RecordingTransport();
        using var client = Client.Create("test-key").Transport(transport).Build();

        using var host = await StartHost(client, app => app.Run(context =>
        {
            context.Response.StatusCode = 500;
            throw new InvalidOperationException("handler blew up");
        }));
        var testClient = host.GetTestClient();

        // TestServer surfaces an unhandled middleware exception by throwing it back to the
        // caller rather than swallowing it into a generic 500 — proving the middleware itself
        // did not swallow it either.
        await Assert.ThrowsAnyAsync<Exception>(() => testClient.GetAsync("/boom"));

        await WaitUntil(() => transport.CallCount() >= 1, TimeSpan.FromSeconds(2));
        Assert.True(1 == transport.CallCount(), "the 500 must still be reported even though the handler threw");
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
