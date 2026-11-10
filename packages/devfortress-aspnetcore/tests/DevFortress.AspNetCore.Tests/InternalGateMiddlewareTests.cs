using DevFortress;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace DevFortress.AspNetCore.Tests;

/// <summary>
/// Internal/hybrid-mode pre-response gate (TODO 407 port) —
/// <c>UseDevFortress</c>'s <c>RunInternalGate</c>. Adapter-level proof
/// against the real middleware through a real ASP.NET Core pipeline via
/// <see cref="TestServer"/>, the same bar as the already-completed Ruby
/// Rails adapter's middleware_test.rb internal-mode tests and the Java
/// Spring Boot adapter's <c>DevFortressFilterInternalGateTest</c> — not
/// just engine-level unit tests.
/// </summary>
public class InternalGateMiddlewareTests
{
    private static async Task<IHost> StartHost(Client client, bool appShouldRun)
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.Configure(app =>
                {
                    app.UseDevFortress(client);
                    app.Run(async context =>
                    {
                        context.Items["appCalled"] = true;
                        context.Response.StatusCode = 200;
                        await context.Response.WriteAsync("ok");
                    });
                });
            })
            .StartAsync();
        return host;
    }

    private static HttpRequestMessage Request(string path, string? forwardedFor = null, string? userAgent = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (forwardedFor is not null)
        {
            req.Headers.Add("X-Forwarded-For", forwardedFor);
        }
        if (userAgent is not null)
        {
            req.Headers.Add("User-Agent", userAgent);
        }
        return req;
    }

    [Fact]
    public async Task InternalMode_CleanRequest_ReachesTheApp()
    {
        using var client = Client.Create("test-key").Transport(new RecordingTransport()).Mode("internal").Build();
        using var host = await StartHost(client, appShouldRun: true);
        var testClient = host.GetTestClient();

        var response = await testClient.SendAsync(Request("/products", forwardedFor: "203.0.113.11"));

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ok", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task InternalMode_ScannerUserAgent_IsBlockedBeforeReachingTheApp()
    {
        using var client = Client.Create("test-key").Transport(new RecordingTransport()).Mode("internal").Build();
        using var host = await StartHost(client, appShouldRun: false);
        var testClient = host.GetTestClient();

        var response = await testClient.SendAsync(Request("/", forwardedFor: "198.51.100.20", userAgent: "sqlmap/1.7"));

        Assert.Equal(System.Net.HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"error\":\"blocked\"", body);
        Assert.True(client.IsBlocked("198.51.100.20"));
    }

    [Fact]
    public async Task InternalMode_BlockedIp_StaysBlockedOnALaterCleanRequest()
    {
        using var client = Client.Create("test-key").Transport(new RecordingTransport()).Mode("internal").Build();
        using var host = await StartHost(client, appShouldRun: true);
        var testClient = host.GetTestClient();

        var first = await testClient.SendAsync(Request("/", forwardedFor: "198.51.100.21", userAgent: "nikto/2.5"));
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, first.StatusCode);

        var second = await testClient.SendAsync(Request("/products", forwardedFor: "198.51.100.21"));
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, second.StatusCode);
    }

    [Fact]
    public async Task ExternalMode_IsUnaffectedByTheInternalGate()
    {
        using var client = Client.Create("test-key").Transport(new RecordingTransport()).Build(); // default mode: external
        using var host = await StartHost(client, appShouldRun: true);
        var testClient = host.GetTestClient();

        var response = await testClient.SendAsync(Request("/", userAgent: "sqlmap/1.7"));

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task HybridMode_BlocksViaInternalFirst_SameAsInternalMode()
    {
        using var client = Client.Create("test-key").Transport(new RecordingTransport()).Mode("hybrid").Build();
        using var host = await StartHost(client, appShouldRun: false);
        var testClient = host.GetTestClient();

        var response = await testClient.SendAsync(Request("/", forwardedFor: "198.51.100.22", userAgent: "nikto/2.5"));

        Assert.Equal(System.Net.HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(CircuitState.Closed, client.CircuitBreaker!.State);
    }

    [Fact]
    public async Task ExcludedHealthPath_BypassesTheInternalGate_EvenInInternalMode()
    {
        using var client = Client.Create("test-key").Transport(new RecordingTransport()).Mode("internal").Build();
        using var host = await StartHost(client, appShouldRun: true);
        var testClient = host.GetTestClient();

        var response = await testClient.SendAsync(Request("/health", userAgent: "sqlmap/1.7"));

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
    }
}
