using System.Collections.Concurrent;
using System.Text;
using DevFortress;

namespace DevFortress.AspNetCore.Tests;

/// <summary>Test-only <see cref="ITransport"/> that records every call. Mirrors devfortress-dotnet's own copy (duplicated per module, same pattern as devfortress-spring-boot's copy of devfortress-java's).</summary>
internal sealed class RecordingTransport : ITransport
{
    public readonly ConcurrentQueue<byte[]> Bodies = new();

    public Task<TransportResponse> SendAsync(string method, string rawUrl, IReadOnlyDictionary<string, string> headers,
        byte[]? body, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        Bodies.Enqueue(body ?? []);
        return Task.FromResult(new TransportResponse(200, Encoding.UTF8.GetBytes("{}")));
    }

    public int CallCount() => Bodies.Count;
}
