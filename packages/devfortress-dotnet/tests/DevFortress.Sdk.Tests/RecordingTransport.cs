using System.Collections.Concurrent;
using System.Text;
using DevFortress;

namespace DevFortress.Sdk.Tests;

/// <summary>Test-only <see cref="ITransport"/> that records every call and plays back scripted responses/failures.</summary>
internal sealed class RecordingTransport : ITransport
{
    public sealed record Call(string Method, string Url, IReadOnlyDictionary<string, string> Headers, byte[] Body);

    public readonly ConcurrentQueue<Call> Calls = new();
    private readonly ConcurrentQueue<Func<TransportResponse>> _script = new();

    public RecordingTransport Respond(int statusCode, string body)
    {
        _script.Enqueue(() => new TransportResponse(statusCode, Encoding.UTF8.GetBytes(body)));
        return this;
    }

    public RecordingTransport Fail(Exception e)
    {
        _script.Enqueue(() => throw e);
        return this;
    }

    public Task<TransportResponse> SendAsync(string method, string rawUrl, IReadOnlyDictionary<string, string> headers,
        byte[]? body, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        Calls.Enqueue(new Call(method, rawUrl, headers, body ?? []));
        if (!_script.TryDequeue(out var next))
        {
            return Task.FromResult(new TransportResponse(200, Encoding.UTF8.GetBytes("{}")));
        }
        return Task.FromResult(next());
    }

    public int CallCount() => Calls.Count;
}
