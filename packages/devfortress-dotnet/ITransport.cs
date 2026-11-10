namespace DevFortress;

/// <summary>
/// Sends one HTTP request and returns the response. The URL and the header/body bytes
/// must go on the wire exactly as given: the request signature covers them.
/// Implementations throw only on a network-level failure (no HTTP response); an HTTP
/// error status is a normal <see cref="TransportResponse"/>. Swappable in tests (a
/// recording transport).
/// </summary>
public interface ITransport
{
    Task<TransportResponse> SendAsync(string method, string rawUrl, IReadOnlyDictionary<string, string> headers,
        byte[]? body, TimeSpan timeout, CancellationToken cancellationToken = default);
}

public sealed record TransportResponse(int StatusCode, byte[] Body);
