namespace DevFortress;

/// <summary>
/// Default <see cref="ITransport"/>: the BCL's built-in <see cref="HttpClient"/>, pinned to
/// HTTP/1.1 with no redirects followed (a 3xx is returned to the caller as-is, never
/// re-requested) — matching Go's <c>net/http</c>-only, Java/Ruby's stdlib-only approach: no
/// new HTTP dependency.
/// </summary>
/// <remarks>
/// The HTTP version is pinned explicitly rather than left to <see cref="HttpClient"/>'s
/// default negotiation: the Java SDK's port of this same transport shipped with a latent bug
/// where an unpinned client silently preferred HTTP/2 and failed outright against a plaintext
/// HTTP/1.1-only server, with every delivery failing silently (delivery failures are logged,
/// never thrown, by design). Pinning here from the start avoids that class of bug rather than
/// discovering it live.
///
/// <paramref name="rawUrl"/>-equivalent endpoints are passed to <see cref="Uri"/> as-is rather
/// than built up through a builder that could re-encode the path or query — the same endpoint
/// string the <see cref="Signer"/> signed is what reaches the wire.
/// </remarks>
public sealed class HttpTransport : ITransport, IDisposable
{
    private readonly HttpClient _client;
    private readonly bool _ownsClient;

    public HttpTransport()
    {
        _client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
        _ownsClient = true;
    }

    public HttpTransport(HttpClient client)
    {
        _client = client;
        _ownsClient = false;
    }

    public async Task<TransportResponse> SendAsync(string method, string rawUrl, IReadOnlyDictionary<string, string> headers,
        byte[]? body, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), new Uri(rawUrl))
        {
            Version = System.Net.HttpVersion.Version11,
            VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionExact,
        };
        if (body is { Length: > 0 })
        {
            request.Content = new ByteArrayContent(body);
        }
        foreach (var header in headers)
        {
            if (header.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                request.Content ??= new ByteArrayContent([]);
                request.Content.Headers.Remove("Content-Type");
                request.Content.Headers.TryAddWithoutValidation("Content-Type", header.Value);
            }
            else
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cts.Token)
            .ConfigureAwait(false);
        byte[] responseBody = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return new TransportResponse((int)response.StatusCode, responseBody);
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _client.Dispose();
        }
    }
}
