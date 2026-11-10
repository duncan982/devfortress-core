namespace DevFortress;

/// <summary>
/// Shared "classify this request/response, queue an event for it" logic for every .NET
/// framework adapter (the ASP.NET Core middleware in devfortress-aspnetcore, and any future
/// one), the same way the Go SDK's Observe/ObserveAndFlush is shared by its net/http and gin
/// adapters, and the Java/Ruby SDKs' Observer modules are shared by their own adapters.
/// </summary>
/// <remarks>
/// <see cref="ObserveAndFlush"/> is what adapters should call, not <see cref="Observe"/>:
/// <see cref="Observe"/> only queues the event. Under sparse traffic (fewer requests than the
/// client's batch size between flushes), a queued-only event can sit undelivered indefinitely
/// unless something else flushes it (a configured flush interval, an explicit flush/dispose
/// elsewhere, or the next batch filling up). This is the exact gap the Go SDK's gin adapter
/// shipped with originally — fixed after the fact there, ported correctly here from the start
/// so the ASP.NET Core adapter never has it.
/// </remarks>
public static class Observer
{
    /// <summary>Input <see cref="Observe"/>/<see cref="ObserveAndFlush"/> need, filled in from the adapter's own request type.</summary>
    public sealed record Input(
        string Method,
        string Path,
        string? RawQuery,
        int StatusCode,
        int LatencyMs,
        string? UserAgent,
        string? ForwardedFor,
        string? RealIp,
        string? RemoteAddr,
        string? UserId = null);

    /// <summary>
    /// Classifies and queues an event on the client's detached observer task, so delivery
    /// never delays the response. Only queues — see the type doc for why adapters should
    /// prefer <see cref="ObserveAndFlush"/>.
    /// </summary>
    public static void Observe(Client client, Input input) => Queue(client, input, flush: false);

    /// <summary>
    /// Behaves like <see cref="Observe"/>, but also flushes the queue once the event has been
    /// classified and queued, on that same detached task — so a single event is delivered
    /// even under sparse traffic, with no separate task racing the enqueue. This is what every
    /// adapter should call.
    /// </summary>
    public static void ObserveAndFlush(Client client, Input input) => Queue(client, input, flush: true);

    private static void Queue(Client client, Input input, bool flush)
    {
        string ip = ClientIp.Resolve(input.ForwardedFor, input.RealIp, RemoteHost(input.RemoteAddr));
        var classify = new Classifier.ClassifyInput(
            ip, input.Method, input.Path, input.StatusCode, input.LatencyMs,
            input.UserAgent, input.RawQuery, input.UserId);

        client.RunDetached(async () =>
        {
            var @event = Classifier.BuildEvent(classify);
            if (@event is null)
            {
                return;
            }
            client.TrackEvent(@event);
            if (flush)
            {
                await client.FlushAsync().ConfigureAwait(false);
            }
        });
    }

    /// <summary>Strips the port from a "host:port" remote address, or returns remoteAddr unchanged.</summary>
    private static string? RemoteHost(string? remoteAddr)
    {
        if (remoteAddr is null)
        {
            return null;
        }
        int lastColon = remoteAddr.LastIndexOf(':');
        if (lastColon == -1)
        {
            return remoteAddr;
        }
        // IPv6 literals ("::1", "[::1]:port") contain multiple colons; only strip a
        // trailing ":port" when the remainder before it isn't itself bare IPv6.
        string hostPart = remoteAddr[..lastColon];
        string portPart = remoteAddr[(lastColon + 1)..];
        if (portPart.Length == 0 || !portPart.All(char.IsDigit))
        {
            return remoteAddr;
        }
        if (hostPart.StartsWith('[') && hostPart.EndsWith(']'))
        {
            return hostPart[1..^1];
        }
        if (hostPart.Contains(':'))
        {
            // Bare IPv6 with no brackets and a trailing ":port" is ambiguous; leave it as-is.
            return remoteAddr;
        }
        return hostPart;
    }
}
