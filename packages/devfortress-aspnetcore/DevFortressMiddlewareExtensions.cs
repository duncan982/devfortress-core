using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace DevFortress.AspNetCore;

/// <summary>
/// ASP.NET Core middleware that observes each request (method, path, status, timing, client
/// IP and classifier result) and reports a security event for it, the same way
/// devfortress-laravel's middleware does for Laravel, devfortress-rails's Rack middleware
/// does for Rails, and devfortress-spring-boot's filter does for Spring: the pipeline is only
/// timed here — nothing in <see cref="UseDevFortress"/> changes or fails the response.
/// </summary>
/// <remarks>
/// Reporting happens in a <c>finally</c> block, after <c>await next(context)</c> returns — the
/// ASP.NET Core-appropriate equivalent of Laravel's <c>terminate()</c> hook, Rack's
/// <c>#close</c> hook and the Spring Boot filter's own post-<c>doFilter</c> <c>finally</c>
/// block, all of which likewise only run once the handler has finished.
///
/// An earlier version of this middleware used <see cref="HttpResponse.OnCompleted"/> instead,
/// on the theory that it was the more exact ASP.NET Core equivalent (documented as firing only
/// once the response has been sent). <b>That is true only on the normal-completion path.</b>
/// Verified live with an isolated repro (no DevFortress code involved): when an unhandled
/// exception propagates out of the request pipeline, <c>OnCompleted</c> callbacks are never
/// invoked at all, under both <c>TestServer</c> and Kestrel's documented connection-abort
/// behaviour for that case — so a request that threw (arguably the single most
/// security-relevant case this SDK exists to catch) would have gone completely unreported
/// with no error anywhere. <c>try</c>/<c>finally</c> around <c>next(context)</c> does not have
/// this gap: the <c>finally</c> block always runs, matching the regression test below.
///
/// It calls <see cref="Observer.ObserveAndFlush"/>, not <see cref="Observer.Observe"/>, so a
/// single request is delivered even under sparse traffic: this is the Go SDK's gin adapter's
/// original sparse-traffic gap, fixed after the fact there and ported here from the start — do
/// not change this to <c>Observe</c> without also wiring in some other guaranteed flush path
/// (<c>Client</c>'s flush interval, or an explicit flush/dispose elsewhere), or a lone event
/// can sit queued and undelivered indefinitely.
///
/// Reporting itself runs on the <see cref="Client"/>'s own detached background task (see
/// <see cref="Observer"/>), so it adds no latency to the response.
/// </remarks>
public static class DevFortressMiddlewareExtensions
{
    private const string UserIdItemKey = "devfortress.userId";

    /// <summary>
    /// Registers the DevFortress adapter. In "external" mode (the <see cref="Client"/>'s
    /// default), behaviour is unchanged from before internal/hybrid mode existed: every request
    /// is timed and reported after the response, as described on this type.
    ///
    /// <para>In "internal"/"hybrid" mode (<see cref="Client.Mode"/>), a pre-response gate runs
    /// first: it builds an <see cref="InternalCLRequest"/> from the incoming
    /// <see cref="HttpContext.Request"/> and calls <see cref="Client.ObserveAsync"/> BEFORE
    /// <c>next(context)</c>. If the request is flagged, this short-circuits the pipeline —
    /// <c>context.Response.StatusCode</c> is set to 403 and a JSON body is written directly;
    /// <c>next</c> is never called, so the downstream application never sees a blocked request.
    /// The after-response reporting step still runs for allowed requests (unchanged).</para>
    /// </summary>
    public static IApplicationBuilder UseDevFortress(this IApplicationBuilder app, Client client, DevFortressOptions? options = null)
    {
        var opts = options ?? new DevFortressOptions();
        return app.Use(async (context, next) =>
        {
            string path = context.Request.Path.Value ?? "";
            if (IsExcluded(path, opts.ExcludePaths))
            {
                await next(context);
                return;
            }

            if (client.Mode is "internal" or "hybrid")
            {
                bool blocked = await RunInternalGate(context, client, opts).ConfigureAwait(false);
                if (blocked)
                {
                    return;
                }
            }

            long started = Stopwatch.GetTimestamp();
            try
            {
                // next(context) is intentionally not inside the catch below (there is none):
                // an exception from the wrapped application must propagate exactly as it would
                // without this middleware. Only the reporting in the finally block is allowed
                // to fail silently.
                await next(context);
            }
            finally
            {
                try
                {
                    int latencyMs = (int)Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                    Report(context, client, latencyMs);
                }
                catch
                {
                    // Reporting must never affect the application; the client already logs
                    // delivery failures, so a failure building the report itself (a malformed
                    // request, an unreadable header) must not surface either.
                }
            }
        });
    }

    /// <summary>
    /// The internal/hybrid-mode pre-response gate. Returns true if the request was blocked (the
    /// caller must not forward to <c>next</c>). See <see cref="DevFortressOptions.InspectRequestBody"/>
    /// for this gate's documented body-inspection scope limitation (off by default).
    /// </summary>
    private static async Task<bool> RunInternalGate(HttpContext context, Client client, DevFortressOptions opts)
    {
        var request = context.Request;

        string? body = null;
        if (opts.InspectRequestBody)
        {
            body = await ReadBufferedBodyAsync(request).ConfigureAwait(false);
        }

        var headers = new Dictionary<string, string>();
        foreach (var kv in request.Headers)
        {
            headers[kv.Key] = kv.Value.ToString();
        }

        var req = new InternalCLRequest
        {
            Ip = ResolveClientIp(context),
            Method = request.Method,
            Path = request.Path.Value ?? "",
            UserAgent = request.Headers.UserAgent.ToString(),
            Query = request.QueryString.HasValue ? request.QueryString.Value!.TrimStart('?') : "",
            Body = body,
            Headers = headers,
        };

        // ObserveAsync delegates to InternalClosedLoopEngine.EvaluateAsync, which already fails
        // closed/open internally per InternalCLConfig.FailMode and should not throw. Unlike the
        // after-response Report() path, an exception here is deliberately NOT swallowed: a gate
        // that cannot decide must not silently fall through to "allow" — it should surface as a
        // 500 instead.
        ObserveResult? result = await client.ObserveAsync(req).ConfigureAwait(false);

        if (result is { Flagged: true })
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            string json = JsonSerializer.Serialize(new
            {
                error = "blocked",
                reason = result.Decision,
                eventId = result.EventId,
            });
            await context.Response.WriteAsync(json).ConfigureAwait(false);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Buffers and reads the full request body, resetting <c>Body.Position</c> to 0 afterwards
    /// so the downstream pipeline still sees it from the start. Only called when
    /// <see cref="DevFortressOptions.InspectRequestBody"/> is true.
    /// </summary>
    private static async Task<string> ReadBufferedBodyAsync(HttpRequest request)
    {
        request.EnableBuffering();
        request.Body.Position = 0;
        using var reader = new StreamReader(request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        string body = await reader.ReadToEndAsync().ConfigureAwait(false);
        request.Body.Position = 0;
        return body;
    }

    /// <summary>Same X-Forwarded-For / X-Real-IP / RemoteIpAddress fallback chain as <see cref="Report"/>'s <see cref="Observer.Input"/>.</summary>
    private static string ResolveClientIp(HttpContext context)
    {
        var request = context.Request;
        string forwardedFor = request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }
        string realIp = request.Headers["X-Real-IP"].ToString();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp;
        }
        return context.Connection.RemoteIpAddress?.ToString() ?? "0.0.0.0";
    }

    private static void Report(HttpContext context, Client client, int latencyMs)
    {
        var request = context.Request;
        string rawQuery = request.QueryString.HasValue ? request.QueryString.Value!.TrimStart('?') : "";
        context.Items.TryGetValue(UserIdItemKey, out var userIdValue);

        var input = new Observer.Input(
            request.Method,
            request.Path.Value ?? "",
            rawQuery,
            context.Response.StatusCode,
            latencyMs,
            request.Headers.UserAgent.ToString(),
            request.Headers["X-Forwarded-For"].ToString(),
            request.Headers["X-Real-IP"].ToString(),
            context.Connection.RemoteIpAddress?.ToString(),
            userIdValue as string);

        Observer.ObserveAndFlush(client, input);
    }

    private static bool IsExcluded(string path, IReadOnlyList<string> excludePaths)
    {
        foreach (var prefix in excludePaths)
        {
            if (path.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }
}
