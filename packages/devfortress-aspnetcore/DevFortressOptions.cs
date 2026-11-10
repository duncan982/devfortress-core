namespace DevFortress.AspNetCore;

/// <summary>Options for <see cref="DevFortressMiddlewareExtensions.UseDevFortress"/>.</summary>
public sealed class DevFortressOptions
{
    /// <summary>Path prefixes to skip reporting for. Defaults to <c>["/health", "/up"]</c>, matching devfortress-laravel/-rails/-spring-boot.</summary>
    public IReadOnlyList<string> ExcludePaths { get; set; } = ["/health", "/up"];

    /// <summary>
    /// When the <see cref="Client"/> is in "internal" or "hybrid" mode (see
    /// <see cref="Client.Mode"/>), whether the pre-response gate calls
    /// <see cref="Microsoft.AspNetCore.Http.HttpRequest.EnableBuffering"/> and reads the full
    /// request body before evaluating Tier 1 rules, so body-based SQLi/XSS patterns can fire on
    /// this path too.
    ///
    /// <para>Default <c>false</c> — the gate inspects only IP, method, path, query string, and
    /// headers, matching the Python port's FastAPI/Starlette ASGI middleware's documented scope
    /// limitation (re-reading a request body without replaying it to the downstream app would
    /// break every route that reads its own body). Turning this on adds per-request memory
    /// overhead (the whole body is buffered) and requires <see cref="UseDevFortress"/> to run
    /// early enough in the pipeline — before any other middleware reads
    /// <see cref="Microsoft.AspNetCore.Http.HttpRequest.Body"/> without itself calling
    /// <c>EnableBuffering()</c> first — or this gate's own buffered read can interfere with that
    /// other middleware's read. This gate always resets <c>Request.Body.Position</c> to 0 after
    /// reading, so the downstream pipeline sees the body from the start exactly as if this gate
    /// had not run, as long as that ordering requirement is met.</para>
    /// </summary>
    public bool InspectRequestBody { get; set; } = false;
}
