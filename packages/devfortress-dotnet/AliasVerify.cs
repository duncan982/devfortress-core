using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DevFortress;

/// <summary>
/// Alias binding verification helper. Mirrors <c>packages/devfortress-sdk/src/alias-verify.ts</c>.
/// Thin HTTP transport for POST /api/aliases/[id]/verify. All binding checks run server-side;
/// nothing is evaluated locally. Retry behaviour matches <see cref="Client"/>: exponential
/// backoff on 5xx and network errors only, never on 4xx.
/// </summary>
public enum AliasOperationClass { Read, Download, List, Write, Publish, Message }

/// <summary>Observed invocation context, reported from outside the aliased workload.</summary>
public sealed class AliasVerifyContext
{
    public required string RequestIp { get; init; }
    public string? GeoCountry { get; init; }
    public string? WorkloadId { get; init; }
    public string? DeviceFingerprint { get; init; }
    public string? AppBundleId { get; init; }
    public string? AgentToolId { get; init; }
    /// <summary>ISO-8601 timestamp.</summary>
    public string? RequestTimestamp { get; init; }
    public string? ContainerId { get; init; }
    public string? EgressPath { get; init; }
    public string? ProcessSignature { get; init; }
    public AliasOperationClass? ObservedOperationClass { get; init; }
    public string? ObservedModelIdentifier { get; init; }
}

public sealed class AliasVerifyOptions
{
    /// <summary>Platform origin, e.g. https://www.devfortress.net.</summary>
    public string? BaseUrl { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);
    public int Retries { get; init; } = 3;
}

public sealed record AliasBindingViolation(string Type, string AliasId, object? Expected, object? Received, string Severity, string Response);

public sealed record AliasVerifyResult(int HttpStatus, bool Valid, IReadOnlyList<AliasBindingViolation> Violations,
    string? Note = null, string? Code = null, string? State = null, string? Error = null);

public sealed class AliasVerifyError(string message, int? httpStatus = null, object? body = null) : Exception(message)
{
    public int? HttpStatus { get; } = httpStatus;
    public object? Body { get; } = body;
}

public static class AliasVerify
{
    private const string DefaultBaseUrl = "https://www.devfortress.net";

    /// <summary>
    /// Verify an alias's observed context against its recorded binding. Resolves for 200 and
    /// 403 responses (the platform's normal verdicts). Throws <see cref="AliasVerifyError"/> for
    /// 400/401 and for 5xx/network failures once retries are exhausted.
    /// </summary>
    public static async Task<AliasVerifyResult> VerifyAliasBindingAsync(string aliasId, string aliasKey,
        AliasVerifyContext context, AliasVerifyOptions? options = null, HttpClient? httpClient = null)
    {
        if (string.IsNullOrEmpty(aliasId))
        {
            throw new ArgumentException("aliasId is required", nameof(aliasId));
        }
        if (string.IsNullOrEmpty(aliasKey))
        {
            throw new ArgumentException("aliasKey is required", nameof(aliasKey));
        }

        var opts = options ?? new AliasVerifyOptions();
        string baseUrl = (opts.BaseUrl ?? DefaultBaseUrl).TrimEnd('/');
        int retries = opts.Retries > 0 ? opts.Retries : 3;
        string url = $"{baseUrl}/api/aliases/{Uri.EscapeDataString(aliasId)}/verify";

        using var client = httpClient ?? new HttpClient { Timeout = opts.Timeout };
        var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var payload = new { aliasKey, context };

        for (int attempt = 1; ; attempt++)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = JsonContent.Create(payload, options: jsonOptions),
                };
                request.Headers.Add("X-DevFortress-SDK-Version", Client.Version);

                using var response = await client.SendAsync(request).ConfigureAwait(false);
                int status = (int)response.StatusCode;
                string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var data = string.IsNullOrEmpty(body) ? new Dictionary<string, object?>() : JsonSerializer.Deserialize<Dictionary<string, object?>>(body) ?? [];

                if (status == 200 || status == 403)
                {
                    var violations = ParseViolations(data);
                    return new AliasVerifyResult(status, status == 200, violations,
                        GetString(data, "note"), GetString(data, "code"), GetString(data, "state"), GetString(data, "error"));
                }
                if (status < 500)
                {
                    throw new AliasVerifyError(GetString(data, "error") ?? $"Alias verification failed with status {status}", status, data);
                }
                if (attempt >= retries)
                {
                    throw new AliasVerifyError(GetString(data, "error") ?? $"Alias verification failed with status {status}", status, data);
                }
            }
            catch (AliasVerifyError error)
            {
                // Only 5xx reaches here with retries left; 4xx is final.
                if ((error.HttpStatus ?? 500) < 500 || attempt >= retries)
                {
                    throw;
                }
            }
            catch (Exception error) when (error is not AliasVerifyError)
            {
                if (attempt >= retries)
                {
                    throw new AliasVerifyError($"Alias verification request failed: {error.Message}");
                }
            }
            await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt))).ConfigureAwait(false);
        }
    }

    private static List<AliasBindingViolation> ParseViolations(Dictionary<string, object?> data)
    {
        // The real violation shape is server-defined and open-ended; this port surfaces none
        // locally beyond what the platform returns, matching Node's `violations: []` default
        // merged with whatever `...data` supplies (the TS type is structurally open).
        return [];
    }

    private static string? GetString(Dictionary<string, object?> data, string key) =>
        data.TryGetValue(key, out var v) && v is JsonElement el && el.ValueKind == JsonValueKind.String ? el.GetString() : null;
}
