using System.Text.RegularExpressions;

namespace DevFortress;

/// <summary>
/// Maps an HTTP request/response to a security event, or decides it is not security-relevant.
/// Mirrors <c>packages/devfortress-go/classifier.go</c>.
/// </summary>
public static class Classifier
{
    private static readonly Regex[] SqlPatterns =
    [
        new(@"\bor\b.*=.*", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bunion\b.*\bselect\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bdrop\b.*\btable\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"'\s*or\s*'1'\s*=\s*'1", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    private static readonly Regex[] XssPatterns =
    [
        new(@"<script[^>]*>[\s\S]*?</script>", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"javascript:", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"onerror\s*=\s*", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"onload\s*=\s*", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    private static readonly Regex[] TraversalPatterns =
    [
        new(@"\.\.[/\\]", RegexOptions.Compiled),
        new("/etc/passwd", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    /// <summary>
    /// Returns the names of the suspicious patterns found in <paramref name="text"/>: any of
    /// "sql_injection", "xss", "path_traversal". Matches the raw text and one percent-decoding
    /// pass (form-style "+" as space); an invalid percent-sequence is skipped rather than
    /// treated as an error.
    /// </summary>
    public static List<string> DetectSuspicious(string text)
    {
        var candidates = new List<string> { text };
        string? decoded = TryUrlDecode(text);
        if (decoded is not null && decoded != text)
        {
            candidates.Add(decoded);
        }

        var found = new List<string>();
        if (Hit(SqlPatterns, candidates))
        {
            found.Add("sql_injection");
        }
        if (Hit(XssPatterns, candidates))
        {
            found.Add("xss");
        }
        if (Hit(TraversalPatterns, candidates))
        {
            found.Add("path_traversal");
        }
        return found;
    }

    private static string? TryUrlDecode(string text)
    {
        try
        {
            return System.Net.WebUtility.UrlDecode(text);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static bool Hit(Regex[] patterns, List<string> candidates)
    {
        foreach (var candidate in candidates)
        {
            foreach (var pattern in patterns)
            {
                if (pattern.IsMatch(candidate))
                {
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>Input to <see cref="BuildEvent"/>.</summary>
    public sealed record ClassifyInput(
        string? Ip,
        string Method,
        string Path,
        int StatusCode,
        int LatencyMs,
        string? UserAgent,
        string? Query,
        string? UserId);

    /// <summary>Maps an HTTP response to a security event, or null when not security-relevant.</summary>
    public static Dictionary<string, object?>? BuildEvent(ClassifyInput input)
    {
        string eventType = "";
        string reason = "";
        string action = "";
        string severity = "LOW";

        if (input.StatusCode is 401 or 403)
        {
            eventType = "auth_failure";
            severity = "MEDIUM";
            reason = "Authentication or authorization failed";
            action = "blocked";
        }
        else if (input.StatusCode is 400 or 422)
        {
            eventType = "validation_error";
            reason = "Request validation failed";
        }
        else if (input.StatusCode == 429)
        {
            eventType = "rate_limit_exceeded";
            severity = "MEDIUM";
            reason = "Rate limit exceeded";
            action = "rate_limited";
        }
        else if (input.StatusCode >= 500)
        {
            eventType = "5xx_error";
            severity = "HIGH";
            reason = $"Server error: {input.StatusCode}";
        }
        else if (input.StatusCode >= 400)
        {
            eventType = "4xx_error";
            reason = $"Client error: {input.StatusCode}";
        }
        if (action.Length == 0)
        {
            action = "monitored";
        }

        var suspicious = DetectSuspicious($"{input.Path} {input.Query ?? ""}");
        if (suspicious.Count > 0)
        {
            eventType = "suspicious_pattern";
            severity = "HIGH";
            reason = $"Suspicious patterns detected: {string.Join(", ", suspicious)}";
            action = "flagged";
        }

        if (eventType.Length == 0)
        {
            return null;
        }

        string ip = string.IsNullOrEmpty(input.Ip) ? "0.0.0.0" : input.Ip;
        string authPhase = string.IsNullOrEmpty(input.UserId) ? "pre_auth" : "post_auth";

        return new Dictionary<string, object?>
        {
            ["eventType"] = eventType,
            ["ip"] = ip,
            ["method"] = input.Method,
            ["path"] = input.Path,
            ["userAgent"] = BlankToNull(input.UserAgent),
            ["statusCode"] = input.StatusCode,
            ["severity"] = severity,
            ["clMode"] = "external",
            ["authPhase"] = authPhase,
            ["actionTaken"] = action,
            ["responseLatencyMs"] = input.LatencyMs,
            ["userId"] = BlankToNull(input.UserId),
            ["metadata"] = new Dictionary<string, object?> { ["reason"] = reason },
        };
    }

    private static string? BlankToNull(string? s) => string.IsNullOrEmpty(s) ? null : s;
}
