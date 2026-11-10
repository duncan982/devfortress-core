using System.Net;

namespace DevFortress;

/// <summary>
/// Picks the end-user IP for an event from what the request shows.
/// </summary>
/// <remarks>
/// Precedence: the first X-Forwarded-For entry, then X-Real-IP, then the socket address,
/// then <c>"0.0.0.0"</c>. A candidate that is not an IP address is skipped, so a malformed
/// forwarded header cannot poison a batch. Mirrors <c>packages/devfortress-go/clientip.go</c>.
/// </remarks>
public static class ClientIp
{
    public static string Resolve(string? forwardedFor, string? realIp, string? remoteAddr)
    {
        string first = "";
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            int comma = forwardedFor.IndexOf(',');
            first = (comma == -1 ? forwardedFor : forwardedFor[..comma]).Trim();
        }

        foreach (var candidate in new[] { first, Trim(realIp), Trim(remoteAddr) })
        {
            if (candidate.Length > 0 && IPAddress.TryParse(candidate, out _))
            {
                return candidate;
            }
        }
        return "0.0.0.0";
    }

    private static string Trim(string? s) => s?.Trim() ?? "";
}
