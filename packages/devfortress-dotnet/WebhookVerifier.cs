using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DevFortress;

/// <summary>
/// Verifies a DevFortress outbound webhook (POST /api/webhooks/deliver).
/// </summary>
/// <remarks>
/// <c>X-DevFortress-Timestamp</c> is the ISO-8601 UTC timestamp of dispatch;
/// <c>X-DevFortress-Signature</c> is the hex HMAC-SHA256, keyed with the project's
/// webhook secret, over the UTF-8 bytes of <c>"{timestamp}.{rawBody}"</c>. Mirrors
/// <c>packages/devfortress-go/webhook.go</c>.
/// </remarks>
public static class WebhookVerifier
{
    public const long ToleranceSeconds = 300;
    public const string SignatureHeader = "X-DevFortress-Signature";
    public const string TimestampHeader = "X-DevFortress-Timestamp";

    private static readonly Regex HexSignaturePattern = new("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);
    private static readonly Regex HexNoncePattern = new("^[0-9a-f]{32}$", RegexOptions.Compiled);

    /// <summary>Outcome of <see cref="Verify(string,string?,string?,string,Options?)"/>.</summary>
    public sealed record Result(bool Valid, string? Reason)
    {
        internal static Result Rejected(string reason) => new(false, reason);
        internal static Result Accepted() => new(true, null);
    }

    public sealed class Options
    {
        public long ToleranceMs { get; set; } = ToleranceSeconds * 1000;
        public long? NowMs { get; set; }

        /// <summary>
        /// A callback returning true the first time a nonce is seen and false on replay.
        /// When supplied, a missing or malformed nonce fails verification. This library
        /// keeps no state; replay tracking is the caller's.
        /// </summary>
        public Func<string, bool>? NonceCheck { get; set; }
    }

    public static Result Verify(string rawBody, string? signature, string? timestamp, string secret, Options? options = null)
    {
        var opts = options ?? new Options();
        long? tsMs = ParseIsoMs(timestamp);
        if (tsMs is null)
        {
            return Result.Rejected("invalid_timestamp");
        }
        long now = opts.NowMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        long ageMs = now - tsMs.Value;
        if (ageMs > opts.ToleranceMs)
        {
            return Result.Rejected("timestamp_expired");
        }

        if (signature is null || !HexSignaturePattern.IsMatch(signature))
        {
            return Result.Rejected("invalid_signature");
        }
        byte[] given = Convert.FromHexString(signature);

        byte[] expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"{timestamp}.{rawBody}"));
        if (!CryptographicOperations.FixedTimeEquals(expected, given))
        {
            return Result.Rejected("signature_mismatch");
        }

        if (opts.NonceCheck is not null)
        {
            string? nonce = null;
            try
            {
                using var doc = JsonDocument.Parse(rawBody);
                if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                    doc.RootElement.TryGetProperty("nonce", out var nonceEl) &&
                    nonceEl.ValueKind == JsonValueKind.String)
                {
                    nonce = nonceEl.GetString();
                }
            }
            catch (JsonException)
            {
                return Result.Rejected("invalid_body");
            }

            if (nonce is null || !HexNoncePattern.IsMatch(nonce))
            {
                return Result.Rejected("nonce_invalid");
            }
            if (!opts.NonceCheck(nonce))
            {
                return Result.Rejected("replay_detected");
            }
        }

        return Result.Accepted();
    }

    /// <summary>Returns epoch milliseconds for an ISO-8601 timestamp with a zone, or null when malformed.</summary>
    private static long? ParseIsoMs(string? value)
    {
        if (value is null)
        {
            return null;
        }
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
        {
            return dto.ToUnixTimeMilliseconds();
        }
        return null;
    }
}
