using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DevFortress;

/// <summary>
/// Computes request integrity headers for every SDK-to-platform call (contract v2).
/// </summary>
/// <remarks>
/// Canonical string: <c>"{METHOD}.{requestTarget}.{timestamp}.{nonce}.{payloadHash}"</c>
/// where METHOD is the uppercase HTTP method, requestTarget is the URL path plus
/// <c>"?query"</c> exactly as sent (no host, no re-encoding), and payloadHash is the
/// lowercase hex SHA-256 of the exact body bytes (the empty string for a request with
/// no body). The signature is the lowercase hex HMAC-SHA256 of that string, keyed with
/// the project API key (UTF-8). The timestamp is Unix epoch milliseconds; the nonce is
/// a dashed UUID v4, fresh for every request attempt. Tolerance is 300 seconds.
///
/// The API key never travels on a signed request. <c>X-DevFortress-Key-Id</c> is a
/// non-secret identifier derived from the key (first 32 hex characters of its SHA-256);
/// the platform verifies the HMAC with the key it has stored. Mirrors
/// <c>packages/devfortress-go/signer.go</c> byte-for-byte.
/// </remarks>
public sealed class Signer
{
    public const string SignatureVersion = "2";
    public const long ToleranceSeconds = 300;

    public const string KeyIdHeader = "X-DevFortress-Key-Id";
    public const string VersionHeader = "X-DevFortress-Signature-Version";
    public const string NonceHeader = "X-DevFortress-Nonce";
    public const string TimestampHeader = "X-DevFortress-Timestamp";
    public const string PayloadHashHeader = "X-DevFortress-Payload-Hash";
    public const string SignatureHeader = "X-DevFortress-Signature";

    private static readonly Regex TimestampPattern = new("^-?[0-9]+$", RegexOptions.Compiled);
    private static readonly Regex SchemeAuthorityPattern =
        new(@"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?]*", RegexOptions.Compiled);

    private readonly string _apiKey;

    public Signer(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey))
        {
            throw new ArgumentException("devfortress: an API key is required", nameof(apiKey));
        }
        _apiKey = apiKey;
    }

    /// <summary>Outcome of <see cref="Verify"/>.</summary>
    public enum VerifyResult
    {
        Valid,
        Invalid,
        Expired,
        Missing,
        UnsupportedVersion,
    }

    /// <summary>The non-secret key ID for <paramref name="apiKey"/>: first 32 lowercase hex chars of SHA-256.</summary>
    public static string DeriveKeyId(string apiKey)
    {
        byte[] sum = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));
        return ToHex(sum)[..32];
    }

    public string KeyId() => DeriveKeyId(_apiKey);

    /// <summary>
    /// Returns the six signing headers for one request attempt. A null or empty
    /// timestamp/nonce is filled in fresh (current time, random UUID v4); pass both
    /// explicitly only to reproduce a fixed vector in tests.
    /// </summary>
    public IReadOnlyDictionary<string, string> Sign(string method, string requestTarget, string body,
        string? timestamp = null, string? nonce = null)
    {
        string ts = string.IsNullOrEmpty(timestamp) ? NowMsString() : timestamp;
        string n = string.IsNullOrEmpty(nonce) ? Guid.NewGuid().ToString() : nonce;
        var (payloadHash, signature) = Digest(_apiKey, method, requestTarget, ts, n, body);

        return new Dictionary<string, string>
        {
            [KeyIdHeader] = KeyId(),
            [VersionHeader] = SignatureVersion,
            [NonceHeader] = n,
            [TimestampHeader] = ts,
            [PayloadHashHeader] = payloadHash,
            [SignatureHeader] = signature,
        };
    }

    /// <summary>
    /// Mirrors the platform's check for a signed request. <paramref name="headers"/> uses
    /// the wire header names (<see cref="KeyIdHeader"/>, ...). <paramref name="nowMs"/> is
    /// the current time as Unix epoch milliseconds, supplied by the caller so the result is
    /// reproducible in tests.
    /// </summary>
    public static VerifyResult Verify(string apiKey, string method, string requestTarget, string body,
        IReadOnlyDictionary<string, string?> headers, long nowMs)
    {
        headers.TryGetValue(NonceHeader, out var nonce);
        headers.TryGetValue(TimestampHeader, out var ts);
        headers.TryGetValue(PayloadHashHeader, out var payloadHash);
        headers.TryGetValue(SignatureHeader, out var signature);
        if (IsBlank(nonce) || IsBlank(ts) || IsBlank(payloadHash) || IsBlank(signature))
        {
            return VerifyResult.Missing;
        }

        headers.TryGetValue(VersionHeader, out var version);
        if (version != SignatureVersion)
        {
            return VerifyResult.UnsupportedVersion;
        }

        var (expectedHash, expectedSig) = Digest(apiKey, method, requestTarget, ts!, nonce!, body);
        bool hashOk = ConstantTimeEquals(expectedHash.ToLowerInvariant(), payloadHash!.ToLowerInvariant());
        bool sigOk = ConstantTimeEquals(expectedSig.ToLowerInvariant(), signature!.ToLowerInvariant());
        if (!(hashOk && sigOk))
        {
            return VerifyResult.Invalid;
        }

        if (!TimestampPattern.IsMatch(ts!))
        {
            return VerifyResult.Invalid;
        }
        if (!long.TryParse(ts, out long tsLong))
        {
            return VerifyResult.Invalid;
        }
        long age = Math.Abs(nowMs - tsLong);
        return age > ToleranceSeconds * 1000 ? VerifyResult.Expired : VerifyResult.Valid;
    }

    /// <summary>
    /// Returns the request target for <paramref name="rawUrl"/>: the path plus
    /// <c>"?query"</c> as written, with no scheme, host or fragment, and nothing
    /// re-encoded or normalised. An empty path is <c>"/"</c>.
    /// </summary>
    public static string RequestTargetFromUrl(string rawUrl)
    {
        string url = rawUrl;
        int hashIdx = url.IndexOf('#');
        if (hashIdx != -1)
        {
            url = url[..hashIdx];
        }
        string rest = SchemeAuthorityPattern.Replace(url, "", 1);
        if (rest.Length == 0 || rest[0] == '?')
        {
            return "/" + rest;
        }
        return rest;
    }

    private static string NowMsString() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();

    private static (string PayloadHash, string Signature) Digest(string apiKey, string method, string requestTarget,
        string timestamp, string nonce, string body)
    {
        string payloadHash = ToHex(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
        string canonical = $"{method.ToUpperInvariant()}.{requestTarget}.{timestamp}.{nonce}.{payloadHash}";
        string signature = ToHex(HMACSHA256.HashData(Encoding.UTF8.GetBytes(apiKey), Encoding.UTF8.GetBytes(canonical)));
        return (payloadHash, signature);
    }

    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static bool IsBlank(string? s) => string.IsNullOrEmpty(s);

    private static bool ConstantTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
