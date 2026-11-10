using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DevFortress;

/// <summary>
/// Delivers closed-loop response commands (session revocation, IP block) to a single
/// customer-configured webhook endpoint — the outbound direction of the closed loop,
/// complementing <see cref="WebhookVerifier"/> (the inbound direction: verifying a command the
/// platform sent to this application). Mirrors the outbound-delivery half of
/// <c>packages/devfortress-sdk/src/devfortress.ts</c> (deliverSessionRevocation /
/// deliverIPBlock / checkWebhookRateLimit), the same way Go's/Ruby's/PHP's SDKs do.
/// </summary>
/// <remarks>
/// Every delivery is HMAC-SHA256 signed the same way <see cref="WebhookVerifier"/> checks it
/// (hex HMAC over "{timestamp}.{body}"), rate limited per endpoint (60/min — S28 webhook
/// flooding protection), and awaited with a short SLA timeout.
/// </remarks>
public sealed record WebhookDeliveryOutcome(bool Delivered, int AckMs);

public sealed class ResponseWebhookClient(string? url, string? secret, ITransport? transport = null)
{
    private const int RateWindowMs = 60_000;
    private const int RateLimit = 60;
    private const int BlockCacheMaxEntries = 10_000;
    private const int DefaultBlockCacheTtlSeconds = 3600;

    private readonly ITransport _transport = transport ?? new HttpTransport();
    private readonly Dictionary<string, (int Count, long WindowStart)> _buckets = [];
    private readonly object _lock = new();
    private readonly LruCache _blockCache = new(BlockCacheMaxEntries, DefaultBlockCacheTtlSeconds);

    /// <summary>
    /// Reports whether <paramref name="ip"/> was locally cached as blocked by a prior
    /// <see cref="RecordInboundCommand"/> call — local-only, no network call. Mirrors Node's own
    /// external-mode isBlocked()/memGet pair and Python's ClosedLoopEngine.is_blocked_ip (TODO
    /// 358): this SDK previously delivered and verified block/revocation commands but never
    /// self-enforced them locally, leaving every embedding app to implement its own cache.
    /// </summary>
    public bool IsIpBlocked(string ip) => _blockCache.Has($"blocked:ip:{ip}");

    /// <summary>
    /// Reports whether <paramref name="userId"/> was locally cached as blocked by a prior
    /// <see cref="RecordInboundCommand"/> call — local-only, no network call.
    /// </summary>
    public bool IsUserBlocked(string userId) => _blockCache.Has($"blocked:user:{userId}");

    /// <summary>
    /// Locally caches the block/revocation decision carried by an already-verified inbound
    /// command (see <see cref="WebhookVerifier.Verify"/> and <see cref="WebhookCommand.Parse"/>),
    /// so a subsequent <see cref="IsIpBlocked"/>/<see cref="IsUserBlocked"/> call enforces it
    /// without a remote round-trip.
    /// </summary>
    /// <remarks>
    /// An "ip_block" command is cached only when its severity is "critical" or "high" (or unset
    /// — <see cref="DeliverIpBlockAsync"/> defaults to "high" when the sender leaves it empty),
    /// matching Node/Python's own severity gate. A "session_revocation" command carries no
    /// severity field on this SDK's wire shape (see <see cref="DeliverSessionRevocationAsync"/>'s
    /// body) — its delivery already represents a decided enforcement action, so it is always
    /// cached.
    /// </remarks>
    public void RecordInboundCommand(JsonElement command)
    {
        int ttlSeconds = command.TryGetProperty("ttl_seconds", out var ttlProp) && ttlProp.TryGetInt32(out int ttl) && ttl > 0
            ? ttl
            : DefaultBlockCacheTtlSeconds;
        string? type = command.TryGetProperty("type", out var typeProp) ? typeProp.GetString() : null;

        switch (type)
        {
            case "ip_block":
                string? severity = command.TryGetProperty("severity", out var sevProp) ? sevProp.GetString() : null;
                if (severity is not null && severity is not ("high" or "critical"))
                {
                    return;
                }
                if (command.TryGetProperty("ip", out var ipProp) && ipProp.GetString() is { Length: > 0 } ip)
                {
                    _blockCache.Set($"blocked:ip:{ip}", "1", ttlSeconds);
                }
                break;
            case "session_revocation":
                if (command.TryGetProperty("user_id", out var userIdProp) && userIdProp.GetString() is { Length: > 0 } userId)
                {
                    _blockCache.Set($"blocked:user:{userId}", "1", ttlSeconds);
                }
                if (command.TryGetProperty("ip", out var ip2Prop) && ip2Prop.GetString() is { Length: > 0 } revocationIp)
                {
                    _blockCache.Set($"blocked:ip:{revocationIp}", "1", ttlSeconds);
                }
                break;
        }
    }

    /// <summary>Deliver a session-revocation command, awaiting acknowledgement with a 2-second SLA timeout.</summary>
    public async Task<WebhookDeliveryOutcome> DeliverSessionRevocationAsync(string sessionId, string reason, string? userId = null, string? ip = null)
    {
        if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(secret))
        {
            return new WebhookDeliveryOutcome(false, 0);
        }
        if (!CheckRateLimit(url))
        {
            return new WebhookDeliveryOutcome(false, 0);
        }

        string timestamp = NowIso();
        string body = JsonSerializer.Serialize(new
        {
            type = "session_revocation",
            session_id = sessionId,
            user_id = userId,
            reason,
            ip,
            issued_at = timestamp,
        });

        return await DeliverAsync(timestamp, body, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
    }

    /// <summary>Deliver an IP-block command so the customer can enforce at the edge (CDN/WAF/load balancer), awaiting acknowledgement with a 5-second SLA timeout.</summary>
    public async Task<WebhookDeliveryOutcome> DeliverIpBlockAsync(string ip, string reason, int ttlSeconds = 3600, string severity = "high")
    {
        if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(secret))
        {
            return new WebhookDeliveryOutcome(false, 0);
        }
        if (!CheckRateLimit(url))
        {
            return new WebhookDeliveryOutcome(false, 0);
        }

        string timestamp = NowIso();
        string body = JsonSerializer.Serialize(new
        {
            type = "ip_block",
            ip,
            reason,
            ttl_seconds = ttlSeconds,
            severity,
            issued_at = timestamp,
        });

        return await DeliverAsync(timestamp, body, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
    }

    private async Task<WebhookDeliveryOutcome> DeliverAsync(string timestamp, string body, TimeSpan timeout)
    {
        string signature = Convert.ToHexString(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret!), Encoding.UTF8.GetBytes($"{timestamp}.{body}"))).ToLowerInvariant();

        var headers = new Dictionary<string, string>
        {
            ["Content-Type"] = "application/json",
            [WebhookVerifier.SignatureHeader] = signature,
            [WebhookVerifier.TimestampHeader] = timestamp,
        };

        long start = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        try
        {
            var response = await _transport.SendAsync("POST", url!, headers, Encoding.UTF8.GetBytes(body), timeout).ConfigureAwait(false);
            int ackMs = (int)(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - start);
            // Matches Node's axios default (throws on non-2xx, caught as "not delivered") and
            // Ruby's/Go's equivalent: ITransport itself never throws on an HTTP error status
            // (see its type doc), so the 2xx check has to happen here instead.
            return new WebhookDeliveryOutcome(response.StatusCode is >= 200 and < 300, ackMs);
        }
        catch
        {
            return new WebhookDeliveryOutcome(false, (int)(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - start));
        }
    }

    /// <summary>S28 webhook flooding protection: at most <see cref="RateLimit"/> deliveries per endpoint per minute.</summary>
    private bool CheckRateLimit(string endpointUrl)
    {
        lock (_lock)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (!_buckets.TryGetValue(endpointUrl, out var bucket) || now - bucket.WindowStart >= RateWindowMs)
            {
                _buckets[endpointUrl] = (1, now);
                return true;
            }
            if (bucket.Count >= RateLimit)
            {
                return false;
            }
            _buckets[endpointUrl] = (bucket.Count + 1, bucket.WindowStart);
            return true;
        }
    }

    private static string NowIso() => DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
}

/// <summary>A parsed, already-verified inbound command from the platform (session_revocation or ip_block) — the inbound direction of the closed loop. Call <see cref="WebhookVerifier.Verify"/> first; this does not re-verify the signature.</summary>
public static class WebhookCommand
{
    public static JsonElement Parse(string rawBody) => JsonDocument.Parse(rawBody).RootElement;
}
