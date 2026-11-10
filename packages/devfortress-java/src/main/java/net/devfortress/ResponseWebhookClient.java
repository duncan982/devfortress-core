package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Delivers closed-loop response commands (session revocation, IP block) to
 * a single customer-configured webhook endpoint — the outbound direction
 * of the closed loop, complementing {@link WebhookVerifier} (the inbound
 * direction: verifying a command the platform sent to this application).
 * Mirrors the outbound-delivery half of
 * {@code packages/devfortress-sdk/src/devfortress.ts} ({@code
 * deliverSessionRevocation}/{@code deliverIPBlock}/{@code
 * checkWebhookRateLimit}), the same way the Go/Ruby/PHP/.NET SDKs do.
 *
 * <p>Every delivery is HMAC-SHA256 signed the same way {@link
 * WebhookVerifier} checks it (hex HMAC over {@code "{timestamp}.{body}"}),
 * rate limited per endpoint (60/min — S28 webhook flooding protection),
 * and awaited with a short SLA timeout.
 */
public final class ResponseWebhookClient {
    private static final long RATE_WINDOW_MS = 60_000;
    private static final int RATE_LIMIT = 60;
    private static final int BLOCK_CACHE_MAX_ENTRIES = 10_000;
    private static final int DEFAULT_BLOCK_CACHE_TTL_SECONDS = 3600;

    public record DeliveryOutcome(boolean delivered, long ackMs) {
    }

    private final String url;
    private final String secret;
    private final Transport transport;
    private final Map<String, long[]> buckets = new HashMap<>(); // endpoint -> {count, windowStart}
    private final Object lock = new Object();
    private final BlockCache blockCache = new BlockCache(BLOCK_CACHE_MAX_ENTRIES, DEFAULT_BLOCK_CACHE_TTL_SECONDS);

    public ResponseWebhookClient(String url, String secret) {
        this(url, secret, new HttpTransport());
    }

    public ResponseWebhookClient(String url, String secret, Transport transport) {
        this.url = url;
        this.secret = secret;
        this.transport = transport;
    }

    /**
     * Reports whether {@code ip} was locally cached as blocked by a prior {@link
     * #recordInboundCommand} call — local-only, no network call. Mirrors Node's own
     * external-mode isBlocked()/memGet pair and Python's ClosedLoopEngine.is_blocked_ip (TODO
     * 358): this SDK previously delivered and verified block/revocation commands but never
     * self-enforced them locally, leaving every embedding app to implement its own cache.
     */
    public boolean isIpBlocked(String ip) {
        return blockCache.has("blocked:ip:" + ip);
    }

    /**
     * Reports whether {@code userId} was locally cached as blocked by a prior {@link
     * #recordInboundCommand} call — local-only, no network call.
     */
    public boolean isUserBlocked(String userId) {
        return blockCache.has("blocked:user:" + userId);
    }

    /**
     * Locally caches the block/revocation decision carried by an already-verified inbound
     * command (see {@link WebhookVerifier#verify} and {@link WebhookCommand#parse}), so a
     * subsequent {@link #isIpBlocked}/{@link #isUserBlocked} call enforces it without a remote
     * round-trip.
     *
     * <p>An "ip_block" command is cached only when its severity is "critical" or "high" (or
     * unset — {@link #deliverIpBlock(String, String)} defaults to "high" when the sender leaves
     * it empty), matching Node/Python's own severity gate. A "session_revocation" command
     * carries no severity field on this SDK's wire shape (see {@link
     * #deliverSessionRevocation(String, String, String, String)}'s body) — its delivery already
     * represents a decided enforcement action, so it is always cached.
     */
    public void recordInboundCommand(Map<String, Object> command) {
        Object ttlRaw = command.get("ttl_seconds");
        int ttlSeconds = (ttlRaw instanceof Number n && n.intValue() > 0) ? n.intValue() : DEFAULT_BLOCK_CACHE_TTL_SECONDS;
        Object type = command.get("type");

        if ("ip_block".equals(type)) {
            Object severity = command.get("severity");
            if (severity != null && !"high".equals(severity) && !"critical".equals(severity)) {
                return;
            }
            Object ip = command.get("ip");
            if (ip instanceof String s && !s.isEmpty()) {
                blockCache.set("blocked:ip:" + s, "1", ttlSeconds);
            }
        } else if ("session_revocation".equals(type)) {
            Object userId = command.get("user_id");
            Object ip = command.get("ip");
            if (userId instanceof String s && !s.isEmpty()) {
                blockCache.set("blocked:user:" + s, "1", ttlSeconds);
            }
            if (ip instanceof String s && !s.isEmpty()) {
                blockCache.set("blocked:ip:" + s, "1", ttlSeconds);
            }
        }
    }

    /** Deliver a session-revocation command, awaiting acknowledgement with a 2-second SLA timeout. */
    public DeliveryOutcome deliverSessionRevocation(String sessionId, String reason, String userId, String ip) {
        if (url == null || url.isEmpty() || secret == null || secret.isEmpty()) {
            return new DeliveryOutcome(false, 0);
        }
        if (!checkRateLimit(url)) {
            return new DeliveryOutcome(false, 0);
        }

        String timestamp = nowIso();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "session_revocation");
        body.put("session_id", sessionId);
        body.put("user_id", userId);
        body.put("reason", reason);
        body.put("ip", ip);
        body.put("issued_at", timestamp);

        return deliver(timestamp, Json.encode(body), Duration.ofSeconds(2));
    }

    public DeliveryOutcome deliverSessionRevocation(String sessionId, String reason) {
        return deliverSessionRevocation(sessionId, reason, null, null);
    }

    /** Deliver an IP-block command so the customer can enforce at the edge, awaiting acknowledgement with a 5-second SLA timeout. */
    public DeliveryOutcome deliverIpBlock(String ip, String reason, int ttlSeconds, String severity) {
        if (url == null || url.isEmpty() || secret == null || secret.isEmpty()) {
            return new DeliveryOutcome(false, 0);
        }
        if (!checkRateLimit(url)) {
            return new DeliveryOutcome(false, 0);
        }

        String timestamp = nowIso();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "ip_block");
        body.put("ip", ip);
        body.put("reason", reason);
        body.put("ttl_seconds", ttlSeconds);
        body.put("severity", severity != null ? severity : "high");
        body.put("issued_at", timestamp);

        return deliver(timestamp, Json.encode(body), Duration.ofSeconds(5));
    }

    public DeliveryOutcome deliverIpBlock(String ip, String reason) {
        return deliverIpBlock(ip, reason, 3600, "high");
    }

    private DeliveryOutcome deliver(String timestamp, String body, Duration timeout) {
        String signature = hex(hmacSha256(secret, timestamp + "." + body));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put(WebhookVerifier.SIGNATURE_HEADER, signature);
        headers.put(WebhookVerifier.TIMESTAMP_HEADER, timestamp);

        long start = System.currentTimeMillis();
        try {
            Transport.TransportResponse response = transport.send("POST", url, headers, body.getBytes(StandardCharsets.UTF_8), timeout);
            long ackMs = System.currentTimeMillis() - start;
            // Matches Node's axios default (throws on non-2xx, caught as "not delivered"): Transport
            // itself never throws on an HTTP error status, so the 2xx check happens here instead.
            return new DeliveryOutcome(response.statusCode() >= 200 && response.statusCode() < 300, ackMs);
        } catch (Exception e) {
            return new DeliveryOutcome(false, System.currentTimeMillis() - start);
        }
    }

    /** S28 webhook flooding protection: at most {@link #RATE_LIMIT} deliveries per endpoint per minute. */
    private boolean checkRateLimit(String endpointUrl) {
        synchronized (lock) {
            long now = System.currentTimeMillis();
            long[] bucket = buckets.get(endpointUrl);
            if (bucket == null || now - bucket[1] >= RATE_WINDOW_MS) {
                buckets.put(endpointUrl, new long[]{1, now});
                return true;
            }
            if (bucket[0] >= RATE_LIMIT) {
                return false;
            }
            bucket[0]++;
            return true;
        }
    }

    private static String nowIso() {
        return Instant.now().atZone(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"));
    }

    private static byte[] hmacSha256(String key, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    /** A parsed, already-verified inbound command (session_revocation or ip_block). Call {@link WebhookVerifier#verify} first; this does not re-verify the signature. */
    public static final class WebhookCommand {
        private WebhookCommand() {
        }

        @SuppressWarnings("unchecked")
        public static Map<String, Object> parse(String rawBody) {
            return (Map<String, Object>) Json.decode(rawBody);
        }
    }

    /** In-memory bounded TTL cache for local block/revocation self-enforcement (TODO 358), matching {@code CredentialIsolation}'s own {@code LruCache} shape. */
    private static final class BlockCache {
        private record Entry(String value, long expiresAtMs) {
        }

        private final int maxEntries;
        private final int defaultTtlSeconds;
        private final Map<String, Entry> cache = new HashMap<>();
        private final List<String> order = new ArrayList<>();
        private final Object lock = new Object();

        BlockCache(int maxEntries, int defaultTtlSeconds) {
            this.maxEntries = maxEntries;
            this.defaultTtlSeconds = defaultTtlSeconds;
        }

        String get(String key) {
            synchronized (lock) {
                Entry entry = cache.get(key);
                if (entry == null) {
                    return null;
                }
                if (System.currentTimeMillis() > entry.expiresAtMs()) {
                    cache.remove(key);
                    order.remove(key);
                    return null;
                }
                order.remove(key);
                order.add(key);
                return entry.value();
            }
        }

        void set(String key, String value, int ttlSeconds) {
            synchronized (lock) {
                if (!cache.containsKey(key) && cache.size() >= maxEntries && !order.isEmpty()) {
                    String oldest = order.remove(0);
                    cache.remove(oldest);
                }
                order.remove(key);
                order.add(key);
                int ttl = ttlSeconds > 0 ? ttlSeconds : defaultTtlSeconds;
                cache.put(key, new Entry(value, System.currentTimeMillis() + ttl * 1000L));
            }
        }

        boolean has(String key) {
            return get(key) != null;
        }
    }
}
