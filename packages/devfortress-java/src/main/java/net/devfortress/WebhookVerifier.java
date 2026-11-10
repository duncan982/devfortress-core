package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verifies a DevFortress outbound webhook (POST /api/webhooks/deliver).
 *
 * <p>{@code X-DevFortress-Timestamp} is the ISO-8601 UTC timestamp of
 * dispatch; {@code X-DevFortress-Signature} is the hex HMAC-SHA256, keyed
 * with the project's webhook secret, over the UTF-8 bytes of
 * {@code "{timestamp}.{rawBody}"}. Mirrors
 * {@code packages/devfortress-go/webhook.go}.
 */
public final class WebhookVerifier {
    public static final long TOLERANCE_SECONDS = 300;
    public static final String SIGNATURE_HEADER = "X-DevFortress-Signature";
    public static final String TIMESTAMP_HEADER = "X-DevFortress-Timestamp";

    private static final Pattern HEX_SIG_PATTERN = Pattern.compile("^[0-9a-fA-F]{64}$");
    private static final Pattern HEX_NONCE_PATTERN = Pattern.compile("^[0-9a-f]{32}$");

    /** Outcome of {@link #verify}. */
    public record Result(boolean valid, String reason) {
        static Result rejected(String reason) {
            return new Result(false, reason);
        }

        static Result accepted() {
            return new Result(true, null);
        }
    }

    public static final class Options {
        long toleranceMs = TOLERANCE_SECONDS * 1000;
        Long nowMs;
        Predicate<String> nonceCheck;

        public Options tolerance(long millis) {
            this.toleranceMs = millis;
            return this;
        }

        public Options now(long epochMs) {
            this.nowMs = epochMs;
            return this;
        }

        /**
         * A callback returning true the first time a nonce is seen and false
         * on replay. When supplied, a missing or malformed nonce fails
         * verification. This library keeps no state; replay tracking is the
         * caller's.
         */
        public Options nonceCheck(Predicate<String> check) {
            this.nonceCheck = check;
            return this;
        }
    }

    private WebhookVerifier() {
    }

    public static Result verify(String rawBody, String signature, String timestamp, String secret) {
        return verify(rawBody, signature, timestamp, secret, new Options());
    }

    public static Result verify(String rawBody, String signature, String timestamp, String secret, Options opts) {
        Long tsMs = parseIsoMs(timestamp);
        if (tsMs == null) {
            return Result.rejected("invalid_timestamp");
        }
        long now = opts.nowMs != null ? opts.nowMs : System.currentTimeMillis();
        long ageMs = now - tsMs;
        if (ageMs > opts.toleranceMs) {
            return Result.rejected("timestamp_expired");
        }

        if (signature == null || !HEX_SIG_PATTERN.matcher(signature).matches()) {
            return Result.rejected("invalid_signature");
        }
        byte[] given = hexDecode(signature);

        byte[] expected = hmacSha256(secret, timestamp + "." + rawBody);
        if (!MessageDigest.isEqual(expected, given)) {
            return Result.rejected("signature_mismatch");
        }

        if (opts.nonceCheck != null) {
            Object decoded;
            try {
                decoded = Json.decode(rawBody);
            } catch (RuntimeException e) {
                return Result.rejected("invalid_body");
            }
            String nonce = null;
            if (decoded instanceof Map<?, ?> map && map.get("nonce") instanceof String s) {
                nonce = s;
            }
            if (nonce == null || !HEX_NONCE_PATTERN.matcher(nonce).matches()) {
                return Result.rejected("nonce_invalid");
            }
            if (!opts.nonceCheck.test(nonce)) {
                return Result.rejected("replay_detected");
            }
        }

        return Result.accepted();
    }

    private static byte[] hexDecode(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
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

    /**
     * Returns epoch milliseconds for an ISO-8601 timestamp with a zone, or
     * null when value is malformed or not a valid calendar date.
     */
    private static Long parseIsoMs(String value) {
        if (value == null) {
            return null;
        }
        try {
            OffsetDateTime odt = OffsetDateTime.parse(value, DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            return odt.toInstant().toEpochMilli();
        } catch (DateTimeParseException e) {
            try {
                Instant instant = Instant.parse(value);
                return instant.toEpochMilli();
            } catch (DateTimeParseException e2) {
                return null;
            }
        }
    }
}
