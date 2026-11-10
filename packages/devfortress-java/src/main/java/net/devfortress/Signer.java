package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Computes request integrity headers for every SDK-to-platform call
 * (contract v2).
 *
 * <p>Canonical string: {@code "{METHOD}.{requestTarget}.{timestamp}.{nonce}.{payloadHash}"}
 * where METHOD is the uppercase HTTP method, requestTarget is the URL path
 * plus {@code "?query"} exactly as sent (no host, no re-encoding), and
 * payloadHash is the lowercase hex SHA-256 of the exact body bytes (the
 * empty string for a request with no body). The signature is the lowercase
 * hex HMAC-SHA256 of that string, keyed with the project API key (UTF-8).
 * The timestamp is Unix epoch milliseconds; the nonce is a dashed UUID v4,
 * fresh for every request attempt. Tolerance is 300 seconds.
 *
 * <p>The API key never travels on a signed request. {@code X-DevFortress-Key-Id}
 * is a non-secret identifier derived from the key (first 32 hex characters
 * of its SHA-256); the platform verifies the HMAC with the key it has
 * stored. Mirrors {@code packages/devfortress-go/signer.go} byte-for-byte.
 */
public final class Signer {
    public static final String SIGNATURE_VERSION = "2";
    public static final long TOLERANCE_SECONDS = 300;

    public static final String KEY_ID_HEADER = "X-DevFortress-Key-Id";
    public static final String VERSION_HEADER = "X-DevFortress-Signature-Version";
    public static final String NONCE_HEADER = "X-DevFortress-Nonce";
    public static final String TIMESTAMP_HEADER = "X-DevFortress-Timestamp";
    public static final String PAYLOAD_HASH_HEADER = "X-DevFortress-Payload-Hash";
    public static final String SIGNATURE_HEADER = "X-DevFortress-Signature";

    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("^-?[0-9]+$");
    private static final Pattern SCHEME_AUTHORITY_PATTERN =
            Pattern.compile("^[A-Za-z][A-Za-z0-9+.\\-]*://[^/?]*");
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Outcome of {@link #verify}. */
    public enum VerifyResult {
        VALID, INVALID, EXPIRED, MISSING, UNSUPPORTED_VERSION
    }

    private final String apiKey;

    public Signer(String apiKey) {
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalArgumentException("devfortress: an API key is required");
        }
        this.apiKey = apiKey;
    }

    /** The non-secret key ID for {@code apiKey}: first 32 lowercase hex chars of SHA-256. */
    public static String deriveKeyId(String apiKey) {
        byte[] sum = sha256(apiKey.getBytes(StandardCharsets.UTF_8));
        return toHex(sum).substring(0, 32);
    }

    public String keyId() {
        return deriveKeyId(apiKey);
    }

    /**
     * Returns the six signing headers for one request attempt. A null or
     * empty timestamp/nonce is filled in fresh (current time, random UUID
     * v4); pass both explicitly only to reproduce a fixed vector in tests.
     */
    public Map<String, String> sign(String method, String requestTarget, String body, String timestamp, String nonce) {
        String ts = (timestamp == null || timestamp.isEmpty()) ? nowMsString() : timestamp;
        String n = (nonce == null || nonce.isEmpty()) ? uuidV4() : nonce;
        String[] digest = digest(apiKey, method, requestTarget, ts, n, body);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(KEY_ID_HEADER, keyId());
        headers.put(VERSION_HEADER, SIGNATURE_VERSION);
        headers.put(NONCE_HEADER, n);
        headers.put(TIMESTAMP_HEADER, ts);
        headers.put(PAYLOAD_HASH_HEADER, digest[0]);
        headers.put(SIGNATURE_HEADER, digest[1]);
        return headers;
    }

    /**
     * Mirrors the platform's check for a signed request. {@code headers}
     * uses the wire header names ({@link #KEY_ID_HEADER}, ...). {@code nowMs}
     * is the current time as Unix epoch milliseconds, supplied by the caller
     * so the result is reproducible in tests.
     */
    public static VerifyResult verify(String apiKey, String method, String requestTarget, String body,
                                       Map<String, String> headers, long nowMs) {
        String nonce = headers.get(NONCE_HEADER);
        String ts = headers.get(TIMESTAMP_HEADER);
        String payloadHash = headers.get(PAYLOAD_HASH_HEADER);
        String signature = headers.get(SIGNATURE_HEADER);
        if (isBlank(nonce) || isBlank(ts) || isBlank(payloadHash) || isBlank(signature)) {
            return VerifyResult.MISSING;
        }
        if (!SIGNATURE_VERSION.equals(headers.get(VERSION_HEADER))) {
            return VerifyResult.UNSUPPORTED_VERSION;
        }

        String[] expected = digest(apiKey, method, requestTarget, ts, nonce, body);
        boolean hashOk = constantTimeEquals(expected[0].toLowerCase(), payloadHash.toLowerCase());
        boolean sigOk = constantTimeEquals(expected[1].toLowerCase(), signature.toLowerCase());
        if (!(hashOk && sigOk)) {
            return VerifyResult.INVALID;
        }

        if (!TIMESTAMP_PATTERN.matcher(ts).matches()) {
            return VerifyResult.INVALID;
        }
        long tsLong;
        try {
            tsLong = Long.parseLong(ts);
        } catch (NumberFormatException e) {
            return VerifyResult.INVALID;
        }
        long age = Math.abs(nowMs - tsLong);
        if (age > TOLERANCE_SECONDS * 1000) {
            return VerifyResult.EXPIRED;
        }
        return VerifyResult.VALID;
    }

    /**
     * Returns the request target for {@code rawUrl}: the path plus
     * {@code "?query"} as written, with no scheme, host or fragment, and
     * nothing re-encoded or normalised. An empty path is {@code "/"}.
     */
    public static String requestTargetFromUrl(String rawUrl) {
        String url = rawUrl;
        int hashIdx = url.indexOf('#');
        if (hashIdx != -1) {
            url = url.substring(0, hashIdx);
        }
        String rest = SCHEME_AUTHORITY_PATTERN.matcher(url).replaceFirst("");
        if (rest.isEmpty() || rest.charAt(0) == '?') {
            return "/" + rest;
        }
        return rest;
    }

    /** A dashed UUID v4 from a cryptographically secure random source. */
    public static String uuidV4() {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        b[6] = (byte) ((b[6] & 0x0f) | 0x40);
        b[8] = (byte) ((b[8] & 0x3f) | 0x80);
        StringBuilder sb = new StringBuilder(36);
        appendHex(sb, b, 0, 4);
        sb.append('-');
        appendHex(sb, b, 4, 6);
        sb.append('-');
        appendHex(sb, b, 6, 8);
        sb.append('-');
        appendHex(sb, b, 8, 10);
        sb.append('-');
        appendHex(sb, b, 10, 16);
        return sb.toString();
    }

    private static void appendHex(StringBuilder sb, byte[] b, int from, int to) {
        for (int i = from; i < to; i++) {
            sb.append(String.format("%02x", b[i] & 0xff));
        }
    }

    private static String nowMsString() {
        return Long.toString(System.currentTimeMillis());
    }

    private static String[] digest(String apiKey, String method, String requestTarget, String timestamp,
                                     String nonce, String body) {
        String payloadHash = toHex(sha256(body.getBytes(StandardCharsets.UTF_8)));
        String canonical = method.toUpperCase() + "." + requestTarget + "." + timestamp + "." + nonce + "." + payloadHash;
        String signature = toHex(hmacSha256(apiKey, canonical));
        return new String[]{payloadHash, signature};
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
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

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static boolean isBlank(String s) {
        return s == null || s.isEmpty();
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
