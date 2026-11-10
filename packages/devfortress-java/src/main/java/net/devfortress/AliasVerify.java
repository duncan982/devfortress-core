package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Alias binding verification helper. Mirrors
 * {@code packages/devfortress-sdk/src/alias-verify.ts}.
 *
 * <p>Thin HTTP transport for {@code POST /api/aliases/{id}/verify}. All
 * binding checks run server-side; nothing is evaluated locally. Retry
 * behavior matches {@link Client}: exponential backoff on 5xx and
 * network errors only, never on 4xx.
 */
public final class AliasVerify {
    private static final String DEFAULT_BASE_URL = "https://www.devfortress.net";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(15);
    private static final int DEFAULT_RETRIES = 3;

    private AliasVerify() {
    }

    public record Context(String requestIp, String geoCountry, String workloadId, String deviceFingerprint,
                           String appBundleId, String agentToolId, String requestTimestamp, String containerId,
                           String egressPath, String processSignature, String observedOperationClass,
                           String observedModelIdentifier) {
        public Context(String requestIp) {
            this(requestIp, null, null, null, null, null, null, null, null, null, null, null);
        }
    }

    public record Options(String baseUrl, Duration timeout, int retries) {
        public Options() {
            this(null, null, 0);
        }
    }

    @SuppressWarnings("unchecked")
    public record Result(int httpStatus, boolean valid, List<Map<String, Object>> violations, String note,
                          String code, String state, String error) {
        static Result from(int status, Map<String, Object> data) {
            Object violationsRaw = data.get("violations");
            List<Map<String, Object>> violations = violationsRaw instanceof List<?> l
                    ? (List<Map<String, Object>>) (List<?>) l : List.of();
            return new Result(status,
                    Boolean.TRUE.equals(data.get("valid")),
                    violations,
                    (String) data.get("note"),
                    (String) data.get("code"),
                    (String) data.get("state"),
                    (String) data.get("error"));
        }
    }

    public static final class AliasVerifyException extends RuntimeException {
        public final Integer httpStatus;

        public AliasVerifyException(String message, Integer httpStatus) {
            super(message);
            this.httpStatus = httpStatus;
        }
    }

    /**
     * Verify an alias's observed context against its recorded binding.
     * Resolves for 200 and 403 responses (the platform's normal verdicts).
     * Throws {@link AliasVerifyException} for 400/401 and for 5xx/network
     * failures once retries are exhausted.
     */
    public static Result verifyAliasBinding(String aliasId, String aliasKey, Context context, Options options) {
        return verifyAliasBinding(aliasId, aliasKey, context, options, new HttpTransport());
    }

    @SuppressWarnings("unchecked")
    public static Result verifyAliasBinding(String aliasId, String aliasKey, Context context, Options options, Transport transport) {
        if (aliasId == null || aliasId.isEmpty()) {
            throw new IllegalArgumentException("verifyAliasBinding: aliasId is required");
        }
        if (aliasKey == null || aliasKey.isEmpty()) {
            throw new IllegalArgumentException("verifyAliasBinding: aliasKey is required");
        }

        String baseUrl = (options != null && options.baseUrl() != null ? options.baseUrl() : DEFAULT_BASE_URL)
                .replaceAll("/+$", "");
        int retries = options != null && options.retries() > 0 ? options.retries() : DEFAULT_RETRIES;
        Duration timeout = options != null && options.timeout() != null ? options.timeout() : DEFAULT_TIMEOUT;
        String url = baseUrl + "/api/aliases/" + urlEncode(aliasId) + "/verify";

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("aliasKey", aliasKey);
        payload.put("context", contextToMap(context));
        byte[] body = Json.encode(payload).getBytes(StandardCharsets.UTF_8);

        Map<String, String> headers = Map.of(
                "Content-Type", "application/json",
                "X-DevFortress-SDK-Version", Client.VERSION);

        for (int attempt = 1; ; attempt++) {
            Transport.TransportResponse response;
            try {
                response = transport.send("POST", url, headers, body, timeout);
            } catch (Exception networkError) {
                if (attempt >= retries) {
                    throw new AliasVerifyException("Alias verification request failed: " + networkError.getMessage(), null);
                }
                sleepBackoff(attempt);
                continue;
            }

            int status = response.statusCode();
            Map<String, Object> data;
            try {
                Object decoded = response.body() != null && response.body().length > 0
                        ? Json.decode(new String(response.body(), StandardCharsets.UTF_8)) : Map.of();
                data = decoded instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
            } catch (RuntimeException e) {
                data = Map.of();
            }

            if (status == 200 || status == 403) {
                return Result.from(status, data);
            }
            if (status < 500) {
                String error = data.get("error") instanceof String s ? s : "Alias verification failed with status " + status;
                throw new AliasVerifyException(error, status);
            }
            if (attempt >= retries) {
                String error = data.get("error") instanceof String s ? s : "Alias verification failed with status " + status;
                throw new AliasVerifyException(error, status);
            }
            sleepBackoff(attempt);
        }
    }

    private static void sleepBackoff(int attempt) {
        try {
            Thread.sleep((long) Math.pow(2, attempt) * 1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static Map<String, Object> contextToMap(Context c) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("requestIp", c.requestIp());
        map.put("geoCountry", c.geoCountry());
        map.put("workloadId", c.workloadId());
        map.put("deviceFingerprint", c.deviceFingerprint());
        map.put("appBundleId", c.appBundleId());
        map.put("agentToolId", c.agentToolId());
        map.put("requestTimestamp", c.requestTimestamp());
        map.put("containerId", c.containerId());
        map.put("egressPath", c.egressPath());
        map.put("processSignature", c.processSignature());
        map.put("observedOperationClass", c.observedOperationClass());
        map.put("observedModelIdentifier", c.observedModelIdentifier());
        return map;
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
