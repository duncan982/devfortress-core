package net.devfortress;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Maps an HTTP request/response to a security event, or decides it is not
 * security-relevant. Mirrors {@code packages/devfortress-go/classifier.go}.
 */
public final class Classifier {
    private Classifier() {
    }

    private static final Pattern[] SQL_PATTERNS = {
            Pattern.compile("\\bor\\b.*=.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bunion\\b.*\\bselect\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bdrop\\b.*\\btable\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'\\s*or\\s*'1'\\s*=\\s*'1", Pattern.CASE_INSENSITIVE),
    };

    private static final Pattern[] XSS_PATTERNS = {
            Pattern.compile("<script[^>]*>[\\s\\S]*?</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("onerror\\s*=\\s*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("onload\\s*=\\s*", Pattern.CASE_INSENSITIVE),
    };

    private static final Pattern[] TRAVERSAL_PATTERNS = {
            Pattern.compile("\\.\\.[/\\\\]"),
            Pattern.compile("/etc/passwd", Pattern.CASE_INSENSITIVE),
    };

    /**
     * Returns the names of the suspicious patterns found in {@code text}:
     * any of "sql_injection", "xss", "path_traversal". Matches the raw text
     * and one percent-decoding pass (form-style "+" as space); an invalid
     * percent-sequence is skipped rather than treated as an error.
     */
    public static List<String> detectSuspicious(String text) {
        List<String> candidates = new ArrayList<>();
        candidates.add(text);
        String decoded = tryUrlDecode(text);
        if (decoded != null && !decoded.equals(text)) {
            candidates.add(decoded);
        }

        List<String> found = new ArrayList<>();
        if (hit(SQL_PATTERNS, candidates)) {
            found.add("sql_injection");
        }
        if (hit(XSS_PATTERNS, candidates)) {
            found.add("xss");
        }
        if (hit(TRAVERSAL_PATTERNS, candidates)) {
            found.add("path_traversal");
        }
        return found;
    }

    private static String tryUrlDecode(String text) {
        try {
            return URLDecoder.decode(text, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean hit(Pattern[] patterns, List<String> candidates) {
        for (String candidate : candidates) {
            for (Pattern pattern : patterns) {
                if (pattern.matcher(candidate).find()) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Input to {@link #buildEvent}. */
    public record ClassifyInput(
            String ip,
            String method,
            String path,
            int statusCode,
            int latencyMs,
            String userAgent,
            String query,
            String userId
    ) {
    }

    /** Maps an HTTP response to a security event, or null when not security-relevant. */
    public static Map<String, Object> buildEvent(ClassifyInput in) {
        String eventType = "";
        String reason = "";
        String action = "";
        String severity = "LOW";

        if (in.statusCode() == 401 || in.statusCode() == 403) {
            eventType = "auth_failure";
            severity = "MEDIUM";
            reason = "Authentication or authorization failed";
            action = "blocked";
        } else if (in.statusCode() == 400 || in.statusCode() == 422) {
            eventType = "validation_error";
            reason = "Request validation failed";
        } else if (in.statusCode() == 429) {
            eventType = "rate_limit_exceeded";
            severity = "MEDIUM";
            reason = "Rate limit exceeded";
            action = "rate_limited";
        } else if (in.statusCode() >= 500) {
            eventType = "5xx_error";
            severity = "HIGH";
            reason = "Server error: " + in.statusCode();
        } else if (in.statusCode() >= 400) {
            eventType = "4xx_error";
            reason = "Client error: " + in.statusCode();
        }
        if (action.isEmpty()) {
            action = "monitored";
        }

        List<String> suspicious = detectSuspicious(in.path() + " " + nullToEmpty(in.query()));
        if (!suspicious.isEmpty()) {
            eventType = "suspicious_pattern";
            severity = "HIGH";
            reason = "Suspicious patterns detected: " + String.join(", ", suspicious);
            action = "flagged";
        }

        if (eventType.isEmpty()) {
            return null;
        }

        String ip = (in.ip() == null || in.ip().isEmpty()) ? "0.0.0.0" : in.ip();
        String authPhase = (in.userId() == null || in.userId().isEmpty()) ? "pre_auth" : "post_auth";

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventType", eventType);
        event.put("ip", ip);
        event.put("method", in.method());
        event.put("path", in.path());
        event.put("userAgent", blankToNull(in.userAgent()));
        event.put("statusCode", in.statusCode());
        event.put("severity", severity);
        event.put("clMode", "external");
        event.put("authPhase", authPhase);
        event.put("actionTaken", action);
        event.put("responseLatencyMs", in.latencyMs());
        event.put("userId", blankToNull(in.userId()));
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("reason", reason);
        event.put("metadata", metadata);
        return event;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String blankToNull(String s) {
        return (s == null || s.isEmpty()) ? null : s;
    }
}
